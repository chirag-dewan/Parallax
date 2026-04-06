"""T1-009: Host Fan-Out — lateral movement via destination diversity.

Designed for authentication log data (LANL Cyber1 and similar). Scores
based on how many distinct destination hosts a user touches within
sliding time windows — the primary signal for lateral movement.

The LANL adapter maps dst_computer into topic_category, so unique
topic_categories within a window proxy for unique hosts reached.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale


class HostFanoutDetector(BaseDetector):
    RULE_ID = RuleID.T1_009
    RULE_NAME = "Host Fan-Out"
    TIER = Tier.TIER_1
    THRESHOLD = 0.4
    WEIGHT = 0.10
    min_events = 20

    # Sliding window parameters
    WINDOW_SECONDS = 3600  # 1 hour
    STRIDE_SECONDS = 900   # 15-minute stride

    # Scoring thresholds for unique hosts per window.
    # LANL adapter maps dst_computer into 9 topic buckets, so effective
    # max is 9.  Real host-level data would use higher thresholds.
    LOW_FANOUT = 3
    HIGH_FANOUT = 8

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        events = profile.events
        if len(events) < self.min_events:
            return 0.0, {"reason": "insufficient_events"}

        start_ts = events[0].timestamp.timestamp()
        end_ts = events[-1].timestamp.timestamp()
        span = end_ts - start_ts

        if span < self.WINDOW_SECONDS:
            # Single window — just count unique topics
            unique = len({e.topic_category for e in events})
            score = linear_scale(
                unique, self.LOW_FANOUT, self.HIGH_FANOUT
            )
            return score, {
                "max_unique_hosts_in_window": unique,
                "peak_window_start": events[0].timestamp.isoformat(),
                "total_windows": 1,
                "new_hosts_per_hour": 0.0,
                "unique_to_event_ratio": round(unique / len(events), 4),
            }

        # Slide windows across the timeline
        max_unique = 0
        peak_window_start = start_ts
        window_scores: list[int] = []

        window_start = start_ts
        while window_start + self.WINDOW_SECONDS <= end_ts + self.STRIDE_SECONDS:
            window_end = window_start + self.WINDOW_SECONDS
            unique_hosts: set[str] = set()
            for e in events:
                ets = e.timestamp.timestamp()
                if window_start <= ets < window_end:
                    unique_hosts.add(e.topic_category)
                elif ets >= window_end:
                    break

            count = len(unique_hosts)
            window_scores.append(count)
            if count > max_unique:
                max_unique = count
                peak_window_start = window_start

            window_start += self.STRIDE_SECONDS

        # New-host velocity: total unique hosts / observation hours
        all_topics = {e.topic_category for e in events}
        obs_hours = span / 3600
        new_hosts_per_hour = len(all_topics) / obs_hours if obs_hours > 0 else 0.0

        # Unique-to-event ratio (high = spraying, low = deep on few hosts)
        unique_ratio = len(all_topics) / len(events)

        # Primary score: peak fan-out in any window
        fanout_score = linear_scale(
            max_unique, self.LOW_FANOUT, self.HIGH_FANOUT
        )

        # Velocity bonus: rapid new-host acquisition
        velocity_bonus = linear_scale(new_hosts_per_hour, 2.0, 8.0) * 0.3

        # Ratio bonus: high unique-to-event ratio means spraying
        ratio_bonus = linear_scale(unique_ratio, 0.1, 0.5) * 0.2

        score = min(1.0, fanout_score + velocity_bonus + ratio_bonus)

        # Average fan-out across windows for context
        avg_fanout = (
            sum(window_scores) / len(window_scores)
            if window_scores
            else 0.0
        )

        return score, {
            "max_unique_hosts_in_window": max_unique,
            "avg_unique_hosts_per_window": round(avg_fanout, 2),
            "peak_window_start": peak_window_start,
            "total_windows": len(window_scores),
            "new_hosts_per_hour": round(new_hosts_per_hour, 4),
            "unique_to_event_ratio": round(unique_ratio, 4),
            "total_unique_hosts": len(all_topics),
            "fanout_score": round(fanout_score, 4),
            "velocity_bonus": round(velocity_bonus, 4),
            "ratio_bonus": round(ratio_bonus, 4),
        }
