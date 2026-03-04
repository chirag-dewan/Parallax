"""T1-008: Concurrent Sessions — parallel session count anomaly."""

from __future__ import annotations

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale


class ConcurrentSessionsDetector(BaseDetector):
    RULE_ID = RuleID.T1_008
    RULE_NAME = "Concurrent Sessions"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 0.06
    min_events = 10

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        if profile.total_conversations < 2:
            return 0.0, {
                "max_concurrent": 1,
                "avg_concurrent": 1.0,
                "total_conversations": profile.total_conversations,
            }

        # Build conversation time windows: (start, end) per conversation
        events_list: list[tuple[float, int]] = []  # (timestamp, +1/-1)
        for conv_events in profile.conversations.values():
            if not conv_events:
                continue
            start_ts = conv_events[0].timestamp.timestamp()
            end_ts = conv_events[-1].timestamp.timestamp()
            # For single-event conversations, create a small window
            if start_ts == end_ts:
                end_ts += 1.0
            events_list.append((start_ts, 1))   # conversation start
            events_list.append((end_ts, -1))     # conversation end

        # Sweep line to find max concurrent
        events_list.sort(key=lambda x: (x[0], -x[1]))

        current = 0
        max_concurrent = 0
        total_area = 0.0
        prev_time = events_list[0][0] if events_list else 0.0

        for ts, delta in events_list:
            total_area += current * (ts - prev_time)
            prev_time = ts
            current += delta
            max_concurrent = max(max_concurrent, current)

        total_span = (
            events_list[-1][0] - events_list[0][0]
            if len(events_list) >= 2
            else 1.0
        )
        avg_concurrent = total_area / total_span if total_span > 0 else 0.0

        # Score: max_concurrent <= 2 -> 0.0, 3-5 -> 0.0-0.5, 6-10 -> 0.5-0.9, > 10 -> 1.0
        if max_concurrent <= 2:
            score = 0.0
        elif max_concurrent <= 5:
            score = linear_scale(max_concurrent, 2.0, 5.0) * 0.5
        elif max_concurrent <= 10:
            score = 0.5 + linear_scale(max_concurrent, 5.0, 10.0) * 0.4
        else:
            score = 1.0

        return score, {
            "max_concurrent": max_concurrent,
            "avg_concurrent": round(avg_concurrent, 2),
            "total_conversations": profile.total_conversations,
        }
