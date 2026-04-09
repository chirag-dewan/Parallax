"""T1-010: Data Transfer Anomaly — exfiltration via abnormal byte volume.

Flags sessions where bytes transferred exceeds 2.5 standard deviations
from the entity's rolling baseline.  Designed for flow-enriched auth data
(LANL Cyber1 flows.txt joined with auth.txt).

When flow data is absent (bytes_transferred == 0 for all events), the
detector returns score 0 with a diagnostic note.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import timedelta

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import sigmoid_normalize


class DataTransferAnomalyDetector(BaseDetector):
    RULE_ID = RuleID.T1_010
    RULE_NAME = "Data Transfer Anomaly"
    TIER = Tier.TIER_1
    THRESHOLD = 0.4
    WEIGHT = 0.0  # Activated via auth profile when flow data is present
    min_events = 10

    # Z-score threshold for anomaly
    SIGMA_THRESHOLD = 2.5

    # Rolling window for baseline computation (seconds)
    ROLLING_WINDOW_SECONDS = 3600  # 1 hour

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        bytes_list = profile.bytes_transferred_list

        # No flow data available — cannot score
        if not bytes_list or all(b == 0 for b in bytes_list):
            return 0.0, {
                "reason": "no_flow_data",
                "total_bytes": 0,
                "events_with_bytes": 0,
            }

        nonzero = [b for b in bytes_list if b > 0]
        events_with_bytes = len(nonzero)

        if events_with_bytes < 3:
            return 0.0, {
                "reason": "insufficient_flow_events",
                "events_with_bytes": events_with_bytes,
            }

        # Compute per-session byte aggregates using sliding windows
        events = profile.events
        session_bytes = self._compute_session_bytes(events)

        if len(session_bytes) < 2:
            # Not enough sessions for rolling baseline
            global_mean = sum(nonzero) / len(nonzero)
            global_std = math.sqrt(
                sum((b - global_mean) ** 2 for b in nonzero) / len(nonzero)
            )
            max_bytes = max(nonzero)
            if global_std == 0:
                return 0.0, {
                    "reason": "zero_variance",
                    "global_mean": round(global_mean, 2),
                    "max_bytes": max_bytes,
                }
            z = (max_bytes - global_mean) / global_std
            score = sigmoid_normalize(z, midpoint=self.SIGMA_THRESHOLD, steepness=1.2)
            return score, {
                "method": "global_zscore",
                "global_mean": round(global_mean, 2),
                "global_std": round(global_std, 2),
                "max_bytes": max_bytes,
                "peak_z_score": round(z, 4),
                "events_with_bytes": events_with_bytes,
            }

        # Rolling baseline: for each session, compute z-score against
        # the mean/std of all preceding sessions
        peak_z = 0.0
        peak_session_bytes = 0
        rolling_mean = 0.0
        rolling_std = 0.0
        history: list[int] = []

        for sb in session_bytes:
            if len(history) >= 2:
                mu = sum(history) / len(history)
                var = sum((h - mu) ** 2 for h in history) / len(history)
                sigma = math.sqrt(var)
                if sigma > 0:
                    z = (sb - mu) / sigma
                elif sb != mu:
                    # Zero variance but value differs from constant baseline:
                    # treat as extreme anomaly. Use mu * 0.01 as synthetic
                    # sigma (1% of mean) to produce a meaningful z-score.
                    synthetic_sigma = max(1.0, mu * 0.01)
                    z = (sb - mu) / synthetic_sigma
                else:
                    z = 0.0
                if z > peak_z:
                    peak_z = z
                    peak_session_bytes = sb
                    rolling_mean = mu
                    rolling_std = sigma
            history.append(sb)

        score = sigmoid_normalize(
            peak_z, midpoint=self.SIGMA_THRESHOLD, steepness=1.2
        )

        # Bonus: overall volume anomaly (total bytes vs expected)
        total = sum(session_bytes)
        expected_total = (sum(session_bytes) / len(session_bytes)) * len(session_bytes)
        volume_ratio = total / expected_total if expected_total > 0 else 1.0

        return score, {
            "method": "rolling_zscore",
            "peak_z_score": round(peak_z, 4),
            "peak_session_bytes": peak_session_bytes,
            "rolling_mean_at_peak": round(rolling_mean, 2),
            "rolling_std_at_peak": round(rolling_std, 2),
            "total_sessions": len(session_bytes),
            "total_bytes_transferred": sum(bytes_list),
            "events_with_bytes": events_with_bytes,
            "avg_bytes_per_event": round(profile.avg_bytes_per_event, 2),
        }

    @staticmethod
    def _compute_session_bytes(events: list) -> list[int]:
        """Aggregate bytes_transferred per conversation (session proxy)."""
        session_totals: dict[str, int] = defaultdict(int)
        session_order: list[str] = []

        for e in events:
            cid = e.conversation_id
            if cid not in session_totals:
                session_order.append(cid)
            session_totals[cid] += e.bytes_transferred

        # Return in chronological order, skip zero-byte sessions
        return [session_totals[cid] for cid in session_order if session_totals[cid] > 0]

    def _compute_confidence(self, profile: AccountProfile) -> float:
        """Confidence scales with both event count and flow data availability."""
        base = min(1.0, profile.total_events / 100)
        # Reduce confidence if most events lack flow data
        nonzero = sum(1 for b in profile.bytes_transferred_list if b > 0)
        flow_ratio = nonzero / len(profile.bytes_transferred_list) if profile.bytes_transferred_list else 0.0
        return base * max(0.1, flow_ratio)
