"""T2-006: Behavioral Shift — sudden change in usage profile."""

from __future__ import annotations

from statistics import mean as stat_mean

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale


class BehavioralShiftDetector(BaseDetector):
    RULE_ID = RuleID.T2_006
    RULE_NAME = "Behavioral Shift"
    TIER = Tier.TIER_2
    THRESHOLD = 0.5
    WEIGHT = 0.02
    min_events = 50

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        events = profile.events
        mid = len(events) // 2
        first_half = events[:mid]
        second_half = events[mid:]

        if not first_half or not second_half:
            return 0.0, {"reason": "insufficient_split"}

        # Compute metrics for each half
        h1_velocity = self._half_velocity(first_half)
        h2_velocity = self._half_velocity(second_half)

        h1_avg_output = stat_mean(e.output_tokens for e in first_half)
        h2_avg_output = stat_mean(e.output_tokens for e in second_half)

        h1_api = sum(1 for e in first_half if e.request_type == "api") / len(first_half)
        h2_api = sum(1 for e in second_half if e.request_type == "api") / len(second_half)

        # Absolute percentage changes
        velocity_shift = self._pct_change(h1_velocity, h2_velocity)
        token_shift = self._pct_change(h1_avg_output, h2_avg_output)
        api_shift = abs(h2_api - h1_api)

        max_shift = max(velocity_shift, token_shift, api_shift)

        # max_shift 0.3-2.0 -> linear 0.0-1.0
        score = linear_scale(max_shift, 0.3, 2.0)

        return score, {
            "velocity_shift": round(velocity_shift, 4),
            "token_shift": round(token_shift, 4),
            "api_shift": round(api_shift, 4),
            "max_shift": round(max_shift, 4),
            "half1_velocity": round(h1_velocity, 2),
            "half2_velocity": round(h2_velocity, 2),
        }

    @staticmethod
    def _half_velocity(events: list) -> float:
        if len(events) < 2:
            return 0.0
        span = (events[-1].timestamp - events[0].timestamp).total_seconds() / 3600
        return len(events) / span if span > 0 else 0.0

    @staticmethod
    def _pct_change(old: float, new: float) -> float:
        denom = max(abs(old), 1.0)
        return abs(new - old) / denom
