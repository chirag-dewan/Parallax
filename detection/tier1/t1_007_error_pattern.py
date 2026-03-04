"""T1-007: Error Pattern — safety triggers + mechanical retry patterns."""

from __future__ import annotations

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import coefficient_of_variation, linear_scale


class ErrorPatternDetector(BaseDetector):
    RULE_ID = RuleID.T1_007
    RULE_NAME = "Error Pattern"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 0.08
    min_events = 10

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        # Sub-signal 1: Safety trigger rate (40%)
        # rate < 0.05 -> 0.0, 0.05-0.15 -> linear, > 0.15 -> 1.0
        safety_score = linear_scale(
            profile.safety_trigger_rate, 0.05, 0.15
        )

        # Sub-signal 2: Mechanical retry pattern (40%)
        retry_cv_score = 0.0
        retry_cv = None
        if len(profile.rate_limit_retry_delays_ms) >= 3:
            retry_cv = coefficient_of_variation(
                profile.rate_limit_retry_delays_ms
            )
            if retry_cv is not None:
                # Low CV = mechanical = high score
                retry_cv_score = 1.0 - linear_scale(retry_cv, 0.15, 0.40)

        # Sub-signal 3: Rate limit hit rate (20%)
        # rate < 0.02 -> 0.0, 0.02-0.10 -> linear, > 0.10 -> 1.0
        rate_limit_score = linear_scale(
            profile.rate_limit_hit_rate, 0.02, 0.10
        )

        score = (
            0.40 * safety_score
            + 0.40 * retry_cv_score
            + 0.20 * rate_limit_score
        )

        return score, {
            "safety_trigger_rate": round(profile.safety_trigger_rate, 4),
            "retry_delay_cv": round(retry_cv, 4) if retry_cv is not None else None,
            "rate_limit_hit_rate": round(profile.rate_limit_hit_rate, 4),
            "retry_delay_count": len(profile.rate_limit_retry_delays_ms),
        }
