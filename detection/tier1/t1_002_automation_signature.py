"""T1-002: Automation Signature — timing regularity + diurnal absence."""

from __future__ import annotations

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import coefficient_of_variation, linear_scale


class AutomationSignatureDetector(BaseDetector):
    RULE_ID = RuleID.T1_002
    RULE_NAME = "Automation Signature"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 0.14
    min_events = 20

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        # Sub-signal 1: Timing regularity (70%)
        cv = coefficient_of_variation(profile.inter_request_intervals_ms)
        if cv is not None:
            # Low CV = mechanical = high score
            # CV < 0.15 -> 1.0, CV 0.15-0.50 -> linear, CV > 0.50 -> 0.0
            cv_score = 1.0 - linear_scale(cv, 0.15, 0.50)
        else:
            cv_score = 0.0

        # Sub-signal 2: Diurnal absence (30%)
        # Bots are active across many hours uniformly; humans cluster
        hours_active_count = len(profile.hours_active)
        # If active > 20 hours, likely automated
        diurnal_score = linear_scale(
            hours_active_count, 16.0, 23.0
        )

        score = 0.70 * cv_score + 0.30 * diurnal_score

        mean_interval = 0.0
        if profile.inter_request_intervals_ms:
            mean_interval = (
                sum(profile.inter_request_intervals_ms)
                / len(profile.inter_request_intervals_ms)
            )

        return score, {
            "cv": round(cv, 4) if cv is not None else None,
            "cv_score": round(cv_score, 4),
            "diurnal_score": round(diurnal_score, 4),
            "hours_active_count": hours_active_count,
            "mean_interval_ms": round(mean_interval, 2),
        }
