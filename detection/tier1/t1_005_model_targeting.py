"""T1-005: Model Targeting — unusual model selection patterns."""

from __future__ import annotations

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale


CHEAP_MODELS = {"gpt-3.5-turbo", "claude-instant", "claude-haiku"}


class ModelTargetingDetector(BaseDetector):
    RULE_ID = RuleID.T1_005
    RULE_NAME = "Model Targeting"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 0.06
    min_events = 10

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        cheap_count = sum(
            count
            for model, count in profile.model_counts.items()
            if model in CHEAP_MODELS
        )
        cheap_ratio = cheap_count / profile.total_events

        # cheap_ratio 0.5-0.95 -> linear 0.0-1.0
        cheap_score = linear_scale(cheap_ratio, 0.5, 0.95)

        # Diversity penalty: using multiple models is less suspicious
        model_diversity = len(profile.model_counts)
        diversity_factor = 0.7 if model_diversity >= 3 else 1.0

        score = cheap_score * diversity_factor

        return score, {
            "cheap_model_ratio": round(cheap_ratio, 4),
            "model_diversity": model_diversity,
            "model_distribution": {
                m: round(r, 4) for m, r in profile.model_ratios.items()
            },
        }
