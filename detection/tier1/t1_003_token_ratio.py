"""T1-003: Token Ratio — short input / max output distillation pattern."""

from __future__ import annotations

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale


class TokenRatioDetector(BaseDetector):
    RULE_ID = RuleID.T1_003
    RULE_NAME = "Token Ratio"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 0.12
    min_events = 5

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        if profile.avg_input_tokens == 0:
            return 0.0, {"token_ratio": 0.0, "avg_input": 0.0, "avg_output": 0.0}

        ratio = profile.token_ratio

        # Ratio 10-50 -> linear 0.0-1.0
        ratio_score = linear_scale(ratio, 10.0, 50.0)

        # Bonus: output tokens near model max (3500+ of 4096)
        max_output_count = sum(
            1 for t in profile.output_tokens if t > 3500
        )
        max_output_fraction = max_output_count / profile.total_events
        max_output_bonus = 0.2 if max_output_fraction > 0.8 else 0.0

        # Bonus: very short inputs (< 100 tokens)
        low_input_count = sum(
            1 for t in profile.input_tokens if t < 100
        )
        low_input_fraction = low_input_count / profile.total_events
        low_input_bonus = 0.1 if low_input_fraction > 0.7 else 0.0

        score = min(1.0, ratio_score + max_output_bonus + low_input_bonus)

        return score, {
            "token_ratio": round(ratio, 2),
            "avg_input": round(profile.avg_input_tokens, 2),
            "avg_output": round(profile.avg_output_tokens, 2),
            "max_output_fraction": round(max_output_fraction, 4),
            "low_input_fraction": round(low_input_fraction, 4),
        }
