"""T1-004: Session Anomaly — single-turn ratio + conversations/day."""

from __future__ import annotations

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale


class SessionAnomalyDetector(BaseDetector):
    RULE_ID = RuleID.T1_004
    RULE_NAME = "Session Anomaly"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 0.08
    min_events = 10

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        # Sub-signal 1: Single-turn ratio (60%)
        # ratio < 0.3 -> 0.0, 0.3-0.8 -> linear, > 0.8 -> 1.0
        single_turn_score = linear_scale(
            profile.single_turn_ratio, 0.3, 0.8
        )

        # Sub-signal 2: Conversations per day (40%)
        # < 20 -> 0.0, 20-100 -> linear, > 100 -> 1.0
        conv_rate_score = linear_scale(
            profile.conversations_per_day, 20.0, 100.0
        )

        score = 0.60 * single_turn_score + 0.40 * conv_rate_score

        return score, {
            "single_turn_ratio": round(profile.single_turn_ratio, 4),
            "conversations_per_day": round(profile.conversations_per_day, 2),
            "total_conversations": profile.total_conversations,
        }
