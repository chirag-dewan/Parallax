"""T2-002: Entropy Analysis — Shannon entropy of request patterns."""

from __future__ import annotations

import math

import numpy as np

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier


class EntropyAnalysisDetector(BaseDetector):
    RULE_ID = RuleID.T2_002
    RULE_NAME = "Entropy Analysis"
    TIER = Tier.TIER_2
    THRESHOLD = 0.5
    WEIGHT = 0.06
    min_events = 20

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        # Topic entropy
        topic_h, topic_h_norm = self._shannon_entropy(
            profile.topic_counts, 9  # 9 possible topic categories
        )

        # Model entropy
        model_h, model_h_norm = self._shannon_entropy(
            profile.model_counts, 6  # 6 possible models in generator
        )

        # Temporal entropy (hour-of-day distribution)
        hourly_counts: dict[int, int] = {}
        for ts in profile.timestamps:
            hourly_counts[ts.hour] = hourly_counts.get(ts.hour, 0) + 1
        temporal_h, temporal_h_norm = self._shannon_entropy(
            hourly_counts, 24
        )

        # Low topic/model entropy = systematic = high threat
        topic_threat = 1.0 - topic_h_norm
        model_threat = 1.0 - model_h_norm

        # High temporal entropy = flat 24/7 = bot-like
        temporal_threat = temporal_h_norm

        score = (
            0.50 * topic_threat
            + 0.20 * model_threat
            + 0.30 * temporal_threat
        )

        return score, {
            "topic_entropy": round(topic_h, 4),
            "topic_entropy_normalized": round(topic_h_norm, 4),
            "model_entropy": round(model_h, 4),
            "model_entropy_normalized": round(model_h_norm, 4),
            "temporal_entropy": round(temporal_h, 4),
            "temporal_entropy_normalized": round(temporal_h_norm, 4),
            "unique_topics": profile.unique_topic_count,
        }

    @staticmethod
    def _shannon_entropy(
        counts: dict, max_categories: int
    ) -> tuple[float, float]:
        """Compute Shannon entropy and normalized version.

        Returns (raw_entropy, normalized_entropy) where normalized
        is in [0, 1] with 1.0 = maximum diversity.
        """
        if not counts:
            return 0.0, 0.0

        total = sum(counts.values())
        if total == 0:
            return 0.0, 0.0

        h = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                h -= p * math.log2(p)

        max_h = math.log2(max_categories) if max_categories > 1 else 1.0
        normalized = h / max_h if max_h > 0 else 0.0

        return h, min(1.0, normalized)
