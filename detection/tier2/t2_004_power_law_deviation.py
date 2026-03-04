"""T2-004: Power-Law Deviation — usage distribution breaks Zipf's law."""

from __future__ import annotations

import numpy as np

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier


class PowerLawDeviationDetector(BaseDetector):
    RULE_ID = RuleID.T2_004
    RULE_NAME = "Power-Law Deviation"
    TIER = Tier.TIER_2
    THRESHOLD = 0.5
    WEIGHT = 0.04
    min_events = 50

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        if profile.unique_topic_count < 3:
            # Too few topics for a meaningful power-law fit
            return 0.5, {
                "alpha": None,
                "r_squared": None,
                "num_unique_topics": profile.unique_topic_count,
            }

        # Rank-frequency distribution of topics
        counts = sorted(profile.topic_counts.values(), reverse=True)
        ranks = np.arange(1, len(counts) + 1, dtype=float)
        freqs = np.array(counts, dtype=float)

        # Log-log linear regression: log(freq) = log(C) - alpha * log(rank)
        log_ranks = np.log(ranks)
        log_freqs = np.log(freqs + 1e-10)  # avoid log(0)

        # Least-squares fit
        n = len(log_ranks)
        sum_x = log_ranks.sum()
        sum_y = log_freqs.sum()
        sum_xy = (log_ranks * log_freqs).sum()
        sum_x2 = (log_ranks ** 2).sum()

        denom = n * sum_x2 - sum_x ** 2
        if abs(denom) < 1e-10:
            return 0.5, {
                "alpha": None,
                "r_squared": 0.0,
                "num_unique_topics": profile.unique_topic_count,
            }

        slope = (n * sum_xy - sum_x * sum_y) / denom
        alpha = -slope  # power-law exponent

        # R-squared
        intercept = (sum_y - slope * sum_x) / n
        predicted = slope * log_ranks + intercept
        ss_res = ((log_freqs - predicted) ** 2).sum()
        ss_tot = ((log_freqs - log_freqs.mean()) ** 2).sum()
        r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
        r_squared = max(0.0, min(1.0, r_squared))

        # Poor power-law fit = suspicious (flat/uniform distribution)
        score = 1.0 - r_squared

        return score, {
            "alpha": round(float(alpha), 4),
            "r_squared": round(float(r_squared), 4),
            "num_unique_topics": profile.unique_topic_count,
        }
