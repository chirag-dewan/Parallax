"""T2-001: Distribution Divergence — KL-divergence from population baseline."""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np
from scipy.special import rel_entr

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import sigmoid_normalize

if TYPE_CHECKING:
    from detection.baselines import PopulationBaseline


class DistributionDivergenceDetector(BaseDetector):
    RULE_ID = RuleID.T2_001
    RULE_NAME = "Distribution Divergence"
    TIER = Tier.TIER_2
    THRESHOLD = 0.5
    WEIGHT = 0.06
    min_events = 50

    # Histogram bin edges
    INTERVAL_BINS = [0, 1000, 5000, 30000, 120000, float("inf")]
    OUTPUT_BINS = [0, 500, 2000, 3500, 4097]

    def __init__(self) -> None:
        super().__init__()
        self._baseline: PopulationBaseline | None = None

    def set_population_baseline(self, baseline: PopulationBaseline) -> None:
        self._baseline = baseline

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        if self._baseline is None:
            return 0.0, {"reason": "no_baseline"}

        # Build account histograms
        acct_interval = self._bin_values(
            profile.inter_request_intervals_ms, self.INTERVAL_BINS
        )
        acct_output = self._bin_values(
            profile.output_tokens, self.OUTPUT_BINS
        )
        acct_topic = self._topic_dist(profile)
        acct_hourly = self._hourly_dist(profile)

        # Population histograms
        pop_interval = self._baseline.interval_histogram
        pop_output = self._baseline.output_token_histogram
        pop_hourly = self._baseline.hourly_distribution

        # KL-divergence per dimension
        interval_kl = self._kl_divergence(acct_interval, pop_interval)
        token_kl = self._kl_divergence(acct_output, pop_output)
        temporal_kl = self._kl_divergence(acct_hourly, pop_hourly)

        # Topic KL
        topic_kl = self._topic_kl(profile, self._baseline.topic_distribution)

        total_kl = interval_kl + token_kl + temporal_kl + topic_kl
        score = sigmoid_normalize(total_kl, midpoint=2.0, steepness=1.0)

        return score, {
            "kl_divergence": round(total_kl, 4),
            "interval_kl": round(interval_kl, 4),
            "token_kl": round(token_kl, 4),
            "topic_kl": round(topic_kl, 4),
            "temporal_kl": round(temporal_kl, 4),
        }

    @staticmethod
    def _bin_values(
        values: list[int], bin_edges: list[float]
    ) -> np.ndarray:
        counts = np.zeros(len(bin_edges) - 1)
        for v in values:
            for i in range(len(bin_edges) - 1):
                if bin_edges[i] <= v < bin_edges[i + 1]:
                    counts[i] += 1
                    break
        total = counts.sum()
        if total > 0:
            return counts / total
        return np.ones(len(counts)) / len(counts)

    @staticmethod
    def _kl_divergence(p: np.ndarray, q: np.ndarray) -> float:
        # Laplace smoothing
        eps = 1e-10
        p_smooth = p + eps
        q_smooth = q + eps
        p_smooth /= p_smooth.sum()
        q_smooth /= q_smooth.sum()
        return float(np.sum(rel_entr(p_smooth, q_smooth)))

    @staticmethod
    def _topic_dist(profile: AccountProfile) -> np.ndarray:
        if not profile.topic_counts:
            return np.array([1.0])
        total = sum(profile.topic_counts.values())
        return np.array(
            [c / total for c in profile.topic_counts.values()]
        )

    @staticmethod
    def _topic_kl(
        profile: AccountProfile, pop_dist: dict[str, float]
    ) -> float:
        if not pop_dist or not profile.topic_counts:
            return 0.0

        all_topics = set(pop_dist.keys()) | set(profile.topic_counts.keys())
        eps = 1e-10
        total = sum(profile.topic_counts.values())

        p = np.array(
            [profile.topic_counts.get(t, 0) / total + eps for t in all_topics]
        )
        q = np.array([pop_dist.get(t, 0.0) + eps for t in all_topics])
        p /= p.sum()
        q /= q.sum()

        return float(np.sum(rel_entr(p, q)))

    def _hourly_dist(self, profile: AccountProfile) -> np.ndarray:
        counts = np.zeros(24)
        for ts in profile.timestamps:
            counts[ts.hour] += 1
        total = counts.sum()
        if total > 0:
            return counts / total
        return np.ones(24) / 24
