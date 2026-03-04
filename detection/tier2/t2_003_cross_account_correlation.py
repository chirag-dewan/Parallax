"""T2-003: Cross-Account Correlation — DBSCAN behavioral clustering."""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale

if TYPE_CHECKING:
    from detection.baselines import PopulationBaseline


class CrossAccountCorrelationDetector(BaseDetector):
    RULE_ID = RuleID.T2_003
    RULE_NAME = "Cross-Account Correlation"
    TIER = Tier.TIER_2
    THRESHOLD = 0.5
    WEIGHT = 0.06
    min_events = 20

    def __init__(self) -> None:
        super().__init__()
        self._baseline: PopulationBaseline | None = None

    def set_population_baseline(self, baseline: PopulationBaseline) -> None:
        self._baseline = baseline

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        if self._baseline is None or not self._baseline.cluster_labels:
            return 0.0, {"reason": "no_baseline"}

        cluster_id = self._baseline.cluster_labels.get(
            profile.account_id, -1
        )

        if cluster_id == -1:
            # Noise point — not in a cluster
            return 0.0, {
                "cluster_id": None,
                "cluster_size": 0,
                "nearest_neighbor_distance": self._nearest_distance(profile),
            }

        # Count cluster size
        cluster_size = sum(
            1
            for label in self._baseline.cluster_labels.values()
            if label == cluster_id
        )

        # Larger clusters are more suspicious
        score = linear_scale(cluster_size, 3.0, 10.0)

        return score, {
            "cluster_id": cluster_id,
            "cluster_size": cluster_size,
            "nearest_neighbor_distance": self._nearest_distance(profile),
        }

    def _nearest_distance(self, profile: AccountProfile) -> float:
        """Find nearest neighbor distance in feature space."""
        if (
            self._baseline is None
            or profile.account_id not in self._baseline.feature_vectors
        ):
            return 0.0

        vec = self._baseline.feature_vectors[profile.account_id]
        min_dist = float("inf")

        for aid, other_vec in self._baseline.feature_vectors.items():
            if aid == profile.account_id:
                continue
            dist = float(np.linalg.norm(vec - other_vec))
            if dist < min_dist:
                min_dist = dist

        return round(min_dist, 4) if min_dist != float("inf") else 0.0
