"""T1-001: Volume Anomaly — requests/hour vs population baseline (z-score)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import sigmoid_normalize

if TYPE_CHECKING:
    from detection.baselines import PopulationBaseline


class VolumeAnomalyDetector(BaseDetector):
    RULE_ID = RuleID.T1_001
    RULE_NAME = "Volume Anomaly"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 0.12
    min_events = 10

    def __init__(self) -> None:
        super().__init__()
        self._baseline_mean: float = 10.0
        self._baseline_std: float = 1.0

    def set_population_baseline(self, baseline: PopulationBaseline) -> None:
        self._baseline_mean = baseline.velocity_mean
        self._baseline_std = max(baseline.velocity_std, 1.0)

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        velocity = profile.requests_per_hour
        z_score = (velocity - self._baseline_mean) / self._baseline_std

        score = sigmoid_normalize(z_score, midpoint=3.0, steepness=1.5)

        return score, {
            "requests_per_hour": round(velocity, 2),
            "baseline_mean": round(self._baseline_mean, 2),
            "baseline_std": round(self._baseline_std, 2),
            "z_score": round(z_score, 2),
        }
