"""
PARALLAX Base Detector

Abstract base class that all detection rules implement.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from detection.models import (
    AccountProfile,
    DetectionResult,
    RuleID,
    Tier,
)

if TYPE_CHECKING:
    from detection.baselines import PopulationBaseline


class BaseDetector(ABC):
    """Abstract base for all detection rules.

    Subclasses define class constants:
        RULE_ID, RULE_NAME, TIER, THRESHOLD, WEIGHT

    Subclasses implement:
        _compute_score(profile) -> tuple[float, dict]
    """

    RULE_ID: RuleID
    RULE_NAME: str
    TIER: Tier
    THRESHOLD: float
    WEIGHT: float
    min_events: int = 2

    def __init__(self) -> None:
        self.logger = logging.getLogger(
            f"parallax.detection.{self.RULE_ID.value}"
        )

    def detect(self, profile: AccountProfile) -> DetectionResult:
        """Run detection on an account profile. Not meant to be overridden."""
        if profile.total_events < self.min_events:
            return DetectionResult(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                tier=self.TIER,
                score=0.0,
                triggered=False,
                confidence=0.0,
                details={"reason": "insufficient_events"},
            )

        score, details = self._compute_score(profile)
        score = max(0.0, min(1.0, score))

        return DetectionResult(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            tier=self.TIER,
            score=score,
            triggered=score > self.THRESHOLD,
            confidence=self._compute_confidence(profile),
            details=details,
        )

    @abstractmethod
    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict]:
        """Compute detection score and diagnostic details."""
        ...

    def _compute_confidence(self, profile: AccountProfile) -> float:
        """Confidence based on data volume. Reaches 1.0 at 100+ events."""
        return min(1.0, profile.total_events / 100)

    def set_population_baseline(self, baseline: PopulationBaseline) -> None:
        """Inject population stats. Tier 2 detectors override this."""
