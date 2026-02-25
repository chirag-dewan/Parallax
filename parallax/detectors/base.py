"""
Abstract base classes for Parallax detectors.

All detectors inherit from BaseDetector and implement the detect() method.
"""

from abc import ABC, abstractmethod
from typing import Iterable

from parallax.models import DetectionResult, Severity, UserActivity


class BaseDetector(ABC):
    """
    Abstract base class for all detectors.

    Detectors consume streams of UserActivity and emit DetectionResult
    when suspicious patterns are identified.
    """

    def __init__(self, name: str, tier: int, description: str):
        """
        Initialize detector.

        Args:
            name: Detector name (e.g., "T0-001: Bulk Registration")
            tier: Detection tier (0=statistical, 1=behavioral, 2=contextual)
            description: Human-readable description of what this detects
        """
        self.name = name
        self.tier = tier
        self.description = description

    @abstractmethod
    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """
        Analyze activity stream and return detections.

        Args:
            activities: Iterable of UserActivity records to analyze

        Returns:
            List of DetectionResult objects (empty if nothing detected)
        """
        pass

    def _create_detection(
        self,
        severity: Severity,
        confidence: float,
        description: str,
        affected_entities: list[str],
        evidence: dict,
        recommended_actions: list[str] | None = None,
        tags: list[str] | None = None,
        sigma_rule_id: str | None = None
    ) -> DetectionResult:
        """
        Helper to create a DetectionResult with consistent metadata.

        Args:
            severity: Alert severity
            confidence: Confidence score 0-1
            description: Human-readable description
            affected_entities: List of user IDs or other entities
            evidence: Supporting data dictionary
            recommended_actions: List of recommended response actions
            tags: Classification tags
            sigma_rule_id: Optional SIGMA rule ID mapping

        Returns:
            DetectionResult object
        """
        return DetectionResult(
            detector_name=self.name,
            detector_tier=self.tier,
            severity=severity,
            confidence=confidence,
            description=description,
            affected_entities=affected_entities,
            evidence=evidence,
            recommended_actions=recommended_actions or [],
            tags=tags or [],
            sigma_rule_id=sigma_rule_id
        )


class StatisticalDetector(BaseDetector):
    """
    Base class for Tier 0 (Statistical) detectors.

    These detectors use simple statistical methods and thresholds.
    No ML, just aggregations and comparisons.
    """

    def __init__(self, name: str, description: str):
        super().__init__(name, tier=0, description=description)


class BehavioralDetector(BaseDetector):
    """
    Base class for Tier 1 (Behavioral) detectors.

    These detectors analyze temporal patterns, sequences, and behavioral signals.
    May use basic ML (clustering, outlier detection).
    """

    def __init__(self, name: str, description: str):
        super().__init__(name, tier=1, description=description)


class ContextualDetector(BaseDetector):
    """
    Base class for Tier 2 (Contextual) detectors.

    These detectors use graph analysis, content understanding,
    and cross-signal correlation.
    """

    def __init__(self, name: str, description: str):
        super().__init__(name, tier=2, description=description)
