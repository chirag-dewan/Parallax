"""Detection engines for Parallax."""

from parallax.detectors.base import (
    BaseDetector,
    BehavioralDetector,
    ContextualDetector,
    StatisticalDetector,
)
from parallax.detectors.tier0 import (
    BulkRegistrationDetector,
    LifecycleAnomalyDetector,
    PaymentClusteringDetector,
)
from parallax.detectors.tier1 import (
    AutomationSignatureDetector,
    TokenReuseDetector,
    VolumeAnomalyDetector,
)

__all__ = [
    # Base classes
    "BaseDetector",
    "StatisticalDetector",
    "BehavioralDetector",
    "ContextualDetector",
    # Tier 0
    "BulkRegistrationDetector",
    "PaymentClusteringDetector",
    "LifecycleAnomalyDetector",
    # Tier 1
    "VolumeAnomalyDetector",
    "AutomationSignatureDetector",
    "TokenReuseDetector",
]
