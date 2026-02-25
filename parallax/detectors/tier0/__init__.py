"""Tier 0 (Statistical) detectors."""

from parallax.detectors.tier0.bulk_registration import BulkRegistrationDetector
from parallax.detectors.tier0.lifecycle_anomaly import LifecycleAnomalyDetector
from parallax.detectors.tier0.payment_clustering import PaymentClusteringDetector

__all__ = [
    "BulkRegistrationDetector",
    "PaymentClusteringDetector",
    "LifecycleAnomalyDetector",
]
