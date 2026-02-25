"""
T0-002: Payment Clustering Detector

Detects financial patterns indicative of coordinated accounts:
- Multiple accounts sharing payment methods
- Payment metadata clustering (timing, amounts, methods)
"""

from collections import defaultdict
from typing import Iterable

from parallax.detectors.base import StatisticalDetector
from parallax.models import ActivityType, DetectionResult, Severity, UserActivity


class PaymentClusteringDetector(StatisticalDetector):
    """
    Detects accounts sharing payment infrastructure.

    Signals:
    1. N+ accounts with identical payment fingerprints
    2. Suspicious payment timing patterns
    3. Unusual payment amount clustering

    Note: In Phase 1, payment metadata is in activity.metadata.
    Production would have dedicated payment tracking.
    """

    def __init__(
        self,
        min_shared_accounts: int = 5,
        confidence_threshold: float = 0.75
    ):
        super().__init__(
            name="T0-002: Payment Clustering",
            description="Detects accounts sharing payment methods or patterns"
        )
        self.min_shared_accounts = min_shared_accounts
        self.confidence_threshold = confidence_threshold

    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """Analyze payment activities for clustering."""
        # Filter to payment events
        payments = [
            a for a in activities
            if a.activity_type == ActivityType.PAYMENT
        ]

        if len(payments) < self.min_shared_accounts:
            return []

        detections: list[DetectionResult] = []

        # Extract payment fingerprints from metadata
        # In production, this would be proper payment token hashing
        payment_fingerprints: dict[str, list[UserActivity]] = defaultdict(list)

        for payment in payments:
            # Simulate payment fingerprint from metadata
            # Real implementation would hash: last4 digits, billing zip, payment provider ID
            fp = payment.metadata.get("payment_fingerprint", f"fp_{payment.device_fingerprint}")
            payment_fingerprints[fp].append(payment)

        # Analyze clusters
        for fp, cluster_payments in payment_fingerprints.items():
            # Get unique users
            unique_users = list(set(p.user_id for p in cluster_payments))

            if len(unique_users) < self.min_shared_accounts:
                continue

            # Calculate confidence based on cluster characteristics
            account_count_score = min(len(unique_users) / (self.min_shared_accounts * 2), 1.0)

            # Check if accounts were created around the same time
            account_ages = [p.account_age_days for p in cluster_payments if p.account_age_days is not None]
            age_similarity = self._calculate_age_similarity(account_ages) if account_ages else 0.5

            # Check device/IP overlap
            shared_infrastructure_score = self._calculate_infrastructure_overlap(cluster_payments)

            confidence = (
                0.4 * account_count_score +
                0.3 * age_similarity +
                0.3 * shared_infrastructure_score
            )

            if confidence >= self.confidence_threshold:
                # Severity based on cluster size
                if len(unique_users) >= self.min_shared_accounts * 3:
                    severity = Severity.CRITICAL
                elif len(unique_users) >= self.min_shared_accounts * 2:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                detection = self._create_detection(
                    severity=severity,
                    confidence=confidence,
                    description=f"Detected {len(unique_users)} accounts sharing payment fingerprint",
                    affected_entities=unique_users,
                    evidence={
                        "shared_account_count": len(unique_users),
                        "payment_fingerprint_hash": fp[:16] + "...",
                        "total_payments": len(cluster_payments),
                        "threshold": self.min_shared_accounts,
                        "account_age_similarity": round(age_similarity, 3),
                        "infrastructure_overlap_score": round(shared_infrastructure_score, 3),
                    },
                    recommended_actions=[
                        "Review payment methods for affected accounts",
                        "Verify billing addresses and identities",
                        "Check for shared credit cards or gift card abuse",
                        "Consider payment velocity limits"
                    ],
                    tags=["payment", "clustering", "shared-infrastructure"],
                    sigma_rule_id="parallax_t0_002_v1"
                )

                detections.append(detection)

        return detections

    def _calculate_age_similarity(self, ages: list[int]) -> float:
        """Calculate how similar account ages are (0-1)."""
        if not ages or len(ages) == 1:
            return 1.0

        import numpy as np
        std_dev = np.std(ages)
        mean_age = np.mean(ages)

        if mean_age == 0:
            return 1.0

        # Normalize by mean - low coefficient of variation = high similarity
        cv = std_dev / mean_age
        similarity = max(0.0, 1.0 - min(cv / 2, 1.0))

        return similarity

    def _calculate_infrastructure_overlap(self, payments: list[UserActivity]) -> float:
        """Calculate degree of shared infrastructure (IPs, devices)."""
        if len(payments) <= 1:
            return 0.0

        unique_users = len(set(p.user_id for p in payments))
        unique_ips = len(set(p.ip_hash for p in payments))
        unique_devices = len(set(p.device_fingerprint for p in payments))

        # High overlap = low diversity
        ip_overlap = 1.0 - (unique_ips / unique_users)
        device_overlap = 1.0 - (unique_devices / unique_users)

        return (ip_overlap + device_overlap) / 2
