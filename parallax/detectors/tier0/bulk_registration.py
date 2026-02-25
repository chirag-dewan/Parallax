"""
T0-001: Bulk Registration Detector

Detects coordinated account creation patterns:
- Multiple registrations from same IP subnet
- Tight temporal clustering
- Similar device fingerprints
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from parallax.detectors.base import StatisticalDetector
from parallax.models import ActivityType, DetectionResult, Severity, UserActivity


class BulkRegistrationDetector(StatisticalDetector):
    """
    Detects bulk registration patterns indicative of coordinated campaigns.

    Signals:
    1. N+ registrations from same /24 subnet in T hours
    2. Registration timestamps within tight window
    3. Similar device characteristics
    """

    def __init__(
        self,
        threshold: int = 10,
        time_window_hours: int = 2,
        confidence_threshold: float = 0.8
    ):
        super().__init__(
            name="T0-001: Bulk Registration",
            description="Detects coordinated bulk account creation patterns"
        )
        self.threshold = threshold
        self.time_window_hours = time_window_hours
        self.confidence_threshold = confidence_threshold

    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """Analyze registration activities for bulk patterns."""
        # Filter to registration events only
        registrations = [
            a for a in activities
            if a.activity_type == ActivityType.REGISTRATION
        ]

        if len(registrations) < self.threshold:
            return []

        # Sort by timestamp
        registrations.sort(key=lambda a: a.timestamp)

        detections: list[DetectionResult] = []

        # Group by IP hash (subnet)
        ip_groups: dict[str, list[UserActivity]] = defaultdict(list)
        for reg in registrations:
            ip_groups[reg.ip_hash].append(reg)

        # Analyze each IP group
        for ip_hash, regs in ip_groups.items():
            if len(regs) < self.threshold:
                continue

            # Check temporal clustering using sliding window
            time_window = timedelta(hours=self.time_window_hours)

            for i in range(len(regs)):
                window_start = regs[i].timestamp
                window_end = window_start + time_window

                # Count registrations in this window
                regs_in_window = [
                    r for r in regs
                    if window_start <= r.timestamp <= window_end
                ]

                if len(regs_in_window) >= self.threshold:
                    # Calculate confidence based on:
                    # 1. Number over threshold
                    # 2. Time concentration
                    # 3. Device similarity

                    excess_ratio = len(regs_in_window) / self.threshold
                    time_concentration = self._calculate_time_concentration(regs_in_window)
                    device_similarity = self._calculate_device_similarity(regs_in_window)

                    confidence = min(1.0, (
                        0.4 * min(excess_ratio / 3, 1.0) +
                        0.3 * time_concentration +
                        0.3 * device_similarity
                    ))

                    if confidence >= self.confidence_threshold:
                        # Determine severity
                        if len(regs_in_window) > self.threshold * 3:
                            severity = Severity.CRITICAL
                        elif len(regs_in_window) > self.threshold * 2:
                            severity = Severity.HIGH
                        else:
                            severity = Severity.MEDIUM

                        affected_users = [r.user_id for r in regs_in_window]

                        detection = self._create_detection(
                            severity=severity,
                            confidence=confidence,
                            description=f"Detected {len(regs_in_window)} registrations from similar IP range in {self.time_window_hours}-hour window",
                            affected_entities=affected_users,
                            evidence={
                                "registration_count": len(regs_in_window),
                                "time_window_hours": self.time_window_hours,
                                "ip_hash": ip_hash,
                                "threshold": self.threshold,
                                "window_start": window_start.isoformat(),
                                "window_end": window_end.isoformat(),
                                "time_concentration_score": round(time_concentration, 3),
                                "device_similarity_score": round(device_similarity, 3),
                            },
                            recommended_actions=[
                                "Review registration patterns for affected accounts",
                                "Consider rate limiting on this IP range",
                                "Verify email/phone verification completion",
                                "Cross-reference with T1-002 (automation signatures)"
                            ],
                            tags=["registration", "ip-clustering", "bulk-creation"],
                            sigma_rule_id="parallax_t0_001_v1"
                        )

                        detections.append(detection)

                        # Only report once per IP group
                        break

        return detections

    def _calculate_time_concentration(self, activities: list[UserActivity]) -> float:
        """
        Calculate how concentrated in time the activities are.

        Returns score 0-1 where 1 = perfectly synchronized.
        """
        if len(activities) <= 1:
            return 1.0

        timestamps = [a.timestamp.timestamp() for a in activities]
        time_range = max(timestamps) - min(timestamps)

        if time_range == 0:
            return 1.0

        # Normalize by expected time window
        expected_range = self.time_window_hours * 3600
        concentration = 1.0 - min(time_range / expected_range, 1.0)

        return concentration

    def _calculate_device_similarity(self, activities: list[UserActivity]) -> float:
        """
        Calculate device fingerprint similarity.

        Returns score 0-1 where 1 = all same device.
        """
        if len(activities) <= 1:
            return 1.0

        unique_devices = len(set(a.device_fingerprint for a in activities))
        similarity = 1.0 - (unique_devices - 1) / len(activities)

        return max(0.0, similarity)
