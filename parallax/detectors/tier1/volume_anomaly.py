"""
T1-001: Volume Anomaly Detector

Detects unusual activity volume patterns using statistical outlier detection:
- Sudden spikes in posting volume
- Accounts with abnormally high activity rates
- Temporal activity bursts
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

import numpy as np
from scipy import stats

from parallax.detectors.base import BehavioralDetector
from parallax.models import ActivityType, DetectionResult, Severity, UserActivity


class VolumeAnomalyDetector(BehavioralDetector):
    """
    Detects volume anomalies using Z-score outlier detection.

    Compares individual user activity volumes against population baseline
    to identify statistical outliers.
    """

    def __init__(
        self,
        z_score_threshold: float = 3.0,
        min_population_size: int = 10,
        time_bucket_hours: int = 1,
        confidence_threshold: float = 0.75
    ):
        super().__init__(
            name="T1-001: Volume Anomaly",
            description="Detects statistical outliers in activity volume"
        )
        self.z_score_threshold = z_score_threshold
        self.min_population_size = min_population_size
        self.time_bucket_hours = time_bucket_hours
        self.confidence_threshold = confidence_threshold

    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """Analyze activity volumes for statistical outliers."""
        activities_list = list(activities)

        if len(activities_list) < self.min_population_size:
            return []

        # Group activities by user
        user_activities: dict[str, list[UserActivity]] = defaultdict(list)
        for activity in activities_list:
            user_activities[activity.user_id].append(activity)

        # Calculate activity counts per user
        user_counts = {user_id: len(acts) for user_id, acts in user_activities.items()}

        if len(user_counts) < self.min_population_size:
            return []

        # Calculate population statistics
        counts = list(user_counts.values())
        mean_count = np.mean(counts)
        std_count = np.std(counts)

        if std_count == 0:
            return []  # No variance to detect outliers

        detections: list[DetectionResult] = []
        outlier_users: list[str] = []
        outlier_evidence: dict[str, dict] = {}

        # Identify outliers using Z-score
        for user_id, count in user_counts.items():
            z_score = (count - mean_count) / std_count

            if z_score >= self.z_score_threshold:
                # Calculate confidence based on:
                # 1. Magnitude of Z-score
                # 2. Temporal burstiness
                # 3. Account age (new accounts with high volume more suspicious)

                z_score_confidence = min((z_score - self.z_score_threshold) / 3, 1.0)

                # Calculate temporal concentration (bursts vs steady)
                user_acts = user_activities[user_id]
                burstiness = self._calculate_burstiness(user_acts)

                # Account age factor (newer = more suspicious)
                account_age = user_acts[0].account_age_days or 30
                age_factor = max(0.0, 1.0 - (account_age / 30))

                confidence = (
                    0.5 * z_score_confidence +
                    0.3 * burstiness +
                    0.2 * age_factor
                )

                if confidence >= self.confidence_threshold:
                    outlier_users.append(user_id)
                    outlier_evidence[user_id] = {
                        "activity_count": count,
                        "population_mean": round(mean_count, 2),
                        "population_std": round(std_count, 2),
                        "z_score": round(z_score, 2),
                        "burstiness_score": round(burstiness, 3),
                        "account_age_days": account_age,
                        "confidence": round(confidence, 3)
                    }

        # Create detection if outliers found
        if outlier_users:
            avg_confidence = np.mean([outlier_evidence[u]["confidence"] for u in outlier_users])

            # Severity based on number of outliers and their Z-scores
            avg_z_score = np.mean([outlier_evidence[u]["z_score"] for u in outlier_users])

            if avg_z_score > 5.0 or len(outlier_users) >= 10:
                severity = Severity.HIGH
            elif avg_z_score > 4.0 or len(outlier_users) >= 5:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            detection = self._create_detection(
                severity=severity,
                confidence=float(avg_confidence),
                description=f"Detected {len(outlier_users)} accounts with anomalous activity volumes (Z-score > {self.z_score_threshold})",
                affected_entities=outlier_users,
                evidence={
                    "outlier_count": len(outlier_users),
                    "population_size": len(user_counts),
                    "population_mean": round(mean_count, 2),
                    "population_std": round(std_count, 2),
                    "z_score_threshold": self.z_score_threshold,
                    "average_z_score": round(avg_z_score, 2),
                    "sample_outliers": {
                        user_id: outlier_evidence[user_id]
                        for user_id in outlier_users[:5]
                    }
                },
                recommended_actions=[
                    "Review posting patterns for outlier accounts",
                    "Check for automation signatures (T1-002)",
                    "Consider rate limiting for high-volume accounts",
                    "Verify account legitimacy"
                ],
                tags=["volume", "outlier", "statistical", "high-activity"],
                sigma_rule_id="parallax_t1_001_v1"
            )

            detections.append(detection)

        return detections

    def _calculate_burstiness(self, activities: list[UserActivity]) -> float:
        """
        Calculate temporal burstiness of activity.

        Uses coefficient of variation of inter-arrival times.
        High burstiness = activity in tight clusters.

        Returns score 0-1 where 1 = highly bursty.
        """
        if len(activities) < 3:
            return 0.0

        # Sort by timestamp
        activities = sorted(activities, key=lambda a: a.timestamp)

        # Calculate inter-arrival times (in seconds)
        timestamps = [a.timestamp.timestamp() for a in activities]
        inter_arrivals = np.diff(timestamps)

        if len(inter_arrivals) == 0:
            return 0.0

        mean_interval = np.mean(inter_arrivals)
        std_interval = np.std(inter_arrivals)

        if mean_interval == 0:
            return 1.0

        # Coefficient of variation
        cv = std_interval / mean_interval

        # Normalize to 0-1 (CV > 2 is considered highly bursty)
        burstiness = min(cv / 2, 1.0)

        return burstiness
