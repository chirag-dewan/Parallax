"""
T0-005: Account Lifecycle Anomaly Detector

Detects unusual account lifecycle patterns:
- Register -> Post immediately (no exploration phase)
- High activity on brand new accounts
- Skipped onboarding steps
"""

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from parallax.detectors.base import StatisticalDetector
from parallax.models import ActivityType, DetectionResult, Severity, UserActivity


class LifecycleAnomalyDetector(StatisticalDetector):
    """
    Detects accounts with anomalous lifecycle patterns.

    Organic users typically:
    - Explore before posting
    - Ramp up activity gradually
    - Complete onboarding flows

    Bots typically:
    - Post immediately after registration
    - High volume from day 1
    - Skip user education flows
    """

    def __init__(
        self,
        immediate_post_threshold_minutes: int = 5,
        new_account_days: int = 3,
        high_activity_threshold: int = 20,
        confidence_threshold: float = 0.7
    ):
        super().__init__(
            name="T0-005: Account Lifecycle Anomaly",
            description="Detects unusual account behavior patterns in early lifecycle"
        )
        self.immediate_post_threshold = immediate_post_threshold_minutes
        self.new_account_days = new_account_days
        self.high_activity_threshold = high_activity_threshold
        self.confidence_threshold = confidence_threshold

    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """Analyze account lifecycle patterns."""
        activities_list = list(activities)

        if not activities_list:
            return []

        # Group by user
        user_activities: dict[str, list[UserActivity]] = defaultdict(list)
        for activity in activities_list:
            user_activities[activity.user_id].append(activity)

        detections: list[DetectionResult] = []
        suspicious_users: list[str] = []
        evidence_map: dict[str, dict] = {}

        for user_id, user_acts in user_activities.items():
            # Sort by timestamp
            user_acts.sort(key=lambda a: a.timestamp)

            # Only analyze new accounts
            account_age = user_acts[-1].account_age_days
            if account_age is None or account_age > self.new_account_days:
                continue

            # Check for lifecycle anomalies
            anomaly_score = 0.0
            anomaly_reasons = []

            # Signal 1: Immediate posting after registration
            registrations = [a for a in user_acts if a.activity_type == ActivityType.REGISTRATION]
            posts = [a for a in user_acts if a.activity_type == ActivityType.CONTENT_POST]

            if registrations and posts:
                reg_time = registrations[0].timestamp
                first_post_time = posts[0].timestamp
                time_to_first_post = (first_post_time - reg_time).total_seconds() / 60  # minutes

                if time_to_first_post <= self.immediate_post_threshold:
                    anomaly_score += 0.4
                    anomaly_reasons.append(f"Posted within {int(time_to_first_post)}min of registration")

            # Signal 2: High volume on new account
            if len(user_acts) >= self.high_activity_threshold:
                anomaly_score += 0.3
                anomaly_reasons.append(f"{len(user_acts)} activities in first {account_age} days")

            # Signal 3: No exploration phase (posting without viewing)
            views = [a for a in user_acts if a.activity_type == ActivityType.CONTENT_VIEW]
            if posts and len(views) < len(posts) * 0.5:
                anomaly_score += 0.2
                anomaly_reasons.append("Posting without content consumption (unusual)")

            # Signal 4: Automation indicators
            device_types = set(a.device_type for a in user_acts)
            if "api" in [str(dt).lower() for dt in device_types]:
                anomaly_score += 0.1
                anomaly_reasons.append("API access detected")

            # Normalize score
            confidence = min(anomaly_score, 1.0)

            if confidence >= self.confidence_threshold:
                suspicious_users.append(user_id)
                evidence_map[user_id] = {
                    "account_age_days": account_age,
                    "total_activities": len(user_acts),
                    "posts_count": len(posts),
                    "views_count": len(views),
                    "anomaly_score": round(confidence, 3),
                    "anomaly_reasons": anomaly_reasons
                }

        # Create detection if we found suspicious accounts
        if suspicious_users:
            avg_confidence = sum(evidence_map[u]["anomaly_score"] for u in suspicious_users) / len(suspicious_users)

            if len(suspicious_users) >= 10:
                severity = Severity.HIGH
            elif len(suspicious_users) >= 5:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            detection = self._create_detection(
                severity=severity,
                confidence=avg_confidence,
                description=f"Detected {len(suspicious_users)} new accounts with anomalous lifecycle patterns",
                affected_entities=suspicious_users,
                evidence={
                    "suspicious_account_count": len(suspicious_users),
                    "account_age_threshold_days": self.new_account_days,
                    "immediate_post_threshold_minutes": self.immediate_post_threshold,
                    "sample_accounts": {
                        user_id: evidence_map[user_id]
                        for user_id in suspicious_users[:5]  # Sample
                    }
                },
                recommended_actions=[
                    "Review account activity patterns",
                    "Verify email/phone verification completion",
                    "Consider additional verification for high-volume new accounts",
                    "Cross-reference with T1-002 (automation signatures)"
                ],
                tags=["lifecycle", "new-account", "high-volume", "automation"],
                sigma_rule_id="parallax_t0_005_v1"
            )

            detections.append(detection)

        return detections
