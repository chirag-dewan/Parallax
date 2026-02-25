"""
Custom Detector Example

Shows how to create and use a custom detector.
"""

from typing import Iterable
from datetime import datetime, timedelta

from parallax.detectors.base import BehavioralDetector
from parallax.models import DetectionResult, Severity, UserActivity, DeviceType
from parallax.simulation import TrafficGenerator


class SuspiciousVPNDetector(BehavioralDetector):
    """
    Example custom detector: Flags new accounts with high VPN usage.

    This is a simple example showing the detector pattern.
    """

    def __init__(
        self,
        min_activities: int = 10,
        vpn_threshold: float = 0.5,
        account_age_days: int = 7
    ):
        super().__init__(
            name="CUSTOM-001: Suspicious VPN Usage",
            description="Detects new accounts with unusually high VPN usage"
        )
        self.min_activities = min_activities
        self.vpn_threshold = vpn_threshold
        self.account_age_days = account_age_days

    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """Detect accounts with suspicious VPN patterns."""

        # Group by user
        user_activities: dict[str, list[UserActivity]] = {}
        for activity in activities:
            if activity.user_id not in user_activities:
                user_activities[activity.user_id] = []
            user_activities[activity.user_id].append(activity)

        suspicious_users = []

        for user_id, user_acts in user_activities.items():
            # Skip if not enough activity
            if len(user_acts) < self.min_activities:
                continue

            # Skip if not a new account
            account_age = user_acts[0].account_age_days
            if account_age is None or account_age > self.account_age_days:
                continue

            # Calculate VPN usage ratio
            vpn_count = sum(1 for a in user_acts if a.ip_is_vpn)
            vpn_ratio = vpn_count / len(user_acts)

            # Flag if above threshold
            if vpn_ratio >= self.vpn_threshold:
                suspicious_users.append({
                    "user_id": user_id,
                    "vpn_ratio": vpn_ratio,
                    "activity_count": len(user_acts),
                    "account_age": account_age
                })

        # Create detection if we found suspicious accounts
        if suspicious_users:
            confidence = min(
                len(suspicious_users) / 10,  # More users = higher confidence
                1.0
            )

            return [self._create_detection(
                severity=Severity.MEDIUM,
                confidence=confidence,
                description=f"Found {len(suspicious_users)} new accounts with high VPN usage",
                affected_entities=[u["user_id"] for u in suspicious_users],
                evidence={
                    "suspicious_count": len(suspicious_users),
                    "vpn_threshold": self.vpn_threshold,
                    "account_age_threshold": self.account_age_days,
                    "samples": suspicious_users[:3]
                },
                recommended_actions=[
                    "Review account verification status",
                    "Check for coordinated behavior",
                    "Consider additional verification for VPN users"
                ],
                tags=["vpn", "new-account", "suspicious-behavior"]
            )]

        return []


def main():
    """Demo the custom detector."""
    print("Custom Detector Example\n")

    # Generate some test traffic
    print("Generating test traffic...")
    generator = TrafficGenerator(seed=42)

    start_time = datetime.utcnow() - timedelta(days=3)
    generator.add_organic_users(20, 10, 5, start_time)

    activities = list(generator.generate_time_window(
        start_time,
        datetime.utcnow()
    ))

    # Add some high-VPN accounts manually for demo
    for i in range(5):
        for j in range(15):
            activities.append(
                UserActivity(
                    user_id=f"vpn_user_{i}",
                    session_id=f"sess_{j}",
                    activity_type="content_post",
                    timestamp=start_time + timedelta(hours=j),
                    ip_hash=f"sha256:vpn_ip_{i}",
                    device_fingerprint=f"fp_{i}",
                    device_type=DeviceType.WEB_DESKTOP,
                    user_agent_family="Chrome",
                    account_age_days=2,
                    lifetime_activity_count=j,
                    ip_is_vpn=True  # High VPN usage
                )
            )

    print(f"Generated {len(activities)} activities\n")

    # Run custom detector
    print("Running custom detector...")
    detector = SuspiciousVPNDetector(
        min_activities=10,
        vpn_threshold=0.6,
        account_age_days=7
    )

    detections = detector.detect(activities)

    # Display results
    if detections:
        print(f"✓ Found {len(detections)} detection(s)\n")

        for detection in detections:
            print(f"Detector: {detection.detector_name}")
            print(f"Severity: {detection.severity.value.upper()}")
            print(f"Confidence: {detection.confidence:.1%}")
            print(f"Description: {detection.description}")
            print(f"Affected: {len(detection.affected_entities)} accounts")
            print(f"\nEvidence:")
            for key, value in detection.evidence.items():
                print(f"  {key}: {value}")
    else:
        print("No detections")

    print("\n✅ Example complete!")


if __name__ == "__main__":
    main()
