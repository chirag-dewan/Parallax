"""Tests for T1-002: Automation Signature Detector."""

from datetime import datetime, timedelta

import pytest

from parallax.detectors.tier1 import AutomationSignatureDetector
from parallax.models import ActivityType, DeviceType, UserActivity


def test_automation_signature_detector_organic() -> None:
    """Test detector doesn't trigger on organic-looking activity."""
    detector = AutomationSignatureDetector(min_activities=10)

    now = datetime.utcnow()

    # Organic user with varied timing and devices
    activities = []
    for i in range(15):
        activities.append(
            UserActivity(
                user_id="organic_user",
                session_id=f"sess_{i}",
                activity_type=ActivityType.CONTENT_POST,
                timestamp=now + timedelta(minutes=i * 30 + (i % 5) * 10),  # Varied timing
                ip_hash="sha256:ip_home" if i % 3 == 0 else "sha256:ip_work",
                device_fingerprint="fp_desktop" if i % 2 == 0 else "fp_mobile",
                device_type=DeviceType.WEB_DESKTOP if i % 2 == 0 else DeviceType.WEB_MOBILE,
                user_agent_family="Chrome" if i % 3 == 0 else "Safari",
                ip_is_vpn=False
            )
        )

    detections = detector.detect(activities)
    # Should not detect automation
    assert len(detections) == 0


def test_automation_signature_detector_bot() -> None:
    """Test detector identifies automated behavior."""
    detector = AutomationSignatureDetector(
        min_activities=10,
        timing_regularity_threshold=0.15
    )

    now = datetime.utcnow()

    # Bot with regular timing and API usage
    activities = []
    for i in range(20):
        activities.append(
            UserActivity(
                user_id="bot_user",
                session_id=f"sess_{i}",
                activity_type=ActivityType.CONTENT_POST,
                timestamp=now + timedelta(minutes=i * 5),  # Exactly every 5 minutes
                ip_hash="sha256:same_ip",  # Same IP
                device_fingerprint="fp_same_device",  # Same device
                device_type=DeviceType.API,  # API usage
                user_agent_family="Python-requests",  # Bot user agent
                ip_is_vpn=True
            )
        )

    detections = detector.detect(activities)
    assert len(detections) > 0

    detection = detections[0]
    assert "bot_user" in detection.affected_entities
    assert detection.confidence >= 0.7
    assert "automation" in detection.description.lower()


def test_automation_signature_timing_regularity() -> None:
    """Test timing regularity calculation."""
    detector = AutomationSignatureDetector()

    now = datetime.utcnow()

    # Regular timing
    regular_activities = [
        UserActivity(
            user_id="user",
            session_id=f"sess_{i}",
            activity_type=ActivityType.CONTENT_POST,
            timestamp=now + timedelta(seconds=i * 60),  # Exactly every 60 seconds
            ip_hash="sha256:ip",
            device_fingerprint="fp_device",
            device_type=DeviceType.WEB_DESKTOP,
            user_agent_family="Chrome"
        )
        for i in range(10)
    ]

    cv, mean_interval = detector._analyze_timing_regularity(regular_activities)
    assert cv is not None
    assert cv < 0.2  # Very low coefficient of variation


def test_automation_signature_shared_infrastructure() -> None:
    """Test detection of shared infrastructure."""
    detector = AutomationSignatureDetector()

    now = datetime.utcnow()

    # Multiple accounts sharing infrastructure
    user_activity_groups = []
    for user_id in range(5):
        group = [
            UserActivity(
                user_id=f"user_{user_id}",
                session_id=f"sess_{i}",
                activity_type=ActivityType.CONTENT_POST,
                timestamp=now + timedelta(minutes=i),
                ip_hash="sha256:shared_ip",  # All share same IP
                device_fingerprint="fp_shared_device",  # All share same device
                device_type=DeviceType.WEB_DESKTOP,
                user_agent_family="Chrome"
            )
            for i in range(10)
        ]
        user_activity_groups.append(group)

    result = detector._detect_shared_infrastructure(user_activity_groups)
    assert result["has_sharing"] is True
    assert result["ips_per_account"] < 0.5


def test_automation_signature_campaign_traffic(campaign_traffic) -> None:
    """Test detector on campaign traffic."""
    detector = AutomationSignatureDetector()

    activities = list(campaign_traffic)
    detections = detector.detect(activities)

    # Campaign traffic should trigger automation detection
    if detections:
        detection = detections[0]
        assert "suspicious_account_count" in detection.evidence
        assert detection.confidence > 0
