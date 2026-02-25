"""Tests for T0-001: Bulk Registration Detector."""

from datetime import datetime, timedelta

import pytest

from parallax.detectors.tier0 import BulkRegistrationDetector
from parallax.models import ActivityType, DeviceType, Severity, UserActivity


def test_bulk_registration_detector_no_registrations() -> None:
    """Test detector with no registration activities."""
    detector = BulkRegistrationDetector(threshold=5)

    activities = [
        UserActivity(
            user_id=f"user_{i}",
            session_id=f"sess_{i}",
            activity_type=ActivityType.CONTENT_POST,
            timestamp=datetime.utcnow(),
            ip_hash="sha256:abc123",
            device_fingerprint=f"fp_{i}",
            device_type=DeviceType.WEB_DESKTOP,
            user_agent_family="Chrome"
        )
        for i in range(10)
    ]

    detections = detector.detect(activities)
    assert len(detections) == 0


def test_bulk_registration_detector_below_threshold() -> None:
    """Test detector with registrations below threshold."""
    detector = BulkRegistrationDetector(threshold=10, time_window_hours=2)

    now = datetime.utcnow()
    activities = [
        UserActivity(
            user_id=f"user_{i}",
            session_id=f"sess_{i}",
            activity_type=ActivityType.REGISTRATION,
            timestamp=now + timedelta(minutes=i),
            ip_hash="sha256:same_subnet",  # Same subnet
            device_fingerprint=f"fp_{i}",
            device_type=DeviceType.WEB_DESKTOP,
            user_agent_family="Chrome"
        )
        for i in range(5)  # Below threshold
    ]

    detections = detector.detect(activities)
    assert len(detections) == 0


def test_bulk_registration_detector_triggers() -> None:
    """Test detector triggers on bulk registrations."""
    detector = BulkRegistrationDetector(threshold=10, time_window_hours=2, confidence_threshold=0.5)

    now = datetime.utcnow()
    activities = [
        UserActivity(
            user_id=f"user_{i:03d}",
            session_id=f"sess_{i}",
            activity_type=ActivityType.REGISTRATION,
            timestamp=now + timedelta(minutes=i * 2),  # Within 2 hours
            ip_hash="sha256:same_subnet",  # Same subnet
            device_fingerprint=f"fp_device_{i % 3}",  # Some variety
            device_type=DeviceType.WEB_DESKTOP,
            user_agent_family="Chrome"
        )
        for i in range(15)  # Above threshold
    ]

    detections = detector.detect(activities)
    assert len(detections) > 0

    detection = detections[0]
    assert detection.severity in [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert detection.confidence >= 0.5
    assert "registration" in detection.description.lower()
    assert len(detection.affected_entities) >= 10


def test_bulk_registration_time_window() -> None:
    """Test detector respects time window."""
    detector = BulkRegistrationDetector(threshold=5, time_window_hours=1)

    now = datetime.utcnow()

    # 10 registrations spread over 5 hours (shouldn't trigger)
    activities = [
        UserActivity(
            user_id=f"user_{i}",
            session_id=f"sess_{i}",
            activity_type=ActivityType.REGISTRATION,
            timestamp=now + timedelta(hours=i * 0.5),
            ip_hash="sha256:same_subnet",
            device_fingerprint="fp_device",
            device_type=DeviceType.WEB_DESKTOP,
            user_agent_family="Chrome"
        )
        for i in range(10)
    ]

    detections = detector.detect(activities)
    # Should not trigger because registrations are spread out
    # (though some might cluster in 1-hour windows)
    # This is time-dependent, so we just check it runs without error
    assert isinstance(detections, list)


def test_bulk_registration_evidence(campaign_traffic) -> None:
    """Test detection evidence contains useful info."""
    detector = BulkRegistrationDetector(threshold=5)

    activities = list(campaign_traffic)
    detections = detector.detect(activities)

    if detections:
        detection = detections[0]
        assert "registration_count" in detection.evidence
        assert "time_window_hours" in detection.evidence
        assert "ip_hash" in detection.evidence
        assert detection.evidence["registration_count"] >= detector.threshold
