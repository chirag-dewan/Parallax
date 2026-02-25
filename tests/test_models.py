"""Tests for Pydantic data models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from parallax.models import (
    ActivityType,
    CampaignProfile,
    DetectionResult,
    DeviceType,
    Severity,
    UserActivity,
)


def test_user_activity_creation(sample_activity: UserActivity) -> None:
    """Test UserActivity model creation."""
    assert sample_activity.user_id == "test_user_001"
    assert sample_activity.activity_type == ActivityType.CONTENT_POST
    assert sample_activity.device_type == DeviceType.WEB_DESKTOP


def test_user_activity_validation() -> None:
    """Test UserActivity validation."""
    # Missing required fields should raise ValidationError
    with pytest.raises(ValidationError):
        UserActivity(user_id="test")

    # Invalid activity type should raise ValidationError
    with pytest.raises(ValidationError):
        UserActivity(
            user_id="test",
            session_id="sess_123",
            activity_type="invalid_type",  # type: ignore
            timestamp=datetime.utcnow(),
            ip_hash="sha256:abc",
            device_fingerprint="fp_123",
            device_type=DeviceType.WEB_DESKTOP,
            user_agent_family="Chrome"
        )


def test_user_activity_timestamp_parsing() -> None:
    """Test timestamp parsing from various formats."""
    # ISO format with Z
    activity = UserActivity(
        user_id="test",
        session_id="sess_123",
        activity_type=ActivityType.CONTENT_POST,
        timestamp="2024-01-15T10:30:00Z",
        ip_hash="sha256:abc",
        device_fingerprint="fp_123",
        device_type=DeviceType.WEB_DESKTOP,
        user_agent_family="Chrome"
    )
    assert isinstance(activity.timestamp, datetime)

    # Datetime object
    now = datetime.utcnow()
    activity2 = UserActivity(
        user_id="test",
        session_id="sess_123",
        activity_type=ActivityType.CONTENT_POST,
        timestamp=now,
        ip_hash="sha256:abc",
        device_fingerprint="fp_123",
        device_type=DeviceType.WEB_DESKTOP,
        user_agent_family="Chrome"
    )
    assert activity2.timestamp == now


def test_detection_result_creation() -> None:
    """Test DetectionResult model."""
    detection = DetectionResult(
        detector_name="Test Detector",
        detector_tier=0,
        severity=Severity.HIGH,
        confidence=0.95,
        description="Test detection",
        affected_entities=["user_001", "user_002"],
        evidence={"metric": 42},
        recommended_actions=["Action 1"],
        tags=["test"]
    )

    assert detection.detector_tier == 0
    assert detection.severity == Severity.HIGH
    assert detection.confidence == 0.95
    assert len(detection.affected_entities) == 2


def test_detection_confidence_validation() -> None:
    """Test confidence score validation (must be 0-1)."""
    with pytest.raises(ValidationError):
        DetectionResult(
            detector_name="Test",
            detector_tier=0,
            severity=Severity.HIGH,
            confidence=1.5,  # Invalid
            description="Test",
            affected_entities=[],
            evidence={}
        )


def test_campaign_profile_creation() -> None:
    """Test CampaignProfile model."""
    profile = CampaignProfile(
        name="Test Campaign",
        num_accounts=50,
        post_frequency_mean=10.0,
        post_frequency_std=2.0,
        content_length_mean=200,
        content_length_std=50
    )

    assert profile.name == "Test Campaign"
    assert profile.num_accounts == 50
    assert profile.ip_diversity == 0.3  # Default value
    assert profile.token_reuse_rate == 0.6  # Default value


def test_campaign_profile_validation() -> None:
    """Test CampaignProfile field constraints."""
    # Diversity fields should be 0-1
    with pytest.raises(ValidationError):
        CampaignProfile(
            name="Test",
            num_accounts=10,
            post_frequency_mean=5.0,
            post_frequency_std=1.0,
            content_length_mean=100,
            content_length_std=20,
            ip_diversity=1.5  # Invalid
        )
