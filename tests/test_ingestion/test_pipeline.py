"""Tests for ingestion pipeline."""

from datetime import datetime

import pytest

from parallax.ingestion.pipeline import (
    ActivityEnricher,
    ActivityNormalizer,
    IngestionPipeline,
)
from parallax.models import ActivityType, DeviceType, UserActivity


def test_activity_normalizer() -> None:
    """Test activity normalizer from dict."""
    data = {
        "user_id": "test_user",
        "session_id": "sess_123",
        "activity_type": "content_post",
        "timestamp": "2024-01-15T10:30:00Z",
        "ip_hash": "sha256:abc",
        "device_fingerprint": "fp_123",
        "device_type": "web_desktop",
        "user_agent_family": "Chrome"
    }

    normalizer = ActivityNormalizer()
    activity = normalizer.from_dict(data)

    assert isinstance(activity, UserActivity)
    assert activity.user_id == "test_user"
    assert activity.activity_type == ActivityType.CONTENT_POST


def test_activity_enricher() -> None:
    """Test activity enricher adds metadata."""
    enricher = ActivityEnricher()

    activity1 = UserActivity(
        user_id="test_user",
        session_id="sess_1",
        activity_type=ActivityType.REGISTRATION,
        timestamp=datetime.utcnow(),
        ip_hash="sha256:ip",
        device_fingerprint="fp_device",
        device_type=DeviceType.WEB_DESKTOP,
        user_agent_family="Chrome"
    )

    enriched1 = enricher.enrich(activity1)

    # First activity should have age 0 and count 0
    assert enriched1.account_age_days == 0
    assert enriched1.lifetime_activity_count == 0

    # Second activity should increment count
    activity2 = UserActivity(
        user_id="test_user",
        session_id="sess_2",
        activity_type=ActivityType.CONTENT_POST,
        timestamp=datetime.utcnow(),
        ip_hash="sha256:ip",
        device_fingerprint="fp_device",
        device_type=DeviceType.WEB_DESKTOP,
        user_agent_family="Chrome"
    )

    enriched2 = enricher.enrich(activity2)
    assert enriched2.lifetime_activity_count == 1


def test_enricher_tracks_device_diversity() -> None:
    """Test enricher tracks device and IP diversity."""
    enricher = ActivityEnricher()

    # Add activities with different devices
    for i in range(3):
        activity = UserActivity(
            user_id="test_user",
            session_id=f"sess_{i}",
            activity_type=ActivityType.CONTENT_POST,
            timestamp=datetime.utcnow(),
            ip_hash=f"sha256:ip_{i}",
            device_fingerprint=f"fp_device_{i}",
            device_type=DeviceType.WEB_DESKTOP,
            user_agent_family="Chrome"
        )
        enricher.enrich(activity)

    assert enricher.get_user_device_count("test_user") == 3
    assert enricher.get_user_ip_count("test_user") == 3


def test_ingestion_pipeline_batch() -> None:
    """Test full ingestion pipeline with batch."""
    pipeline = IngestionPipeline()

    records = [
        {
            "user_id": "user_001",
            "session_id": "sess_1",
            "activity_type": "registration",
            "timestamp": "2024-01-15T10:00:00Z",
            "ip_hash": "sha256:ip1",
            "device_fingerprint": "fp_1",
            "device_type": "web_desktop",
            "user_agent_family": "Chrome"
        },
        {
            "user_id": "user_001",
            "session_id": "sess_2",
            "activity_type": "content_post",
            "timestamp": "2024-01-15T11:00:00Z",
            "ip_hash": "sha256:ip1",
            "device_fingerprint": "fp_1",
            "device_type": "web_desktop",
            "user_agent_family": "Chrome"
        }
    ]

    enriched = list(pipeline.process_batch(records))

    assert len(enriched) == 2
    assert enriched[0].lifetime_activity_count == 0
    assert enriched[1].lifetime_activity_count == 1


def test_ingestion_pipeline_reset() -> None:
    """Test pipeline state reset."""
    pipeline = IngestionPipeline()

    record = {
        "user_id": "test_user",
        "session_id": "sess_1",
        "activity_type": "registration",
        "timestamp": "2024-01-15T10:00:00Z",
        "ip_hash": "sha256:ip",
        "device_fingerprint": "fp",
        "device_type": "web_desktop",
        "user_agent_family": "Chrome"
    }

    list(pipeline.process_batch([record]))

    # Enricher should have state
    assert "test_user" in pipeline.enricher.account_created

    # Reset
    pipeline.reset_state()

    # State should be cleared
    assert "test_user" not in pipeline.enricher.account_created
