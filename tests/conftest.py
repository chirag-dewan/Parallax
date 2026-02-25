"""Pytest configuration and shared fixtures."""

from datetime import datetime, timedelta
from typing import Iterator

import pytest

from parallax.models import (
    ActivityType,
    CampaignProfile,
    DeviceType,
    UserActivity,
)
from parallax.simulation.generator import TrafficGenerator


@pytest.fixture
def sample_activity() -> UserActivity:
    """Create a single sample UserActivity."""
    return UserActivity(
        user_id="test_user_001",
        session_id="sess_test_123",
        activity_type=ActivityType.CONTENT_POST,
        timestamp=datetime.utcnow(),
        ip_hash="sha256:abc123",
        device_fingerprint="fp_test_device",
        device_type=DeviceType.WEB_DESKTOP,
        user_agent_family="Chrome",
        content_length=250,
        account_age_days=30,
        lifetime_activity_count=100,
        ip_geo_country="US",
        ip_is_vpn=False,
        metadata={}
    )


@pytest.fixture
def organic_traffic() -> Iterator[UserActivity]:
    """Generate organic traffic for testing."""
    generator = TrafficGenerator(seed=42)

    start_time = datetime.utcnow() - timedelta(days=7)
    generator.add_organic_users(
        num_casual=10,
        num_moderate=10,
        num_power=5,
        start_time=start_time
    )

    end_time = datetime.utcnow()
    return generator.generate_time_window(start_time, end_time)


@pytest.fixture
def campaign_traffic() -> Iterator[UserActivity]:
    """Generate campaign traffic for testing."""
    generator = TrafficGenerator(seed=42)

    start_time = datetime.utcnow() - timedelta(days=7)

    campaign = CampaignProfile(
        name="test_campaign",
        num_accounts=20,
        post_frequency_mean=15.0,
        post_frequency_std=2.0,
        content_length_mean=180,
        content_length_std=30,
        use_shared_ips=True,
        ip_diversity=0.2,
        device_diversity=0.1,
        time_concentration=0.8,
        token_reuse_rate=0.7
    )

    generator.add_campaign(campaign, start_time)

    end_time = datetime.utcnow()
    return generator.generate_time_window(
        start_time,
        end_time,
        include_registrations=True
    )


@pytest.fixture
def mixed_traffic() -> list[UserActivity]:
    """Generate mixed organic + campaign traffic."""
    generator = TrafficGenerator(seed=42)

    start_time = datetime.utcnow() - timedelta(days=7)

    # Organic users
    generator.add_organic_users(
        num_casual=20,
        num_moderate=20,
        num_power=10,
        start_time=start_time
    )

    # Campaign
    campaign = CampaignProfile(
        name="test_campaign",
        num_accounts=30,
        post_frequency_mean=20.0,
        post_frequency_std=3.0,
        content_length_mean=180,
        content_length_std=40,
        use_shared_ips=True,
        ip_diversity=0.15,
        device_diversity=0.1,
        time_concentration=0.85,
        token_reuse_rate=0.75
    )

    generator.add_campaign(campaign, start_time)

    end_time = datetime.utcnow()
    return list(generator.generate_time_window(
        start_time,
        end_time,
        include_registrations=True
    ))
