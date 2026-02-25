"""Tests for synthetic traffic generator."""

from datetime import datetime, timedelta

import pytest

from parallax.models import ActivityType, CampaignProfile
from parallax.simulation.generator import (
    DistillationCampaign,
    OrganicUserProfile,
    TrafficGenerator,
)


def test_organic_user_profile() -> None:
    """Test organic user profile creation."""
    user = OrganicUserProfile("test_user_001", profile_type="casual")

    assert user.user_id == "test_user_001"
    assert user.profile_type == "casual"
    assert user.post_freq_mean > 0


def test_organic_user_activity_generation() -> None:
    """Test organic user generates valid activities."""
    user = OrganicUserProfile("test_user_001", profile_type="moderate")
    timestamp = datetime.utcnow()

    activity = user.generate_activity(
        ActivityType.CONTENT_POST,
        timestamp,
        lifetime_activity_count=50
    )

    assert activity.user_id == "test_user_001"
    assert activity.activity_type == ActivityType.CONTENT_POST
    assert activity.timestamp == timestamp
    assert activity.content_length is not None
    assert activity.content_length > 0


def test_distillation_campaign_creation() -> None:
    """Test campaign creation."""
    profile = CampaignProfile(
        name="test_campaign",
        num_accounts=20,
        post_frequency_mean=15.0,
        post_frequency_std=2.0,
        content_length_mean=180,
        content_length_std=30
    )

    campaign = DistillationCampaign(profile, datetime.utcnow())

    assert len(campaign.accounts) == 20
    assert all("test_campaign" in acc for acc in campaign.accounts)


def test_campaign_activity_generation() -> None:
    """Test campaign account activity generation."""
    profile = CampaignProfile(
        name="test",
        num_accounts=10,
        post_frequency_mean=10.0,
        post_frequency_std=1.0,
        content_length_mean=150,
        content_length_std=20,
        token_reuse_rate=0.8
    )

    campaign = DistillationCampaign(profile, datetime.utcnow())
    activity = campaign.generate_activity(
        campaign.accounts[0],
        ActivityType.CONTENT_POST,
        datetime.utcnow(),
        lifetime_activity_count=10
    )

    assert activity.user_id == campaign.accounts[0]
    assert activity.activity_type == ActivityType.CONTENT_POST


def test_traffic_generator_initialization() -> None:
    """Test traffic generator with seed."""
    gen1 = TrafficGenerator(seed=42)
    gen2 = TrafficGenerator(seed=42)

    start_time = datetime.utcnow() - timedelta(days=1)

    gen1.add_organic_users(5, 5, 2, start_time)
    gen2.add_organic_users(5, 5, 2, start_time)

    # Same seed should produce same user IDs
    assert len(gen1.organic_users) == len(gen2.organic_users) == 12


def test_traffic_generator_organic_users(organic_traffic) -> None:
    """Test organic traffic generation."""
    activities = list(organic_traffic)

    assert len(activities) > 0

    # Check activities are sorted by timestamp
    timestamps = [a.timestamp for a in activities]
    assert timestamps == sorted(timestamps)

    # Check variety of activity types
    activity_types = set(a.activity_type for a in activities)
    assert len(activity_types) > 1


def test_traffic_generator_campaign(campaign_traffic) -> None:
    """Test campaign traffic generation."""
    activities = list(campaign_traffic)

    assert len(activities) > 0

    # Should include registrations
    registrations = [a for a in activities if a.activity_type == ActivityType.REGISTRATION]
    assert len(registrations) > 0

    # Check for coordination signals
    user_ids = set(a.user_id for a in activities)
    assert "test_campaign" in list(user_ids)[0]


def test_mixed_traffic_generation(mixed_traffic) -> None:
    """Test mixed organic + campaign traffic."""
    assert len(mixed_traffic) > 0

    # Should have both organic and campaign users
    user_ids = [a.user_id for a in mixed_traffic]
    has_organic = any("org_" in uid for uid in user_ids)
    has_campaign = any("campaign_" in uid for uid in user_ids)

    assert has_organic
    assert has_campaign
