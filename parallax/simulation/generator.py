"""
Synthetic traffic generator for Parallax.

Generates realistic user activity streams including:
- Organic users (casual, power, moderate)
- Distillation campaigns (coordinated inauthentic behavior)
"""

import hashlib
import random
from datetime import datetime, timedelta
from typing import Iterator

import numpy as np
from faker import Faker

from parallax.models import (
    ActivityType,
    CampaignProfile,
    DeviceType,
    UserActivity,
)

fake = Faker()


class OrganicUserProfile:
    """Behavioral profile for organic (real) users."""

    def __init__(
        self,
        user_id: str,
        profile_type: str = "moderate",
        created_at: datetime | None = None
    ):
        self.user_id = user_id
        self.profile_type = profile_type
        self.created_at = created_at or datetime.utcnow()

        # Set behavioral parameters based on profile type
        if profile_type == "casual":
            self.post_freq_mean = 2.0  # posts per day
            self.post_freq_std = 1.0
            self.session_duration_mean = 300  # seconds
            self.session_duration_std = 120
        elif profile_type == "power":
            self.post_freq_mean = 15.0
            self.post_freq_std = 5.0
            self.session_duration_mean = 1800
            self.session_duration_std = 600
        else:  # moderate
            self.post_freq_mean = 6.0
            self.post_freq_std = 2.0
            self.session_duration_mean = 900
            self.session_duration_std = 300

        # Stable characteristics
        self.primary_device = random.choice(list(DeviceType))
        self.primary_ip = self._generate_ip()
        self.device_fp = self._generate_device_fingerprint()

    def _generate_ip(self) -> str:
        """Generate a realistic IP address."""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _generate_device_fingerprint(self) -> str:
        """Generate a stable device fingerprint."""
        components = [
            fake.user_agent(),
            str(random.randint(1000, 2000)),  # screen width
            str(random.randint(600, 1200)),   # screen height
            str(random.randint(1, 32))        # color depth
        ]
        return hashlib.sha256("|".join(components).encode()).hexdigest()[:16]

    def _hash_ip(self, ip: str) -> str:
        """Hash IP with last octet removed (privacy-preserving)."""
        parts = ip.split('.')
        subnet = '.'.join(parts[:3])
        return f"sha256:{hashlib.sha256(subnet.encode()).hexdigest()[:16]}"

    def generate_activity(
        self,
        activity_type: ActivityType,
        timestamp: datetime,
        lifetime_activity_count: int
    ) -> UserActivity:
        """Generate a single activity for this user."""
        # Organic users occasionally change devices/IPs
        use_primary_device = random.random() > 0.1
        use_primary_ip = random.random() > 0.15

        ip = self.primary_ip if use_primary_ip else self._generate_ip()
        device_type = self.primary_device if use_primary_device else random.choice(list(DeviceType))

        # Realistic content characteristics
        if activity_type == ActivityType.CONTENT_POST:
            content_length = int(np.random.normal(250, 80))
            content_length = max(10, min(500, content_length))  # clamp
        else:
            content_length = None

        account_age = (timestamp - self.created_at).days

        return UserActivity(
            user_id=self.user_id,
            session_id=f"sess_{fake.uuid4()[:8]}",
            activity_type=activity_type,
            timestamp=timestamp,
            ip_hash=self._hash_ip(ip),
            device_fingerprint=self.device_fp if use_primary_device else self._generate_device_fingerprint(),
            device_type=device_type,
            user_agent_family=random.choice(["Chrome", "Safari", "Firefox", "Edge"]),
            content_length=content_length,
            interaction_count=random.randint(1, 20) if activity_type == ActivityType.CONTENT_VIEW else None,
            time_on_page=random.uniform(10, 300) if activity_type == ActivityType.CONTENT_VIEW else None,
            account_age_days=account_age,
            lifetime_activity_count=lifetime_activity_count,
            ip_geo_country=random.choice(["US", "GB", "CA", "AU", "DE"]),
            ip_is_vpn=random.random() < 0.05,  # 5% VPN usage
            metadata={}
        )


class DistillationCampaign:
    """Generates coordinated inauthentic behavior patterns."""

    def __init__(self, profile: CampaignProfile, start_time: datetime):
        self.profile = profile
        self.start_time = start_time

        # Create campaign accounts
        self.accounts = [
            f"campaign_{profile.name}_{i:03d}"
            for i in range(profile.num_accounts)
        ]

        # Shared infrastructure (fingerprints of coordination)
        self._shared_ips = [self._generate_ip() for _ in range(max(1, int(profile.num_accounts * profile.ip_diversity)))]
        self._shared_devices = [self._generate_device_fp() for _ in range(max(1, int(profile.num_accounts * profile.device_diversity)))]

        # Shared content tokens (for token reuse detection)
        self._token_pool = [
            fake.sentence(nb_words=3) for _ in range(50)
        ]

    def _generate_ip(self) -> str:
        """Generate an IP address."""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _generate_device_fp(self) -> str:
        """Generate a device fingerprint."""
        return hashlib.sha256(fake.user_agent().encode()).hexdigest()[:16]

    def _hash_ip(self, ip: str) -> str:
        """Hash IP with last octet removed."""
        parts = ip.split('.')
        subnet = '.'.join(parts[:3])
        return f"sha256:{hashlib.sha256(subnet.encode()).hexdigest()[:16]}"

    def _select_shared_resource(self, pool: list, diversity: float) -> str:
        """Select from shared resource pool based on diversity setting."""
        # Low diversity = more sharing
        if random.random() > diversity:
            # Use shared resource
            return random.choice(pool[:max(1, len(pool) // 3)])
        else:
            return random.choice(pool)

    def generate_activity(
        self,
        account_id: str,
        activity_type: ActivityType,
        timestamp: datetime,
        lifetime_activity_count: int
    ) -> UserActivity:
        """Generate activity for a campaign account (exhibits automation signatures)."""

        account_age = (timestamp - self.start_time).days

        # Campaign accounts share infrastructure
        ip = self._select_shared_resource(self._shared_ips, self.profile.ip_diversity)
        device_fp = self._select_shared_resource(self._shared_devices, self.profile.device_diversity)

        # Content characteristics (more uniform than organic)
        if activity_type == ActivityType.CONTENT_POST:
            # Tighter distribution around mean (automation signature)
            content_length = int(np.random.normal(
                self.profile.content_length_mean,
                self.profile.content_length_std * 0.5  # Less variance than organic
            ))
            content_length = max(10, min(500, content_length))

            # Token reuse metadata (for T1-003 detection)
            if random.random() < self.profile.token_reuse_rate:
                reused_token = random.choice(self._token_pool)
                metadata = {"contains_common_token": True, "token_hash": hashlib.md5(reused_token.encode()).hexdigest()[:8]}
            else:
                metadata = {}
        else:
            content_length = None
            metadata = {}

        return UserActivity(
            user_id=account_id,
            session_id=f"sess_{fake.uuid4()[:8]}",
            activity_type=activity_type,
            timestamp=timestamp,
            ip_hash=self._hash_ip(ip),
            device_fingerprint=device_fp,
            device_type=DeviceType.API if random.random() < 0.3 else DeviceType.WEB_DESKTOP,
            user_agent_family="Python-requests" if random.random() < 0.2 else "Chrome",
            content_length=content_length,
            interaction_count=random.randint(5, 15) if activity_type == ActivityType.CONTENT_VIEW else None,
            time_on_page=random.uniform(5, 30) if activity_type == ActivityType.CONTENT_VIEW else None,  # Shorter than organic
            account_age_days=account_age,
            lifetime_activity_count=lifetime_activity_count,
            ip_geo_country="US",  # Less geographic diversity
            ip_is_vpn=random.random() < 0.4,  # Higher VPN usage than organic
            metadata=metadata
        )


class TrafficGenerator:
    """
    Main traffic generator combining organic and campaign traffic.

    Generates temporal streams of UserActivity records.
    """

    def __init__(self, seed: int | None = None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
            Faker.seed(seed)

        self.organic_users: list[OrganicUserProfile] = []
        self.campaigns: list[DistillationCampaign] = []
        self.activity_counters: dict[str, int] = {}

    def add_organic_users(self, num_casual: int, num_moderate: int, num_power: int, start_time: datetime) -> None:
        """Add organic user profiles."""
        for i in range(num_casual):
            user_id = f"org_casual_{i:04d}"
            self.organic_users.append(OrganicUserProfile(user_id, "casual", start_time - timedelta(days=random.randint(30, 365))))
            self.activity_counters[user_id] = random.randint(50, 200)

        for i in range(num_moderate):
            user_id = f"org_moderate_{i:04d}"
            self.organic_users.append(OrganicUserProfile(user_id, "moderate", start_time - timedelta(days=random.randint(30, 365))))
            self.activity_counters[user_id] = random.randint(200, 800)

        for i in range(num_power):
            user_id = f"org_power_{i:04d}"
            self.organic_users.append(OrganicUserProfile(user_id, "power", start_time - timedelta(days=random.randint(30, 365))))
            self.activity_counters[user_id] = random.randint(800, 3000)

    def add_campaign(self, profile: CampaignProfile, start_time: datetime) -> None:
        """Add a distillation campaign."""
        campaign = DistillationCampaign(profile, start_time)
        self.campaigns.append(campaign)

        # Initialize activity counters for campaign accounts
        for account_id in campaign.accounts:
            self.activity_counters[account_id] = 0

    def generate_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
        include_registrations: bool = False
    ) -> Iterator[UserActivity]:
        """
        Generate activity stream for a time window.

        Yields UserActivity records in chronological order.
        """
        activities: list[UserActivity] = []

        # Generate registrations if requested
        if include_registrations:
            for campaign in self.campaigns:
                for account_id in campaign.accounts:
                    # Bulk registration signature: tight time clustering
                    reg_time = start_time + timedelta(
                        seconds=random.uniform(0, 3600 * 2)  # Within 2 hours
                    )
                    if reg_time <= end_time:
                        activity = campaign.generate_activity(
                            account_id,
                            ActivityType.REGISTRATION,
                            reg_time,
                            0
                        )
                        activities.append(activity)
                        self.activity_counters[account_id] += 1

        # Generate organic user activities
        for user in self.organic_users:
            # Determine number of activities in this window
            window_days = (end_time - start_time).total_seconds() / 86400
            expected_activities = user.post_freq_mean * window_days

            num_activities = max(0, int(np.random.poisson(expected_activities)))

            for _ in range(num_activities):
                timestamp = start_time + timedelta(
                    seconds=random.uniform(0, (end_time - start_time).total_seconds())
                )

                activity_type = random.choices(
                    [ActivityType.CONTENT_POST, ActivityType.CONTENT_VIEW, ActivityType.LIKE, ActivityType.COMMENT],
                    weights=[0.3, 0.4, 0.2, 0.1]
                )[0]

                activity = user.generate_activity(
                    activity_type,
                    timestamp,
                    self.activity_counters[user.user_id]
                )
                activities.append(activity)
                self.activity_counters[user.user_id] += 1

        # Generate campaign activities
        for campaign in self.campaigns:
            for account_id in campaign.accounts:
                # Campaign accounts post more frequently and in bursts
                window_days = (end_time - start_time).total_seconds() / 86400
                expected_posts = campaign.profile.post_frequency_mean * window_days

                num_posts = max(0, int(np.random.normal(expected_posts, campaign.profile.post_frequency_std)))

                for _ in range(num_posts):
                    # Time concentration: high concentration = coordinated timing
                    if random.random() < campaign.profile.time_concentration:
                        # Burst window (1 hour)
                        burst_start = start_time + timedelta(hours=random.randint(0, int(window_days * 24)))
                        timestamp = burst_start + timedelta(seconds=random.uniform(0, 3600))
                    else:
                        # Random timing
                        timestamp = start_time + timedelta(
                            seconds=random.uniform(0, (end_time - start_time).total_seconds())
                        )

                    if timestamp <= end_time:
                        activity = campaign.generate_activity(
                            account_id,
                            ActivityType.CONTENT_POST,
                            timestamp,
                            self.activity_counters[account_id]
                        )
                        activities.append(activity)
                        self.activity_counters[account_id] += 1

        # Sort by timestamp and yield
        activities.sort(key=lambda a: a.timestamp)
        for activity in activities:
            yield activity
