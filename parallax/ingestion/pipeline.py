"""
Ingestion pipeline for Parallax.

Normalizes and enriches raw activity data before it flows to detectors.
"""

from datetime import datetime, timedelta
from typing import Any, Iterator

from parallax.models import UserActivity


class ActivityEnricher:
    """
    Enriches UserActivity records with contextual metadata.

    Stateful enricher that maintains account history to compute:
    - Account age
    - Lifetime activity counts
    - Historical behavioral baselines
    """

    def __init__(self) -> None:
        # State tracking
        self.account_created: dict[str, datetime] = {}
        self.activity_counts: dict[str, int] = {}

        # Historical data for behavioral analysis
        self.user_devices: dict[str, set[str]] = {}  # user_id -> set of device_fps
        self.user_ips: dict[str, set[str]] = {}      # user_id -> set of ip_hashes

    def enrich(self, activity: UserActivity) -> UserActivity:
        """
        Enrich a single activity record with contextual metadata.

        This method is stateful - it updates internal state based on observed activities.
        """
        user_id = activity.user_id

        # Initialize tracking for new users
        if user_id not in self.account_created:
            self.account_created[user_id] = activity.timestamp
            self.activity_counts[user_id] = 0
            self.user_devices[user_id] = set()
            self.user_ips[user_id] = set()

        # Compute enrichment fields
        account_age = (activity.timestamp - self.account_created[user_id]).days
        lifetime_count = self.activity_counts[user_id]

        # Update activity with enrichments
        activity.account_age_days = account_age
        activity.lifetime_activity_count = lifetime_count

        # Track device/IP diversity (useful for detectors)
        self.user_devices[user_id].add(activity.device_fingerprint)
        self.user_ips[user_id].add(activity.ip_hash)

        # Increment counter
        self.activity_counts[user_id] += 1

        return activity

    def get_user_device_count(self, user_id: str) -> int:
        """Get number of unique devices seen for a user."""
        return len(self.user_devices.get(user_id, set()))

    def get_user_ip_count(self, user_id: str) -> int:
        """Get number of unique IPs seen for a user."""
        return len(self.user_ips.get(user_id, set()))


class ActivityNormalizer:
    """
    Normalizes raw activity data into canonical UserActivity schema.

    Handles various input formats and applies privacy-preserving transformations.
    """

    @staticmethod
    def from_dict(data: dict[str, Any]) -> UserActivity:
        """
        Normalize from dictionary format.

        This would handle various platform-specific formats in production.
        For Phase 1, we assume data is already in our schema.
        """
        # In production, this would contain mapping logic like:
        # - Hashing raw IPs
        # - Extracting user agent families
        # - Normalizing timestamps
        # - Removing PII

        return UserActivity(**data)

    @staticmethod
    def from_json_line(line: str) -> UserActivity:
        """Parse from JSON Lines format."""
        import json
        return ActivityNormalizer.from_dict(json.loads(line))


class IngestionPipeline:
    """
    Complete ingestion pipeline: normalize -> enrich -> validate.

    This is the entry point for all activity data entering Parallax.
    """

    def __init__(self) -> None:
        self.normalizer = ActivityNormalizer()
        self.enricher = ActivityEnricher()

    def process_batch(self, raw_records: list[dict[str, Any]]) -> Iterator[UserActivity]:
        """
        Process a batch of raw activity records.

        Yields enriched UserActivity records ready for detection.
        """
        for record in raw_records:
            # Normalize
            activity = self.normalizer.from_dict(record)

            # Enrich
            activity = self.enricher.enrich(activity)

            # Validate (Pydantic handles this)
            yield activity

    def process_stream(self, records: Iterator[dict[str, Any]]) -> Iterator[UserActivity]:
        """
        Process a stream of raw activity records.

        Useful for real-time processing.
        """
        for record in records:
            activity = self.normalizer.from_dict(record)
            activity = self.enricher.enrich(activity)
            yield activity

    def reset_state(self) -> None:
        """Reset enricher state (useful for testing)."""
        self.enricher = ActivityEnricher()
