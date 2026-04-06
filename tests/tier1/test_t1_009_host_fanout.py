"""Tests for T1-009: Host Fan-Out."""

from datetime import datetime, timedelta, timezone

from detection.tier1.t1_009_host_fanout import HostFanoutDetector
from tests.conftest import make_event, build_profile


class TestHostFanout:
    def setup_method(self):
        self.detector = HostFanoutDetector()

    def test_low_fanout_low_score(self):
        """User hitting 2 distinct hosts in 1 hour -> low score."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        for i in range(50):
            events.append(
                make_event(
                    account_id="normal_user",
                    timestamp=base + timedelta(seconds=60 * i),
                    inter_request_interval_ms=60000 if i > 0 else 0,
                    topic_category="fileserver" if i % 2 == 0 else "database",
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score < 0.3
        assert not result.triggered

    def test_high_fanout_high_score(self):
        """User hitting 9 distinct hosts in 1 hour -> high score."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        topics = [
            "authentication", "fileserver", "database", "webserver",
            "mailserver", "dns", "directory", "compute", "monitoring",
        ]
        events = []
        for i in range(90):
            events.append(
                make_event(
                    account_id="lateral_mover",
                    archetype="compromised",
                    timestamp=base + timedelta(seconds=30 * i),
                    inter_request_interval_ms=30000 if i > 0 else 0,
                    topic_category=topics[i % len(topics)],
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.5
        assert result.triggered

    def test_burst_fanout_across_windows(self):
        """Normal for 3 hours, then lateral movement burst in hour 4."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        # First 3 hours: 2 topics, slow
        for i in range(30):
            events.append(
                make_event(
                    account_id="burst_user",
                    timestamp=base + timedelta(minutes=6 * i),
                    inter_request_interval_ms=360000 if i > 0 else 0,
                    topic_category="fileserver" if i % 2 == 0 else "database",
                )
            )
        # Hour 4: burst hitting 8 topics in 1 hour
        burst_start = base + timedelta(hours=3)
        burst_topics = [
            "authentication", "fileserver", "database", "webserver",
            "mailserver", "dns", "directory", "compute",
        ]
        for i in range(40):
            events.append(
                make_event(
                    account_id="burst_user",
                    timestamp=burst_start + timedelta(seconds=90 * i),
                    inter_request_interval_ms=90000 if i > 0 else 0,
                    topic_category=burst_topics[i % len(burst_topics)],
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.4
        assert result.details["max_unique_hosts_in_window"] >= 7

    def test_insufficient_events(self):
        """Fewer than min_events -> zero score."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                account_id="sparse_user",
                timestamp=base + timedelta(seconds=60 * i),
                inter_request_interval_ms=60000 if i > 0 else 0,
            )
            for i in range(5)
        ]
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score == 0.0
        assert result.confidence == 0.0

    def test_single_host_zero_score(self):
        """All events to same host -> zero score."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                account_id="single_host",
                timestamp=base + timedelta(seconds=30 * i),
                inter_request_interval_ms=30000 if i > 0 else 0,
                topic_category="fileserver",
            )
            for i in range(100)
        ]
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score < 0.1

    def test_details_fields(self):
        """Check that diagnostic details are populated."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        topics = ["authentication", "fileserver", "database", "webserver", "mailserver"]
        events = [
            make_event(
                account_id="detail_check",
                timestamp=base + timedelta(seconds=60 * i),
                inter_request_interval_ms=60000 if i > 0 else 0,
                topic_category=topics[i % len(topics)],
            )
            for i in range(50)
        ]
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert "max_unique_hosts_in_window" in result.details
        assert "new_hosts_per_hour" in result.details
        assert "unique_to_event_ratio" in result.details
        assert "total_windows" in result.details
