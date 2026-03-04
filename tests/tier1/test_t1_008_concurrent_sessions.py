"""Tests for T1-008: Concurrent Sessions."""

from datetime import datetime, timedelta, timezone

from detection.tier1.t1_008_concurrent_sessions import ConcurrentSessionsDetector
from tests.conftest import make_event, build_profile


class TestConcurrentSessions:
    def setup_method(self):
        self.detector = ConcurrentSessionsDetector()

    def test_no_overlap_low_score(self):
        """Sequential conversations should score low."""
        events = []
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(20):
            # Each conv has 1 event, no overlap possible
            events.append(
                make_event(
                    timestamp=base + timedelta(minutes=i * 10),
                    conversation_id=f"conv_{i}",
                    inter_request_interval_ms=600000 if i > 0 else 0,
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score < 0.3

    def test_high_overlap_high_score(self):
        """Many overlapping conversations should score high."""
        events = []
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Create 15 conversations all overlapping in a 1-minute window
        for i in range(15):
            for turn in range(3):
                events.append(
                    make_event(
                        timestamp=base + timedelta(seconds=turn * 20 + i),
                        conversation_id=f"conv_{i}",
                        turn_number=turn,
                        inter_request_interval_ms=20000 if turn > 0 else 0,
                    )
                )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.5

    def test_details(self):
        events = []
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(20):
            events.append(
                make_event(
                    timestamp=base + timedelta(minutes=i),
                    conversation_id=f"conv_{i}",
                    inter_request_interval_ms=60000 if i > 0 else 0,
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert "max_concurrent" in result.details
