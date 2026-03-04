"""Tests for T2-006: Behavioral Shift."""

from datetime import datetime, timedelta, timezone

from detection.tier2.t2_006_behavioral_shift import BehavioralShiftDetector
from tests.conftest import make_event, build_profile


class TestBehavioralShift:
    def setup_method(self):
        self.detector = BehavioralShiftDetector()

    def test_consistent_profile_low_score(self, normal_profile):
        result = self.detector.detect(normal_profile)
        # Normal profile is consistent throughout
        assert result.score < 0.5

    def test_sudden_shift_high_score(self):
        """Profile that changes dramatically mid-stream."""
        events = []
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)

        # First half: normal behavior
        for i in range(30):
            events.append(
                make_event(
                    timestamp=base + timedelta(minutes=i * 5),
                    input_tokens=200,
                    output_tokens=500,
                    inter_request_interval_ms=300000 if i > 0 else 0,
                    request_type="web",
                )
            )

        # Second half: attacker behavior
        for i in range(30):
            events.append(
                make_event(
                    timestamp=base + timedelta(minutes=150 + i),
                    input_tokens=40,
                    output_tokens=3900,
                    inter_request_interval_ms=60000 if i > 0 else 0,
                    request_type="api",
                )
            )

        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.3  # Significant shift detected

    def test_details(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "velocity_shift" in result.details
        assert "token_shift" in result.details
        assert "max_shift" in result.details
