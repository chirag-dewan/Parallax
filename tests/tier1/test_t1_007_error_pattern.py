"""Tests for T1-007: Error Pattern."""

from detection.tier1.t1_007_error_pattern import ErrorPatternDetector
from tests.conftest import make_events, build_profile


class TestErrorPattern:
    def setup_method(self):
        self.detector = ErrorPatternDetector()

    def test_clean_profile_low_score(self, normal_profile):
        result = self.detector.detect(normal_profile)
        assert result.score < 0.3

    def test_high_safety_triggers(self):
        events = make_events(50, safety_filter_triggered=True)
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.3  # 100% safety trigger rate

    def test_attacker_profile(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score > 0.3

    def test_details(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "safety_trigger_rate" in result.details
        assert "rate_limit_hit_rate" in result.details
