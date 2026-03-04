"""Tests for T2-004: Power-Law Deviation."""

from detection.tier2.t2_004_power_law_deviation import PowerLawDeviationDetector
from tests.conftest import make_events, build_profile


class TestPowerLawDeviation:
    def setup_method(self):
        self.detector = PowerLawDeviationDetector()

    def test_few_topics_default_score(self):
        events = make_events(60, topic_category="coding")
        profile = build_profile(events)
        result = self.detector.detect(profile)
        # Single topic = < 3 unique, returns 0.5
        assert result.score == 0.5

    def test_attacker_profile(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert 0.0 <= result.score <= 1.0
        assert "r_squared" in result.details

    def test_normal_profile(self, normal_profile):
        result = self.detector.detect(normal_profile)
        assert 0.0 <= result.score <= 1.0
