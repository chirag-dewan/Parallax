"""Tests for T1-003: Token Ratio."""

from detection.tier1.t1_003_token_ratio import TokenRatioDetector
from tests.conftest import make_events, build_profile


class TestTokenRatio:
    def setup_method(self):
        self.detector = TokenRatioDetector()

    def test_normal_ratio_low_score(self):
        events = make_events(50, input_tokens=200, output_tokens=500)
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score < 0.3  # ratio = 2.5, well below threshold

    def test_distillation_ratio_high_score(self):
        events = make_events(50, input_tokens=40, output_tokens=3900)
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.8  # ratio = 97.5

    def test_attacker_profile(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score > 0.5
        assert result.triggered

    def test_details(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "token_ratio" in result.details
        assert "max_output_fraction" in result.details
