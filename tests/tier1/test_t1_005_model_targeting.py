"""Tests for T1-005: Model Targeting."""

from detection.tier1.t1_005_model_targeting import ModelTargetingDetector
from tests.conftest import make_events, build_profile


class TestModelTargeting:
    def setup_method(self):
        self.detector = ModelTargetingDetector()

    def test_cheap_models_high_score(self):
        events = make_events(50, model="gpt-3.5-turbo")
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.5

    def test_expensive_models_low_score(self):
        events = make_events(50, model="gpt-4")
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score == 0.0

    def test_attacker_profile(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score > 0.3  # All cheap models

    def test_details(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "cheap_model_ratio" in result.details
        assert "model_diversity" in result.details
