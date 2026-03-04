"""Tests for T1-002: Automation Signature."""

from detection.tier1.t1_002_automation_signature import AutomationSignatureDetector
from tests.conftest import make_events, build_profile


class TestAutomationSignature:
    def setup_method(self):
        self.detector = AutomationSignatureDetector()

    def test_mechanical_timing_high_score(self):
        # Very regular intervals (CV ~ 0)
        events = make_events(100, interval_ms=1000)
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.5

    def test_normal_user_low_score(self, normal_profile):
        result = self.detector.detect(normal_profile)
        # Normal profile has varied intervals
        assert result.score < 0.8

    def test_attacker_high_score(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score > 0.5

    def test_details_fields(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "cv" in result.details
        assert "cv_score" in result.details
        assert "diurnal_score" in result.details
