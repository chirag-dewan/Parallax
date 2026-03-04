"""Tests for T1-004: Session Anomaly."""

from detection.tier1.t1_004_session_anomaly import SessionAnomalyDetector
from tests.conftest import make_events, build_profile


class TestSessionAnomaly:
    def setup_method(self):
        self.detector = SessionAnomalyDetector()

    def test_single_turn_attacker(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        # Attacker has 100% single-turn ratio and high conv/day
        assert result.score > 0.5
        assert result.triggered

    def test_multi_turn_normal(self, normal_profile):
        result = self.detector.detect(normal_profile)
        assert result.score < 0.5

    def test_details(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "single_turn_ratio" in result.details
        assert "conversations_per_day" in result.details
