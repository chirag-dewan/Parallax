"""Tests for T2-002: Entropy Analysis."""

from detection.tier2.t2_002_entropy_analysis import EntropyAnalysisDetector
from tests.conftest import make_events, build_profile


class TestEntropyAnalysis:
    def setup_method(self):
        self.detector = EntropyAnalysisDetector()

    def test_low_topic_diversity_high_score(self):
        """Attacker with 3 topics cycling should score high on topic threat."""
        events = make_events(100, topic_category="extraction")
        profile = build_profile(events)
        result = self.detector.detect(profile)
        # Single topic = zero entropy = max topic_threat
        assert result.score > 0.4

    def test_high_diversity_lower_score(self, normal_profile):
        result = self.detector.detect(normal_profile)
        # Normal profile has 6 topics
        assert result.details["unique_topics"] >= 5

    def test_attacker_profile(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score > 0.3  # Low topic entropy

    def test_details(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "topic_entropy" in result.details
        assert "topic_entropy_normalized" in result.details
        assert "model_entropy" in result.details
