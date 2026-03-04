"""Tests for T2-005: Temporal Clustering."""

from detection.tier2.t2_005_temporal_clustering import TemporalClusteringDetector
from tests.conftest import make_events, build_profile


class TestTemporalClustering:
    def setup_method(self):
        self.detector = TemporalClusteringDetector()

    def test_regular_timing_high_score(self):
        """Perfectly regular intervals should have low Fano factor."""
        events = make_events(100, interval_ms=1000)
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.3  # Regular = mechanical

    def test_attacker_profile(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "fano_factor" in result.details

    def test_normal_profile(self, normal_profile):
        result = self.detector.detect(normal_profile)
        assert 0.0 <= result.score <= 1.0
