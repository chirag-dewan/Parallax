"""Tests for T1-001: Volume Anomaly."""

from detection.tier1.t1_001_volume_anomaly import VolumeAnomalyDetector
from tests.conftest import make_events, build_profile


class TestVolumeAnomaly:
    def setup_method(self):
        self.detector = VolumeAnomalyDetector()

    def test_normal_user_low_score(self, normal_profile, attacker_profile):
        from detection.baselines import PopulationBaseline

        baseline = PopulationBaseline.from_profiles(
            [normal_profile, attacker_profile]
        )
        self.detector.set_population_baseline(baseline)
        result = self.detector.detect(normal_profile)
        assert result.score < 0.5
        assert not result.triggered

    def test_attacker_high_score(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score > 0.5
        assert result.triggered

    def test_insufficient_events(self):
        events = make_events(3, interval_ms=60000)
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score == 0.0
        assert result.confidence == 0.0

    def test_details_contain_z_score(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert "z_score" in result.details
        assert "requests_per_hour" in result.details
