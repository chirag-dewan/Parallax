"""Tests for T2-001: Distribution Divergence."""

from detection.tier2.t2_001_distribution_divergence import DistributionDivergenceDetector
from detection.baselines import PopulationBaseline
from tests.conftest import make_events, build_profile


class TestDistributionDivergence:
    def setup_method(self):
        self.detector = DistributionDivergenceDetector()

    def test_no_baseline_returns_zero(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score == 0.0

    def test_with_baseline(self, normal_profile, attacker_profile):
        baseline = PopulationBaseline.from_profiles(
            [normal_profile, attacker_profile]
        )
        self.detector.set_population_baseline(baseline)
        result = self.detector.detect(attacker_profile)
        assert "kl_divergence" in result.details

    def test_details_fields(self, normal_profile, attacker_profile):
        baseline = PopulationBaseline.from_profiles(
            [normal_profile, attacker_profile]
        )
        self.detector.set_population_baseline(baseline)
        result = self.detector.detect(attacker_profile)
        assert "interval_kl" in result.details
        assert "token_kl" in result.details
        assert "topic_kl" in result.details
