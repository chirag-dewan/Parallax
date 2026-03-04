"""Tests for T2-003: Cross-Account Correlation."""

from detection.tier2.t2_003_cross_account_correlation import (
    CrossAccountCorrelationDetector,
)
from detection.baselines import PopulationBaseline
from tests.conftest import make_events, build_profile


class TestCrossAccountCorrelation:
    def setup_method(self):
        self.detector = CrossAccountCorrelationDetector()

    def test_no_baseline_returns_zero(self, attacker_profile):
        result = self.detector.detect(attacker_profile)
        assert result.score == 0.0

    def test_with_baseline(self, normal_profile, attacker_profile):
        baseline = PopulationBaseline.from_profiles(
            [normal_profile, attacker_profile]
        )
        self.detector.set_population_baseline(baseline)
        result = self.detector.detect(attacker_profile)
        assert "cluster_id" in result.details or "reason" in result.details

    def test_details_fields(self, normal_profile, attacker_profile):
        # Need at least 3 profiles for DBSCAN to run
        from tests.conftest import make_events, build_profile

        extra_events = make_events(
            50, account_id="extra_001", archetype="normal_user"
        )
        extra_profile = build_profile(extra_events)
        baseline = PopulationBaseline.from_profiles(
            [normal_profile, attacker_profile, extra_profile]
        )
        self.detector.set_population_baseline(baseline)
        result = self.detector.detect(normal_profile)
        assert "nearest_neighbor_distance" in result.details
