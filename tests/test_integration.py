"""Integration tests for the full detection pipeline."""

import pytest

from detection.pipeline import DetectionPipeline
from detection.models import ThreatLevel, RuleID


class TestFullPipeline:
    def test_register_and_score(self, normal_profile, attacker_profile):
        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()

        # Manually inject profiles
        pipeline._profiles[normal_profile.account_id] = normal_profile
        pipeline._profiles[attacker_profile.account_id] = attacker_profile

        # Build baseline and inject into Tier 2 detectors
        from detection.baselines import PopulationBaseline
        from detection.models import Tier

        baseline = PopulationBaseline.from_profiles(
            list(pipeline._profiles.values())
        )
        pipeline._baseline = baseline
        for detector in pipeline._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(baseline)

        # Score all
        assessments = pipeline.score_all()

        assert len(assessments) == 2
        assert attacker_profile.account_id in assessments
        assert normal_profile.account_id in assessments

        attacker_score = assessments[attacker_profile.account_id]
        normal_score = assessments[normal_profile.account_id]

        # Attacker should score higher
        assert attacker_score.composite_score > normal_score.composite_score
        assert attacker_score.composite_score > 0.5
        assert normal_score.composite_score < 0.5

    def test_all_14_rules_present(self, attacker_profile):
        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()
        pipeline._profiles[attacker_profile.account_id] = attacker_profile

        from detection.baselines import PopulationBaseline
        from detection.models import Tier

        baseline = PopulationBaseline.from_profiles([attacker_profile])
        for detector in pipeline._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(baseline)

        assessment = pipeline.score_account(attacker_profile.account_id)
        assert len(assessment.results) == 14

        for rule_id in RuleID:
            assert rule_id in assessment.results

    def test_weights_sum_to_one(self):
        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()
        total = sum(d.WEIGHT for d in pipeline.detectors)
        assert abs(total - 1.0) < 0.01

    def test_top_signals_sorted(self, attacker_profile):
        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()
        pipeline._profiles[attacker_profile.account_id] = attacker_profile

        from detection.baselines import PopulationBaseline
        from detection.models import Tier

        baseline = PopulationBaseline.from_profiles([attacker_profile])
        for detector in pipeline._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(baseline)

        assessment = pipeline.score_account(attacker_profile.account_id)
        scores = [ws for _, ws in assessment.top_signals]
        assert scores == sorted(scores, reverse=True)

    def test_escalation_threshold(self, attacker_profile, normal_profile):
        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()
        pipeline._profiles[attacker_profile.account_id] = attacker_profile
        pipeline._profiles[normal_profile.account_id] = normal_profile

        from detection.baselines import PopulationBaseline
        from detection.models import Tier

        baseline = PopulationBaseline.from_profiles(
            list(pipeline._profiles.values())
        )
        for detector in pipeline._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(baseline)

        pipeline.score_all()

        attacker_assessment = pipeline.assessments[attacker_profile.account_id]
        normal_assessment = pipeline.assessments[normal_profile.account_id]

        assert attacker_assessment.escalation_recommended
        assert not normal_assessment.escalation_recommended
