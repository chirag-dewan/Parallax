"""Tests for detection pipeline."""

import pytest
from datetime import datetime, timezone

from detection.models import AccountProfile, RuleID, ThreatLevel
from detection.pipeline import DetectionPipeline
from detection.base import BaseDetector
from detection.models import Tier

from tests.conftest import make_events, build_profile


class DummyDetector(BaseDetector):
    RULE_ID = RuleID.T1_001
    RULE_NAME = "Dummy"
    TIER = Tier.TIER_1
    THRESHOLD = 0.5
    WEIGHT = 1.0

    def __init__(self, fixed_score: float = 0.5):
        super().__init__()
        self._fixed_score = fixed_score

    def _compute_score(self, profile):
        return self._fixed_score, {"fixed": True}


class TestPipeline:
    def test_build_profile(self):
        events = make_events(50, interval_ms=30000)
        profile = build_profile(events)
        assert profile.total_events == 50
        assert profile.account_id == "test_001"
        assert profile.requests_per_hour > 0

    def test_build_profile_tokens(self):
        events = make_events(20, input_tokens=100, output_tokens=400)
        profile = build_profile(events)
        assert profile.avg_input_tokens == 100.0
        assert profile.avg_output_tokens == 400.0
        assert profile.token_ratio == pytest.approx(4.0)

    def test_build_profile_conversations(self):
        events = make_events(10, conversation_id="conv_single")
        profile = build_profile(events)
        assert profile.total_conversations == 1
        assert profile.single_turn_count == 0  # 10 events in 1 conv

    def test_score_with_dummy_detector(self):
        pipeline = DetectionPipeline()
        pipeline.register_detector(DummyDetector(fixed_score=0.8))

        events = make_events(50)
        profile = build_profile(events)
        pipeline._profiles["test_001"] = profile

        assessment = pipeline.score_account("test_001")
        assert assessment.composite_score > 0
        assert assessment.account_id == "test_001"
        assert RuleID.T1_001 in assessment.results

    def test_threat_level_assignment(self):
        pipeline = DetectionPipeline()

        # High score detector
        pipeline.register_detector(DummyDetector(fixed_score=0.9))
        events = make_events(200)
        profile = build_profile(events)
        pipeline._profiles["test_001"] = profile

        assessment = pipeline.score_account("test_001")
        assert assessment.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

    def test_zero_score_detector(self):
        pipeline = DetectionPipeline()
        pipeline.register_detector(DummyDetector(fixed_score=0.0))

        events = make_events(50)
        profile = build_profile(events)
        pipeline._profiles["test_001"] = profile

        assessment = pipeline.score_account("test_001")
        assert assessment.composite_score == 0.0
        assert assessment.threat_level == ThreatLevel.NONE
        assert not assessment.escalation_recommended


class TestProfileEdgeCases:
    def test_single_event(self):
        events = make_events(1)
        profile = build_profile(events)
        assert profile.total_events == 1
        assert profile.observation_hours == 0.0
        assert profile.requests_per_hour == 0.0

    def test_all_api_requests(self):
        events = make_events(20, request_type="api")
        profile = build_profile(events)
        assert profile.api_ratio == 1.0

    def test_all_web_requests(self):
        events = make_events(20, request_type="web")
        profile = build_profile(events)
        assert profile.api_ratio == 0.0
