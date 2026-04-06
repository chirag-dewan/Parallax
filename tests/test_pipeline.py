"""Tests for detection pipeline."""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from detection.models import AccountProfile, RuleID, ThreatLevel, ThreatAssessment
from detection.pipeline import DetectionPipeline
from detection.base import BaseDetector
from detection.models import Tier

from tests.conftest import make_events, make_event, build_profile


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


def _write_events_jsonl(tmp_path: Path, events) -> Path:
    """Write events to a JSONL file for async loading tests."""
    filepath = tmp_path / "test_traffic.jsonl"
    with filepath.open("w") as f:
        for event in events:
            f.write(event.model_dump_json() + "\n")
    return filepath


class TestAsyncPipeline:
    """Tests for async generator methods on DetectionPipeline."""

    @pytest.mark.asyncio
    async def test_aiter_events_yields_all(self, tmp_path):
        events = make_events(25)
        filepath = _write_events_jsonl(tmp_path, events)

        pipeline = DetectionPipeline()
        collected = []
        async for event in pipeline.aiter_events(filepath):
            collected.append(event)

        assert len(collected) == 25
        assert all(e.account_id == "test_001" for e in collected)

    @pytest.mark.asyncio
    async def test_aiter_events_skips_malformed(self, tmp_path):
        events = make_events(5)
        filepath = tmp_path / "mixed.jsonl"
        with filepath.open("w") as f:
            f.write(events[0].model_dump_json() + "\n")
            f.write("NOT VALID JSON\n")
            f.write(events[1].model_dump_json() + "\n")

        pipeline = DetectionPipeline()
        collected = []
        async for event in pipeline.aiter_events(filepath):
            collected.append(event)

        assert len(collected) == 2

    @pytest.mark.asyncio
    async def test_aload_traffic_builds_profiles(self, tmp_path):
        events = make_events(50)
        filepath = _write_events_jsonl(tmp_path, events)

        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()
        await pipeline.aload_traffic(filepath)

        assert "test_001" in pipeline.profiles
        assert pipeline.profiles["test_001"].total_events == 50
        assert pipeline.baseline is not None

    @pytest.mark.asyncio
    async def test_ascore_all_yields_assessments(self, tmp_path):
        events = make_events(50)
        filepath = _write_events_jsonl(tmp_path, events)

        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()
        await pipeline.aload_traffic(filepath)

        assessments = []
        async for assessment in pipeline.ascore_all():
            assessments.append(assessment)

        assert len(assessments) == 1
        assert isinstance(assessments[0], ThreatAssessment)
        assert assessments[0].account_id == "test_001"
        # Also stored in pipeline
        assert "test_001" in pipeline.assessments

    @pytest.mark.asyncio
    async def test_async_matches_sync(self, tmp_path):
        """Async and sync paths produce identical results."""
        events = make_events(80)
        filepath = _write_events_jsonl(tmp_path, events)

        # Sync path
        sync_pipeline = DetectionPipeline()
        sync_pipeline.register_default_detectors()
        sync_pipeline.load_traffic(str(filepath))
        sync_pipeline.score_all()

        # Async path
        async_pipeline = DetectionPipeline()
        async_pipeline.register_default_detectors()
        await async_pipeline.aload_traffic(filepath)
        async for _ in async_pipeline.ascore_all():
            pass

        sync_score = sync_pipeline.assessments["test_001"].composite_score
        async_score = async_pipeline.assessments["test_001"].composite_score
        assert sync_score == pytest.approx(async_score)
