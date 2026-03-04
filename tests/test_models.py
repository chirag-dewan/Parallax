"""Tests for detection models."""

import pytest
from datetime import datetime, timezone

from detection.models import (
    APIEvent,
    DetectionResult,
    RuleID,
    Tier,
    ThreatAssessment,
    ThreatLevel,
)


class TestAPIEvent:
    def test_parse_z_timestamp(self):
        event = APIEvent(
            timestamp="2026-01-01T00:00:00Z",
            account_id="test",
            archetype="normal_user",
            account_age_days=30,
            request_type="api",
            inter_request_interval_ms=1000,
            input_tokens=100,
            output_tokens=200,
            conversation_id="conv_1",
            turn_number=0,
            session_duration_hours=1.0,
            topic_category="coding",
            safety_filter_triggered=False,
            rate_limit_hit=False,
            rate_limit_retry_delay_ms=0,
            response_time_ms=500,
            http_status=200,
            model="gpt-4",
        )
        assert isinstance(event.timestamp, datetime)
        assert event.timestamp.tzinfo is not None

    def test_parse_from_json(self):
        json_str = '{"timestamp":"2026-01-01T00:00:00Z","account_id":"t","archetype":"normal_user","account_age_days":30,"request_type":"api","inter_request_interval_ms":1000,"input_tokens":100,"output_tokens":200,"conversation_id":"c","turn_number":0,"session_duration_hours":1.0,"topic_category":"coding","safety_filter_triggered":false,"rate_limit_hit":false,"rate_limit_retry_delay_ms":0,"response_time_ms":500,"http_status":200,"model":"gpt-4"}'
        event = APIEvent.model_validate_json(json_str)
        assert event.account_id == "t"
        assert event.input_tokens == 100


class TestDetectionResult:
    def test_score_bounds(self):
        result = DetectionResult(
            rule_id=RuleID.T1_001,
            rule_name="Test",
            tier=Tier.TIER_1,
            score=0.75,
            triggered=True,
        )
        assert 0.0 <= result.score <= 1.0

    def test_score_validation(self):
        with pytest.raises(Exception):
            DetectionResult(
                rule_id=RuleID.T1_001,
                rule_name="Test",
                tier=Tier.TIER_1,
                score=1.5,
                triggered=True,
            )


class TestThreatLevel:
    def test_enum_values(self):
        assert ThreatLevel.NONE.value == "none"
        assert ThreatLevel.CRITICAL.value == "critical"


class TestRuleID:
    def test_all_14_rules(self):
        assert len(RuleID) == 14
        assert RuleID.T1_001.value == "T1-001"
        assert RuleID.T2_006.value == "T2-006"
