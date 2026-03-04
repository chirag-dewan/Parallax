"""
PARALLAX Detection Models

All structured data flows through Pydantic BaseModel instances.
"""

from __future__ import annotations

import enum
from datetime import datetime

from typing import Any

from pydantic import BaseModel, Field, field_validator


class Tier(str, enum.Enum):
    TIER_1 = "tier_1"
    TIER_2 = "tier_2"


class RuleID(str, enum.Enum):
    T1_001 = "T1-001"
    T1_002 = "T1-002"
    T1_003 = "T1-003"
    T1_004 = "T1-004"
    T1_005 = "T1-005"
    T1_006 = "T1-006"
    T1_007 = "T1-007"
    T1_008 = "T1-008"
    T2_001 = "T2-001"
    T2_002 = "T2-002"
    T2_003 = "T2-003"
    T2_004 = "T2-004"
    T2_005 = "T2-005"
    T2_006 = "T2-006"


class ThreatLevel(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class APIEvent(BaseModel):
    """Single API request event from JSONL traffic data."""

    timestamp: datetime
    account_id: str
    archetype: str
    account_age_days: int
    request_type: str
    inter_request_interval_ms: int
    input_tokens: int
    output_tokens: int
    conversation_id: str
    turn_number: int
    session_duration_hours: float
    topic_category: str
    safety_filter_triggered: bool
    rate_limit_hit: bool
    rate_limit_retry_delay_ms: int
    response_time_ms: int
    http_status: int
    model: str

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: str | datetime) -> datetime:
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v


class AccountProfile(BaseModel):
    """Pre-computed behavioral profile for one account."""

    account_id: str
    archetype: str
    account_age_days: int
    events: list[APIEvent]
    total_events: int

    # Timing
    timestamps: list[datetime]
    inter_request_intervals_ms: list[int]
    observation_hours: float
    requests_per_hour: float

    # Tokens
    input_tokens: list[int]
    output_tokens: list[int]
    avg_input_tokens: float
    avg_output_tokens: float
    token_ratio: float

    # Conversations
    conversation_ids: list[str]
    conversations: dict[str, list[APIEvent]]
    total_conversations: int
    single_turn_count: int
    single_turn_ratio: float
    conversations_per_day: float

    # Sessions
    session_durations_hours: list[float]
    hours_active: set[int]
    hours_coverage: float

    # Request types
    api_request_count: int
    web_request_count: int
    api_ratio: float

    # Models
    model_counts: dict[str, int]
    model_ratios: dict[str, float]

    # Safety / rate limiting
    safety_trigger_count: int
    safety_trigger_rate: float
    rate_limit_hit_count: int
    rate_limit_hit_rate: float
    rate_limit_retry_delays_ms: list[int]

    # Topics
    topic_counts: dict[str, int]
    unique_topic_count: int

    model_config = {"arbitrary_types_allowed": True}


class DetectionResult(BaseModel):
    """Output from a single detector for a single account."""

    rule_id: RuleID
    rule_name: str
    tier: Tier
    score: float = Field(ge=0.0, le=1.0)
    triggered: bool
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    details: dict[str, Any] = Field(default_factory=dict)


class ThreatAssessment(BaseModel):
    """Composite scoring output for one account."""

    account_id: str
    archetype: str
    results: dict[RuleID, DetectionResult]
    composite_score: float = Field(ge=0.0, le=1.0)
    threat_level: ThreatLevel
    escalation_recommended: bool
    tier1_triggered_count: int
    tier2_triggered_count: int
    total_triggered_count: int
    top_signals: list[tuple[RuleID, float]]
