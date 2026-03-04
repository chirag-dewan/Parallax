"""Shared test fixtures for PARALLAX detection tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection.models import APIEvent, AccountProfile
from detection.pipeline import DetectionPipeline


def make_event(
    account_id: str = "test_001",
    archetype: str = "normal_user",
    timestamp: datetime | None = None,
    account_age_days: int = 90,
    request_type: str = "api",
    inter_request_interval_ms: int = 30000,
    input_tokens: int = 200,
    output_tokens: int = 500,
    conversation_id: str = "conv_1",
    turn_number: int = 0,
    session_duration_hours: float = 1.0,
    topic_category: str = "coding",
    safety_filter_triggered: bool = False,
    rate_limit_hit: bool = False,
    rate_limit_retry_delay_ms: int = 0,
    response_time_ms: int = 500,
    http_status: int = 200,
    model: str = "claude-3-sonnet",
) -> APIEvent:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    return APIEvent(
        timestamp=timestamp,
        account_id=account_id,
        archetype=archetype,
        account_age_days=account_age_days,
        request_type=request_type,
        inter_request_interval_ms=inter_request_interval_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        conversation_id=conversation_id,
        turn_number=turn_number,
        session_duration_hours=session_duration_hours,
        topic_category=topic_category,
        safety_filter_triggered=safety_filter_triggered,
        rate_limit_hit=rate_limit_hit,
        rate_limit_retry_delay_ms=rate_limit_retry_delay_ms,
        response_time_ms=response_time_ms,
        http_status=http_status,
        model=model,
    )


def make_events(
    count: int,
    account_id: str = "test_001",
    archetype: str = "normal_user",
    interval_ms: int = 30000,
    **kwargs,
) -> list[APIEvent]:
    """Create a list of events with sequential timestamps."""
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = []
    for i in range(count):
        ts = base_time + timedelta(milliseconds=interval_ms * i)
        conv_id = kwargs.get("conversation_id", f"conv_{i}")
        events.append(
            make_event(
                account_id=account_id,
                archetype=archetype,
                timestamp=ts,
                inter_request_interval_ms=interval_ms if i > 0 else 0,
                conversation_id=conv_id,
                turn_number=kwargs.get("turn_number", 0),
                **{
                    k: v
                    for k, v in kwargs.items()
                    if k not in ("conversation_id", "turn_number")
                },
            )
        )
    return events


def build_profile(events: list[APIEvent]) -> AccountProfile:
    """Build an AccountProfile from events using the pipeline builder."""
    events.sort(key=lambda e: e.timestamp)
    return DetectionPipeline._build_profile(events[0].account_id, events)


@pytest.fixture
def normal_profile() -> AccountProfile:
    """A normal user profile: low volume, high variance, multi-turn."""
    events = []
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    topics = ["coding", "writing", "analysis", "creative", "research", "translation"]

    for i in range(100):
        # Multi-turn conversations (5 turns each)
        conv_idx = i // 5
        turn = i % 5
        ts = base_time + timedelta(seconds=120 * i + (i % 3) * 40)
        events.append(
            make_event(
                account_id="normal_test",
                archetype="normal_user",
                timestamp=ts,
                inter_request_interval_ms=120000 + (i % 3) * 40000 if i > 0 else 0,
                input_tokens=100 + i * 3,
                output_tokens=300 + i * 5,
                conversation_id=f"conv_{conv_idx}",
                turn_number=turn,
                topic_category=topics[i % len(topics)],
                model=["gpt-4", "claude-3-sonnet", "claude-3-opus", "gpt-3.5-turbo"][i % 4],
                request_type="web" if i % 3 == 0 else "api",
            )
        )
    return build_profile(events)


@pytest.fixture
def attacker_profile() -> AccountProfile:
    """An attacker profile: high volume, low variance, single-turn, max output."""
    events = []
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    attack_topics = ["extraction", "jailbreak", "scraping"]

    for i in range(500):
        ts = base_time + timedelta(milliseconds=1100 * i)
        events.append(
            make_event(
                account_id="attacker_test",
                archetype="attacker",
                timestamp=ts,
                account_age_days=5,
                inter_request_interval_ms=1100 if i > 0 else 0,
                input_tokens=40,
                output_tokens=3900,
                conversation_id=f"conv_{i}",
                turn_number=0,
                topic_category=attack_topics[i % len(attack_topics)],
                model=["gpt-3.5-turbo", "claude-instant", "claude-haiku"][i % 3],
                request_type="api",
                safety_filter_triggered=i % 8 == 0,
                rate_limit_hit=i % 15 == 0,
                rate_limit_retry_delay_ms=120 if i % 15 == 0 else 0,
            )
        )
    return build_profile(events)
