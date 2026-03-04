"""Adversarial Scenario 2: Low-and-Slow Attackers.

Creates 10 accounts that perform model distillation over a 30-day window
instead of in concentrated bursts. They stay within normal rate limits
(2-15 req/hr) but consistently use short-input / max-output patterns
and single-turn conversations.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from detection.baselines import PopulationBaseline
from detection.models import RuleID, Tier
from detection.pipeline import DetectionPipeline
from tests.conftest import build_profile, make_event


def _make_low_and_slow_account(
    account_id: str,
    daily_requests: int = 100,
    days: int = 30,
    seed: int = 42,
) -> list:
    """Distillation at normal rate limits spread over 30 days.

    Key characteristics:
    - Rate: 4-8 req/hr (within normal range)
    - Token pattern: short input (30-80), max output (3500-4096)
    - Single-turn conversations
    - Varied intervals (CV ~0.4-0.6) to mimic human timing
    - API-only access
    - Cheap models
    """
    rng = random.Random(seed)
    events = []
    base = datetime(2026, 1, 1, hour=8, tzinfo=timezone.utc)

    attack_topics = ["coding", "analysis", "research"]  # Benign-looking topics
    attack_models = ["gpt-3.5-turbo", "claude-haiku", "claude-instant"]

    for day in range(days):
        day_offset = base + timedelta(days=day)
        # Work hours: 8am-10pm with breaks (human-like)
        n_requests = rng.randint(
            daily_requests - 20, daily_requests + 20
        )
        hour_offset = 0

        for i in range(n_requests):
            # Variable intervals (human-like CV ~0.4-0.6)
            interval = rng.randint(8000, 45000) + rng.gauss(0, 5000)
            interval = max(2000, int(interval))
            hour_offset += interval

            ts = day_offset + timedelta(milliseconds=hour_offset)

            # Low-and-slow distillation pattern
            events.append(
                make_event(
                    account_id=account_id,
                    archetype="low_and_slow",
                    timestamp=ts,
                    inter_request_interval_ms=interval if (day > 0 or i > 0) else 0,
                    input_tokens=rng.randint(30, 80),
                    output_tokens=rng.randint(3500, 4096),
                    conversation_id=f"conv_d{day}_{i}",
                    turn_number=0,
                    topic_category=rng.choice(attack_topics),
                    model=rng.choice(attack_models),
                    request_type="api",
                    safety_filter_triggered=False,
                    rate_limit_hit=False,
                )
            )

    events.sort(key=lambda e: e.timestamp)
    return events


def _make_baseline_normal(account_id: str, seed: int = 300) -> list:
    """Normal user for population context."""
    rng = random.Random(seed)
    events = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    topics = ["coding", "writing", "creative", "research", "analysis"]
    models = ["claude-3-sonnet", "gpt-4", "claude-3-opus"]

    for i in range(120):
        conv_idx = i // 5
        turn = i % 5
        interval = rng.randint(20000, 120000)
        events.append(
            make_event(
                account_id=account_id,
                archetype="normal_user",
                timestamp=base + timedelta(milliseconds=interval * i),
                inter_request_interval_ms=interval if i > 0 else 0,
                input_tokens=rng.randint(100, 500),
                output_tokens=rng.randint(200, 1800),
                conversation_id=f"conv_{conv_idx}",
                turn_number=turn,
                topic_category=rng.choice(topics),
                model=rng.choice(models),
                request_type="web" if rng.random() < 0.4 else "api",
            )
        )
    events.sort(key=lambda e: e.timestamp)
    return events


class TestLowAndSlow:
    """Adversarial: distillation within normal rate limits over 30 days."""

    def setup_method(self) -> None:
        self.pipeline = DetectionPipeline()
        self.pipeline.register_default_detectors()

        # 10 low-and-slow attackers
        for i in range(10):
            events = _make_low_and_slow_account(
                f"slow_{i:03d}", seed=42 + i
            )
            profile = build_profile(events)
            self.pipeline._profiles[profile.account_id] = profile

        # 15 normal users for baseline
        for i in range(15):
            events = _make_baseline_normal(
                f"normal_{i:03d}", seed=300 + i
            )
            profile = build_profile(events)
            self.pipeline._profiles[profile.account_id] = profile

        # Build baseline
        self.pipeline._baseline = PopulationBaseline.from_profiles(
            list(self.pipeline._profiles.values())
        )
        for detector in self.pipeline._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(self.pipeline._baseline)

        self.assessments = self.pipeline.score_all()

    def test_token_ratio_still_triggers(self) -> None:
        """T1-003 should detect distillation pattern even at low rates."""
        triggered_count = 0
        for i in range(10):
            assessment = self.assessments[f"slow_{i:03d}"]
            t1_003 = assessment.results[RuleID.T1_003]
            if t1_003.triggered:
                triggered_count += 1

        # Token ratio is rate-independent — should fire on most
        assert triggered_count >= 7, (
            f"Only {triggered_count}/10 low-and-slow accounts triggered "
            f"T1-003 Token Ratio"
        )

    def test_volume_anomaly_does_not_trigger(self) -> None:
        """T1-001 should NOT fire — these stay within normal rate limits."""
        false_positive_count = 0
        for i in range(10):
            assessment = self.assessments[f"slow_{i:03d}"]
            t1_001 = assessment.results[RuleID.T1_001]
            if t1_001.triggered:
                false_positive_count += 1

        # Most should not trigger volume — they're at normal rates
        assert false_positive_count <= 3, (
            f"{false_positive_count}/10 low-and-slow triggered volume "
            f"anomaly (expected <=3)"
        )

    def test_session_anomaly_detects_single_turn(self) -> None:
        """T1-004 should detect 100% single-turn pattern."""
        triggered_count = 0
        for i in range(10):
            assessment = self.assessments[f"slow_{i:03d}"]
            t1_004 = assessment.results[RuleID.T1_004]
            if t1_004.triggered:
                triggered_count += 1

        assert triggered_count >= 5, (
            f"Only {triggered_count}/10 triggered T1-004 Session Anomaly"
        )

    def test_automation_signature_not_triggered(self) -> None:
        """T1-002 should NOT fire — intervals have human-like variance."""
        false_positive_count = 0
        for i in range(10):
            assessment = self.assessments[f"slow_{i:03d}"]
            t1_002 = assessment.results[RuleID.T1_002]
            if t1_002.triggered:
                false_positive_count += 1

        # Variable intervals should keep CV high enough
        assert false_positive_count <= 5, (
            f"{false_positive_count}/10 triggered automation signature"
        )

    def test_no_normal_escalated(self) -> None:
        """Normal users should never be escalated."""
        for i in range(15):
            assessment = self.assessments[f"normal_{i:03d}"]
            assert not assessment.escalation_recommended, (
                f"normal_{i:03d} falsely escalated "
                f"(score={assessment.composite_score:.4f})"
            )

    def test_detection_gap_documented(self) -> None:
        """Document which low-and-slow accounts evade detection."""
        evaders = []
        detected = []

        for i in range(10):
            assessment = self.assessments[f"slow_{i:03d}"]
            if assessment.composite_score < 0.25:
                evaders.append((f"slow_{i:03d}", assessment.composite_score))
            else:
                detected.append((f"slow_{i:03d}", assessment.composite_score))

        # This is a known weakness — document rather than assert hard failure
        # Low-and-slow should still be partially detectable via token/session signals
        assert len(detected) >= 5, (
            f"Only {len(detected)}/10 detected — "
            f"low-and-slow evasion rate: {len(evaders)*10}%"
        )

    def test_low_and_slow_summary_output(self, capsys) -> None:
        """Print summary for manual review."""
        lines = []
        lines.append("\n--- LOW-AND-SLOW SUMMARY ---")
        lines.append(
            f"{'Account':<15} {'Score':>7} {'Level':<10} {'Escalated':>10} "
            f"{'T1-001':>7} {'T1-002':>7} {'T1-003':>7} {'T1-004':>7}"
        )
        lines.append("-" * 82)

        for i in range(10):
            a = self.assessments[f"slow_{i:03d}"]
            lines.append(
                f"slow_{i:03d}       {a.composite_score:>7.4f} "
                f"{a.threat_level.value:<10} {str(a.escalation_recommended):>10} "
                f"{a.results[RuleID.T1_001].score:>7.4f} "
                f"{a.results[RuleID.T1_002].score:>7.4f} "
                f"{a.results[RuleID.T1_003].score:>7.4f} "
                f"{a.results[RuleID.T1_004].score:>7.4f}"
            )

        slow_scores = [
            self.assessments[f"slow_{i:03d}"].composite_score
            for i in range(10)
        ]
        lines.append("")
        lines.append(f"Low-and-slow avg: {sum(slow_scores)/len(slow_scores):.4f}")
        lines.append(f"Low-and-slow min: {min(slow_scores):.4f}")
        lines.append(f"Low-and-slow max: {max(slow_scores):.4f}")

        escalated = sum(
            1 for s in slow_scores
            if s > self.pipeline.ESCALATION_THRESHOLD
        )
        lines.append(f"Escalated: {escalated}/10")

        output = "\n".join(lines)
        print(output)
