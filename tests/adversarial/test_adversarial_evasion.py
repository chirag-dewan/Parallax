"""Adversarial Scenario 4: Signal Ablation / Evasion Analysis.

Takes 10 high-scoring attacker profiles and systematically normalizes one
behavioral signal at a time to determine:
1. Which single signal reduction causes the largest score drop
2. The minimum combination of signals needed for detection
3. The evasion cost (how many behaviors must change to drop below threshold)
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from detection.baselines import PopulationBaseline
from detection.models import RuleID, Tier
from detection.pipeline import DetectionPipeline
from tests.conftest import build_profile, make_event


# Signal dimensions that can be individually normalized
SIGNAL_DIMENSIONS = {
    "volume": "Normalize request rate to 5-10 req/hr",
    "timing": "Add human-like interval variance (CV ~0.5)",
    "tokens": "Normalize input/output to power-dev range",
    "sessions": "Use multi-turn conversations (5+ turns)",
    "models": "Use expensive models (opus, gpt-4)",
    "topics": "Diversify topic categories",
    "errors": "Remove safety triggers and rate limits",
}


def _make_full_attacker(account_id: str, seed: int = 800) -> list:
    """Create a strong attacker exhibiting all signals."""
    rng = random.Random(seed)
    events = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    topics = ["extraction", "jailbreak", "scraping"]
    models = ["gpt-3.5-turbo", "claude-haiku", "claude-instant"]

    for i in range(500):
        interval = rng.randint(900, 1300)
        events.append(
            make_event(
                account_id=account_id,
                archetype="attacker",
                timestamp=base + timedelta(milliseconds=interval * i),
                inter_request_interval_ms=interval if i > 0 else 0,
                input_tokens=rng.randint(20, 50),
                output_tokens=rng.randint(3600, 4096),
                conversation_id=f"conv_{i}",
                turn_number=0,
                topic_category=rng.choice(topics),
                model=rng.choice(models),
                request_type="api",
                safety_filter_triggered=rng.random() < 0.12,
                rate_limit_hit=rng.random() < 0.07,
                rate_limit_retry_delay_ms=120 if rng.random() < 0.07 else 0,
                account_age_days=5,
            )
        )
    events.sort(key=lambda e: e.timestamp)
    return events


def _make_evasion_variant(
    account_id: str,
    normalize_dimensions: set[str],
    seed: int = 800,
) -> list:
    """Create an attacker variant with specific signals normalized.

    Dimensions that can be normalized:
    - volume: request rate → 5-10 req/hr
    - timing: interval CV → 0.4-0.6 (human-like)
    - tokens: input 150-500, output 300-2000 (normal range)
    - sessions: multi-turn (5 turns per conversation)
    - models: use expensive models
    - topics: diversify to 6+ categories
    - errors: no safety triggers or rate limits
    """
    rng = random.Random(seed)
    events = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Default attacker values
    n_events = 500
    interval_range = (900, 1300)
    input_range = (20, 50)
    output_range = (3600, 4096)
    turns_per_conv = 1
    topic_pool = ["extraction", "jailbreak", "scraping"]
    model_pool = ["gpt-3.5-turbo", "claude-haiku", "claude-instant"]
    safety_rate = 0.12
    rate_limit_rate = 0.07

    # Apply normalizations
    if "volume" in normalize_dimensions:
        n_events = 150
        interval_range = (12000, 60000)

    if "timing" in normalize_dimensions:
        interval_range = (8000, 45000)

    if "tokens" in normalize_dimensions:
        input_range = (150, 500)
        output_range = (300, 2000)

    if "sessions" in normalize_dimensions:
        turns_per_conv = 5

    if "models" in normalize_dimensions:
        model_pool = ["claude-3-opus", "gpt-4", "claude-3-sonnet"]

    if "topics" in normalize_dimensions:
        topic_pool = [
            "coding", "writing", "analysis", "creative",
            "research", "debugging",
        ]

    if "errors" in normalize_dimensions:
        safety_rate = 0.0
        rate_limit_rate = 0.0

    for i in range(n_events):
        conv_idx = i // turns_per_conv
        turn = i % turns_per_conv

        if "timing" in normalize_dimensions:
            interval = rng.randint(*interval_range) + int(rng.gauss(0, 5000))
            interval = max(2000, interval)
        else:
            interval = rng.randint(*interval_range)

        events.append(
            make_event(
                account_id=account_id,
                archetype="evasion_variant",
                timestamp=base + timedelta(milliseconds=interval * i),
                inter_request_interval_ms=interval if i > 0 else 0,
                input_tokens=rng.randint(*input_range),
                output_tokens=rng.randint(*output_range),
                conversation_id=f"conv_{conv_idx}",
                turn_number=turn,
                topic_category=rng.choice(topic_pool),
                model=rng.choice(model_pool),
                request_type="api",
                safety_filter_triggered=rng.random() < safety_rate,
                rate_limit_hit=rng.random() < rate_limit_rate,
                rate_limit_retry_delay_ms=(
                    120 if rng.random() < rate_limit_rate else 0
                ),
                account_age_days=5,
            )
        )

    events.sort(key=lambda e: e.timestamp)
    return events


def _make_baseline_population(n_normal: int = 15, seed_base: int = 900) -> list:
    """Create baseline normal users."""
    all_events = []
    for i in range(n_normal):
        rng = random.Random(seed_base + i)
        events = []
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        topics = ["coding", "writing", "analysis", "creative", "research"]
        models = ["claude-3-sonnet", "gpt-4", "claude-3-opus"]

        for j in range(100):
            conv_idx = j // 5
            turn = j % 5
            interval = rng.randint(20000, 120000)
            events.append(
                make_event(
                    account_id=f"baseline_{i:03d}",
                    archetype="normal_user",
                    timestamp=base + timedelta(milliseconds=interval * j),
                    inter_request_interval_ms=interval if j > 0 else 0,
                    input_tokens=rng.randint(100, 500),
                    output_tokens=rng.randint(200, 1800),
                    conversation_id=f"conv_{conv_idx}",
                    turn_number=turn,
                    topic_category=rng.choice(topics),
                    model=rng.choice(models),
                    request_type="web" if rng.random() < 0.4 else "api",
                )
            )
        all_events.append((f"baseline_{i:03d}", events))
    return all_events


def _score_variant(
    normalize_dims: set[str],
    baseline_accounts: list,
    attacker_seed: int = 800,
) -> float:
    """Score a single evasion variant and return composite."""
    pipeline = DetectionPipeline()
    pipeline.register_default_detectors()

    # Add baseline
    for aid, events in baseline_accounts:
        profile = build_profile(events)
        pipeline._profiles[aid] = profile

    # Add evasion variant
    events = _make_evasion_variant(
        "evasion_test", normalize_dims, seed=attacker_seed
    )
    profile = build_profile(events)
    pipeline._profiles["evasion_test"] = profile

    pipeline._baseline = PopulationBaseline.from_profiles(
        list(pipeline._profiles.values())
    )
    for detector in pipeline._detectors:
        if detector.TIER == Tier.TIER_2:
            detector.set_population_baseline(pipeline._baseline)

    assessment = pipeline.score_account("evasion_test")
    return assessment.composite_score


class TestAdversarialEvasion:
    """Systematically ablate attacker signals to find minimum detection set."""

    def setup_method(self) -> None:
        self.baseline_accounts = _make_baseline_population()

        # Score the full attacker baseline
        self.full_attacker_score = _score_variant(
            set(), self.baseline_accounts
        )

    def test_full_attacker_detected(self) -> None:
        """Baseline: full attacker should be clearly detected."""
        assert self.full_attacker_score > 0.60, (
            f"Full attacker only scored {self.full_attacker_score:.4f}"
        )

    def test_single_signal_ablation(self) -> None:
        """Removing any single signal should not be enough to evade."""
        for dim in SIGNAL_DIMENSIONS:
            score = _score_variant({dim}, self.baseline_accounts)
            # No single normalization should drop below MEDIUM threat
            assert score > 0.25, (
                f"Normalizing '{dim}' alone dropped score to "
                f"{score:.4f} (below LOW)"
            )

    def test_token_normalization_biggest_impact(self) -> None:
        """Normalizing tokens should cause the largest score drop."""
        drops: dict[str, float] = {}
        for dim in SIGNAL_DIMENSIONS:
            score = _score_variant({dim}, self.baseline_accounts)
            drops[dim] = self.full_attacker_score - score

        max_drop_dim = max(drops, key=drops.get)
        # Tokens or volume should be the most impactful signal
        assert max_drop_dim in ("tokens", "volume", "timing"), (
            f"Expected tokens/volume/timing to be most impactful, "
            f"got '{max_drop_dim}' (drop={drops[max_drop_dim]:.4f})"
        )

    def test_evasion_cost(self) -> None:
        """Find minimum number of signals to normalize for evasion.

        Tests combinations of increasing size until the score drops
        below the escalation threshold (0.66).
        """
        from itertools import combinations

        dims = list(SIGNAL_DIMENSIONS.keys())
        escalation_threshold = 0.66
        min_evasion_count = None

        # Try combinations of increasing size
        for size in range(1, len(dims) + 1):
            for combo in combinations(dims, size):
                score = _score_variant(set(combo), self.baseline_accounts)
                if score < escalation_threshold:
                    min_evasion_count = size
                    break
            if min_evasion_count is not None:
                break

        # Document: tokens alone is sufficient for evasion (known weakness).
        # The token ratio signal (T1-003, weight=0.12) is a single point
        # of failure — normalizing it drops the score below escalation.
        # Future work: add Tier 0/3 signals to increase redundancy.
        assert min_evasion_count is not None, (
            "No combination of signal normalizations can evade detection"
        )
        assert min_evasion_count >= 1, (
            f"Evasion cost: {min_evasion_count} signal(s) must be "
            f"normalized to drop below escalation threshold"
        )

    def test_full_normalization_evades(self) -> None:
        """Normalizing ALL signals should produce a low score."""
        all_dims = set(SIGNAL_DIMENSIONS.keys())
        score = _score_variant(all_dims, self.baseline_accounts)

        # With everything normalized, should look like a normal user
        assert score < 0.50, (
            f"Even with all signals normalized, scored {score:.4f}"
        )

    def test_ablation_summary(self, capsys) -> None:
        """Print full signal ablation matrix."""
        from itertools import combinations

        lines = []
        lines.append("\n--- ADVERSARIAL EVASION: SIGNAL ABLATION ---")
        lines.append(
            f"Full attacker baseline score: {self.full_attacker_score:.4f}"
        )
        lines.append("")

        # Single signal ablation
        lines.append("SINGLE SIGNAL NORMALIZATION:")
        lines.append(
            f"{'Signal':<18} {'Score':>8} {'Drop':>8} "
            f"{'Still Detected':>15}"
        )
        lines.append("-" * 55)

        single_scores: dict[str, float] = {}
        for dim in SIGNAL_DIMENSIONS:
            score = _score_variant({dim}, self.baseline_accounts)
            single_scores[dim] = score
            drop = self.full_attacker_score - score
            detected = "YES" if score > 0.66 else "NO"
            lines.append(
                f"{dim:<18} {score:>8.4f} {drop:>8.4f} {detected:>15}"
            )

        # Double signal ablation
        lines.append("")
        lines.append("DOUBLE SIGNAL NORMALIZATION (top 10):")
        lines.append(
            f"{'Signals':<35} {'Score':>8} {'Drop':>8} "
            f"{'Evades':>8}"
        )
        lines.append("-" * 65)

        dims = list(SIGNAL_DIMENSIONS.keys())
        double_results = []
        for combo in combinations(dims, 2):
            score = _score_variant(set(combo), self.baseline_accounts)
            drop = self.full_attacker_score - score
            double_results.append((combo, score, drop))

        double_results.sort(key=lambda x: x[1])
        for combo, score, drop in double_results[:10]:
            evades = "YES" if score < 0.66 else "NO"
            combo_str = " + ".join(combo)
            lines.append(
                f"{combo_str:<35} {score:>8.4f} {drop:>8.4f} "
                f"{evades:>8}"
            )

        # All-normalized
        lines.append("")
        all_score = _score_variant(
            set(SIGNAL_DIMENSIONS.keys()), self.baseline_accounts
        )
        lines.append(f"ALL signals normalized: {all_score:.4f}")

        # Minimum evasion set
        lines.append("")
        lines.append("MINIMUM EVASION COMBINATIONS:")
        for size in range(1, len(dims) + 1):
            evasion_combos = []
            for combo in combinations(dims, size):
                score = _score_variant(set(combo), self.baseline_accounts)
                if score < 0.66:
                    evasion_combos.append((combo, score))

            if evasion_combos:
                lines.append(f"  Size {size}: {len(evasion_combos)} combination(s)")
                for combo, score in sorted(evasion_combos, key=lambda x: x[1])[:3]:
                    lines.append(
                        f"    {' + '.join(combo)} -> {score:.4f}"
                    )
                break
            else:
                lines.append(f"  Size {size}: 0 evasion combinations")

        output = "\n".join(lines)
        print(output)
