"""Adversarial Scenario 3: Threshold Sensitivity / ROC Analysis.

Sweeps escalation threshold from 0.2 to 0.6 in 0.05 increments.
Reports false positive rate (FPR) and false negative rate (FNR) at each
threshold. Outputs ROC curve data for manual analysis.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from detection.baselines import PopulationBaseline
from detection.models import Tier
from detection.pipeline import DetectionPipeline
from tests.conftest import build_profile, make_event


def _make_known_attacker(account_id: str, seed: int = 500) -> list:
    """Create a known attacker profile."""
    rng = random.Random(seed)
    events = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    topics = ["extraction", "jailbreak", "scraping"]
    models = ["gpt-3.5-turbo", "claude-haiku", "claude-instant"]

    for i in range(400):
        interval = rng.randint(800, 1500)
        events.append(
            make_event(
                account_id=account_id,
                archetype="attacker",
                timestamp=base + timedelta(milliseconds=interval * i),
                inter_request_interval_ms=interval if i > 0 else 0,
                input_tokens=rng.randint(20, 60),
                output_tokens=rng.randint(3500, 4096),
                conversation_id=f"conv_{i}",
                turn_number=0,
                topic_category=rng.choice(topics),
                model=rng.choice(models),
                request_type="api",
                safety_filter_triggered=rng.random() < 0.12,
                rate_limit_hit=rng.random() < 0.07,
                account_age_days=rng.randint(1, 10),
            )
        )
    events.sort(key=lambda e: e.timestamp)
    return events


def _make_known_normal(account_id: str, seed: int = 600) -> list:
    """Create a known normal user profile."""
    rng = random.Random(seed)
    events = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    topics = ["coding", "writing", "analysis", "creative", "research"]
    models = ["claude-3-sonnet", "gpt-4", "claude-3-opus"]

    for i in range(100):
        conv_idx = i // 5
        turn = i % 5
        interval = rng.randint(30000, 180000)
        events.append(
            make_event(
                account_id=account_id,
                archetype="normal_user",
                timestamp=base + timedelta(milliseconds=interval * i),
                inter_request_interval_ms=interval if i > 0 else 0,
                input_tokens=rng.randint(100, 500),
                output_tokens=rng.randint(200, 1500),
                conversation_id=f"conv_{conv_idx}",
                turn_number=turn,
                topic_category=rng.choice(topics),
                model=rng.choice(models),
                request_type="web" if rng.random() < 0.5 else "api",
            )
        )
    events.sort(key=lambda e: e.timestamp)
    return events


def _make_known_power_dev(account_id: str, seed: int = 700) -> list:
    """Create a known power developer profile."""
    rng = random.Random(seed)
    events = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    topics = ["coding", "debugging", "architecture", "research"]
    models = ["claude-3-sonnet", "claude-3-opus", "gpt-4"]

    for i in range(250):
        conv_idx = i // 4
        turn = i % 4
        interval = rng.randint(5000, 40000)
        events.append(
            make_event(
                account_id=account_id,
                archetype="power_developer",
                timestamp=base + timedelta(milliseconds=interval * i),
                inter_request_interval_ms=interval if i > 0 else 0,
                input_tokens=rng.randint(150, 800),
                output_tokens=rng.randint(300, 2500),
                conversation_id=f"conv_{conv_idx}",
                turn_number=turn,
                topic_category=rng.choice(topics),
                model=rng.choice(models),
                request_type="web" if rng.random() < 0.3 else "api",
            )
        )
    events.sort(key=lambda e: e.timestamp)
    return events


class TestThresholdSensitivity:
    """Sweep escalation threshold and measure FPR/FNR."""

    THRESHOLDS = [round(0.20 + 0.05 * i, 2) for i in range(9)]
    # [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]

    def setup_method(self) -> None:
        self.pipeline = DetectionPipeline()
        self.pipeline.register_default_detectors()

        # Ground truth: 10 attackers, 15 normal, 10 power devs
        self.true_positives_ids: list[str] = []
        self.true_negatives_ids: list[str] = []

        for i in range(10):
            events = _make_known_attacker(f"atk_{i:03d}", seed=500 + i)
            profile = build_profile(events)
            self.pipeline._profiles[profile.account_id] = profile
            self.true_positives_ids.append(profile.account_id)

        for i in range(15):
            events = _make_known_normal(f"norm_{i:03d}", seed=600 + i)
            profile = build_profile(events)
            self.pipeline._profiles[profile.account_id] = profile
            self.true_negatives_ids.append(profile.account_id)

        for i in range(10):
            events = _make_known_power_dev(f"pdev_{i:03d}", seed=700 + i)
            profile = build_profile(events)
            self.pipeline._profiles[profile.account_id] = profile
            self.true_negatives_ids.append(profile.account_id)

        # Build baseline and score
        self.pipeline._baseline = PopulationBaseline.from_profiles(
            list(self.pipeline._profiles.values())
        )
        for detector in self.pipeline._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(self.pipeline._baseline)

        self.assessments = self.pipeline.score_all()

    def _compute_rates(
        self, threshold: float
    ) -> tuple[float, float, float, float]:
        """Compute FPR, FNR, TPR, precision at a given threshold."""
        tp = fp = tn = fn = 0

        for aid in self.true_positives_ids:
            if self.assessments[aid].composite_score > threshold:
                tp += 1
            else:
                fn += 1

        for aid in self.true_negatives_ids:
            if self.assessments[aid].composite_score > threshold:
                fp += 1
            else:
                tn += 1

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        return fpr, fnr, tpr, precision

    def test_optimal_threshold_exists(self) -> None:
        """There should be a threshold where FPR=0 and FNR<0.5."""
        found_optimal = False
        for threshold in self.THRESHOLDS:
            fpr, fnr, _, _ = self._compute_rates(threshold)
            if fpr == 0.0 and fnr < 0.5:
                found_optimal = True
                break

        assert found_optimal, (
            "No threshold found with FPR=0 and FNR<0.5"
        )

    def test_current_threshold_performance(self) -> None:
        """The default 0.66 threshold should have zero FPR."""
        fpr, fnr, tpr, precision = self._compute_rates(0.66)
        assert fpr == 0.0, f"Default threshold FPR={fpr:.4f} (expected 0)"
        assert tpr >= 0.5, f"Default threshold TPR={tpr:.4f} (expected >=0.5)"

    def test_low_threshold_catches_all(self) -> None:
        """At threshold 0.20, all attackers should be flagged (high recall)."""
        _, fnr, tpr, _ = self._compute_rates(0.20)
        assert tpr >= 0.8, (
            f"At threshold 0.20, TPR={tpr:.4f} (expected >=0.8)"
        )

    def test_high_threshold_no_fp(self) -> None:
        """At threshold 0.60, there should be zero false positives."""
        fpr, _, _, _ = self._compute_rates(0.60)
        assert fpr == 0.0, f"At threshold 0.60, FPR={fpr:.4f}"

    def test_roc_curve_monotonic(self) -> None:
        """TPR should decrease monotonically as threshold increases."""
        tpr_values = []
        for threshold in self.THRESHOLDS:
            _, _, tpr, _ = self._compute_rates(threshold)
            tpr_values.append(tpr)

        for i in range(1, len(tpr_values)):
            assert tpr_values[i] <= tpr_values[i - 1] + 0.01, (
                f"TPR increased from {tpr_values[i-1]:.4f} to "
                f"{tpr_values[i]:.4f} at threshold "
                f"{self.THRESHOLDS[i]}"
            )

    def test_threshold_sweep_summary(self, capsys) -> None:
        """Print full ROC table for analysis."""
        lines = []
        lines.append("\n--- THRESHOLD SENSITIVITY / ROC DATA ---")
        lines.append(
            f"{'Threshold':>10} {'TPR':>7} {'FPR':>7} {'FNR':>7} "
            f"{'Precision':>10} {'F1':>7}"
        )
        lines.append("-" * 56)

        for threshold in self.THRESHOLDS:
            fpr, fnr, tpr, precision = self._compute_rates(threshold)
            f1 = (
                2 * precision * tpr / (precision + tpr)
                if (precision + tpr) > 0
                else 0.0
            )
            lines.append(
                f"{threshold:>10.2f} {tpr:>7.4f} {fpr:>7.4f} "
                f"{fnr:>7.4f} {precision:>10.4f} {f1:>7.4f}"
            )

        # Also print individual scores by class
        lines.append("")
        lines.append("--- SCORE DISTRIBUTION BY CLASS ---")
        lines.append(f"{'Account':<15} {'Score':>8} {'Class':<15}")
        lines.append("-" * 42)

        all_accounts = (
            [(aid, "attacker") for aid in self.true_positives_ids]
            + [(aid, "legitimate") for aid in self.true_negatives_ids]
        )
        all_accounts.sort(
            key=lambda x: self.assessments[x[0]].composite_score,
            reverse=True,
        )

        for aid, cls in all_accounts:
            score = self.assessments[aid].composite_score
            marker = " <-- FP" if cls == "legitimate" and score > 0.66 else ""
            marker = " <-- FN" if cls == "attacker" and score <= 0.66 else marker
            lines.append(
                f"{aid:<15} {score:>8.4f} {cls:<15}{marker}"
            )

        output = "\n".join(lines)
        print(output)
