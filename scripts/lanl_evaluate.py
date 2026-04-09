#!/usr/bin/env python3
"""Run LANL evaluation: windowed + auth profile, dump CSV, compute thresholds.

Usage:
    python scripts/lanl_evaluate.py data/lanl/parallax_events.jsonl \
        --redteam scripts/redteam.txt.gz \
        --output data/lanl/evaluation_v2.csv
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger("parallax.evaluate")


def load_redteam_users(path: str | Path) -> set[str]:
    """Load set of compromised user IDs from redteam file."""
    users: set[str] = set()
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                users.add(parts[1])
    return users


def main() -> None:
    parser = argparse.ArgumentParser(description="LANL Evaluation Pipeline")
    parser.add_argument("traffic_file", help="Path to PARALLAX JSONL")
    parser.add_argument("--redteam", required=True, help="Path to redteam.txt[.gz]")
    parser.add_argument("--output", default="data/lanl/evaluation_v2.csv")
    parser.add_argument("--window-hours", type=float, default=4.0)
    parser.add_argument("--stride-hours", type=float, default=1.0)
    parser.add_argument("--flow-enriched", action="store_true",
                        help="Activate T1-010 with flow-enriched weight profile")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Load red team labels
    redteam_users = load_redteam_users(args.redteam)
    logger.info("Red team users: %d", len(redteam_users))

    # Set up pipeline
    from detection.pipeline import DetectionPipeline

    pipeline = DetectionPipeline()
    pipeline.register_default_detectors()
    pipeline.apply_auth_profile(flow_enriched=args.flow_enriched)
    pipeline.load_traffic(args.traffic_file)

    # Windowed scoring
    logger.info("Starting windowed scoring...")
    pipeline.score_all_windowed(
        window_hours=args.window_hours,
        stride_hours=args.stride_hours,
    )

    # Dump CSV
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    detector_ids = [d.RULE_ID for d in pipeline.detectors]
    fieldnames = [
        "account_id", "is_compromised", "archetype",
        "peak_score", "peak_window_start", "windows_evaluated",
    ] + [f"score_{rid.value}" for rid in detector_ids]

    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for aid, assessment in pipeline.assessments.items():
            row = {
                "account_id": aid,
                "is_compromised": 1 if aid in redteam_users else 0,
                "archetype": assessment.archetype,
                "peak_score": round(assessment.composite_score, 6),
                "peak_window_start": assessment.peak_window_start or "",
                "windows_evaluated": assessment.windows_evaluated,
            }
            for rid in detector_ids:
                if rid in assessment.results:
                    row[f"score_{rid.value}"] = round(
                        assessment.results[rid].score, 6
                    )
                else:
                    row[f"score_{rid.value}"] = 0.0
            writer.writerow(row)

    logger.info("CSV written to %s", output_path)

    # --- Threshold Analysis ---
    scores_compromised = []
    scores_normal = []

    for aid, assessment in pipeline.assessments.items():
        if aid in redteam_users:
            scores_compromised.append(assessment.composite_score)
        else:
            scores_normal.append(assessment.composite_score)

    sys.stderr.write(f"\n{'='*70}\n")
    sys.stderr.write("THRESHOLD ANALYSIS\n")
    sys.stderr.write(f"{'='*70}\n")
    sys.stderr.write(f"Compromised users: {len(scores_compromised)}\n")
    sys.stderr.write(f"Normal users:      {len(scores_normal)}\n")

    if scores_compromised:
        from statistics import mean, stdev
        sys.stderr.write(f"\nCompromised scores: mean={mean(scores_compromised):.4f}, "
                        f"std={stdev(scores_compromised) if len(scores_compromised) > 1 else 0:.4f}, "
                        f"min={min(scores_compromised):.4f}, max={max(scores_compromised):.4f}\n")
    if scores_normal:
        from statistics import mean, stdev
        sys.stderr.write(f"Normal scores:      mean={mean(scores_normal):.4f}, "
                        f"std={stdev(scores_normal) if len(scores_normal) > 1 else 0:.4f}, "
                        f"min={min(scores_normal):.4f}, max={max(scores_normal):.4f}\n")

    # Precision/Recall at fixed thresholds
    fixed_thresholds = [0.25, 0.35, 0.45, 0.55]
    sys.stderr.write(f"\n{'Threshold':>10} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5} "
                    f"{'Precision':>10} {'Recall':>8} {'F1':>8}\n")
    sys.stderr.write("-" * 65 + "\n")

    best_f1 = 0.0
    best_threshold = 0.0

    # Sweep thresholds from 0.05 to 0.95 in 0.01 increments
    all_thresholds = [round(0.05 + 0.01 * i, 2) for i in range(91)]

    for threshold in all_thresholds:
        tp = sum(1 for s in scores_compromised if s > threshold)
        fn = sum(1 for s in scores_compromised if s <= threshold)
        fp = sum(1 for s in scores_normal if s > threshold)
        tn = sum(1 for s in scores_normal if s <= threshold)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold

        if threshold in fixed_thresholds:
            sys.stderr.write(
                f"{threshold:>10.2f} {tp:>5} {fp:>5} {fn:>5} {tn:>5} "
                f"{precision:>10.4f} {recall:>8.4f} {f1:>8.4f}\n"
            )

    sys.stderr.write(f"\nBest F1: {best_f1:.4f} at threshold {best_threshold:.2f}\n")

    # Print the best threshold's numbers
    tp = sum(1 for s in scores_compromised if s > best_threshold)
    fn = sum(1 for s in scores_compromised if s <= best_threshold)
    fp = sum(1 for s in scores_normal if s > best_threshold)
    tn = sum(1 for s in scores_normal if s <= best_threshold)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    sys.stderr.write(f"  TP={tp}, FP={fp}, FN={fn}, TN={tn}\n")
    sys.stderr.write(f"  Precision={precision:.4f}, Recall={recall:.4f}\n")

    # ROC AUC
    try:
        from sklearn.metrics import roc_auc_score
        y_true = [1 if aid in redteam_users else 0 for aid in pipeline.assessments]
        y_scores = [pipeline.assessments[aid].composite_score for aid in pipeline.assessments]
        auc = roc_auc_score(y_true, y_scores)
        sys.stderr.write(f"\nROC AUC: {auc:.4f}\n")
    except ImportError:
        sys.stderr.write("\n(sklearn not installed — skipping ROC AUC)\n")
    except Exception as e:
        sys.stderr.write(f"\nROC AUC error: {e}\n")

    # Per-detector contribution analysis
    sys.stderr.write(f"\n{'='*70}\n")
    sys.stderr.write("DETECTOR CONTRIBUTION TO SEPARATION\n")
    sys.stderr.write(f"{'='*70}\n")
    sys.stderr.write(f"{'Detector':<35} {'Comp Mean':>10} {'Norm Mean':>10} {'Delta':>8}\n")
    sys.stderr.write("-" * 65 + "\n")

    for det in pipeline.detectors:
        rid = det.RULE_ID
        if det.WEIGHT == 0:
            continue
        comp_scores = []
        norm_scores = []
        for aid, assessment in pipeline.assessments.items():
            if rid in assessment.results:
                score = assessment.results[rid].score
                if aid in redteam_users:
                    comp_scores.append(score)
                else:
                    norm_scores.append(score)

        if comp_scores and norm_scores:
            from statistics import mean
            comp_mean = mean(comp_scores)
            norm_mean = mean(norm_scores)
            delta = comp_mean - norm_mean
            sys.stderr.write(
                f"{rid.value} {det.RULE_NAME:<30} "
                f"{comp_mean:>10.4f} {norm_mean:>10.4f} {delta:>+8.4f}\n"
            )

    sys.stderr.write(f"{'='*70}\n")


if __name__ == "__main__":
    main()
