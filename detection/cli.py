"""
PARALLAX Detection CLI

Usage:
    python -m detection data/traffic.jsonl
    python -m detection data/test_24h.jsonl --top 20
    python -m detection data/traffic.jsonl --account attacker_0003
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import defaultdict
from statistics import mean

from detection.pipeline import DetectionPipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="PARALLAX Detection Engine")
    parser.add_argument("traffic_file", help="Path to JSONL traffic file")
    parser.add_argument(
        "--top",
        type=int,
        default=0,
        help="Show only top N accounts by score",
    )
    parser.add_argument(
        "--account", type=str, default=None, help="Score a single account"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    pipeline = DetectionPipeline()
    pipeline.register_default_detectors()
    pipeline.load_traffic(args.traffic_file)
    pipeline.score_all()

    if args.account:
        _print_account_detail(pipeline, args.account)
    else:
        _print_summary(pipeline, top_n=args.top)


def _print_account_detail(pipeline: DetectionPipeline, account_id: str) -> None:
    if account_id not in pipeline.assessments:
        sys.stderr.write(f"Account {account_id} not found\n")
        sys.exit(1)

    assessment = pipeline.assessments[account_id]
    profile = pipeline.profiles[account_id]

    sys.stdout.write(f"\n{'='*80}\n")
    sys.stdout.write(f"Account: {account_id}\n")
    sys.stdout.write(f"Archetype: {profile.archetype}\n")
    sys.stdout.write(f"Events: {profile.total_events:,}\n")
    sys.stdout.write(f"Account Age: {profile.account_age_days} days\n")
    sys.stdout.write(f"Composite Score: {assessment.composite_score:.4f}\n")
    sys.stdout.write(f"Threat Level: {assessment.threat_level.value.upper()}\n")
    sys.stdout.write(f"Escalation: {'YES' if assessment.escalation_recommended else 'NO'}\n")
    sys.stdout.write(f"{'='*80}\n\n")

    sys.stdout.write(f"{'Rule':<10} {'Name':<30} {'Score':<8} {'Trig':<6} {'Conf':<6}\n")
    sys.stdout.write(f"{'-'*60}\n")

    for rule_id, result in sorted(
        assessment.results.items(), key=lambda x: x[1].score, reverse=True
    ):
        sys.stdout.write(
            f"{result.rule_id.value:<10} {result.rule_name:<30} "
            f"{result.score:<8.4f} {'YES' if result.triggered else 'NO':<6} "
            f"{result.confidence:<6.2f}\n"
        )


def _print_summary(pipeline: DetectionPipeline, top_n: int) -> None:
    assessments = sorted(
        pipeline.assessments.values(),
        key=lambda a: a.composite_score,
        reverse=True,
    )

    if top_n > 0:
        assessments = assessments[:top_n]

    sys.stdout.write(f"\n{'='*120}\n")
    sys.stdout.write("PARALLAX THREAT SCORING RESULTS\n")
    sys.stdout.write(f"{'='*120}\n")
    sys.stdout.write(
        f"{'Account ID':<20} {'Type':<20} {'Level':<10} "
        f"{'Score':<8} {'Escal':<6} {'T1':<4} {'T2':<4} {'Top Signals':<40}\n"
    )
    sys.stdout.write(f"{'-'*120}\n")

    for a in assessments:
        signals = []
        for rule_id, weighted in a.top_signals[:3]:
            if weighted > 0.001:
                signals.append(f"{rule_id.value}:{weighted:.3f}")
        signals_str = ", ".join(signals) if signals else "None"

        sys.stdout.write(
            f"{a.account_id:<20} {a.archetype:<20} "
            f"{a.threat_level.value.upper():<10} "
            f"{a.composite_score:<8.4f} "
            f"{'YES' if a.escalation_recommended else 'NO':<6} "
            f"{a.tier1_triggered_count:<4} {a.tier2_triggered_count:<4} "
            f"{signals_str:<40}\n"
        )

    sys.stdout.write(f"{'='*120}\n")

    # Summary by archetype
    by_arch: dict[str, list[float]] = defaultdict(list)
    for a in pipeline.assessments.values():
        by_arch[a.archetype].append(a.composite_score)

    sys.stdout.write("\nSUMMARY BY ARCHETYPE:\n")
    for arch, scores in sorted(by_arch.items()):
        escalated = sum(
            1
            for a in pipeline.assessments.values()
            if a.archetype == arch and a.escalation_recommended
        )
        sys.stdout.write(
            f"  {arch:<20} Avg: {mean(scores):.4f}  "
            f"Escalated: {escalated}/{len(scores)}\n"
        )
    sys.stdout.write(f"\n{'='*120}\n")
