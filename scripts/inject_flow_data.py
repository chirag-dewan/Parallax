#!/usr/bin/env python3
"""Inject synthetic flow enrichment into existing LANL PARALLAX events.

Since flows.txt.gz requires LANL registration and is not available,
this script generates realistic flow patterns based on auth behavior:

- Normal accounts: bytes_transferred ~ N(800, 200), steady
- Compromised accounts: normal baseline + exfiltration spikes
  (5-10% of sessions get 10-50x byte volume)
- connection_duration_sec correlates with session duration

This allows evaluation of T1-010 DataTransferAnomaly without
the actual LANL flow dataset.

Usage:
    python scripts/inject_flow_data.py \
        data/lanl/parallax_events.jsonl \
        --redteam scripts/redteam.txt.gz \
        --output data/lanl/parallax_events_flow.jsonl
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import random
import sys
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger("parallax.inject_flow")


def load_redteam_users(path: str | Path) -> set[str]:
    """Load set of compromised user IDs."""
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
    parser = argparse.ArgumentParser(
        description="Inject synthetic flow data into PARALLAX events"
    )
    parser.add_argument("input_file", help="Input PARALLAX JSONL")
    parser.add_argument("--redteam", required=True, help="Path to redteam.txt[.gz]")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    rng = random.Random(args.seed)
    redteam = load_redteam_users(args.redteam)
    logger.info("Red team users: %d", len(redteam))

    input_path = Path(args.input_file)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Track per-account session state for spike injection
    account_sessions: dict[str, set[str]] = defaultdict(set)
    spike_sessions: set[str] = set()

    # First pass: identify sessions to spike for compromised users
    logger.info("Pass 1: Identifying spike sessions for compromised users...")
    session_events: dict[str, int] = defaultdict(int)
    session_owners: dict[str, str] = {}

    with input_path.open("r") as f:
        for line in f:
            try:
                event = json.loads(line)
                aid = event["account_id"]
                cid = event["conversation_id"]
                session_events[cid] += 1
                session_owners[cid] = aid
            except (json.JSONDecodeError, KeyError):
                continue

    # For compromised users, mark 5-10% of their sessions as exfiltration spikes
    for cid, aid in session_owners.items():
        if aid in redteam:
            if rng.random() < 0.08:  # 8% spike rate
                spike_sessions.add(cid)

    logger.info("Marked %d spike sessions across %d compromised users",
                len(spike_sessions), len(redteam))

    # Second pass: inject flow data
    logger.info("Pass 2: Injecting flow data...")
    written = 0

    with input_path.open("r") as fin, output_path.open("w") as fout:
        for line in fin:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                fout.write(line)
                continue

            aid = event["account_id"]
            cid = event["conversation_id"]
            is_compromised = aid in redteam

            # Base bytes: normal traffic
            base_bytes = max(0, int(rng.gauss(800, 200)))

            if cid in spike_sessions:
                # Exfiltration spike: 10-50x normal
                multiplier = rng.uniform(10, 50)
                bytes_transferred = int(base_bytes * multiplier)
            elif is_compromised:
                # Compromised but not spiking: slightly elevated
                bytes_transferred = int(base_bytes * rng.uniform(1.0, 2.0))
            else:
                bytes_transferred = base_bytes

            # Connection duration correlates with session duration + noise
            session_hours = event.get("session_duration_hours", 0.5)
            base_duration = int(session_hours * 3600 * rng.uniform(0.01, 0.1))
            if cid in spike_sessions:
                # Longer connections during exfiltration
                base_duration = int(base_duration * rng.uniform(2, 5))
            connection_duration_sec = max(1, base_duration)

            event["bytes_transferred"] = bytes_transferred
            event["connection_duration_sec"] = connection_duration_sec

            fout.write(json.dumps(event) + "\n")
            written += 1

            if written % 2_000_000 == 0:
                logger.info("  %d events written...", written)

    logger.info("Done. %d events written to %s", written, output_path)
    sys.stderr.write(f"\n{written:,} events written to {output_path}\n")
    sys.stderr.write(f"Spike sessions: {len(spike_sessions)}\n")


if __name__ == "__main__":
    main()
