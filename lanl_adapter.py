#!/usr/bin/env python3
"""
LANL Cyber1 -> PARALLAX Adapter

Converts Los Alamos National Laboratory's Comprehensive Multi-Source
Cyber-Security Events dataset into PARALLAX APIEvent JSONL format.

Data source: https://csr.lanl.gov/data/cyber1/
License: CC0 (public domain)

Usage:
    python lanl_adapter.py \
        --auth data/lanl/auth.txt.gz \
        --redteam data/lanl/redteam.txt.gz \
        --output data/lanl/parallax_events.jsonl

    # With enrichment sources and user sampling:
    python lanl_adapter.py \
        --auth data/lanl/auth.txt.gz \
        --proc data/lanl/proc.txt.gz \
        --flows data/lanl/flows.txt.gz \
        --redteam data/lanl/redteam.txt.gz \
        --output data/lanl/parallax_events.jsonl \
        --sample-users 500
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("parallax.lanl_adapter")

# LANL epoch starts at 1 (second 1 of the observation window).
# We anchor to an arbitrary real date for ISO 8601 output.
LANL_EPOCH = datetime(2015, 1, 1, tzinfo=timezone.utc)

# Logon types that map to "web" (interactive) vs "api" (programmatic)
INTERACTIVE_LOGON_TYPES = {"Interactive", "RemoteInteractive", "CachedInteractive"}

# Session gap: if >30 min between auth events on same (user, dst, logon_type),
# start a new session.
SESSION_GAP_SECONDS = 1800

# Burst threshold: if inter-request interval <= 2 seconds, treat as rate-limit analog
BURST_THRESHOLD_MS = 2000

# Token scaling: LANL byte counts -> PARALLAX token-range proxy
# Divide bytes by 4 (rough bytes-per-token), cap at 4096
TOKEN_SCALE_FACTOR = 4
TOKEN_MAX = 4096


# ---------------------------------------------------------------------------
# Streaming Parsers
# ---------------------------------------------------------------------------

def _open_file(path: str | Path) -> Iterator[str]:
    """Open plain text or gzip, yield lines."""
    path = Path(path)
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            try:
                yield from f
            except EOFError:
                logger.warning("Truncated gzip file %s — processing partial data", path)
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            yield from f


def iter_auth_events(path: str | Path) -> Iterator[dict]:
    """Yield parsed auth events from auth.txt[.gz].

    Format: time,src_user@domain,dst_user@domain,src_computer,
            dst_computer,auth_type,logon_type,orientation,success/failure
    """
    for line_num, line in enumerate(_open_file(path), 1):
        parts = line.strip().split(",")
        if len(parts) < 9:
            continue
        try:
            yield {
                "time": int(parts[0]),
                "src_user": parts[1],
                "dst_user": parts[2],
                "src_computer": parts[3],
                "dst_computer": parts[4],
                "auth_type": parts[5],
                "logon_type": parts[6],
                "orientation": parts[7],
                "success": parts[8],
            }
        except (ValueError, IndexError):
            logger.debug("Skipping malformed auth line %d", line_num)


def iter_proc_events(path: str | Path) -> Iterator[dict]:
    """Yield parsed proc events from proc.txt[.gz].

    Format: time,user@domain,computer,process_name,start/end
    """
    for line_num, line in enumerate(_open_file(path), 1):
        parts = line.strip().split(",")
        if len(parts) < 5:
            continue
        try:
            yield {
                "time": int(parts[0]),
                "user": parts[1],
                "computer": parts[2],
                "process": parts[3],
                "action": parts[4],
            }
        except (ValueError, IndexError):
            logger.debug("Skipping malformed proc line %d", line_num)


def iter_flow_events(path: str | Path) -> Iterator[dict]:
    """Yield parsed flow events from flows.txt[.gz].

    Format: time,duration,src_computer,src_port,dst_computer,
            dst_port,protocol,packet_count,byte_count
    """
    for line_num, line in enumerate(_open_file(path), 1):
        parts = line.strip().split(",")
        if len(parts) < 9:
            continue
        try:
            yield {
                "time": int(parts[0]),
                "duration": int(parts[1]) if parts[1] != "?" else 0,
                "src_computer": parts[2],
                "src_port": parts[3],
                "dst_computer": parts[4],
                "dst_port": parts[5],
                "protocol": parts[6],
                "packets": int(parts[7]) if parts[7] != "?" else 0,
                "bytes": int(parts[8]) if parts[8] != "?" else 0,
            }
        except (ValueError, IndexError):
            logger.debug("Skipping malformed flow line %d", line_num)


def load_redteam(path: str | Path) -> dict[str, set[int]]:
    """Load red team labels. Returns {user@domain: {compromise_times}}."""
    labels: dict[str, set[int]] = defaultdict(set)
    for line in _open_file(path):
        parts = line.strip().split(",")
        if len(parts) < 4:
            continue
        try:
            time = int(parts[0])
            user = parts[1]
            labels[user].add(time)
        except (ValueError, IndexError):
            continue
    logger.info("Loaded red team labels: %d users, %d events",
                len(labels), sum(len(v) for v in labels.values()))
    return dict(labels)


# ---------------------------------------------------------------------------
# Enrichment Index Builders
# ---------------------------------------------------------------------------

def build_proc_index(
    path: str | Path, target_users: set[str] | None = None
) -> dict[str, list[dict]]:
    """Build per-user process event index. Optionally filter to target users."""
    index: dict[str, list[dict]] = defaultdict(list)
    count = 0
    for event in iter_proc_events(path):
        user = event["user"]
        if target_users and user not in target_users:
            continue
        index[user].append(event)
        count += 1
        if count % 5_000_000 == 0:
            logger.info("  proc index: %d events ingested", count)
    logger.info("Proc index: %d events across %d users", count, len(index))
    return dict(index)


def build_flow_index(
    path: str | Path, target_computers: set[str] | None = None
) -> dict[str, list[dict]]:
    """Build per-source-computer flow index."""
    index: dict[str, list[dict]] = defaultdict(list)
    count = 0
    for event in iter_flow_events(path):
        src = event["src_computer"]
        if target_computers and src not in target_computers:
            continue
        index[src].append(event)
        count += 1
        if count % 5_000_000 == 0:
            logger.info("  flow index: %d events ingested", count)
    logger.info("Flow index: %d events across %d computers", count, len(index))
    return dict(index)


def build_flow_pair_index(
    path: str | Path,
    target_pairs: set[tuple[str, str]] | None = None,
) -> dict[tuple[str, str], list[dict]]:
    """Build flow index keyed by (src_computer, dst_computer) for auth join.

    Each entry is sorted by time for efficient window lookups.
    """
    index: dict[tuple[str, str], list[dict]] = defaultdict(list)
    count = 0
    for event in iter_flow_events(path):
        pair = (event["src_computer"], event["dst_computer"])
        if target_pairs and pair not in target_pairs:
            continue
        index[pair].append(event)
        count += 1
        if count % 5_000_000 == 0:
            logger.info("  flow pair index: %d events ingested", count)

    # Sort each pair's flows by time for binary search
    for flows in index.values():
        flows.sort(key=lambda f: f["time"])

    logger.info("Flow pair index: %d events across %d pairs", count, len(index))
    return dict(index)


# ---------------------------------------------------------------------------
# Profile Builder
# ---------------------------------------------------------------------------

class LANLProfileBuilder:
    """Builds per-user auth event lists with enrichment and session grouping."""

    def __init__(
        self,
        redteam_labels: dict[str, set[int]],
        proc_index: dict[str, list[dict]] | None = None,
        flow_index: dict[str, list[dict]] | None = None,
        flow_pair_index: dict[tuple[str, str], list[dict]] | None = None,
    ) -> None:
        self.redteam = redteam_labels
        self.proc_index = proc_index or {}
        self.flow_index = flow_index or {}
        self.flow_pair_index = flow_pair_index or {}

    def is_compromised(self, user: str) -> bool:
        """Check if user appears in red team labels at any time."""
        return user in self.redteam

    def get_archetype(self, user: str) -> str:
        return "compromised" if self.is_compromised(user) else "normal"

    def compute_account_age(self, first_seen: int, current_time: int) -> int:
        """Days between first event and current event."""
        delta = current_time - first_seen
        return max(1, delta // 86400)

    def get_flow_bytes(
        self, computer: str, time: int, window: int = 60
    ) -> tuple[int, int]:
        """Get (bytes_out, bytes_in) for computer in time window.

        bytes_out = bytes from flows where computer is source
        bytes_in = bytes from flows where computer is destination
        (approximated: we only index by source, so bytes_in is from
        flows where this computer is dst — requires reverse lookup
        which is expensive. We use source bytes as proxy for both.)
        """
        flows = self.flow_index.get(computer, [])
        if not flows:
            return 200, 500  # defaults matching normal PARALLAX range

        bytes_out = 0
        count = 0
        for f in flows:
            if abs(f["time"] - time) <= window:
                bytes_out += f["bytes"]
                count += 1
            if count > 20:
                break

        if bytes_out == 0:
            return 200, 500

        # Scale to token range
        tokens_out = min(TOKEN_MAX, bytes_out // TOKEN_SCALE_FACTOR)
        # Estimate input as fraction of output (requests are smaller)
        tokens_in = min(TOKEN_MAX, max(50, tokens_out // 4))
        return tokens_in, tokens_out

    def get_flow_for_auth(
        self, src_computer: str, dst_computer: str, time: int, window: int = 60
    ) -> tuple[int, int]:
        """Get (bytes_transferred, connection_duration_sec) for an auth event.

        Joins auth with flow data on (src_computer, dst_computer) within
        a time window. Returns summed bytes and max duration from matching flows.
        """
        pair = (src_computer, dst_computer)
        flows = self.flow_pair_index.get(pair, [])
        if not flows:
            return 0, 0

        total_bytes = 0
        max_duration = 0
        matched = 0

        # Binary search for start of window (flows are sorted by time)
        lo, hi = 0, len(flows)
        target = time - window
        while lo < hi:
            mid = (lo + hi) // 2
            if flows[mid]["time"] < target:
                lo = mid + 1
            else:
                hi = mid

        for i in range(lo, len(flows)):
            f = flows[i]
            if f["time"] > time + window:
                break
            total_bytes += f["bytes"]
            max_duration = max(max_duration, f["duration"])
            matched += 1

        return total_bytes, max_duration

    def get_topic_from_proc(self, user: str, time: int, window: int = 300) -> str | None:
        """Get dominant process near this time as topic proxy."""
        procs = self.proc_index.get(user, [])
        if not procs:
            return None

        nearby = [p["process"] for p in procs if abs(p["time"] - time) <= window]
        if not nearby:
            return None

        # Most common process in window
        counts: dict[str, int] = defaultdict(int)
        for p in nearby:
            counts[p] += 1
        return max(counts, key=counts.get)


# ---------------------------------------------------------------------------
# Converter
# ---------------------------------------------------------------------------

def _epoch_to_iso(lanl_time: int) -> str:
    """Convert LANL epoch seconds to ISO 8601 string."""
    dt = LANL_EPOCH + timedelta(seconds=lanl_time)
    return dt.isoformat()


def _make_session_key(event: dict) -> str:
    return f"{event['src_user']}|{event['dst_computer']}|{event['logon_type']}"


def _dst_to_topic(dst_computer: str) -> str:
    """Map destination computer identifier to a topic category.

    LANL de-identifies computers as C1, C2, ..., C17684.
    We hash into topic buckets to simulate service diversity.
    """
    # Extract numeric ID if possible
    if dst_computer.startswith("C") and dst_computer[1:].isdigit():
        num = int(dst_computer[1:])
    else:
        num = hash(dst_computer)

    topics = [
        "authentication", "fileserver", "database", "webserver",
        "mailserver", "dns", "directory", "compute", "monitoring",
    ]
    return topics[num % len(topics)]


def convert_auth_to_parallax(
    auth_path: str | Path,
    builder: LANLProfileBuilder,
    output_path: str | Path,
    sample_users: int | None = None,
) -> dict[str, int]:
    """Stream auth events and write PARALLAX JSONL.

    Returns stats dict with counts.
    """
    output_path = Path(output_path)

    # --- Pass 1: Identify users and first-seen times ---
    logger.info("Pass 1: Scanning users and first-seen times...")
    user_first_seen: dict[str, int] = {}
    user_event_counts: dict[str, int] = defaultdict(int)

    for event in iter_auth_events(auth_path):
        user = event["src_user"]
        if user == "?" or user.startswith("ANONYMOUS"):
            continue
        t = event["time"]
        if user not in user_first_seen or t < user_first_seen[user]:
            user_first_seen[user] = t
        user_event_counts[user] += 1

    all_users = set(user_first_seen.keys())
    logger.info("Found %d unique users", len(all_users))

    # --- Select users ---
    if sample_users and sample_users < len(all_users):
        # Always include compromised users, then sample the rest
        compromised = {u for u in all_users if builder.is_compromised(u)}
        normal = all_users - compromised
        # Sort by event count descending for more interesting profiles
        normal_sorted = sorted(normal, key=lambda u: user_event_counts[u], reverse=True)
        n_normal = sample_users - len(compromised)
        selected = compromised | set(normal_sorted[:max(0, n_normal)])
        logger.info("Sampled %d users (%d compromised, %d normal)",
                    len(selected), len(compromised), len(selected) - len(compromised))
    else:
        selected = all_users

    # --- Pass 2: Convert events ---
    logger.info("Pass 2: Converting auth events to PARALLAX format...")
    session_state: dict[str, dict] = {}  # session_key -> {id, turn, last_time}
    user_last_time: dict[str, int] = {}
    session_counter = 0
    written = 0
    skipped = 0

    with output_path.open("w") as out:
        for event in iter_auth_events(auth_path):
            user = event["src_user"]
            if user not in selected:
                skipped += 1
                continue

            t = event["time"]
            dst = event["dst_computer"]
            logon_type = event["logon_type"]
            auth_type = event["auth_type"]
            success = event["success"]

            # Session grouping
            sess_key = _make_session_key(event)
            if sess_key in session_state:
                state = session_state[sess_key]
                gap = t - state["last_time"]
                if gap > SESSION_GAP_SECONDS:
                    # New session
                    session_counter += 1
                    session_state[sess_key] = {
                        "id": f"sess_{session_counter}",
                        "turn": 0,
                        "start_time": t,
                        "last_time": t,
                    }
                else:
                    state["turn"] += 1
                    state["last_time"] = t
            else:
                session_counter += 1
                session_state[sess_key] = {
                    "id": f"sess_{session_counter}",
                    "turn": 0,
                    "start_time": t,
                    "last_time": t,
                }

            state = session_state[sess_key]

            # Inter-request interval
            interval_ms = 0
            if user in user_last_time:
                interval_ms = (t - user_last_time[user]) * 1000
            user_last_time[user] = t

            # Token proxy from flows
            input_tokens, output_tokens = builder.get_flow_bytes(
                event["src_computer"], t
            )

            # Flow enrichment: bytes transferred and connection duration
            bytes_transferred, connection_duration_sec = builder.get_flow_for_auth(
                event["src_computer"], dst, t
            )

            # Topic from proc or destination
            topic = builder.get_topic_from_proc(user, t)
            if topic is None:
                topic = _dst_to_topic(dst)

            # Safety / rate limit analogs
            is_failure = (success == "Fail")
            is_burst = (interval_ms > 0 and interval_ms < BURST_THRESHOLD_MS)

            # Retry delay (time after failure before next attempt)
            retry_delay_ms = 0
            if is_burst and is_failure:
                retry_delay_ms = max(0, interval_ms)

            # Session duration
            session_hours = (t - state["start_time"]) / 3600

            # Request type
            request_type = "web" if logon_type in INTERACTIVE_LOGON_TYPES else "api"

            # HTTP status analog
            if is_failure:
                http_status = 403
            elif is_burst:
                http_status = 429
            else:
                http_status = 200

            # Model = auth mechanism
            model = auth_type if auth_type != "?" else "Unknown"

            api_event = {
                "timestamp": _epoch_to_iso(t),
                "account_id": user,
                "archetype": builder.get_archetype(user),
                "account_age_days": builder.compute_account_age(
                    user_first_seen[user], t
                ),
                "request_type": request_type,
                "inter_request_interval_ms": interval_ms,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "conversation_id": state["id"],
                "turn_number": state["turn"],
                "session_duration_hours": round(session_hours, 2),
                "topic_category": topic,
                "safety_filter_triggered": is_failure,
                "rate_limit_hit": is_burst,
                "rate_limit_retry_delay_ms": retry_delay_ms,
                "response_time_ms": 500,  # No latency data in LANL
                "http_status": http_status,
                "model": model,
                "bytes_transferred": bytes_transferred,
                "connection_duration_sec": connection_duration_sec,
            }

            out.write(json.dumps(api_event) + "\n")
            written += 1

            if written % 1_000_000 == 0:
                logger.info("  %d events written...", written)

    stats = {
        "total_written": written,
        "total_skipped": skipped,
        "users_selected": len(selected),
        "users_compromised": sum(
            1 for u in selected if builder.is_compromised(u)
        ),
        "sessions_created": session_counter,
    }
    logger.info("Conversion complete: %s", stats)
    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert LANL Cyber1 dataset to PARALLAX format"
    )
    parser.add_argument("--auth", required=True, help="Path to auth.txt[.gz]")
    parser.add_argument("--proc", default=None, help="Path to proc.txt[.gz]")
    parser.add_argument("--flows", default=None, help="Path to flows.txt[.gz]")
    parser.add_argument("--redteam", required=True, help="Path to redteam.txt[.gz]")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument(
        "--sample-users", type=int, default=None,
        help="Limit to N users (always includes compromised)"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Load ground truth
    redteam = load_redteam(args.redteam)

    # Build enrichment indexes (optional)
    proc_index = None
    flow_index = None

    if args.proc:
        logger.info("Building process enrichment index...")
        proc_index = build_proc_index(args.proc)

    flow_pair_index = None
    if args.flows:
        logger.info("Building flow enrichment index...")
        flow_index = build_flow_index(args.flows)
        logger.info("Building flow pair index for auth join...")
        flow_pair_index = build_flow_pair_index(args.flows)

    builder = LANLProfileBuilder(
        redteam_labels=redteam,
        proc_index=proc_index,
        flow_index=flow_index,
        flow_pair_index=flow_pair_index,
    )

    # Convert
    stats = convert_auth_to_parallax(
        auth_path=args.auth,
        builder=builder,
        output_path=args.output,
        sample_users=args.sample_users,
    )

    sys.stderr.write(f"\nDone. {stats['total_written']:,} events written to {args.output}\n")
    sys.stderr.write(f"  Users: {stats['users_selected']} ({stats['users_compromised']} compromised)\n")
    sys.stderr.write(f"  Sessions: {stats['sessions_created']:,}\n")


if __name__ == "__main__":
    main()
