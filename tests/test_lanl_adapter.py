"""Tests for LANL Cyber1 -> PARALLAX adapter.

Uses synthetic LANL-format data — no dataset download needed.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lanl_adapter import (
    LANL_EPOCH,
    LANLProfileBuilder,
    _dst_to_topic,
    _epoch_to_iso,
    convert_auth_to_parallax,
    iter_auth_events,
    iter_flow_events,
    iter_proc_events,
    load_redteam,
)


# ---------------------------------------------------------------------------
# Helpers: write synthetic LANL files
# ---------------------------------------------------------------------------

def _write_auth(tmp_path: Path, lines: list[str], gz: bool = False) -> Path:
    fname = "auth.txt.gz" if gz else "auth.txt"
    p = tmp_path / fname
    if gz:
        with gzip.open(p, "wt") as f:
            f.write("\n".join(lines) + "\n")
    else:
        p.write_text("\n".join(lines) + "\n")
    return p


def _write_proc(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "proc.txt"
    p.write_text("\n".join(lines) + "\n")
    return p


def _write_flows(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "flows.txt"
    p.write_text("\n".join(lines) + "\n")
    return p


def _write_redteam(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "redteam.txt"
    p.write_text("\n".join(lines) + "\n")
    return p


# ---------------------------------------------------------------------------
# Auth line parsing
# ---------------------------------------------------------------------------

class TestAuthParsing:
    def test_parse_normal_line(self, tmp_path):
        lines = ["1,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success"]
        path = _write_auth(tmp_path, lines)
        events = list(iter_auth_events(path))
        assert len(events) == 1
        e = events[0]
        assert e["time"] == 1
        assert e["src_user"] == "U1@DOM1"
        assert e["dst_user"] == "U2@DOM1"
        assert e["auth_type"] == "Kerberos"
        assert e["logon_type"] == "Network"
        assert e["success"] == "Success"

    def test_parse_failure_event(self, tmp_path):
        lines = ["100,U5@DOM1,U5@DOM1,C10,C20,NTLM,Interactive,LogOn,Fail"]
        path = _write_auth(tmp_path, lines)
        events = list(iter_auth_events(path))
        assert events[0]["success"] == "Fail"
        assert events[0]["logon_type"] == "Interactive"

    def test_skip_short_lines(self, tmp_path):
        lines = ["1,U1@DOM1,too,few,fields", "1,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success"]
        path = _write_auth(tmp_path, lines)
        events = list(iter_auth_events(path))
        assert len(events) == 1

    def test_gzip_support(self, tmp_path):
        lines = ["500,U3@DOM1,U4@DOM1,C5,C6,Negotiate,Network,LogOn,Success"]
        path = _write_auth(tmp_path, lines, gz=True)
        events = list(iter_auth_events(path))
        assert len(events) == 1
        assert events[0]["time"] == 500

    def test_multiple_events(self, tmp_path):
        lines = [
            f"{t},U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success"
            for t in range(1, 101)
        ]
        path = _write_auth(tmp_path, lines)
        events = list(iter_auth_events(path))
        assert len(events) == 100


# ---------------------------------------------------------------------------
# Proc and flow parsing
# ---------------------------------------------------------------------------

class TestProcParsing:
    def test_parse_proc_line(self, tmp_path):
        lines = ["10,U1@DOM1,C1,P1,Start"]
        path = _write_proc(tmp_path, lines)
        events = list(iter_proc_events(path))
        assert len(events) == 1
        assert events[0]["process"] == "P1"
        assert events[0]["action"] == "Start"


class TestFlowParsing:
    def test_parse_flow_line(self, tmp_path):
        lines = ["10,5,C1,443,C2,80,6,100,50000"]
        path = _write_flows(tmp_path, lines)
        events = list(iter_flow_events(path))
        assert len(events) == 1
        assert events[0]["bytes"] == 50000
        assert events[0]["packets"] == 100

    def test_missing_values(self, tmp_path):
        lines = ["10,?,C1,443,C2,80,6,?,?"]
        path = _write_flows(tmp_path, lines)
        events = list(iter_flow_events(path))
        assert events[0]["duration"] == 0
        assert events[0]["bytes"] == 0


# ---------------------------------------------------------------------------
# Red team labels
# ---------------------------------------------------------------------------

class TestRedteam:
    def test_load_labels(self, tmp_path):
        lines = [
            "150336,U748@DOM1,C17693,C1003",
            "150670,U748@DOM1,C17693,C305",
            "200000,U1000@DOM1,C100,C200",
        ]
        path = _write_redteam(tmp_path, lines)
        labels = load_redteam(path)
        assert "U748@DOM1" in labels
        assert len(labels["U748@DOM1"]) == 2
        assert 150336 in labels["U748@DOM1"]
        assert "U1000@DOM1" in labels

    def test_empty_redteam(self, tmp_path):
        path = _write_redteam(tmp_path, [])
        labels = load_redteam(path)
        assert len(labels) == 0


# ---------------------------------------------------------------------------
# Profile Builder
# ---------------------------------------------------------------------------

class TestProfileBuilder:
    def test_compromised_detection(self):
        labels = {"U1@DOM1": {100, 200}}
        builder = LANLProfileBuilder(redteam_labels=labels)
        assert builder.is_compromised("U1@DOM1")
        assert not builder.is_compromised("U2@DOM1")

    def test_archetype_assignment(self):
        labels = {"U1@DOM1": {100}}
        builder = LANLProfileBuilder(redteam_labels=labels)
        assert builder.get_archetype("U1@DOM1") == "compromised"
        assert builder.get_archetype("U99@DOM1") == "normal"

    def test_account_age(self):
        builder = LANLProfileBuilder(redteam_labels={})
        assert builder.compute_account_age(0, 86400) == 1
        assert builder.compute_account_age(0, 86400 * 30) == 30
        # Same second -> minimum 1 day
        assert builder.compute_account_age(100, 100) == 1


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_epoch_to_iso(self):
        iso = _epoch_to_iso(1)
        # Should be LANL_EPOCH + 1 second
        dt = datetime.fromisoformat(iso)
        expected = LANL_EPOCH.replace(tzinfo=None) + __import__("datetime").timedelta(seconds=1)
        assert dt.replace(tzinfo=None) == expected

    def test_dst_to_topic_deterministic(self):
        # Same input -> same output
        t1 = _dst_to_topic("C100")
        t2 = _dst_to_topic("C100")
        assert t1 == t2

    def test_dst_to_topic_variety(self):
        # Different computers should produce some variety
        topics = {_dst_to_topic(f"C{i}") for i in range(100)}
        assert len(topics) > 3  # Should hit multiple topic categories


# ---------------------------------------------------------------------------
# Full conversion pipeline
# ---------------------------------------------------------------------------

class TestConversion:
    def _make_test_data(self, tmp_path, n_normal=50, n_attacker=20):
        """Generate synthetic LANL auth data with known attacker."""
        auth_lines = []
        # Normal user: moderate pace, varied destinations, mostly success
        for i in range(n_normal):
            t = 1000 + i * 30  # 30-second intervals
            dst = f"C{(i % 10) + 1}"
            auth_lines.append(
                f"{t},U1@DOM1,U2@DOM1,C1,{dst},Kerberos,Network,LogOn,Success"
            )

        # Attacker: rapid bursts, lots of failures, single destination
        for i in range(n_attacker):
            t = 5000 + i  # 1-second intervals (burst)
            fail = "Fail" if i % 3 == 0 else "Success"
            auth_lines.append(
                f"{t},U999@DOM1,U999@DOM1,C50,C2,NTLM,Network,LogOn,{fail}"
            )

        auth_path = _write_auth(tmp_path, auth_lines)
        redteam_lines = ["5000,U999@DOM1,C50,C2"]
        redteam_path = _write_redteam(tmp_path, redteam_lines)
        return auth_path, redteam_path

    def test_basic_conversion(self, tmp_path):
        auth_path, redteam_path = self._make_test_data(tmp_path)
        output_path = tmp_path / "output.jsonl"

        labels = load_redteam(redteam_path)
        builder = LANLProfileBuilder(redteam_labels=labels)

        stats = convert_auth_to_parallax(auth_path, builder, output_path)

        assert stats["total_written"] == 70  # 50 normal + 20 attacker
        assert stats["users_compromised"] == 1

        # Read and validate output
        events = []
        with output_path.open() as f:
            for line in f:
                events.append(json.loads(line))

        assert len(events) == 70

        # Check field presence
        required_fields = {
            "timestamp", "account_id", "archetype", "account_age_days",
            "request_type", "inter_request_interval_ms", "input_tokens",
            "output_tokens", "conversation_id", "turn_number",
            "session_duration_hours", "topic_category",
            "safety_filter_triggered", "rate_limit_hit",
            "rate_limit_retry_delay_ms", "response_time_ms",
            "http_status", "model",
        }
        for event in events:
            assert required_fields.issubset(event.keys()), (
                f"Missing fields: {required_fields - event.keys()}"
            )

    def test_attacker_labeled_correctly(self, tmp_path):
        auth_path, redteam_path = self._make_test_data(tmp_path)
        output_path = tmp_path / "output.jsonl"

        labels = load_redteam(redteam_path)
        builder = LANLProfileBuilder(redteam_labels=labels)
        convert_auth_to_parallax(auth_path, builder, output_path)

        events = [json.loads(line) for line in output_path.open()]

        attacker_events = [e for e in events if e["account_id"] == "U999@DOM1"]
        normal_events = [e for e in events if e["account_id"] == "U1@DOM1"]

        assert all(e["archetype"] == "compromised" for e in attacker_events)
        assert all(e["archetype"] == "normal" for e in normal_events)

    def test_attacker_has_failures(self, tmp_path):
        auth_path, redteam_path = self._make_test_data(tmp_path)
        output_path = tmp_path / "output.jsonl"

        labels = load_redteam(redteam_path)
        builder = LANLProfileBuilder(redteam_labels=labels)
        convert_auth_to_parallax(auth_path, builder, output_path)

        events = [json.loads(line) for line in output_path.open()]
        attacker_events = [e for e in events if e["account_id"] == "U999@DOM1"]

        failure_count = sum(1 for e in attacker_events if e["safety_filter_triggered"])
        assert failure_count > 0  # Attacker has auth failures

    def test_attacker_has_bursts(self, tmp_path):
        auth_path, redteam_path = self._make_test_data(tmp_path)
        output_path = tmp_path / "output.jsonl"

        labels = load_redteam(redteam_path)
        builder = LANLProfileBuilder(redteam_labels=labels)
        convert_auth_to_parallax(auth_path, builder, output_path)

        events = [json.loads(line) for line in output_path.open()]
        attacker_events = [e for e in events if e["account_id"] == "U999@DOM1"]

        burst_count = sum(1 for e in attacker_events if e["rate_limit_hit"])
        assert burst_count > 0  # Attacker has burst activity

    def test_sample_users(self, tmp_path):
        auth_path, redteam_path = self._make_test_data(tmp_path)
        output_path = tmp_path / "output.jsonl"

        labels = load_redteam(redteam_path)
        builder = LANLProfileBuilder(redteam_labels=labels)

        stats = convert_auth_to_parallax(
            auth_path, builder, output_path, sample_users=1
        )

        # Should include the 1 compromised user at minimum
        assert stats["users_compromised"] == 1
        # With sample_users=1, we get only the compromised user
        assert stats["users_selected"] == 1

    def test_session_grouping(self, tmp_path):
        """Events >30min apart should get different session IDs."""
        auth_lines = [
            "1000,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
            "1010,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
            # 2-hour gap -> new session
            "8200,U1@DOM1,U2@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
        ]
        auth_path = _write_auth(tmp_path, auth_lines)
        redteam_path = _write_redteam(tmp_path, [])
        output_path = tmp_path / "output.jsonl"

        builder = LANLProfileBuilder(redteam_labels={})
        convert_auth_to_parallax(auth_path, builder, output_path)

        events = [json.loads(line) for line in output_path.open()]
        assert len(events) == 3
        # First two in same session
        assert events[0]["conversation_id"] == events[1]["conversation_id"]
        # Third in different session
        assert events[2]["conversation_id"] != events[0]["conversation_id"]

    def test_output_loadable_by_pipeline(self, tmp_path):
        """Converted output can be loaded by DetectionPipeline."""
        import random
        rng = random.Random(42)

        auth_lines = []
        # Normal user: varied intervals (human-like), multi-destination,
        # multi-topic, mostly success
        for i in range(200):
            t = 1000 + i * rng.randint(15, 120)  # 15s-120s intervals (varied)
            dst = f"C{rng.randint(1, 20)}"  # Many destinations
            auth_type = rng.choice(["Kerberos", "Negotiate", "NTLM"])
            logon = rng.choice(["Network", "Interactive", "RemoteInteractive"])
            auth_lines.append(
                f"{t},U1@DOM1,U2@DOM1,C1,{dst},{auth_type},{logon},LogOn,Success"
            )

        # Attacker: rapid-fire, lateral movement across many hosts,
        # high failure rate, mechanical timing, single auth type
        for i in range(300):
            t = 50000 + i  # 1-second intervals (mechanical)
            fail = "Fail" if i % 2 == 0 else "Success"  # 50% failure rate
            dst = f"C{(i % 50) + 100}"  # Lateral movement: 50 destinations
            auth_lines.append(
                f"{t},U999@DOM1,U999@DOM1,C50,{dst},NTLM,Network,LogOn,{fail}"
            )

        auth_path = _write_auth(tmp_path, auth_lines)
        redteam_lines = ["50000,U999@DOM1,C50,C2"]
        redteam_path = _write_redteam(tmp_path, redteam_lines)
        output_path = tmp_path / "output.jsonl"

        labels = load_redteam(redteam_path)
        builder = LANLProfileBuilder(redteam_labels=labels)
        convert_auth_to_parallax(auth_path, builder, output_path)

        from detection.pipeline import DetectionPipeline

        pipeline = DetectionPipeline()
        pipeline.register_default_detectors()
        pipeline.load_traffic(str(output_path))
        pipeline.score_all()

        assert len(pipeline.assessments) == 2  # 2 users
        assert "U999@DOM1" in pipeline.assessments
        assert "U1@DOM1" in pipeline.assessments

        # Compromised user should score higher than normal
        attacker_score = pipeline.assessments["U999@DOM1"].composite_score
        normal_score = pipeline.assessments["U1@DOM1"].composite_score

        assert attacker_score > normal_score, (
            f"Expected compromised ({attacker_score:.4f}) > "
            f"normal ({normal_score:.4f})"
        )
