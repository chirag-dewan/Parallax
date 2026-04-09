"""Tests for T1-010: Data Transfer Anomaly."""

from datetime import datetime, timedelta, timezone

from detection.tier1.t1_010_data_transfer_anomaly import (
    DataTransferAnomalyDetector,
)
from tests.conftest import make_event, build_profile


class TestDataTransferAnomaly:
    def setup_method(self):
        self.detector = DataTransferAnomalyDetector()

    def test_no_flow_data_zero_score(self):
        """Events without bytes_transferred -> score 0."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                account_id="no_flow",
                timestamp=base + timedelta(seconds=60 * i),
                inter_request_interval_ms=60000 if i > 0 else 0,
                bytes_transferred=0,
            )
            for i in range(50)
        ]
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score == 0.0
        assert result.details["reason"] == "no_flow_data"

    def test_uniform_bytes_low_score(self):
        """Consistent byte transfer across sessions -> low score."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        for i in range(100):
            events.append(
                make_event(
                    account_id="uniform_user",
                    timestamp=base + timedelta(seconds=120 * i),
                    inter_request_interval_ms=120000 if i > 0 else 0,
                    conversation_id=f"conv_{i // 5}",
                    turn_number=i % 5,
                    bytes_transferred=1000,  # uniform
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score < 0.3

    def test_spike_bytes_high_score(self):
        """Normal baseline then a massive byte transfer spike -> high score."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        # 80 events in 16 sessions with ~1000 bytes each
        for i in range(80):
            events.append(
                make_event(
                    account_id="exfil_user",
                    timestamp=base + timedelta(seconds=120 * i),
                    inter_request_interval_ms=120000 if i > 0 else 0,
                    conversation_id=f"conv_{i // 5}",
                    turn_number=i % 5,
                    bytes_transferred=1000,
                )
            )
        # Session 17: massive spike — 50x normal
        for i in range(5):
            events.append(
                make_event(
                    account_id="exfil_user",
                    timestamp=base + timedelta(seconds=120 * (80 + i)),
                    inter_request_interval_ms=120000,
                    conversation_id="conv_exfil",
                    turn_number=i,
                    bytes_transferred=50000,  # 50x spike
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score > 0.5
        assert result.triggered
        assert result.details["method"] == "rolling_zscore"
        assert result.details["peak_z_score"] > 2.0

    def test_gradual_increase_moderate_score(self):
        """Slowly increasing byte transfer -> moderate score."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        for i in range(60):
            # Bytes grow linearly from 500 to 5000
            bx = 500 + int((i / 60) * 4500)
            events.append(
                make_event(
                    account_id="gradual_user",
                    timestamp=base + timedelta(seconds=120 * i),
                    inter_request_interval_ms=120000 if i > 0 else 0,
                    conversation_id=f"conv_{i // 5}",
                    turn_number=i % 5,
                    bytes_transferred=bx,
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        # Gradual increase shouldn't spike z-score as much
        assert result.score < 0.7

    def test_insufficient_flow_events(self):
        """Only 2 events with bytes -> insufficient."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        for i in range(20):
            bx = 5000 if i < 2 else 0
            events.append(
                make_event(
                    account_id="sparse_flow",
                    timestamp=base + timedelta(seconds=120 * i),
                    inter_request_interval_ms=120000 if i > 0 else 0,
                    bytes_transferred=bx,
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score == 0.0
        assert result.details["reason"] == "insufficient_flow_events"

    def test_insufficient_events_min(self):
        """Fewer than min_events -> zero score, zero confidence."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                account_id="tiny",
                timestamp=base + timedelta(seconds=60 * i),
                inter_request_interval_ms=60000 if i > 0 else 0,
                bytes_transferred=5000,
            )
            for i in range(5)
        ]
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.score == 0.0
        assert result.confidence == 0.0

    def test_confidence_scales_with_flow_ratio(self):
        """Confidence should be lower when few events have flow data."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        for i in range(100):
            # Only 10% of events have bytes
            bx = 1000 if i < 10 else 0
            events.append(
                make_event(
                    account_id="partial_flow",
                    timestamp=base + timedelta(seconds=120 * i),
                    inter_request_interval_ms=120000 if i > 0 else 0,
                    conversation_id=f"conv_{i // 5}",
                    turn_number=i % 5,
                    bytes_transferred=bx,
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        # 100 events / 100 = 1.0 base, but flow_ratio = 0.1 -> conf ~0.1
        assert result.confidence < 0.2

    def test_full_flow_data_high_confidence(self):
        """All events have flow data -> full confidence."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                account_id="full_flow",
                timestamp=base + timedelta(seconds=120 * i),
                inter_request_interval_ms=120000 if i > 0 else 0,
                conversation_id=f"conv_{i // 5}",
                turn_number=i % 5,
                bytes_transferred=1000,
            )
            for i in range(200)
        ]
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert result.confidence == 1.0

    def test_details_populated(self):
        """Check diagnostic details are present."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        for i in range(60):
            bx = 1000 if i < 55 else 50000
            events.append(
                make_event(
                    account_id="detail_user",
                    timestamp=base + timedelta(seconds=120 * i),
                    inter_request_interval_ms=120000 if i > 0 else 0,
                    conversation_id=f"conv_{i // 5}",
                    turn_number=i % 5,
                    bytes_transferred=bx,
                )
            )
        profile = build_profile(events)
        result = self.detector.detect(profile)
        assert "peak_z_score" in result.details
        assert "events_with_bytes" in result.details
        assert "total_bytes_transferred" in result.details or "total_bytes" in result.details

    def test_session_bytes_aggregation(self):
        """_compute_session_bytes aggregates correctly per conversation."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                timestamp=base + timedelta(seconds=i * 60),
                conversation_id="s1",
                turn_number=i,
                bytes_transferred=100,
            )
            for i in range(5)
        ] + [
            make_event(
                timestamp=base + timedelta(seconds=(5 + i) * 60),
                conversation_id="s2",
                turn_number=i,
                bytes_transferred=200,
            )
            for i in range(3)
        ]
        result = DataTransferAnomalyDetector._compute_session_bytes(events)
        assert result == [500, 600]  # s1=5*100, s2=3*200
