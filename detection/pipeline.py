"""
PARALLAX Detection Pipeline

Orchestrates event loading, profile building, detection, and scoring.

Supports both batch and async-generator modes:
- Batch: load_traffic / score_all (returns complete results)
- Async: aiter_events / ascore_all (yields results incrementally)
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from collections.abc import AsyncIterator
from pathlib import Path
from statistics import mean

from detection.base import BaseDetector
from detection.baselines import PopulationBaseline
from detection.models import (
    APIEvent,
    AccountProfile,
    DetectionResult,
    RuleID,
    Tier,
    ThreatAssessment,
    ThreatLevel,
)

logger = logging.getLogger("parallax.pipeline")


class DetectionPipeline:
    """Orchestrates the full detection flow."""

    THREAT_THRESHOLDS: dict[ThreatLevel, float] = {
        ThreatLevel.CRITICAL: 0.85,
        ThreatLevel.HIGH: 0.70,
        ThreatLevel.MEDIUM: 0.50,
        ThreatLevel.LOW: 0.25,
        ThreatLevel.NONE: 0.0,
    }

    ESCALATION_THRESHOLD: float = 0.66

    def __init__(self) -> None:
        self._detectors: list[BaseDetector] = []
        self._profiles: dict[str, AccountProfile] = {}
        self._baseline: PopulationBaseline | None = None
        self._assessments: dict[str, ThreatAssessment] = {}

    def register_detector(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)

    def register_default_detectors(self) -> None:
        """Register all 16 detection rules."""
        from detection.tier1 import (
            VolumeAnomalyDetector,
            AutomationSignatureDetector,
            TokenRatioDetector,
            SessionAnomalyDetector,
            ModelTargetingDetector,
            ContextExploitationDetector,
            ErrorPatternDetector,
            ConcurrentSessionsDetector,
            HostFanoutDetector,
            DataTransferAnomalyDetector,
        )
        from detection.tier2 import (
            DistributionDivergenceDetector,
            EntropyAnalysisDetector,
            CrossAccountCorrelationDetector,
            PowerLawDeviationDetector,
            TemporalClusteringDetector,
            BehavioralShiftDetector,
        )

        self._detectors = [
            VolumeAnomalyDetector(),
            AutomationSignatureDetector(),
            TokenRatioDetector(),
            SessionAnomalyDetector(),
            ModelTargetingDetector(),
            ContextExploitationDetector(),
            ErrorPatternDetector(),
            ConcurrentSessionsDetector(),
            HostFanoutDetector(),
            DataTransferAnomalyDetector(),
            DistributionDivergenceDetector(),
            EntropyAnalysisDetector(),
            CrossAccountCorrelationDetector(),
            PowerLawDeviationDetector(),
            TemporalClusteringDetector(),
            BehavioralShiftDetector(),
        ]

        total_weight = sum(d.WEIGHT for d in self._detectors)
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(
                "Detector weights sum to %.3f, expected 1.0", total_weight
            )

    # Explicit auth-profile weights derived from LANL v2 evaluation.
    # Only detectors with positive compromised-vs-normal delta survive.
    # Weights are proportional to measured delta magnitude.
    AUTH_WEIGHTS: dict[RuleID, float] = {
        RuleID.T2_006: 0.30,  # Behavioral Shift   (+0.41 delta)
        RuleID.T1_009: 0.25,  # Host Fan-Out        (+0.12 delta)
        RuleID.T1_008: 0.20,  # Concurrent Sessions (+0.06 delta)
        RuleID.T1_007: 0.15,  # Error Pattern       (+0.04 delta)
        RuleID.T1_004: 0.10,  # Session Anomaly     (+0.04 delta)
    }

    # Auth profile with flow enrichment: T1-010 gets 10% weight,
    # redistributed proportionally from existing detectors.
    AUTH_WEIGHTS_FLOW: dict[RuleID, float] = {
        RuleID.T2_006: 0.27,  # Behavioral Shift
        RuleID.T1_009: 0.22,  # Host Fan-Out
        RuleID.T1_008: 0.18,  # Concurrent Sessions
        RuleID.T1_007: 0.13,  # Error Pattern
        RuleID.T1_004: 0.10,  # Session Anomaly
        RuleID.T1_010: 0.10,  # Data Transfer Anomaly (flow-enriched)
    }

    def apply_auth_profile(self, flow_enriched: bool = False) -> None:
        """Reconfigure weights for auth log data (LANL / AD logs).

        Zeroes detectors that are dead-weight or anti-correlated with
        compromise on auth data.  Sets explicit weights on the 5 (or 6
        with flow enrichment) detectors with positive signal.

        Args:
            flow_enriched: When True, activates T1-010 DataTransferAnomaly
                with weight redistributed from existing detectors.
        """
        weights = self.AUTH_WEIGHTS_FLOW if flow_enriched else self.AUTH_WEIGHTS
        zeroed = 0
        for d in self._detectors:
            if d.RULE_ID in weights:
                d.WEIGHT = weights[d.RULE_ID]
            else:
                d.WEIGHT = 0.0
                zeroed += 1

        logger.info(
            "Auth profile%s: %d detectors active (%.2f total weight), "
            "%d zeroed",
            " (flow-enriched)" if flow_enriched else "",
            len(weights),
            sum(d.WEIGHT for d in self._detectors),
            zeroed,
        )

    # -- Loading --

    def load_traffic(self, filepath: str | Path) -> None:
        """Load JSONL traffic data and build account profiles."""
        filepath = Path(filepath)
        raw_events: dict[str, list[APIEvent]] = defaultdict(list)

        logger.info("Loading traffic from %s", filepath)
        with filepath.open("r") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    event = APIEvent.model_validate_json(line)
                    raw_events[event.account_id].append(event)
                except Exception:
                    logger.warning(
                        "Skipping malformed event at line %d", line_num
                    )

        total_events = sum(len(evts) for evts in raw_events.values())
        logger.info(
            "Loaded %d events across %d accounts",
            total_events,
            len(raw_events),
        )

        for account_id, events in raw_events.items():
            events.sort(key=lambda e: e.timestamp)
            self._profiles[account_id] = self._build_profile(
                account_id, events
            )

        self._baseline = PopulationBaseline.from_profiles(
            list(self._profiles.values())
        )

        for detector in self._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(self._baseline)

    def load_events(self, events: list[dict]) -> None:
        """Load events from in-memory dicts (for Flask integration)."""
        raw_events: dict[str, list[APIEvent]] = defaultdict(list)

        for event_dict in events:
            event = APIEvent.model_validate(event_dict)
            raw_events[event.account_id].append(event)

        for account_id, acct_events in raw_events.items():
            acct_events.sort(key=lambda e: e.timestamp)
            self._profiles[account_id] = self._build_profile(
                account_id, acct_events
            )

        self._baseline = PopulationBaseline.from_profiles(
            list(self._profiles.values())
        )
        for detector in self._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(self._baseline)

    # -- Profile Building --

    @staticmethod
    def _build_profile(
        account_id: str, events: list[APIEvent]
    ) -> AccountProfile:
        """Build AccountProfile from sorted events."""
        timestamps = [e.timestamp for e in events]
        total = len(events)

        # Observation window
        obs_hours = 0.0
        if len(timestamps) >= 2:
            obs_hours = (
                (timestamps[-1] - timestamps[0]).total_seconds() / 3600
            )
        rph = total / obs_hours if obs_hours > 0 else 0.0

        # Intervals (filter out 0s)
        intervals = [
            e.inter_request_interval_ms
            for e in events
            if e.inter_request_interval_ms > 0
        ]

        # Tokens
        input_toks = [e.input_tokens for e in events]
        output_toks = [e.output_tokens for e in events]
        avg_in = mean(input_toks) if input_toks else 0.0
        avg_out = mean(output_toks) if output_toks else 0.0
        tok_ratio = avg_out / avg_in if avg_in > 0 else 0.0

        # Conversations
        convs: dict[str, list[APIEvent]] = defaultdict(list)
        conv_order: list[str] = []
        for e in events:
            if e.conversation_id not in convs:
                conv_order.append(e.conversation_id)
            convs[e.conversation_id].append(e)

        single_turn = sum(1 for evts in convs.values() if len(evts) == 1)
        st_ratio = single_turn / len(convs) if convs else 0.0
        days = obs_hours / 24 if obs_hours > 0 else 1.0
        cpd = len(convs) / max(1.0, days)

        # Sessions
        session_durs = [e.session_duration_hours for e in events]

        # Hours active
        hours_set = {ts.hour for ts in timestamps}
        h_coverage = len(hours_set) / 24

        # Request types
        api_count = sum(1 for e in events if e.request_type == "api")
        web_count = total - api_count
        api_r = api_count / total if total > 0 else 0.0

        # Models
        model_cts: dict[str, int] = defaultdict(int)
        for e in events:
            model_cts[e.model] += 1
        model_rats = {m: c / total for m, c in model_cts.items()}

        # Safety / rate limiting
        safety_ct = sum(1 for e in events if e.safety_filter_triggered)
        rl_ct = sum(1 for e in events if e.rate_limit_hit)
        retry_delays = [
            e.rate_limit_retry_delay_ms
            for e in events
            if e.rate_limit_hit and e.rate_limit_retry_delay_ms > 0
        ]

        # Topics
        topic_cts: dict[str, int] = defaultdict(int)
        for e in events:
            topic_cts[e.topic_category] += 1

        # Flow enrichment
        bytes_list = [e.bytes_transferred for e in events]
        total_bytes = sum(bytes_list)
        avg_bytes = mean(bytes_list) if bytes_list else 0.0
        conn_durs = [e.connection_duration_sec for e in events]
        avg_conn_dur = mean(conn_durs) if conn_durs else 0.0

        return AccountProfile(
            account_id=account_id,
            archetype=events[0].archetype,
            account_age_days=events[0].account_age_days,
            events=events,
            total_events=total,
            timestamps=timestamps,
            inter_request_intervals_ms=intervals,
            observation_hours=obs_hours,
            requests_per_hour=rph,
            input_tokens=input_toks,
            output_tokens=output_toks,
            avg_input_tokens=avg_in,
            avg_output_tokens=avg_out,
            token_ratio=tok_ratio,
            conversation_ids=conv_order,
            conversations=dict(convs),
            total_conversations=len(convs),
            single_turn_count=single_turn,
            single_turn_ratio=st_ratio,
            conversations_per_day=cpd,
            session_durations_hours=session_durs,
            hours_active=hours_set,
            hours_coverage=h_coverage,
            api_request_count=api_count,
            web_request_count=web_count,
            api_ratio=api_r,
            model_counts=dict(model_cts),
            model_ratios=model_rats,
            safety_trigger_count=safety_ct,
            safety_trigger_rate=safety_ct / total if total > 0 else 0.0,
            rate_limit_hit_count=rl_ct,
            rate_limit_hit_rate=rl_ct / total if total > 0 else 0.0,
            rate_limit_retry_delays_ms=retry_delays,
            topic_counts=dict(topic_cts),
            unique_topic_count=len(topic_cts),
            bytes_transferred_list=bytes_list,
            total_bytes_transferred=total_bytes,
            avg_bytes_per_event=avg_bytes,
            connection_durations_sec=conn_durs,
            avg_connection_duration_sec=avg_conn_dur,
        )

    # -- Detection --

    def score_account(self, account_id: str) -> ThreatAssessment:
        """Run all detectors on a single account."""
        profile = self._profiles[account_id]
        results: dict[RuleID, DetectionResult] = {}

        for detector in self._detectors:
            result = detector.detect(profile)
            results[result.rule_id] = result

        return self._build_assessment(profile, results)

    def score_all(self) -> dict[str, ThreatAssessment]:
        """Score all loaded accounts."""
        self._assessments = {}
        for account_id in self._profiles:
            self._assessments[account_id] = self.score_account(account_id)
        return self._assessments

    # -- Composite Scoring --

    def _build_assessment(
        self,
        profile: AccountProfile,
        results: dict[RuleID, DetectionResult],
    ) -> ThreatAssessment:
        weighted_sum = 0.0
        weight_sum = 0.0

        for detector in self._detectors:
            result = results[detector.RULE_ID]
            w = detector.WEIGHT
            weighted_sum += result.score * w * result.confidence
            weight_sum += w

        composite = weighted_sum / weight_sum if weight_sum > 0 else 0.0
        composite = max(0.0, min(1.0, composite))

        # Threat level
        threat_level = ThreatLevel.NONE
        for level, threshold in self.THREAT_THRESHOLDS.items():
            if composite >= threshold:
                threat_level = level
                break

        # Tier counts
        t1_triggered = sum(
            1
            for r in results.values()
            if r.tier == Tier.TIER_1 and r.triggered
        )
        t2_triggered = sum(
            1
            for r in results.values()
            if r.tier == Tier.TIER_2 and r.triggered
        )

        # Top signals
        signal_scores: list[tuple[RuleID, float]] = []
        for detector in self._detectors:
            r = results[detector.RULE_ID]
            signal_scores.append((r.rule_id, r.score * detector.WEIGHT))
        signal_scores.sort(key=lambda x: x[1], reverse=True)

        return ThreatAssessment(
            account_id=profile.account_id,
            archetype=profile.archetype,
            results=results,
            composite_score=round(composite, 4),
            threat_level=threat_level,
            escalation_recommended=composite > self.ESCALATION_THRESHOLD,
            tier1_triggered_count=t1_triggered,
            tier2_triggered_count=t2_triggered,
            total_triggered_count=t1_triggered + t2_triggered,
            top_signals=signal_scores[:5],
        )

    # -- Windowed Scoring --

    def score_account_windowed(
        self,
        account_id: str,
        window_hours: float = 4.0,
        stride_hours: float = 1.0,
    ) -> ThreatAssessment:
        """Score an account using sliding time windows.

        Builds a temporary AccountProfile for each window, runs all
        detectors, and returns the assessment with the highest composite
        score across all windows.
        """
        from datetime import timedelta

        profile = self._profiles[account_id]
        events = profile.events

        if len(events) < 2:
            return self.score_account(account_id)

        start_ts = events[0].timestamp
        end_ts = events[-1].timestamp
        span = (end_ts - start_ts).total_seconds()
        window_secs = window_hours * 3600
        stride_secs = stride_hours * 3600

        # If observation window is shorter than one window, fall back
        if span <= window_secs:
            return self.score_account(account_id)

        best_assessment: ThreatAssessment | None = None
        best_score = -1.0
        window_count = 0
        best_window_start = start_ts
        best_window_end = end_ts

        w_start = start_ts
        while w_start + timedelta(seconds=window_secs) <= end_ts + timedelta(seconds=stride_secs):
            w_end = w_start + timedelta(seconds=window_secs)

            # Collect events in this window
            window_events = [
                e for e in events
                if w_start <= e.timestamp < w_end
            ]

            if len(window_events) >= 2:
                window_profile = self._build_profile(
                    account_id, window_events
                )
                results: dict[RuleID, DetectionResult] = {}
                for detector in self._detectors:
                    results[detector.RULE_ID] = detector.detect(window_profile)

                assessment = self._build_assessment(window_profile, results)
                window_count += 1

                if assessment.composite_score > best_score:
                    best_score = assessment.composite_score
                    best_assessment = assessment
                    best_window_start = w_start
                    best_window_end = w_end

            w_start += timedelta(seconds=stride_secs)

        if best_assessment is None:
            return self.score_account(account_id)

        # Annotate with window metadata
        best_assessment.peak_window_start = best_window_start.isoformat()
        best_assessment.peak_window_end = best_window_end.isoformat()
        best_assessment.windows_evaluated = window_count

        return best_assessment

    def score_all_windowed(
        self,
        window_hours: float = 4.0,
        stride_hours: float = 1.0,
    ) -> dict[str, ThreatAssessment]:
        """Run windowed scoring on all loaded accounts."""
        self._assessments = {}
        total = len(self._profiles)
        for i, account_id in enumerate(self._profiles, 1):
            if i % 50 == 0:
                logger.info(
                    "Windowed scoring: %d/%d accounts", i, total
                )
            self._assessments[account_id] = self.score_account_windowed(
                account_id,
                window_hours=window_hours,
                stride_hours=stride_hours,
            )
        return self._assessments

    # -- Async Generator Interface --

    async def aiter_events(
        self, filepath: str | Path
    ) -> AsyncIterator[APIEvent]:
        """Yield parsed APIEvent objects one at a time from a JSONL file.

        Runs file I/O in a thread to avoid blocking the event loop.
        """
        filepath = Path(filepath)

        def _read_lines() -> list[str]:
            with filepath.open("r") as f:
                return f.readlines()

        lines = await asyncio.to_thread(_read_lines)
        for line_num, line in enumerate(lines, 1):
            try:
                yield APIEvent.model_validate_json(line)
            except Exception:
                logger.warning(
                    "Skipping malformed event at line %d", line_num
                )

    async def aload_traffic(self, filepath: str | Path) -> None:
        """Async variant of load_traffic.

        Streams events through an async generator, builds profiles
        incrementally, then computes baselines.
        """
        raw_events: dict[str, list[APIEvent]] = defaultdict(list)
        event_count = 0

        async for event in self.aiter_events(filepath):
            raw_events[event.account_id].append(event)
            event_count += 1

        logger.info(
            "Loaded %d events across %d accounts",
            event_count,
            len(raw_events),
        )

        for account_id, events in raw_events.items():
            events.sort(key=lambda e: e.timestamp)
            self._profiles[account_id] = self._build_profile(
                account_id, events
            )

        self._baseline = PopulationBaseline.from_profiles(
            list(self._profiles.values())
        )

        for detector in self._detectors:
            if detector.TIER == Tier.TIER_2:
                detector.set_population_baseline(self._baseline)

    async def ascore_all(self) -> AsyncIterator[ThreatAssessment]:
        """Yield ThreatAssessment for each account incrementally.

        Stores results in self._assessments as a side effect.
        """
        for account_id in self._profiles:
            assessment = self.score_account(account_id)
            self._assessments[account_id] = assessment
            yield assessment

    # -- Accessors --

    @property
    def profiles(self) -> dict[str, AccountProfile]:
        return self._profiles

    @property
    def assessments(self) -> dict[str, ThreatAssessment]:
        return self._assessments

    @property
    def baseline(self) -> PopulationBaseline | None:
        return self._baseline

    @property
    def detectors(self) -> list[BaseDetector]:
        return self._detectors
