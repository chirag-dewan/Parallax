"""
PARALLAX Detection Pipeline

Orchestrates event loading, profile building, detection, and scoring.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
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
        """Register all 14 detection rules."""
        from detection.tier1 import (
            VolumeAnomalyDetector,
            AutomationSignatureDetector,
            TokenRatioDetector,
            SessionAnomalyDetector,
            ModelTargetingDetector,
            ContextExploitationDetector,
            ErrorPatternDetector,
            ConcurrentSessionsDetector,
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
