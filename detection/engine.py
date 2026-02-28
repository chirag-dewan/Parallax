#!/usr/bin/env python3
"""
PARALLAX Scoring Engine
Calculates weighted threat scores from behavioral signals
"""

import json
import sys
from dataclasses import dataclass
from collections import defaultdict
from statistics import mean, stdev
from typing import List, Dict, Any


@dataclass
class ThreatScore:
    """Threat scoring breakdown for an account"""
    account_id: str
    archetype: str  # Ground truth for validation

    # Tier 1 signals
    velocity_score: float
    timing_regularity: float
    account_risk: float

    # Tier 2 signals
    conversation_pattern: float
    activity_window: float
    rate_limit_behavior: float

    # Tier 3 signals
    token_ratio: float
    safety_trigger_rate: float
    topic_entropy: float

    # Composite
    composite_score: float
    current_tier: int
    escalation_recommended: bool


class ScoringEngine:
    """
    Behavioral threat scoring engine
    Implements five-tier escalation framework
    """

    # Signal weights
    WEIGHTS = {
        'timing_regularity': 0.20,
        'velocity_score': 0.15,
        'token_ratio': 0.15,
        'account_risk': 0.10,
        'conversation_pattern': 0.10,
        'rate_limit_behavior': 0.10,
        'safety_trigger_rate': 0.08,
        'topic_entropy': 0.07,
        'activity_window': 0.05
    }

    # Tier thresholds
    TIER1_VELOCITY = 100  # requests/hour
    TIER1_TIMING_CV = 0.3  # coefficient of variation
    TIER1_ACCOUNT_RISK = 0.7  # normalized score

    TIER2_THRESHOLD = 0.5  # signal must be > 0.5
    TIER3_THRESHOLD = 0.5

    ESCALATION_THRESHOLD = 0.66

    def __init__(self):
        self.accounts = defaultdict(list)
        self.baselines = {}

    def load_traffic(self, filepath: str):
        """Load traffic data from JSON lines file"""
        print(f"[+] Loading traffic from {filepath}...")

        with open(filepath, 'r') as f:
            for line in f:
                event = json.loads(line)
                self.accounts[event['account_id']].append(event)

        print(f"[+] Loaded {sum(len(events) for events in self.accounts.values()):,} events")
        print(f"[+] Across {len(self.accounts)} accounts\n")

        self._calculate_baselines()

    def _calculate_baselines(self):
        """Calculate baseline metrics from normal users"""
        normal_velocities = []

        for account_id, events in self.accounts.items():
            if events[0]['archetype'] == 'normal_user':
                # Calculate requests per hour
                if len(events) > 1:
                    first = events[0]['timestamp']
                    last = events[-1]['timestamp']
                    from datetime import datetime
                    start = datetime.fromisoformat(first.replace('Z', '+00:00'))
                    end = datetime.fromisoformat(last.replace('Z', '+00:00'))
                    hours = (end - start).total_seconds() / 3600
                    if hours > 0:
                        velocity = len(events) / hours
                        normal_velocities.append(velocity)

        self.baselines['normal_velocity'] = mean(normal_velocities) if normal_velocities else 10
        print(f"[+] Baseline normal velocity: {self.baselines['normal_velocity']:.2f} req/hr\n")

    def score_account(self, account_id: str) -> ThreatScore:
        """Calculate threat score for an account"""
        events = self.accounts[account_id]

        # Tier 1 signals
        velocity = self._calculate_velocity(events)
        timing_reg = self._calculate_timing_regularity(events)
        acct_risk = self._calculate_account_risk(events)

        # Tier 2 signals
        conv_pattern = self._calculate_conversation_pattern(events)
        activity_win = self._calculate_activity_window(events)
        rate_limit_behavior = self._calculate_rate_limit_behavior(events)

        # Tier 3 signals
        token_ratio = self._calculate_token_ratio(events)
        safety_rate = self._calculate_safety_trigger_rate(events)
        topic_ent = self._calculate_topic_entropy(events)

        # Calculate composite score
        composite = (
            self.WEIGHTS['timing_regularity'] * timing_reg +
            self.WEIGHTS['velocity_score'] * velocity +
            self.WEIGHTS['token_ratio'] * token_ratio +
            self.WEIGHTS['account_risk'] * acct_risk +
            self.WEIGHTS['conversation_pattern'] * conv_pattern +
            self.WEIGHTS['rate_limit_behavior'] * rate_limit_behavior +
            self.WEIGHTS['safety_trigger_rate'] * safety_rate +
            self.WEIGHTS['topic_entropy'] * topic_ent +
            self.WEIGHTS['activity_window'] * activity_win
        )

        # Determine tier
        tier = self._assign_tier(velocity, timing_reg, acct_risk,
                                conv_pattern, activity_win, rate_limit_behavior,
                                token_ratio, safety_rate, topic_ent)

        escalation = composite > self.ESCALATION_THRESHOLD

        return ThreatScore(
            account_id=account_id,
            archetype=events[0]['archetype'],
            velocity_score=velocity,
            timing_regularity=timing_reg,
            account_risk=acct_risk,
            conversation_pattern=conv_pattern,
            activity_window=activity_win,
            rate_limit_behavior=rate_limit_behavior,
            token_ratio=token_ratio,
            safety_trigger_rate=safety_rate,
            topic_entropy=topic_ent,
            composite_score=composite,
            current_tier=tier,
            escalation_recommended=escalation
        )

    def _calculate_velocity(self, events: List[Dict]) -> float:
        """Requests per hour normalized against baseline"""
        if len(events) < 2:
            return 0.0

        from datetime import datetime
        first = datetime.fromisoformat(events[0]['timestamp'].replace('Z', '+00:00'))
        last = datetime.fromisoformat(events[-1]['timestamp'].replace('Z', '+00:00'))
        hours = (last - first).total_seconds() / 3600

        if hours == 0:
            return 0.0

        velocity = len(events) / hours
        baseline = self.baselines.get('normal_velocity', 10)

        # Normalize: velocity / baseline, capped at 1.0
        normalized = min(1.0, velocity / (baseline * 10))
        return normalized

    def _calculate_timing_regularity(self, events: List[Dict]) -> float:
        """Low variance = mechanical (high score)"""
        intervals = [e['inter_request_interval_ms'] for e in events if e['inter_request_interval_ms'] > 0]

        if len(intervals) < 2:
            return 0.0

        avg = mean(intervals)
        std = stdev(intervals)

        if avg == 0 or std == 0:
            # Zero variance = perfectly mechanical = max score
            return 1.0 if std == 0 and avg > 0 else 0.0

        cv = std / avg  # coefficient of variation

        # Low CV = mechanical = high score
        # CV < 0.3 is suspicious, normalize it
        if cv < 0.3:
            score = 1.0 - (cv / 0.3)  # Lower CV = higher score
        else:
            score = 0.0  # High CV (human variance) = low threat

        return min(1.0, score)

    def _calculate_account_risk(self, events: List[Dict]) -> float:
        """Account age vs usage volume ratio"""
        account_age = events[0]['account_age_days']
        total_events = len(events)

        # Expected events per day for normal user: ~10
        expected_events = account_age * 10

        if expected_events == 0:
            return 1.0

        # Ratio of actual to expected
        ratio = total_events / expected_events

        # High ratio = suspicious
        normalized = min(1.0, ratio / 10)  # 10x normal usage = max score
        return normalized

    def _calculate_conversation_pattern(self, events: List[Dict]) -> float:
        """Single-turn ratio + conversations per day"""
        conversations = {}

        for event in events:
            conv_id = event['conversation_id']
            if conv_id not in conversations:
                conversations[conv_id] = []
            conversations[conv_id].append(event)

        # Single-turn ratio
        single_turn_count = sum(1 for turns in conversations.values() if len(turns) == 1)
        single_turn_ratio = single_turn_count / len(conversations) if conversations else 0

        # Conversations per day
        from datetime import datetime
        if len(events) > 1:
            first = datetime.fromisoformat(events[0]['timestamp'].replace('Z', '+00:00'))
            last = datetime.fromisoformat(events[-1]['timestamp'].replace('Z', '+00:00'))
            days = (last - first).total_seconds() / 86400
            convs_per_day = len(conversations) / max(1, days)
        else:
            convs_per_day = 0

        # High single-turn ratio + high conv/day = suspicious
        score = (single_turn_ratio * 0.7) + min(1.0, convs_per_day / 100) * 0.3
        return min(1.0, score)

    def _calculate_activity_window(self, events: List[Dict]) -> float:
        """Hours active per day + timing consistency"""
        from datetime import datetime

        if len(events) < 10:
            return 0.0

        # Group by hour of day
        hours_active = set()
        for event in events:
            dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            hours_active.add(dt.hour)

        # 24/7 operation = suspicious
        hours_coverage = len(hours_active) / 24

        # If active > 20 hours/day = high score
        if hours_coverage > 0.8:
            return hours_coverage
        else:
            return 0.0

    def _calculate_rate_limit_behavior(self, events: List[Dict]) -> float:
        """Mechanical retry patterns"""
        retry_delays = [e['rate_limit_retry_delay_ms'] for e in events
                       if e['rate_limit_hit'] and e['rate_limit_retry_delay_ms'] > 0]

        if len(retry_delays) < 2:
            return 0.0

        avg = mean(retry_delays)
        std = stdev(retry_delays)

        if avg == 0:
            return 0.0

        cv = std / avg

        # Low CV on retries = mechanical
        if cv < 0.3:
            score = 1.0 - (cv / 0.3)
        else:
            score = 0.0

        return min(1.0, score)

    def _calculate_token_ratio(self, events: List[Dict]) -> float:
        """Short input, max output = distillation"""
        avg_input = mean(e['input_tokens'] for e in events)
        avg_output = mean(e['output_tokens'] for e in events)

        if avg_input == 0:
            return 0.0

        ratio = avg_output / avg_input

        # Ratio > 30 is suspicious
        if ratio > 30:
            normalized = min(1.0, ratio / 100)
        else:
            normalized = 0.0

        return normalized

    def _calculate_safety_trigger_rate(self, events: List[Dict]) -> float:
        """High safety filter trigger rate"""
        total = len(events)
        triggers = sum(1 for e in events if e['safety_filter_triggered'])

        rate = triggers / total if total > 0 else 0

        # > 8% is suspicious
        if rate > 0.08:
            normalized = min(1.0, rate / 0.2)
        else:
            normalized = 0.0

        return normalized

    def _calculate_topic_entropy(self, events: List[Dict]) -> float:
        """Low topic diversity = systematic sweeping (high score)"""
        topics = [e['topic_category'] for e in events]
        unique_count = len(set(topics))

        if len(topics) == 0:
            return 0.0

        # Use unique topic COUNT, not ratio
        # Attackers: 2-4 unique topics (systematic sweeping)
        # Normal users: 5-8+ unique topics (random browsing)

        if unique_count <= 3:
            # Very low diversity (systematic) = max threat
            score = 1.0
        elif unique_count <= 5:
            # Low-medium diversity = scaled threat
            # 4-5 topics maps to 0.5-0.0
            score = (5 - unique_count) / 2.0
        else:
            # High diversity (random) = no threat
            score = 0.0

        return min(1.0, max(0.0, score))

    def _assign_tier(self, velocity, timing, acct_risk,
                    conv_pattern, activity, rate_limit,
                    token_ratio, safety, topic_ent) -> int:
        """Assign tier based on signal thresholds"""

        # Tier 1: Any Tier 1 signal above threshold
        tier1_triggered = (
            velocity > 0.5 or
            timing > 0.7 or
            acct_risk > self.TIER1_ACCOUNT_RISK
        )

        if not tier1_triggered:
            return 0  # No threat

        # Tier 2: Tier 1 + any two Tier 2 signals
        tier2_signals = [
            conv_pattern > self.TIER2_THRESHOLD,
            activity > self.TIER2_THRESHOLD,
            rate_limit > self.TIER2_THRESHOLD
        ]
        tier2_triggered = sum(tier2_signals) >= 2

        if not tier2_triggered:
            return 1

        # Tier 3: Tier 2 + any Tier 3 signal
        tier3_signals = [
            token_ratio > self.TIER3_THRESHOLD,
            safety > self.TIER3_THRESHOLD,
            topic_ent > self.TIER3_THRESHOLD
        ]
        tier3_triggered = any(tier3_signals)

        if tier3_triggered:
            return 3
        else:
            return 2


def main():
    if len(sys.argv) != 2:
        print("Usage: python engine.py <traffic.jsonl>")
        sys.exit(1)

    engine = ScoringEngine()
    engine.load_traffic(sys.argv[1])

    # Score all accounts
    scores = []
    for account_id in engine.accounts.keys():
        score = engine.score_account(account_id)
        scores.append(score)

    # Sort by composite score (highest first)
    scores.sort(key=lambda s: s.composite_score, reverse=True)

    print("="*120)
    print("PARALLAX THREAT SCORING RESULTS")
    print("="*120)
    print(f"{'Account ID':<20} {'Type':<20} {'Tier':<6} {'Score':<8} {'Escal':<6} {'Key Signals':<40}")
    print("-"*120)

    for score in scores:
        # Identify top signals
        signals = []
        if score.timing_regularity > 0.5:
            signals.append(f"Timing:{score.timing_regularity:.2f}")
        if score.token_ratio > 0.5:
            signals.append(f"Tokens:{score.token_ratio:.2f}")
        if score.velocity_score > 0.5:
            signals.append(f"Velocity:{score.velocity_score:.2f}")
        if score.safety_trigger_rate > 0.5:
            signals.append(f"Safety:{score.safety_trigger_rate:.2f}")
        if score.topic_entropy > 0.5:
            signals.append(f"Topics:{score.topic_entropy:.2f}")

        signals_str = ", ".join(signals[:3]) if signals else "None"

        print(f"{score.account_id:<20} {score.archetype:<20} {score.current_tier:<6} "
              f"{score.composite_score:<8.3f} {'YES' if score.escalation_recommended else 'NO':<6} "
              f"{signals_str:<40}")

    print("="*120)

    # Summary stats
    by_archetype = defaultdict(list)
    for score in scores:
        by_archetype[score.archetype].append(score.composite_score)

    print("\nSUMMARY BY ARCHETYPE:")
    for archetype, composite_scores in by_archetype.items():
        avg = mean(composite_scores)
        escalated = sum(1 for s in scores if s.archetype == archetype and s.escalation_recommended)
        print(f"  {archetype:<20} Avg Score: {avg:.3f}  Escalated: {escalated}/{len(composite_scores)}")

    print("\n" + "="*120)


if __name__ == '__main__':
    main()
