#!/usr/bin/env python3
"""
Realistic API Session Traffic Generator

Generates synthetic traffic logs for three user archetypes:
- Normal Users: Casual API consumers with varied patterns
- Power Developers: Heavy legitimate API users with consistent patterns
- Attackers: Malicious actors exhibiting suspicious behavior

Output: JSON Lines format with realistic noise and variance
"""

import argparse
import json
import random
import sys
import math
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import List, Dict, Any
from enum import Enum


class UserArchetype(Enum):
    NORMAL = "normal_user"
    POWER_DEV = "power_developer"
    ATTACKER = "attacker"


class TopicCategory(Enum):
    CODING = "coding"
    WRITING = "writing"
    ANALYSIS = "analysis"
    CREATIVE = "creative"
    RESEARCH = "research"
    TRANSLATION = "translation"
    EXTRACTION = "extraction"
    JAILBREAK = "jailbreak"
    SCRAPING = "scraping"


@dataclass
class APIEvent:
    """Single API request event"""
    timestamp: str
    account_id: str
    archetype: str
    account_age_days: int
    request_type: str  # "api" or "web"
    inter_request_interval_ms: int
    input_tokens: int
    output_tokens: int
    conversation_id: str
    turn_number: int
    session_duration_hours: float
    topic_category: str
    safety_filter_triggered: bool
    rate_limit_hit: bool
    rate_limit_retry_delay_ms: int
    response_time_ms: int
    http_status: int
    model: str

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(asdict(self))


class UserProfile:
    """Defines behavioral parameters for a user archetype"""

    def __init__(self, archetype: UserArchetype, account_id: str):
        self.archetype = archetype
        self.account_id = account_id
        self.current_conversation_id = None
        self.current_turn = 0
        self.session_start_time = None
        self.requests_made_today = 0
        self.rate_limits_hit_today = 0
        self.last_request_time = None

        # Set archetype-specific parameters with noise
        if archetype == UserArchetype.NORMAL:
            self.account_age_days = random.randint(30, 365)
            self.requests_per_hour_base = random.uniform(2, 15)
            self.inter_request_interval_range = (5000, 120000)
            self.inter_request_variance = 0.8  # High variance
            self.input_tokens_range = (50, 500)
            self.output_tokens_range = (100, 2000)
            self.conversations_per_day = random.randint(2, 8)
            self.turns_per_conversation_range = (3, 20)
            self.session_duration_range = (1, 4)
            self.safety_filter_rate = random.uniform(0.01, 0.03)
            self.rate_limit_hits_per_day = random.randint(0, 2)
            self.api_probability = 0.3  # 70% web
            self.topic_entropy = "high"

        elif archetype == UserArchetype.POWER_DEV:
            self.account_age_days = random.randint(30, 730)
            self.requests_per_hour_base = random.uniform(30, 100)
            self.inter_request_interval_range = (2000, 30000)
            self.inter_request_variance = 0.5  # Medium variance
            self.input_tokens_range = (100, 800)
            self.output_tokens_range = (200, 3000)
            self.conversations_per_day = random.randint(10, 40)
            self.turns_per_conversation_range = (5, 30)
            self.session_duration_range = (4, 12)
            self.safety_filter_rate = random.uniform(0.02, 0.05)
            self.rate_limit_hits_per_day = random.randint(2, 10)
            self.rate_limit_retry_variance = (2000, 10000)
            self.api_probability = 0.9  # 90% API
            self.topic_entropy = "medium"

        else:  # ATTACKER
            self.account_age_days = random.randint(1, 30)
            self.requests_per_hour_base = random.uniform(150, 500)
            self.inter_request_interval_range = (800, 1500)
            self.inter_request_variance = 0.15  # Low variance (mechanical)
            self.input_tokens_range = (20, 80)
            self.output_tokens_range = (3500, 4096)  # Max out tokens
            self.conversations_per_day = random.randint(80, 300)
            self.turns_per_conversation_range = (1, 1)  # Single-turn
            self.session_duration_range = (20, 24)
            self.safety_filter_rate = random.uniform(0.08, 0.20)
            self.rate_limit_hits_per_day = random.randint(20, 80)
            self.rate_limit_retry_variance = (50, 200)  # Very mechanical
            self.api_probability = 1.0  # 100% API
            self.topic_entropy = "low"

            # Attackers add more noise to avoid perfect detection
            # Randomize some parameters slightly
            self.noise_factor = random.uniform(0.9, 1.1)

    def get_inter_request_interval(self) -> int:
        """Calculate next request interval with realistic variance"""
        min_ms, max_ms = self.inter_request_interval_range

        if self.archetype == UserArchetype.NORMAL:
            # Normal users: high variance (CV ~0.4-0.8)
            # Base ~120s but heavily randomized (30s to 5min range)
            mean = 120000  # 2 minutes
            std = 50000    # Large variance
            interval = random.gauss(mean, std)
            return int(max(5000, min(300000, interval)))  # Clamp to 5s-5min

        elif self.archetype == UserArchetype.POWER_DEV:
            # Power developers: moderate variance (CV ~0.3-0.5)
            # Base ~30s, moderate randomization
            mean = 30000   # 30 seconds
            std = 12000    # Moderate variance
            interval = random.gauss(mean, std)
            return int(max(2000, min(120000, interval)))  # Clamp to 2s-2min

        else:  # ATTACKER
            # Attackers: low variance (CV ~0.15-0.25)
            # Mechanical but not perfectly robotic
            mean = 1100    # ~1 second
            std = 250      # Tiny variance
            interval = random.gauss(mean, std)
            return int(max(500, min(2000, interval)))  # Clamp to 0.5s-2s

    def get_topic_category(self) -> str:
        """Select topic based on entropy level"""
        if self.archetype == UserArchetype.ATTACKER:
            # Low entropy: sequential sweep through categories
            if not hasattr(self, '_topic_sequence'):
                self._topic_sequence = 0

            attack_topics = [TopicCategory.EXTRACTION, TopicCategory.JAILBREAK,
                           TopicCategory.SCRAPING, TopicCategory.EXTRACTION]
            topic = attack_topics[self._topic_sequence % len(attack_topics)]
            self._topic_sequence += 1
            return topic.value

        elif self.archetype == UserArchetype.POWER_DEV:
            # Medium entropy: clustered around common dev topics
            dev_topics = [TopicCategory.CODING, TopicCategory.ANALYSIS,
                         TopicCategory.RESEARCH, TopicCategory.WRITING]
            weights = [0.4, 0.3, 0.2, 0.1]
            return random.choices(dev_topics, weights=weights)[0].value

        else:  # NORMAL
            # High entropy: truly random
            all_topics = [t for t in TopicCategory if t not in
                         [TopicCategory.JAILBREAK, TopicCategory.SCRAPING]]
            return random.choice(all_topics).value

    def start_new_conversation(self, timestamp: datetime) -> str:
        """Start a new conversation session"""
        self.current_conversation_id = f"conv_{self.account_id}_{timestamp.timestamp()}"
        self.current_turn = 0
        self.session_start_time = timestamp
        return self.current_conversation_id

    def should_trigger_safety_filter(self) -> bool:
        """Determine if safety filter triggers"""
        return random.random() < self.safety_filter_rate

    def should_hit_rate_limit(self) -> bool:
        """Determine if request hits rate limit"""
        if self.rate_limits_hit_today >= self.rate_limit_hits_per_day:
            return False

        # Probability increases as we approach daily limit
        prob = (self.rate_limits_hit_today + 1) / max(1, self.rate_limit_hits_per_day)
        if random.random() < prob * 0.1:  # 10% base probability
            self.rate_limits_hit_today += 1
            return True
        return False

    def get_rate_limit_retry_delay(self) -> int:
        """Get retry delay after rate limit hit"""
        if self.archetype == UserArchetype.ATTACKER:
            # Very mechanical retries
            min_ms, max_ms = self.rate_limit_retry_variance
            return random.randint(min_ms, max_ms)
        elif self.archetype == UserArchetype.POWER_DEV:
            # Moderate variance with exponential backoff simulation
            min_ms, max_ms = self.rate_limit_retry_variance
            base = random.uniform(min_ms, max_ms)
            return int(base * random.uniform(1.0, 2.0))  # Some backoff
        else:
            # Normal users don't typically retry immediately
            return 0


class TrafficGenerator:
    """Generates realistic API traffic for multiple user archetypes"""

    def __init__(self,
                 num_normal: int = 50,
                 num_power: int = 15,
                 num_attackers: int = 10):
        self.users: List[UserProfile] = []

        # Create user profiles
        for i in range(num_normal):
            self.users.append(UserProfile(UserArchetype.NORMAL, f"normal_{i:04d}"))

        for i in range(num_power):
            self.users.append(UserProfile(UserArchetype.POWER_DEV, f"power_{i:04d}"))

        for i in range(num_attackers):
            self.users.append(UserProfile(UserArchetype.ATTACKER, f"attacker_{i:04d}"))

        print(f"[+] Initialized {len(self.users)} user profiles:", file=sys.stderr)
        print(f"    - {num_normal} normal users", file=sys.stderr)
        print(f"    - {num_power} power developers", file=sys.stderr)
        print(f"    - {num_attackers} attackers", file=sys.stderr)

    def generate_traffic(self, hours: int, output_file: str):
        """Generate traffic for specified duration"""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        end_time = datetime.utcnow()

        events: List[APIEvent] = []

        print(f"[+] Generating {hours} hours of traffic...", file=sys.stderr)
        print(f"    Start: {start_time}", file=sys.stderr)
        print(f"    End: {end_time}", file=sys.stderr)

        # Generate events for each user
        for user in self.users:
            user_events = self._generate_user_traffic(user, start_time, end_time)
            events.extend(user_events)

        # Sort events by timestamp
        events.sort(key=lambda e: e.timestamp)

        print(f"[+] Generated {len(events):,} total events", file=sys.stderr)

        # Write to file
        with open(output_file, 'w') as f:
            for event in events:
                f.write(event.to_json() + '\n')

        print(f"[+] Saved to {output_file}", file=sys.stderr)

        # Print statistics
        self._print_statistics(events)

    def _generate_user_traffic(self, user: UserProfile, start_time: datetime, end_time: datetime) -> List[APIEvent]:
        """Generate traffic for a single user"""
        events = []
        current_time = start_time + timedelta(hours=random.uniform(0, 2))  # Stagger start

        current_conversation_id = None
        current_turn = 0
        max_turns = 0
        next_interval_ms = 0  # Track interval to next event

        while current_time < end_time:
            # Check if we need a new conversation
            if current_conversation_id is None or current_turn >= max_turns:
                current_conversation_id = user.start_new_conversation(current_time)
                current_turn = 0
                max_turns = random.randint(*user.turns_per_conversation_range)

            # Generate event with the interval
            event = self._create_event(user, current_time, current_conversation_id, current_turn, next_interval_ms)
            events.append(event)

            # Update state
            current_turn += 1
            user.requests_made_today += 1

            # Calculate NEXT request time and interval
            next_interval_ms = user.get_inter_request_interval()
            current_time += timedelta(milliseconds=next_interval_ms)

            # Reset daily counters at midnight
            if current_time.hour == 0 and current_time.minute < 5:
                user.requests_made_today = 0
                user.rate_limits_hit_today = 0

            # Simulate session breaks for normal/power users
            if user.archetype != UserArchetype.ATTACKER:
                if random.random() < 0.05:  # 5% chance of break
                    break_duration = random.uniform(0.5, 3.0)  # 30min - 3hr break
                    current_time += timedelta(hours=break_duration)
                    current_conversation_id = None  # Force new conversation after break

        return events

    def _create_event(self, user: UserProfile, timestamp: datetime,
                     conversation_id: str, turn: int, interval_ms: int) -> APIEvent:
        """Create a single API event"""

        # Determine request type
        is_api = random.random() < user.api_probability

        # Generate token counts with realistic distribution (using triangular distribution)
        min_in, max_in = user.input_tokens_range
        input_tokens = int(random.triangular(min_in, max_in, (min_in + max_in) / 2))

        min_out, max_out = user.output_tokens_range
        output_tokens = int(random.triangular(min_out, max_out, (min_out + max_out) / 2))

        # Safety filter and rate limiting
        safety_triggered = user.should_trigger_safety_filter()
        rate_limit_hit = user.should_hit_rate_limit()

        # HTTP status based on safety/rate limit
        if rate_limit_hit:
            http_status = 429
        elif safety_triggered:
            http_status = 400
        else:
            http_status = 200

        # Response time (faster for attackers using API)
        if user.archetype == UserArchetype.ATTACKER:
            response_time = random.randint(100, 500)
        elif is_api:
            response_time = random.randint(200, 2000)
        else:
            response_time = random.randint(500, 5000)

        # Session duration
        if user.session_start_time:
            session_duration = (timestamp - user.session_start_time).total_seconds() / 3600
        else:
            session_duration = 0

        # Model selection (attackers prefer faster models)
        if user.archetype == UserArchetype.ATTACKER:
            model = random.choice(["gpt-3.5-turbo", "claude-instant", "claude-haiku"])
        else:
            model = random.choice(["gpt-4", "claude-3-sonnet", "claude-3-opus", "gpt-3.5-turbo"])

        return APIEvent(
            timestamp=timestamp.isoformat() + 'Z',
            account_id=user.account_id,
            archetype=user.archetype.value,
            account_age_days=user.account_age_days,
            request_type="api" if is_api else "web",
            inter_request_interval_ms=int(interval_ms),
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
            conversation_id=conversation_id,
            turn_number=turn,
            session_duration_hours=round(session_duration, 2),
            topic_category=user.get_topic_category(),
            safety_filter_triggered=safety_triggered,
            rate_limit_hit=rate_limit_hit,
            rate_limit_retry_delay_ms=user.get_rate_limit_retry_delay() if rate_limit_hit else 0,
            response_time_ms=response_time,
            http_status=http_status,
            model=model
        )

    def _print_statistics(self, events: List[APIEvent]):
        """Print traffic statistics"""
        print("\n" + "="*60, file=sys.stderr)
        print("TRAFFIC STATISTICS", file=sys.stderr)
        print("="*60, file=sys.stderr)

        by_archetype = {}
        for event in events:
            arch = event.archetype
            if arch not in by_archetype:
                by_archetype[arch] = {
                    'count': 0,
                    'safety_triggers': 0,
                    'rate_limits': 0,
                    'api_requests': 0,
                    'total_input_tokens': 0,
                    'total_output_tokens': 0
                }

            by_archetype[arch]['count'] += 1
            if event.safety_filter_triggered:
                by_archetype[arch]['safety_triggers'] += 1
            if event.rate_limit_hit:
                by_archetype[arch]['rate_limits'] += 1
            if event.request_type == 'api':
                by_archetype[arch]['api_requests'] += 1
            by_archetype[arch]['total_input_tokens'] += event.input_tokens
            by_archetype[arch]['total_output_tokens'] += event.output_tokens

        for arch, stats in by_archetype.items():
            print(f"\n{arch.upper()}:", file=sys.stderr)
            print(f"  Total requests: {stats['count']:,}", file=sys.stderr)
            print(f"  Safety triggers: {stats['safety_triggers']} ({100*stats['safety_triggers']/stats['count']:.2f}%)", file=sys.stderr)
            print(f"  Rate limits: {stats['rate_limits']} ({100*stats['rate_limits']/stats['count']:.2f}%)", file=sys.stderr)
            print(f"  API requests: {stats['api_requests']} ({100*stats['api_requests']/stats['count']:.1f}%)", file=sys.stderr)
            print(f"  Avg input tokens: {stats['total_input_tokens']/stats['count']:.1f}", file=sys.stderr)
            print(f"  Avg output tokens: {stats['total_output_tokens']/stats['count']:.1f}", file=sys.stderr)

        print("\n" + "="*60, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Generate realistic API session traffic logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --hours 48 --output data/traffic.jsonl
  %(prog)s --hours 168 --normal 100 --power 30 --attackers 20 --output data/week.jsonl
        """
    )

    parser.add_argument('--hours', type=int, default=48,
                       help='Hours of traffic to generate (default: 48)')
    parser.add_argument('--output', type=str, required=True,
                       help='Output file path (JSON Lines format)')
    parser.add_argument('--normal', type=int, default=50,
                       help='Number of normal user accounts (default: 50)')
    parser.add_argument('--power', type=int, default=15,
                       help='Number of power developer accounts (default: 15)')
    parser.add_argument('--attackers', type=int, default=10,
                       help='Number of attacker accounts (default: 10)')
    parser.add_argument('--seed', type=int, default=None,
                       help='Random seed for reproducibility')

    args = parser.parse_args()

    # Set random seed if provided
    if args.seed is not None:
        random.seed(args.seed)
        print(f"[+] Random seed: {args.seed}", file=sys.stderr)

    # Create output directory if needed
    import os
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)

    # Generate traffic
    generator = TrafficGenerator(
        num_normal=args.normal,
        num_power=args.power,
        num_attackers=args.attackers
    )

    generator.generate_traffic(args.hours, args.output)

    print(f"\n✅ Traffic generation complete!", file=sys.stderr)


if __name__ == '__main__':
    main()
