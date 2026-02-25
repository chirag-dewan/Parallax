"""
T1-003: Token Reuse Detector

Detects content manipulation campaigns through token/phrase reuse:
- Same phrases across multiple accounts
- Template-based content generation
- Coordinated messaging patterns
"""

from collections import defaultdict
from typing import Iterable

import numpy as np

from parallax.detectors.base import BehavioralDetector
from parallax.models import ActivityType, DetectionResult, Severity, UserActivity


class TokenReuseDetector(BehavioralDetector):
    """
    Detects coordinated content manipulation through token/phrase reuse.

    In Phase 1, uses metadata["token_hash"] as a proxy for content analysis.
    Production would use proper NLP/semantic analysis.

    Signals:
    1. Same tokens appearing across N+ accounts
    2. High reuse rate within account cluster
    3. Temporal coordination of token usage
    """

    def __init__(
        self,
        min_reuse_accounts: int = 5,
        reuse_threshold: float = 0.5,  # 50%+ posts contain shared tokens
        confidence_threshold: float = 0.7
    ):
        super().__init__(
            name="T1-003: Token Reuse",
            description="Detects coordinated messaging through content token reuse"
        )
        self.min_reuse_accounts = min_reuse_accounts
        self.reuse_threshold = reuse_threshold
        self.confidence_threshold = confidence_threshold

    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """Analyze content patterns for token reuse."""
        # Filter to content posts with token metadata
        posts = [
            a for a in activities
            if a.activity_type == ActivityType.CONTENT_POST
            and a.metadata.get("contains_common_token") is True
        ]

        if len(posts) < self.min_reuse_accounts:
            return []

        # Group by token hash
        token_usage: dict[str, list[UserActivity]] = defaultdict(list)
        for post in posts:
            token_hash = post.metadata.get("token_hash")
            if token_hash:
                token_usage[token_hash].append(post)

        detections: list[DetectionResult] = []

        # Analyze each token cluster
        for token_hash, token_posts in token_usage.items():
            # Get unique users
            users_using_token = list(set(p.user_id for p in token_posts))

            if len(users_using_token) < self.min_reuse_accounts:
                continue

            # Calculate reuse metrics
            user_post_counts: dict[str, int] = defaultdict(int)
            user_token_counts: dict[str, int] = defaultdict(int)

            # Get all posts from these users (not just token posts)
            all_user_posts: dict[str, list[UserActivity]] = defaultdict(list)
            for user_id in users_using_token:
                all_user_posts[user_id] = [
                    a for a in posts if a.user_id == user_id
                ]

            for user_id in users_using_token:
                user_post_counts[user_id] = len(all_user_posts[user_id])
                user_token_counts[user_id] = sum(
                    1 for p in all_user_posts[user_id]
                    if p.metadata.get("token_hash") == token_hash
                )

            # Calculate reuse rates per user
            reuse_rates = [
                user_token_counts[uid] / max(user_post_counts[uid], 1)
                for uid in users_using_token
            ]

            avg_reuse_rate = np.mean(reuse_rates)

            if avg_reuse_rate < self.reuse_threshold:
                continue

            # Calculate temporal coordination
            token_timestamps = [p.timestamp.timestamp() for p in token_posts]
            temporal_concentration = self._calculate_temporal_concentration(token_timestamps)

            # Calculate shared infrastructure
            shared_infra = self._calculate_infrastructure_sharing(token_posts)

            # Confidence calculation
            reuse_confidence = min(avg_reuse_rate / self.reuse_threshold, 1.0)
            coordination_confidence = (
                0.5 * reuse_confidence +
                0.3 * temporal_concentration +
                0.2 * shared_infra
            )

            if coordination_confidence >= self.confidence_threshold:
                # Severity based on scale
                if len(users_using_token) >= self.min_reuse_accounts * 3:
                    severity = Severity.CRITICAL
                elif len(users_using_token) >= self.min_reuse_accounts * 2:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                detection = self._create_detection(
                    severity=severity,
                    confidence=coordination_confidence,
                    description=f"Detected {len(users_using_token)} accounts reusing common content tokens (avg reuse rate: {avg_reuse_rate*100:.1f}%)",
                    affected_entities=users_using_token,
                    evidence={
                        "account_count": len(users_using_token),
                        "token_hash": token_hash,
                        "total_posts_with_token": len(token_posts),
                        "average_reuse_rate": round(avg_reuse_rate, 3),
                        "reuse_threshold": self.reuse_threshold,
                        "temporal_concentration": round(temporal_concentration, 3),
                        "infrastructure_sharing_score": round(shared_infra, 3),
                        "sample_users": {
                            uid: {
                                "total_posts": user_post_counts[uid],
                                "posts_with_token": user_token_counts[uid],
                                "reuse_rate": round(reuse_rates[i], 3)
                            }
                            for i, uid in enumerate(users_using_token[:5])
                        }
                    },
                    recommended_actions=[
                        "Review content for manipulation/spam",
                        "Analyze semantic meaning of shared tokens",
                        "Check for coordinated narrative pushing",
                        "Cross-reference with T1-002 (automation) and T0-001 (bulk registration)"
                    ],
                    tags=["content", "coordination", "token-reuse", "messaging"],
                    sigma_rule_id="parallax_t1_003_v1"
                )

                detections.append(detection)

        return detections

    def _calculate_temporal_concentration(self, timestamps: list[float]) -> float:
        """
        Calculate how concentrated in time the token usage is.

        Returns score 0-1 where 1 = highly synchronized.
        """
        if len(timestamps) <= 1:
            return 1.0

        timestamps_sorted = sorted(timestamps)
        time_range = timestamps_sorted[-1] - timestamps_sorted[0]

        if time_range == 0:
            return 1.0

        # Calculate intervals
        intervals = np.diff(timestamps_sorted)
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)

        if mean_interval == 0:
            return 1.0

        # Low CV = high concentration
        cv = std_interval / mean_interval
        concentration = max(0.0, 1.0 - min(cv / 2, 1.0))

        return concentration

    def _calculate_infrastructure_sharing(self, posts: list[UserActivity]) -> float:
        """
        Calculate degree of shared infrastructure among accounts.

        Returns score 0-1 where 1 = high sharing.
        """
        if len(posts) <= 1:
            return 0.0

        unique_users = len(set(p.user_id for p in posts))
        unique_ips = len(set(p.ip_hash for p in posts))
        unique_devices = len(set(p.device_fingerprint for p in posts))

        if unique_users == 0:
            return 0.0

        # Sharing score: less diversity = more sharing
        ip_sharing = 1.0 - min(unique_ips / unique_users, 1.0)
        device_sharing = 1.0 - min(unique_devices / unique_users, 1.0)

        return (ip_sharing + device_sharing) / 2
