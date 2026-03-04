"""
Population-level baseline statistics computed across all accounts.
Used by Tier 2 detectors that need cross-account context.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from statistics import mean, median, stdev

import numpy as np

from detection.models import AccountProfile

logger = logging.getLogger("parallax.baselines")


@dataclass
class PopulationBaseline:
    """Aggregated statistics across all accounts."""

    # Velocity
    velocity_mean: float = 0.0
    velocity_std: float = 1.0
    velocity_median: float = 0.0

    # Token ratios
    token_ratio_mean: float = 0.0
    token_ratio_std: float = 1.0

    # Interval statistics
    interval_mean: float = 0.0
    interval_std: float = 1.0

    # Population distributions (for KL-divergence)
    interval_histogram: np.ndarray = field(
        default_factory=lambda: np.zeros(5)
    )
    output_token_histogram: np.ndarray = field(
        default_factory=lambda: np.zeros(4)
    )
    topic_distribution: dict[str, float] = field(default_factory=dict)
    hourly_distribution: np.ndarray = field(
        default_factory=lambda: np.zeros(24)
    )

    # Feature vectors for DBSCAN (T2-003)
    feature_vectors: dict[str, np.ndarray] = field(default_factory=dict)
    cluster_labels: dict[str, int] = field(default_factory=dict)

    # All profiles reference
    all_profiles: list[AccountProfile] = field(default_factory=list)

    @classmethod
    def from_profiles(
        cls, profiles: list[AccountProfile]
    ) -> PopulationBaseline:
        """Build baseline from all account profiles."""
        baseline = cls()
        baseline.all_profiles = profiles

        if not profiles:
            return baseline

        # Velocity stats
        velocities = [p.requests_per_hour for p in profiles]
        baseline.velocity_mean = mean(velocities)
        baseline.velocity_median = median(velocities)
        baseline.velocity_std = (
            stdev(velocities) if len(velocities) > 1 else 1.0
        )

        # Token ratio stats
        ratios = [p.token_ratio for p in profiles]
        baseline.token_ratio_mean = mean(ratios)
        baseline.token_ratio_std = (
            stdev(ratios) if len(ratios) > 1 else 1.0
        )

        # Interval stats (population-wide mean of per-account mean intervals)
        account_mean_intervals = []
        for p in profiles:
            if p.inter_request_intervals_ms:
                account_mean_intervals.append(
                    mean(p.inter_request_intervals_ms)
                )
        if account_mean_intervals:
            baseline.interval_mean = mean(account_mean_intervals)
            baseline.interval_std = (
                stdev(account_mean_intervals)
                if len(account_mean_intervals) > 1
                else 1.0
            )

        # Population histograms
        baseline._build_histograms(profiles)

        # Feature vectors for DBSCAN
        baseline._build_feature_vectors(profiles)

        logger.info(
            "Baseline: velocity_mean=%.2f, velocity_std=%.2f, "
            "token_ratio_mean=%.2f, %d accounts",
            baseline.velocity_mean,
            baseline.velocity_std,
            baseline.token_ratio_mean,
            len(profiles),
        )

        return baseline

    def _build_histograms(self, profiles: list[AccountProfile]) -> None:
        """Build population-wide distribution histograms."""
        # Interval bins: [0-1s, 1-5s, 5-30s, 30-120s, 120s+]
        interval_bins = [0, 1000, 5000, 30000, 120000, float("inf")]
        interval_counts = np.zeros(5)

        # Output token bins: [0-500, 500-2000, 2000-3500, 3500-4096]
        output_bins = [0, 500, 2000, 3500, 4097]
        output_counts = np.zeros(4)

        # Topic counts
        topic_totals: dict[str, int] = {}

        # Hourly
        hourly_counts = np.zeros(24)

        total_events = 0
        for profile in profiles:
            for interval in profile.inter_request_intervals_ms:
                for i in range(len(interval_bins) - 1):
                    if interval_bins[i] <= interval < interval_bins[i + 1]:
                        interval_counts[i] += 1
                        break

            for out_tok in profile.output_tokens:
                for i in range(len(output_bins) - 1):
                    if output_bins[i] <= out_tok < output_bins[i + 1]:
                        output_counts[i] += 1
                        break

            for topic, count in profile.topic_counts.items():
                topic_totals[topic] = topic_totals.get(topic, 0) + count

            for ts in profile.timestamps:
                hourly_counts[ts.hour] += 1

            total_events += profile.total_events

        # Normalize to probabilities
        if interval_counts.sum() > 0:
            self.interval_histogram = interval_counts / interval_counts.sum()
        if output_counts.sum() > 0:
            self.output_token_histogram = (
                output_counts / output_counts.sum()
            )
        if total_events > 0:
            self.topic_distribution = {
                t: c / total_events for t, c in topic_totals.items()
            }
        if hourly_counts.sum() > 0:
            self.hourly_distribution = hourly_counts / hourly_counts.sum()

    def _build_feature_vectors(
        self, profiles: list[AccountProfile]
    ) -> None:
        """Build normalized feature vectors for DBSCAN clustering."""
        if len(profiles) < 3:
            return

        raw_vectors: dict[str, list[float]] = {}
        for p in profiles:
            raw_vectors[p.account_id] = [
                p.requests_per_hour,
                mean(p.inter_request_intervals_ms)
                if p.inter_request_intervals_ms
                else 0.0,
                p.avg_input_tokens,
                p.avg_output_tokens,
                p.api_ratio,
                p.safety_trigger_rate,
                p.single_turn_ratio,
                p.hours_coverage,
            ]

        # Z-score normalize
        matrix = np.array(list(raw_vectors.values()))
        means = matrix.mean(axis=0)
        stds = matrix.std(axis=0)
        stds[stds == 0] = 1.0
        normalized = (matrix - means) / stds

        for i, account_id in enumerate(raw_vectors.keys()):
            self.feature_vectors[account_id] = normalized[i]

        # Run DBSCAN
        self._run_dbscan(eps=1.5, min_samples=3)

    def _run_dbscan(self, eps: float, min_samples: int) -> None:
        """Simple DBSCAN implementation using scipy distance matrix."""
        from scipy.spatial.distance import cdist

        account_ids = list(self.feature_vectors.keys())
        if len(account_ids) < min_samples:
            return

        vectors = np.array(
            [self.feature_vectors[aid] for aid in account_ids]
        )
        dist_matrix = cdist(vectors, vectors, metric="euclidean")

        n = len(account_ids)
        labels = [-1] * n  # -1 = noise
        cluster_id = 0
        visited = [False] * n

        for i in range(n):
            if visited[i]:
                continue
            visited[i] = True

            neighbors = [
                j for j in range(n) if dist_matrix[i][j] <= eps and j != i
            ]

            if len(neighbors) < min_samples - 1:
                continue  # noise

            labels[i] = cluster_id
            seed_set = list(neighbors)

            while seed_set:
                q = seed_set.pop(0)
                if not visited[q]:
                    visited[q] = True
                    q_neighbors = [
                        j
                        for j in range(n)
                        if dist_matrix[q][j] <= eps and j != q
                    ]
                    if len(q_neighbors) >= min_samples - 1:
                        seed_set.extend(
                            j for j in q_neighbors if not visited[j]
                        )
                if labels[q] == -1:
                    labels[q] = cluster_id

            cluster_id += 1

        for i, aid in enumerate(account_ids):
            self.cluster_labels[aid] = labels[i]
