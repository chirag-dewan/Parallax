"""T2-005: Temporal Clustering — Fano factor of request timing."""

from __future__ import annotations

import numpy as np

from detection.base import BaseDetector
from detection.models import AccountProfile, RuleID, Tier
from detection.utils import linear_scale


class TemporalClusteringDetector(BaseDetector):
    RULE_ID = RuleID.T2_005
    RULE_NAME = "Temporal Clustering"
    TIER = Tier.TIER_2
    THRESHOLD = 0.5
    WEIGHT = 0.04
    min_events = 30

    BIN_SIZE_SECONDS = 60  # 1-minute bins

    def _compute_score(
        self, profile: AccountProfile
    ) -> tuple[float, dict[str, float | int | str | bool | None]]:
        if len(profile.timestamps) < 2:
            return 0.0, {"fano_factor": None}

        # Bin events into 1-minute intervals
        start_ts = profile.timestamps[0].timestamp()
        end_ts = profile.timestamps[-1].timestamp()
        span = end_ts - start_ts

        if span < self.BIN_SIZE_SECONDS:
            return 0.0, {"fano_factor": None, "bin_size_seconds": self.BIN_SIZE_SECONDS}

        num_bins = max(1, int(span / self.BIN_SIZE_SECONDS))
        counts = np.zeros(num_bins)

        for ts in profile.timestamps:
            idx = min(
                int((ts.timestamp() - start_ts) / self.BIN_SIZE_SECONDS),
                num_bins - 1,
            )
            counts[idx] += 1

        mean_count = counts.mean()
        var_count = counts.var()

        if mean_count == 0:
            return 0.0, {"fano_factor": 0.0}

        # Fano factor: F = var/mean
        # F < 1 = more regular than Poisson (mechanical)
        # F = 1 = Poisson (random)
        # F > 1 = bursty (human)
        fano = float(var_count / mean_count)

        # Low Fano = mechanical = high score
        # F < 0.3 -> 1.0, 0.3-1.0 -> linear 1.0-0.0, > 1.0 -> 0.0
        regularity_score = 1.0 - linear_scale(fano, 0.3, 1.0)

        return regularity_score, {
            "fano_factor": round(fano, 4),
            "bin_size_seconds": self.BIN_SIZE_SECONDS,
            "num_bins": num_bins,
            "mean_events_per_bin": round(float(mean_count), 4),
        }
