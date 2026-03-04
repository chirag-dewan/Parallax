"""Shared utility functions for detectors."""

from __future__ import annotations

import math


def sigmoid_normalize(
    value: float,
    midpoint: float = 3.0,
    steepness: float = 1.0,
) -> float:
    """Map an unbounded non-negative value to [0, 1] using a sigmoid.

    At value == midpoint, returns 0.5.
    steepness controls how quickly it approaches 1.0.
    """
    return 1.0 / (1.0 + math.exp(-steepness * (value - midpoint)))


def coefficient_of_variation(values: list[int | float]) -> float | None:
    """Compute CV (std/mean). Returns None if insufficient data."""
    if len(values) < 2:
        return None
    mean_val = sum(values) / len(values)
    if mean_val == 0:
        return None
    variance = sum((x - mean_val) ** 2 for x in values) / len(values)
    std_val = math.sqrt(variance)
    return std_val / mean_val


def linear_scale(
    value: float, low: float, high: float, clip: bool = True
) -> float:
    """Linearly scale value from [low, high] to [0, 1].

    Below low -> 0.0, above high -> 1.0 (if clip=True).
    """
    if high <= low:
        return 0.0
    scaled = (value - low) / (high - low)
    if clip:
        return max(0.0, min(1.0, scaled))
    return scaled
