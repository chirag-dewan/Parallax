"""
Parallax: Privacy-Preserving Threat Detection for AI Platforms

A behavioral analysis framework for detecting coordinated inauthentic behavior
and influence operations without compromising user privacy.
"""

__version__ = "2.0.0"

from parallax.models import (
    ActivityType,
    Alert,
    CampaignProfile,
    DetectionResult,
    DeviceType,
    Severity,
    UserActivity,
)

__all__ = [
    "__version__",
    "UserActivity",
    "ActivityType",
    "DeviceType",
    "DetectionResult",
    "Alert",
    "Severity",
    "CampaignProfile",
]
