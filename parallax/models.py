"""
Core data models for Parallax behavioral traffic analysis.

These Pydantic models represent the canonical schema for user activity records,
detections, and alerts in the system.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class ActivityType(str, Enum):
    """Types of user activities we track."""

    REGISTRATION = "registration"
    LOGIN = "login"
    CONTENT_POST = "content_post"
    CONTENT_VIEW = "content_view"
    MESSAGE_SENT = "message_sent"
    PROFILE_UPDATE = "profile_update"
    PAYMENT = "payment"
    SEARCH = "search"
    LIKE = "like"
    SHARE = "share"
    COMMENT = "comment"
    FOLLOW = "follow"
    REPORT = "report"


class DeviceType(str, Enum):
    """Device types for fingerprinting."""

    WEB_DESKTOP = "web_desktop"
    WEB_MOBILE = "web_mobile"
    IOS_APP = "ios_app"
    ANDROID_APP = "android_app"
    API = "api"
    UNKNOWN = "unknown"


class UserActivity(BaseModel):
    """
    Canonical representation of a single user activity event.

    This is the core schema that all detectors operate on. Privacy-preserving
    by design - no PII stored, only behavioral signals.
    """

    # Identity (pseudonymized)
    user_id: str = Field(..., description="Pseudonymized user identifier")
    session_id: str = Field(..., description="Session identifier")

    # Activity metadata
    activity_type: ActivityType
    timestamp: datetime

    # Technical fingerprint (privacy-preserving)
    ip_hash: str = Field(..., description="Hashed IP address (last octet removed before hash)")
    device_fingerprint: str = Field(..., description="Hash of device characteristics")
    device_type: DeviceType
    user_agent_family: str = Field(..., description="Browser/app family (not full UA string)")

    # Behavioral signals
    content_length: Optional[int] = Field(None, description="Length of content created (chars)")
    interaction_count: Optional[int] = Field(None, description="Number of items interacted with")
    time_on_page: Optional[float] = Field(None, description="Seconds spent on page/screen")

    # Platform-specific metadata (extensible)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Enrichment fields (added by ingestion pipeline)
    account_age_days: Optional[int] = Field(None, description="Days since account creation")
    lifetime_activity_count: Optional[int] = Field(None, description="Total activities by user")
    ip_geo_country: Optional[str] = Field(None, description="Country code from IP")
    ip_is_vpn: Optional[bool] = Field(None, description="VPN/proxy detection flag")

    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        raise ValueError(f"Cannot parse timestamp: {v}")

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "usr_a1b2c3d4e5",
                "session_id": "sess_x1y2z3",
                "activity_type": "content_post",
                "timestamp": "2024-01-15T10:30:00Z",
                "ip_hash": "sha256:abc123...",
                "device_fingerprint": "fp_def456",
                "device_type": "web_desktop",
                "user_agent_family": "Chrome",
                "content_length": 250,
                "account_age_days": 5,
                "lifetime_activity_count": 47,
                "ip_geo_country": "US",
                "ip_is_vpn": False,
                "metadata": {}
            }
        }


class Severity(str, Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionResult(BaseModel):
    """
    Output from a single detector run.

    Contains metadata about what was detected, confidence scores,
    and supporting evidence for analysts.
    """

    detection_id: UUID = Field(default_factory=uuid4)
    detector_name: str = Field(..., description="e.g., 'T0-001: Bulk Registration'")
    detector_tier: int = Field(..., ge=0, le=2, description="0=statistical, 1=behavioral, 2=contextual")

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")

    # What was detected
    description: str = Field(..., description="Human-readable description")
    affected_entities: list[str] = Field(default_factory=list, description="User IDs or other entities")

    # Evidence
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting data (e.g., metrics, thresholds, patterns)"
    )

    # Context for response
    recommended_actions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list, description="e.g., ['distillation', 'automation']")

    # SIGMA rule mapping (if applicable)
    sigma_rule_id: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "detector_name": "T0-001: Bulk Registration",
                "detector_tier": 0,
                "severity": "high",
                "confidence": 0.92,
                "description": "Detected 47 registrations from similar IP range in 2-hour window",
                "affected_entities": ["usr_001", "usr_002"],
                "evidence": {
                    "registration_count": 47,
                    "time_window_hours": 2,
                    "ip_subnet": "192.168.1.0/24",
                    "threshold": 10
                },
                "recommended_actions": ["Review registration patterns", "Consider rate limiting"],
                "tags": ["registration", "ip-clustering"]
            }
        }


class Alert(BaseModel):
    """
    Aggregated alert from multiple detections.

    Correlates multiple DetectionResults into a single actionable alert
    for security/trust teams.
    """

    alert_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    title: str
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)

    # Detections that contributed to this alert
    detections: list[DetectionResult] = Field(default_factory=list)

    # Summary
    summary: str = Field(..., description="Executive summary of the threat")
    affected_users: list[str] = Field(default_factory=list)

    # Investigation context
    investigation_priority: int = Field(..., ge=1, le=5, description="1=highest, 5=lowest")
    recommended_actions: list[str] = Field(default_factory=list)

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Coordinated Distillation Campaign Detected",
                "severity": "critical",
                "confidence": 0.87,
                "summary": "47 accounts exhibiting automation signatures with coordinated posting patterns",
                "affected_users": ["usr_001", "usr_002"],
                "investigation_priority": 1,
                "recommended_actions": ["Review accounts for suspension", "Analyze content themes"]
            }
        }


class CampaignProfile(BaseModel):
    """
    Configuration for a synthetic influence operation campaign.

    Used by the traffic generator to create realistic distillation patterns.
    """

    name: str
    num_accounts: int

    # Behavioral patterns
    post_frequency_mean: float = Field(..., description="Average posts per day")
    post_frequency_std: float = Field(..., description="Standard deviation")

    content_length_mean: int = Field(..., description="Average content length (chars)")
    content_length_std: int = Field(..., description="Standard deviation")

    # Automation signatures
    use_shared_ips: bool = True
    ip_diversity: float = Field(0.3, ge=0.0, le=1.0, description="0=same IP, 1=unique IPs")

    device_diversity: float = Field(0.2, ge=0.0, le=1.0)

    time_concentration: float = Field(
        0.7,
        ge=0.0,
        le=1.0,
        description="How clustered in time (0=random, 1=synchronized)"
    )

    # Content patterns
    token_reuse_rate: float = Field(
        0.6,
        ge=0.0,
        le=1.0,
        description="Rate of token/phrase reuse across accounts"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Aggressive Distillation Campaign",
                "num_accounts": 50,
                "post_frequency_mean": 20.0,
                "post_frequency_std": 3.0,
                "content_length_mean": 180,
                "content_length_std": 40,
                "use_shared_ips": True,
                "ip_diversity": 0.2,
                "device_diversity": 0.1,
                "time_concentration": 0.8,
                "token_reuse_rate": 0.7
            }
        }
