"""
T1-002: Automation Signature Detector

Detects behavioral signatures of automated/scripted activity:
- Regular timing intervals (e.g., posting every 15 minutes)
- Identical user agents across accounts
- API/headless browser usage patterns
- Low temporal variance in actions
"""

from collections import defaultdict
from typing import Iterable

import numpy as np

from parallax.detectors.base import BehavioralDetector
from parallax.models import ActivityType, DetectionResult, DeviceType, Severity, UserActivity


class AutomationSignatureDetector(BehavioralDetector):
    """
    Detects accounts exhibiting automation signatures.

    Signals:
    1. Regular timing patterns (e.g., posts every N seconds)
    2. Low variance in inter-event timing
    3. API/headless browser user agents
    4. Identical device fingerprints across multiple accounts
    5. Unnaturally consistent behavior
    """

    def __init__(
        self,
        min_activities: int = 10,
        timing_regularity_threshold: float = 0.15,  # Low CV = regular
        confidence_threshold: float = 0.7
    ):
        super().__init__(
            name="T1-002: Automation Signature",
            description="Detects behavioral signatures of automated accounts"
        )
        self.min_activities = min_activities
        self.timing_regularity_threshold = timing_regularity_threshold
        self.confidence_threshold = confidence_threshold

    def detect(self, activities: Iterable[UserActivity]) -> list[DetectionResult]:
        """Analyze behavioral patterns for automation signatures."""
        activities_list = list(activities)

        if len(activities_list) < self.min_activities:
            return []

        # Group by user
        user_activities: dict[str, list[UserActivity]] = defaultdict(list)
        for activity in activities_list:
            user_activities[activity.user_id].append(activity)

        detections: list[DetectionResult] = []
        suspicious_users: list[str] = []
        evidence_map: dict[str, dict] = {}

        for user_id, user_acts in user_activities.items():
            if len(user_acts) < self.min_activities:
                continue

            # Sort by timestamp
            user_acts.sort(key=lambda a: a.timestamp)

            automation_score = 0.0
            signals = []

            # Signal 1: Timing regularity (low coefficient of variation)
            timing_regularity, mean_interval = self._analyze_timing_regularity(user_acts)
            if timing_regularity is not None and timing_regularity <= self.timing_regularity_threshold:
                automation_score += 0.35
                signals.append(f"Regular timing pattern (CV={timing_regularity:.3f}, interval={mean_interval:.0f}s)")

            # Signal 2: API/headless browser usage
            device_types = [a.device_type for a in user_acts]
            api_ratio = sum(1 for dt in device_types if dt == DeviceType.API) / len(device_types)
            if api_ratio > 0.3:
                automation_score += 0.25
                signals.append(f"API usage detected ({api_ratio*100:.1f}% of activities)")

            # Signal 3: User agent consistency (bots often don't rotate UAs)
            user_agents = [a.user_agent_family for a in user_acts]
            ua_diversity = len(set(user_agents)) / len(user_agents)
            if ua_diversity < 0.2:  # Very low diversity
                automation_score += 0.15
                signals.append(f"Low user-agent diversity ({ua_diversity:.2f})")

            # Signal 4: Device fingerprint consistency (across all activities)
            device_fps = [a.device_fingerprint for a in user_acts]
            fp_diversity = len(set(device_fps)) / len(device_fps)
            if fp_diversity < 0.1:  # Perfect or near-perfect consistency
                automation_score += 0.15
                signals.append(f"Identical device fingerprint across {len(device_fps)} activities")

            # Signal 5: VPN/proxy usage
            vpn_ratio = sum(1 for a in user_acts if a.ip_is_vpn) / len(user_acts)
            if vpn_ratio > 0.5:
                automation_score += 0.1
                signals.append(f"High VPN usage ({vpn_ratio*100:.1f}%)")

            # Normalize score
            confidence = min(automation_score, 1.0)

            if confidence >= self.confidence_threshold:
                suspicious_users.append(user_id)
                evidence_map[user_id] = {
                    "activity_count": len(user_acts),
                    "automation_score": round(confidence, 3),
                    "signals_detected": signals,
                    "timing_regularity_cv": round(timing_regularity, 3) if timing_regularity else None,
                    "api_usage_ratio": round(api_ratio, 3),
                    "user_agent_diversity": round(ua_diversity, 3),
                    "device_fp_diversity": round(fp_diversity, 3),
                    "vpn_usage_ratio": round(vpn_ratio, 3)
                }

        # Create detection if suspicious accounts found
        if suspicious_users:
            avg_confidence = np.mean([evidence_map[u]["automation_score"] for u in suspicious_users])

            # Check for shared infrastructure (strong signal of coordination)
            shared_infra = self._detect_shared_infrastructure(
                [user_activities[uid] for uid in suspicious_users]
            )

            if shared_infra["has_sharing"]:
                avg_confidence = min(avg_confidence * 1.2, 1.0)  # Boost confidence

            if len(suspicious_users) >= 10 or shared_infra["has_sharing"]:
                severity = Severity.HIGH
            elif len(suspicious_users) >= 5:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            detection = self._create_detection(
                severity=severity,
                confidence=float(avg_confidence),
                description=f"Detected {len(suspicious_users)} accounts with automation signatures",
                affected_entities=suspicious_users,
                evidence={
                    "suspicious_account_count": len(suspicious_users),
                    "min_activity_threshold": self.min_activities,
                    "timing_regularity_threshold": self.timing_regularity_threshold,
                    "shared_infrastructure": shared_infra,
                    "sample_accounts": {
                        user_id: evidence_map[user_id]
                        for user_id in suspicious_users[:5]
                    }
                },
                recommended_actions=[
                    "Review account legitimacy",
                    "Consider CAPTCHA challenges for suspected bots",
                    "Analyze content for spam/manipulation",
                    "Cross-reference with T0-001 (bulk registration) and T1-001 (volume anomalies)"
                ],
                tags=["automation", "bot", "scripted", "timing-pattern"],
                sigma_rule_id="parallax_t1_002_v1"
            )

            detections.append(detection)

        return detections

    def _analyze_timing_regularity(self, activities: list[UserActivity]) -> tuple[float | None, float]:
        """
        Analyze timing regularity using coefficient of variation.

        Returns:
            (CV of inter-arrival times, mean interval in seconds)
            Low CV = regular/automated, High CV = organic
        """
        if len(activities) < 3:
            return None, 0.0

        timestamps = [a.timestamp.timestamp() for a in activities]
        inter_arrivals = np.diff(timestamps)

        if len(inter_arrivals) == 0:
            return None, 0.0

        mean_interval = np.mean(inter_arrivals)
        std_interval = np.std(inter_arrivals)

        if mean_interval == 0:
            return None, 0.0

        cv = std_interval / mean_interval
        return cv, mean_interval

    def _detect_shared_infrastructure(self, user_activity_groups: list[list[UserActivity]]) -> dict:
        """
        Detect if suspicious accounts share infrastructure (IPs, devices).

        Strong signal of coordination if multiple automated accounts use same resources.
        """
        all_ips = set()
        all_devices = set()
        all_users = set()

        for acts in user_activity_groups:
            if acts:
                all_users.add(acts[0].user_id)
                for act in acts:
                    all_ips.add(act.ip_hash)
                    all_devices.add(act.device_fingerprint)

        if len(all_users) == 0:
            return {"has_sharing": False}

        # Calculate sharing ratios
        ip_per_user = len(all_ips) / len(all_users)
        device_per_user = len(all_devices) / len(all_users)

        # Significant sharing if < 50% unique resources per user
        has_ip_sharing = ip_per_user < 0.5
        has_device_sharing = device_per_user < 0.5

        return {
            "has_sharing": has_ip_sharing or has_device_sharing,
            "unique_ips": len(all_ips),
            "unique_devices": len(all_devices),
            "account_count": len(all_users),
            "ips_per_account": round(ip_per_user, 2),
            "devices_per_account": round(device_per_user, 2)
        }
