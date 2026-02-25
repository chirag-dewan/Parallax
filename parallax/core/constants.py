"""
Global constants and configuration for Parallax.
"""

# Version
VERSION = "2.0.0"

# Detection thresholds (defaults)
DEFAULT_CONFIDENCE_THRESHOLD = 0.7
DEFAULT_MIN_POPULATION_SIZE = 10

# Ingestion settings
MAX_ACTIVITY_BATCH_SIZE = 10000
ENRICHMENT_CACHE_SIZE = 100000

# Privacy settings
IP_HASH_PREFIX = "sha256:"
DEVICE_FP_LENGTH = 16

# Detector IDs
DETECTOR_IDS = {
    # Tier 0: Statistical
    "T0-001": "Bulk Registration",
    "T0-002": "Payment Clustering",
    "T0-005": "Account Lifecycle Anomaly",
    # Tier 1: Behavioral
    "T1-001": "Volume Anomaly",
    "T1-002": "Automation Signature",
    "T1-003": "Token Reuse",
}

# SIGMA rule mappings
SIGMA_RULES = {
    "T0-001": "parallax_t0_001_v1",
    "T0-002": "parallax_t0_002_v1",
    "T0-005": "parallax_t0_005_v1",
    "T1-001": "parallax_t1_001_v1",
    "T1-002": "parallax_t1_002_v1",
    "T1-003": "parallax_t1_003_v1",
}
