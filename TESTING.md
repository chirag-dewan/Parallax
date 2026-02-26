# Parallax Testing Guide

Complete guide to testing Parallax functionality.

---

## Quick Start (2 minutes)

### 1. Verify Installation

```bash
# Activate virtual environment
source venv/bin/activate  # Windows: venv\Scripts\activate

# Check version
parallax version
```

**Expected output:**
```
Parallax v2.0.0
```

---

## End-to-End Testing

### 2. Generate Synthetic Traffic

```bash
parallax generate \
  --output data/demo_traffic.jsonl \
  --organic 100 \
  --campaign-size 50 \
  --days 7 \
  --seed 42
```

**What this does:**
- Creates 100 organic users (mix of casual, moderate, and power users)
- Adds a 50-account distillation campaign
- Generates 7 days of activity
- Saves to `data/demo_traffic.jsonl`

**Expected output:**
```
✓ Added 100 organic users
✓ Added distillation campaign with 50 accounts
✓ Generated ~5000 activities over 7 days
✓ Saved to data/demo_traffic.jsonl
```

### 3. Scan for Threats

```bash
parallax scan data/demo_traffic.jsonl --min-confidence 0.6
```

**What this does:**
- Loads the generated traffic
- Runs all 6 detectors
- Shows detections with ≥60% confidence

**Expected output:**
You should see detections like:
```
⚠ 3 Detection(s)

╭───── T0-005: Account Lifecycle Anomaly ─────╮
│ Detected XX new accounts with anomalous     │
│ lifecycle patterns                           │
│ Confidence: 90%                              │
╰──────────────────────────────────────────────╯
```

### 4. Export Results to JSON

```bash
parallax scan data/demo_traffic.jsonl \
  --output results.json \
  --min-confidence 0.6
```

**What this does:**
- Runs detection and saves results to JSON file
- Machine-readable format for integration

---

## Automated Test Suite

### 5. Run All Tests

```bash
pytest tests/ -v
```

**Expected output:**
```
35 passed in 0.66s
```

### 6. Run Tests with Coverage

```bash
pytest tests/ -v --cov=parallax --cov-report=term-missing
```

**What this shows:**
- Which code lines are tested
- Coverage percentage per file
- Missing coverage areas

### 7. Run Specific Test Categories

```bash
# Test only detectors
pytest tests/test_detectors/ -v

# Test only ingestion
pytest tests/test_ingestion/ -v

# Test only models
pytest tests/test_models.py -v

# Test only simulation
pytest tests/test_simulation/ -v
```

---

## Python API Testing

### 8. Run Basic Example

```bash
python3 examples/basic_usage.py
```

**What this does:**
- Generates traffic programmatically
- Runs detection pipeline
- Displays results

**Expected output:**
```
Step 1: Generating synthetic traffic...
  ✓ Generated 1868 activities

Step 2: Processing through ingestion pipeline...
  ✓ Enriched 1868 activities

Step 3: Running detectors...
  ✓ T0-001: Bulk Registration: No threats detected
  ...

✅ Example complete!
```

### 9. Test Custom Detector

```bash
python3 examples/custom_detector.py
```

**What this demonstrates:**
- How to create custom detectors
- Detector base class usage
- Integration with the framework

---

## Manual Testing Scenarios

### 10. Test Individual Detectors

```python
from datetime import datetime, timedelta
from parallax.models import UserActivity, ActivityType, DeviceType
from parallax.detectors import BulkRegistrationDetector

# Create test data
now = datetime.utcnow()
activities = [
    UserActivity(
        user_id=f"test_user_{i}",
        session_id=f"sess_{i}",
        activity_type=ActivityType.REGISTRATION,
        timestamp=now,
        ip_hash="sha256:same_subnet",  # Same IP subnet
        device_fingerprint=f"fp_{i}",
        device_type=DeviceType.WEB,
        user_agent_family="Chrome"
    )
    for i in range(15)  # 15 registrations from same subnet
]

# Run detector
detector = BulkRegistrationDetector(threshold=10, time_window_hours=2)
detections = detector.detect(activities)

# Check results
assert len(detections) > 0
print(f"✓ Detected {len(detections)} threat(s)")
print(f"Confidence: {detections[0].confidence:.1%}")
```

### 11. Test Traffic Generator

```python
from parallax import TrafficGenerator, CampaignProfile
from datetime import datetime, timedelta

# Initialize generator
generator = TrafficGenerator(seed=42)

# Add organic users
generator.add_organic_users(
    num_casual=20,
    num_moderate=15,
    num_power=5,
    start_time=datetime.utcnow() - timedelta(days=7)
)

# Add campaign
campaign = CampaignProfile(
    name="test_campaign",
    num_accounts=30,
    post_frequency_mean=20.0,
    ip_diversity=0.1,      # Low diversity = coordinated
    device_diversity=0.05,  # Very low diversity
    token_reuse_rate=0.8    # High token reuse
)
generator.add_campaign(campaign, datetime.utcnow() - timedelta(days=7))

# Generate activities
activities = list(generator.generate_time_window(
    datetime.utcnow() - timedelta(days=7),
    datetime.utcnow()
))

print(f"✓ Generated {len(activities)} activities")
```

### 12. Test Ingestion Pipeline

```python
from parallax.ingestion import IngestionPipeline
from parallax.models import UserActivity

# Create pipeline
pipeline = IngestionPipeline()

# Process activities
raw_data = [
    {
        "user_id": "test_user_1",
        "session_id": "sess_1",
        "activity_type": "content_post",
        "timestamp": "2024-02-25T12:00:00",
        "ip_hash": "sha256:abc123",
        "device_fingerprint": "fp_123",
        "device_type": "web",
        "user_agent_family": "Chrome"
    }
]

enriched = list(pipeline.process_batch(raw_data))
print(f"✓ Enriched {len(enriched)} activities")
print(f"Account age: {enriched[0].account_age_days} days")
print(f"Lifetime activities: {enriched[0].lifetime_activity_count}")
```

---

## Performance Testing

### 13. Large-Scale Traffic Generation

```bash
# Generate 10,000 activities
parallax generate \
  --output data/large_test.jsonl \
  --organic 500 \
  --campaign-size 200 \
  --days 30 \
  --seed 12345

# Scan large dataset
time parallax scan data/large_test.jsonl
```

**Benchmarks** (approximate on MacBook Pro M1):
- Generate 10K activities: ~5 seconds
- Scan 10K activities: ~2 seconds
- All 6 detectors run in parallel

### 14. Memory Usage Testing

```bash
# Use pytest with memory profiling
pip install pytest-memray
pytest tests/ --memray
```

---

## CI/CD Testing

### 15. Run CI Pipeline Locally

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linters
black parallax tests --check
ruff check parallax tests

# Run type checking
mypy parallax

# Run tests
pytest tests/ -v --cov=parallax
```

**All checks must pass** before committing.

### 16. GitHub Actions

GitHub Actions automatically runs on every push:
- Python 3.11 and 3.12 testing
- Linting (black, ruff)
- Type checking (mypy)
- Test suite with coverage

View results at: `https://github.com/chirag-dewan/Parallax/actions`

---

## Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'parallax'`
```bash
# Solution: Install in development mode
pip install -e .
```

**Issue**: `FileNotFoundError: data/traffic.jsonl`
```bash
# Solution: Create data directory
mkdir -p data
```

**Issue**: Tests fail with datetime warnings
```
# Solution: These are deprecation warnings, not errors
# Tests still pass. Will be fixed in future version.
```

**Issue**: `ImportError: cannot import name 'X'`
```bash
# Solution: Reinstall dependencies
pip install --upgrade -e .
```

---

## Test Data

### Sample Traffic File Format

Each line is a JSON object:
```json
{
  "user_id": "campaign_account_1",
  "session_id": "sess_abc123",
  "activity_type": "content_post",
  "timestamp": "2024-02-25T12:00:00",
  "ip_hash": "sha256:a913a531e71ec37b",
  "device_fingerprint": "e74b1ba5f3c2afab",
  "device_type": "api",
  "user_agent_family": "Chrome",
  "content_length": 175,
  "metadata": {
    "contains_common_token": true,
    "token_hash": "7969d536"
  }
}
```

### Expected Detections

With default settings, you should see:

**T0-005 (Lifecycle Anomaly)**: Always triggers on campaign accounts
- New accounts posting immediately
- High volume without content consumption

**T1-002 (Automation Signature)**: Triggers on ~70% of campaign accounts
- Regular timing patterns
- API usage
- Low device diversity

**T1-003 (Token Reuse)**: Triggers when token_reuse_rate > 0.5
- Shared content across accounts
- Coordinated messaging

**T0-001 (Bulk Registration)**: Triggers on registration events
- Only if you generate with `include_registrations=True`

---

## Quality Metrics

### Current Status

- **Tests**: 35/35 passing ✅
- **Coverage**: ~85% (estimated)
- **Linting**: All checks pass ✅
- **Type Safety**: Mypy strict mode compatible
- **Performance**: <3s for 10K activities

### Test Categories

| Category | Tests | Status |
|----------|-------|--------|
| Models | 7 | ✅ |
| Simulation | 8 | ✅ |
| Ingestion | 5 | ✅ |
| Detectors | 15 | ✅ |
| **Total** | **35** | **✅** |

---

## Next Steps

1. **Add your own test cases** to `tests/`
2. **Create custom detectors** using examples
3. **Run on real data** (ensure proper privacy compliance)
4. **Contribute** improvements back to the project

---

## Support

For testing issues:
- Check [DOCUMENTATION.md](DOCUMENTATION.md) for API details
- Review examples in `examples/`
- Open an issue: https://github.com/chirag-dewan/Parallax/issues

**Happy Testing!** 🧪
