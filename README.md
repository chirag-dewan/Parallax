# Parallax

**Privacy-Preserving Threat Detection for AI Platforms**

Parallax is a behavioral analysis framework for detecting coordinated inauthentic behavior and influence operations on AI platforms without compromising user privacy.

[![CI](https://github.com/yourusername/parallax/workflows/CI/badge.svg)](https://github.com/yourusername/parallax/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Overview

Modern AI platforms face sophisticated threats from coordinated campaigns designed to manipulate content, distill models, or abuse systems. Parallax provides a layered detection framework that identifies these threats through behavioral analysis while preserving user privacy.

### Key Features

- **Privacy-Preserving Design**: No PII stored, only behavioral signals
- **Tiered Detection Architecture**: Statistical → Behavioral → Contextual analysis
- **Synthetic Traffic Generation**: Built-in campaign simulation for testing
- **Production-Ready**: Clean APIs, comprehensive tests, CI/CD ready
- **SIGMA Rule Compatible**: Detections map to security standards

## 🚀 Quick Start

### Installation

```bash
pip install parallax
```

### Generate Synthetic Traffic

```bash
parallax generate \
  --output data/traffic.jsonl \
  --organic 100 \
  --campaign-size 50 \
  --days 7
```

### Run Threat Detection

```bash
parallax scan data/traffic.jsonl --output detections.json
```

### Example Output

```
⚠ 3 Detection(s)

╭────────────── T0-001: Bulk Registration ──────────────╮
│ Detected 47 registrations from similar IP range in    │
│ 2-hour window                                          │
│                                                        │
│ Confidence: 92%                                        │
│ Severity: HIGH                                         │
│ Affected Entities: 47                                  │
╰────────────────────────────────────────────────────────╯
```

## 🏗️ Architecture

### Three-Tier Detection System

#### **Tier 0: Statistical**
Simple aggregations and thresholds. Fast, low false-positive.
- T0-001: Bulk Registration
- T0-002: Payment Clustering
- T0-005: Lifecycle Anomalies

#### **Tier 1: Behavioral**
Temporal patterns, sequences, ML-based outliers.
- T1-001: Volume Anomaly (Z-score)
- T1-002: Automation Signatures
- T1-003: Token Reuse

#### **Tier 2: Contextual** *(Coming in Phase 2)*
Graph analysis, content understanding, cross-signal correlation.

### Data Flow

```
Raw Activity → Normalize → Enrich → Detect → Alert
                  ↓          ↓         ↓       ↓
              Privacy    Context   Tiered   Action
              Transform  Metadata  Analysis  Feed
```

## 📊 Detection Catalog

| ID | Name | Tier | Description |
|----|------|------|-------------|
| T0-001 | Bulk Registration | 0 | Multiple accounts from same IP/subnet |
| T0-002 | Payment Clustering | 0 | Shared payment methods across accounts |
| T0-005 | Lifecycle Anomaly | 0 | Unusual new account behavior patterns |
| T1-001 | Volume Anomaly | 1 | Statistical outliers in activity volume |
| T1-002 | Automation Signature | 1 | Bot-like timing and device patterns |
| T1-003 | Token Reuse | 1 | Coordinated messaging across accounts |

## 🛠️ Development

### Setup

```bash
git clone https://github.com/yourusername/parallax.git
cd parallax
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/ -v --cov=parallax
```

### Run Linters

```bash
black parallax tests
ruff check parallax tests
mypy parallax
```

## 📖 Documentation

### Python API

```python
from parallax import CampaignProfile, TrafficGenerator
from parallax.detectors import BulkRegistrationDetector
from parallax.ingestion import IngestionPipeline

# Generate synthetic traffic
generator = TrafficGenerator(seed=42)
campaign = CampaignProfile(
    name="test_campaign",
    num_accounts=50,
    post_frequency_mean=20.0,
    post_frequency_std=3.0,
    content_length_mean=180,
    content_length_std=40
)
generator.add_campaign(campaign, start_time)

# Run detection
pipeline = IngestionPipeline()
detector = BulkRegistrationDetector()

activities = list(generator.generate_time_window(start, end))
enriched = list(pipeline.process_batch(activities))
detections = detector.detect(enriched)
```

### Custom Detectors

```python
from parallax.detectors.base import StatisticalDetector
from parallax.models import Severity

class MyCustomDetector(StatisticalDetector):
    def __init__(self):
        super().__init__(
            name="CUSTOM-001: My Detector",
            description="Detects custom patterns"
        )

    def detect(self, activities):
        # Your detection logic here
        if suspicious_pattern_found:
            return [self._create_detection(
                severity=Severity.HIGH,
                confidence=0.9,
                description="Custom pattern detected",
                affected_entities=["user_123"],
                evidence={"metric": 42}
            )]
        return []
```

## 🗺️ Roadmap

### Phase 1: Foundation (Complete ✅)
- [x] Core data models
- [x] Synthetic traffic generator
- [x] Ingestion pipeline
- [x] 6 initial detectors (T0: 3, T1: 3)
- [x] CLI interface
- [x] Test suite
- [x] CI/CD

### Phase 2: Intelligence (Weeks 4-6)
- [ ] Content analysis (embeddings)
- [ ] Graph-based detectors (T2)
- [ ] Alert correlation engine
- [ ] Investigation workflows

### Phase 3: Scale (Weeks 7-9)
- [ ] Streaming ingestion
- [ ] Detector optimization
- [ ] Dashboard & viz
- [ ] Multi-platform support

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔒 Security

This project implements defensive security capabilities. Please use responsibly and only on platforms you own or have authorization to test.

To report security vulnerabilities, please email security@example.com.

## 📚 Citation

If you use Parallax in your research, please cite:

```bibtex
@software{parallax2024,
  title={Parallax: Privacy-Preserving Threat Detection for AI Platforms},
  author={Dewan, Chirag},
  year={2024},
  url={https://github.com/yourusername/parallax}
}
```

## 🙏 Acknowledgments

Inspired by threat intelligence frameworks from Meta, Google, Twitter, and the broader trust & safety community.

---

**Built with privacy, precision, and purpose.**
