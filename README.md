# PARALLAX

[![CI](https://github.com/chirag-dewan/Parallax/actions/workflows/ci.yml/badge.svg)](https://github.com/chirag-dewan/Parallax/actions/workflows/ci.yml)

**Privacy-Aware Risk Labeling and Lateral Analysis for Cross-Platform Exploitation**

## The Problem

AI platforms face a growing threat from adversarial actors who abuse API access to systematically extract model capabilities — a process known as model distillation. Detecting these attacks typically requires deep inspection of user conversations, creating a fundamental tension: the more aggressively a platform monitors for abuse, the more it compromises the privacy of every legitimate user.

PARALLAX solves this by detecting adversarial behavior through behavioral pattern analysis — examining *how* someone uses the platform, not *what* they say. Using a tiered escalation framework, PARALLAX resolves the majority of threats without ever inspecting message content, proving that effective threat detection and user privacy are not mutually exclusive.

## Detection Architecture

PARALLAX implements 16 detection rules across two tiers, each running as an independent detector with weighted composite scoring.

### Tier 1 — Behavioral Telemetry (10 rules, 72% weight)

| Rule | Signal | Weight | What It Catches |
|------|--------|--------|----------------|
| T1-001 | Volume Anomaly | 0.12 | Z-score of req/hr vs population baseline |
| T1-002 | Automation Signature | 0.14 | Timing regularity (CV) + diurnal absence |
| T1-003 | Token Ratio | 0.09 | Short input / max output distillation pattern |
| T1-004 | Session Anomaly | 0.08 | Single-turn ratio + conversations/day |
| T1-005 | Model Targeting | 0.02 | Cheap model preference ratio |
| T1-006 | Context Exploitation | 0.03 | Max output rate + long conversation rate |
| T1-007 | Error Pattern | 0.08 | Safety trigger rate + mechanical retries |
| T1-008 | Concurrent Sessions | 0.06 | Sweep-line max concurrent conversations |
| T1-009 | Host Fan-Out | 0.10 | Destination diversity in sliding time windows |
| T1-010 | Data Transfer Anomaly | 0.00* | Exfiltration via abnormal byte volume (auth profile only) |

### Tier 2 — Statistical Analysis (6 rules, 28% weight)

| Rule | Signal | Weight | What It Catches |
|------|--------|--------|----------------|
| T2-001 | Distribution Divergence | 0.06 | KL-divergence from population norms |
| T2-002 | Entropy Analysis | 0.06 | Shannon entropy of topics, models, timing |
| T2-003 | Cross-Account Correlation | 0.06 | DBSCAN behavioral clustering |
| T2-004 | Power-Law Deviation | 0.04 | Zipf's law R² fit on topic distribution |
| T2-005 | Temporal Clustering | 0.04 | Fano factor of request timing |
| T2-006 | Behavioral Shift | 0.02 | First-half vs second-half metric comparison |

### Composite Scoring

Each detector produces a score (0.0–1.0), a confidence value, and diagnostic details. The pipeline computes a weighted composite:

```
composite = Σ(score × weight × confidence) / Σ(weight)
```

Threat levels: NONE (<0.25), LOW (0.25–0.49), MEDIUM (0.50–0.69), HIGH (0.70–0.84), CRITICAL (0.85+). Escalation recommended above 0.66.

## Five-Tier Privacy Hierarchy

PARALLAX operates on a core principle: **use the minimum information necessary at each stage, and only escalate when the evidence justifies it.**

| Tier | Name | Automation | Privacy Impact |
|------|------|-----------|----------------|
| 0 | Metadata Screening | Fully automated | None — account age, IP, payment |
| 1 | Behavioral Telemetry | Fully automated | Minimal — timing, volume, patterns |
| 2 | Statistical Analysis | Fully automated | Low — cross-account distributions |
| 3 | Content-Adjacent Analysis | Fully automated | Moderate — token properties, no content |
| 4 | Human Gate | Analyst review | N/A — authorization checkpoint |
| 5 | Content Review | Audited, time-limited | Full — last resort |

Tiers 1–2 are currently implemented. Tiers 0 and 3 are planned.

## Detection Performance

### Synthetic Data (API Abuse)

Tested on synthetic traffic (1.57M events, 75 accounts):

| Archetype | Accounts | Avg Score | Escalation Rate |
|-----------|----------|-----------|----------------|
| Attacker | 10 | 0.524 | 0% |
| Power Developer | 15 | 0.265 | 0% |
| Normal User | 50 | 0.230 | 0% |

**Clean separation at MEDIUM threshold (0.50)** — zero false positives, 100% true positive rate on standard archetypes.

### LANL Cyber1 (Real Auth Log Data)

Validated against the [LANL Comprehensive Multi-Source Cyber-Security Events](https://csr.lanl.gov/data/cyber1/) dataset — 16.9M authentication events across 500 users (87 compromised per red team labels).

Uses `--windowed --profile auth` mode: sliding 4-hour windows with auth-specific detector weights.

| Metric | Value |
|--------|-------|
| **ROC AUC** | **0.68** |
| **Best F1** | **0.49** (threshold 0.77) |
| Precision @ best F1 | 48.8% |
| Recall @ best F1 | 48.3% |
| Compromised mean score | 0.599 |
| Normal mean score | 0.483 |

The auth profile activates only 5 detectors that positively correlate with compromise on auth data:

| Detector | Auth Weight | Signal |
|----------|-----------|--------|
| T2-006 Behavioral Shift | 0.30 | Sudden usage pattern changes in peak windows |
| T1-009 Host Fan-Out | 0.25 | Lateral movement across many destinations |
| T1-008 Concurrent Sessions | 0.20 | Parallel authentication to multiple hosts |
| T1-007 Error Pattern | 0.15 | Auth failure bursts (credential spraying) |
| T1-004 Session Anomaly | 0.10 | Anomalous session structure |

See [docs/lanl_evaluation_v3.md](docs/lanl_evaluation_v3.md) for the full evaluation report.

## Adversarial Evaluation

Four adversarial scenarios test detection robustness against sophisticated evasion:

### 1. Blended Behavior (90/10 mix)
10 accounts behaving as power developers 90% of the time with 10% attacker-like extraction.

**Result:** Avg score 0.302 (LOW). Indistinguishable from legitimate power devs. The 10% attacker events get diluted in whole-account averages. **Known limitation** — requires windowed or session-level analysis to detect.

### 2. Low-and-Slow Distillation
10 accounts performing extraction over 30 days at normal rate limits (4–8 req/hr) with human-like timing variance.

**Result:** Avg score 0.410 (LOW). Token ratio (T1-003) and session anomaly (T1-004) both fire at 1.0, but their combined weight (0.20) is insufficient for escalation. Volume anomaly correctly does not trigger. **Detected but not escalated** — the system knows something is off but can't act.

### 3. Signal Ablation / Evasion Cost
Systematically normalize one attacker signal at a time to find minimum evasion cost.

**Result:** Full attacker scores 0.695. Normalizing tokens alone drops to 0.468 — single-signal evasion is possible. 5 of 7 single-signal normalizations evade the escalation threshold. **Tokens, volume, and timing are single points of failure.** Normalizing all 7 signals drops to 0.237 (indistinguishable from normal).

| Signal Normalized | Score | Drop | Evades? |
|-------------------|-------|------|---------|
| Tokens | 0.468 | -0.227 | Yes |
| Volume | 0.579 | -0.116 | Yes |
| Timing | 0.588 | -0.107 | Yes |
| Errors | 0.631 | -0.064 | Yes |
| Models | 0.653 | -0.042 | Yes |
| Sessions | 0.672 | -0.023 | No |
| Topics | 0.678 | -0.017 | No |

### 4. Threshold Sensitivity
Swept escalation threshold 0.20–0.60 in 0.05 steps. Perfect F1=1.00 across thresholds 0.40–0.60 on standard archetypes.

## Project Structure

```
detection/
  models.py              # Pydantic: APIEvent, AccountProfile, DetectionResult, ThreatAssessment
  base.py                # BaseDetector ABC
  baselines.py           # PopulationBaseline (cross-account stats)
  utils.py               # sigmoid_normalize, coefficient_of_variation, linear_scale
  pipeline.py            # DetectionPipeline orchestrator (batch + windowed + auth profile)
  cli.py                 # CLI entry point
  __main__.py            # python -m detection support
  tier1/                 # 10 Tier 1 detector implementations (T1-001 through T1-010)
  tier2/                 # 6 Tier 2 detector implementations (T2-001 through T2-006)
tests/
  conftest.py            # Shared fixtures (make_event, build_profile)
  test_models.py         # Data model tests
  test_pipeline.py       # Pipeline orchestration tests
  tier1/                 # 10 Tier 1 detector test files
  tier2/                 # 6 Tier 2 detector test files
  adversarial/           # 4 adversarial evaluation scenarios
lanl_adapter.py          # LANL Cyber1 -> PARALLAX event converter
scripts/
  lanl_evaluate.py       # LANL evaluation pipeline (CSV dump, threshold analysis, ROC AUC)
  inject_flow_data.py    # Join LANL flow data into enriched auth events
  download_lanl.sh       # LANL dataset download instructions
docs/
  lanl_evaluation_v2.md  # LANL v2 evaluation (all detectors — AUC 0.48)
  lanl_evaluation_v3.md  # LANL v3 evaluation (signal-only — AUC 0.68)
  flow_enrichment_results.md  # Flow data enrichment results
app.py                   # Flask API server
traffic_generator.py     # Synthetic data generator
templates/dashboard.html # Dashboard UI
```

## Setup

```bash
# Clone and install
git clone https://github.com/chirag-dewan/parallax.git
cd parallax
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Generate synthetic traffic
python traffic_generator.py

# Run detection (CLI)
python -m detection data/traffic.jsonl

# Windowed scoring with auth profile (for LANL / auth log data)
python -m detection data/lanl/parallax_events.jsonl --windowed --profile auth

# Run detection (API server)
python app.py
# GET /api/accounts — all accounts with scores
# GET /api/account/<id> — per-rule breakdown

# Run tests
pytest tests/ --cov=detection
```

### LANL Dataset

```bash
# 1. Download from https://csr.lanl.gov/data/cyber1/ (requires form submission)
# 2. Place auth.txt.gz and redteam.txt.gz in scripts/

# Convert LANL auth events to PARALLAX format
python lanl_adapter.py \
  --auth scripts/auth.txt.gz \
  --redteam scripts/redteam.txt.gz \
  --output data/lanl/parallax_events.jsonl \
  --sample-users 500

# Run evaluation with threshold analysis
python scripts/lanl_evaluate.py data/lanl/parallax_events.jsonl \
  --redteam scripts/redteam.txt.gz \
  --output data/lanl/evaluation.csv
```

<!-- AUTO-GENERATED: commands -->
## Commands Reference

| Command | Description |
|---------|-------------|
| `python traffic_generator.py` | Generate synthetic traffic (3 archetypes) |
| `python -m detection data/traffic.jsonl` | Run batch detection via CLI |
| `python -m detection <file> --windowed --profile auth` | Windowed scoring with auth profile |
| `python app.py` | Start Flask API server (port 5000) |
| `pytest tests/ --cov=detection` | Run test suite with coverage |
| `python lanl_adapter.py --auth ... --redteam ...` | Convert LANL auth events to PARALLAX format |
| `python scripts/lanl_evaluate.py <file> --redteam ...` | Run LANL evaluation with threshold analysis |
| `python scripts/inject_flow_data.py` | Join LANL flow data into enriched auth events |
<!-- /AUTO-GENERATED: commands -->

<!-- AUTO-GENERATED: environment -->
## Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `FLASK_DEBUG` | No | Enable Flask debug mode | `0` |
| `FLASK_HOST` | No | Flask bind address | `127.0.0.1` |
| `FLASK_PORT` | No | Flask listen port | `5000` |
<!-- /AUTO-GENERATED: environment -->

## Test Coverage

136 tests across all detection modules.

```
pytest tests/ -v --cov=detection --cov-report=term-missing
```

## API

### `GET /api/accounts`
Returns all scored accounts with composite scores, threat levels, and triggered rule counts.

### `GET /api/account/<account_id>`
Returns full per-rule breakdown with 16 detection results, diagnostic details, and top contributing signals.

### `GET /api/evaluation`
Returns LANL v3 evaluation results from `data/lanl/evaluation_v3.csv` (requires prior evaluation run).

## Known Limitations

1. **Single-signal evasion.** Token ratio normalization alone is sufficient to drop below the escalation threshold on API data. Detection needs signal correlation bonuses.
2. **Blending blind spot.** Accounts mixing 90% legitimate / 10% attacker behavior score identically to power developers on whole-profile scoring. Windowed mode mitigates this.
3. **Low-and-slow gap.** Distillation at normal rates is detected (0.41) but not escalated (threshold 0.66). Token + session signals lack sufficient combined weight.
4. **LANL AUC ceiling.** Auth profile achieves 0.68 AUC on LANL — meaningful but not production-grade. High-volume normal users and low-activity compromised users overlap in score.
5. **Partial LANL data.** Evaluation used 4% of auth.txt.gz. Full dataset may show different distributions.
6. **Batch-only scoring.** No streaming or real-time detection.

## Roadmap

- [x] 16-rule detection engine (Tier 1 + Tier 2)
- [x] Weighted composite scoring with confidence
- [x] Population baselines for cross-account analysis
- [x] Synthetic traffic generator (3 archetypes)
- [x] Flask API with per-rule breakdowns
- [x] Adversarial evaluation suite (4 scenarios)
- [x] 136 tests
- [x] Windowed temporal scoring (sliding windows with peak detection)
- [x] Auth log profile mode (LANL-calibrated weights)
- [x] LANL Cyber1 adapter and evaluation (AUC 0.68)
- [x] T1-009 Host Fan-Out detector for lateral movement
- [x] T1-010 Data Transfer Anomaly detector with flow enrichment
- [ ] Auth failure sequence detector (credential spraying)
- [ ] Tier 0 signals (account age curve, IP clustering)
- [ ] Tier 3 signals (content-adjacent analysis)
- [ ] Signal correlation bonuses
- [ ] Window-level red team label alignment
- [ ] Adaptive threshold tuning with feedback loop
- [ ] Streaming ingestion and real-time alerting
- [ ] Dashboard with live traffic feed and escalation queue

## License

MIT
