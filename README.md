# PARALLAX

[![CI](https://github.com/chirag-dewan/Parallax/actions/workflows/ci.yml/badge.svg)](https://github.com/chirag-dewan/Parallax/actions/workflows/ci.yml)

**Privacy-Aware Risk Labeling and Lateral Analysis for Cross-Platform Exploitation**

## The Problem

AI platforms face a growing threat from adversarial actors who abuse API access to systematically extract model capabilities — a process known as model distillation. Detecting these attacks typically requires deep inspection of user conversations, creating a fundamental tension: the more aggressively a platform monitors for abuse, the more it compromises the privacy of every legitimate user.

PARALLAX solves this by detecting adversarial behavior through behavioral pattern analysis — examining *how* someone uses the platform, not *what* they say. Using a tiered escalation framework, PARALLAX resolves the majority of threats without ever inspecting message content, proving that effective threat detection and user privacy are not mutually exclusive.

## Detection Architecture

PARALLAX implements 14 detection rules across two tiers, each running as an independent detector with weighted composite scoring.

### Tier 1 — Behavioral Telemetry (8 rules, 72% weight)

| Rule | Signal | Weight | What It Catches |
|------|--------|--------|----------------|
| T1-001 | Volume Anomaly | 0.12 | Z-score of req/hr vs population baseline |
| T1-002 | Automation Signature | 0.14 | Timing regularity (CV) + diurnal absence |
| T1-003 | Token Ratio | 0.12 | Short input / max output distillation pattern |
| T1-004 | Session Anomaly | 0.08 | Single-turn ratio + conversations/day |
| T1-005 | Model Targeting | 0.06 | Cheap model preference ratio |
| T1-006 | Context Exploitation | 0.06 | Max output rate + long conversation rate |
| T1-007 | Error Pattern | 0.08 | Safety trigger rate + mechanical retries |
| T1-008 | Concurrent Sessions | 0.06 | Sweep-line max concurrent conversations |

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

Tested on synthetic traffic (1.57M events, 75 accounts):

| Archetype | Accounts | Avg Score | Escalation Rate |
|-----------|----------|-----------|----------------|
| Attacker | 10 | 0.737 | 100% |
| Power Developer | 15 | 0.265 | 0% |
| Normal User | 50 | 0.230 | 0% |

**Perfect class separation at threshold 0.40** — zero false positives, zero false negatives on standard archetypes.

### Threshold Sensitivity (ROC)

| Threshold | TPR | FPR | Precision | F1 |
|-----------|-----|-----|-----------|-----|
| 0.35 | 1.00 | 0.32 | 0.56 | 0.71 |
| 0.40 | 1.00 | 0.00 | 1.00 | 1.00 |
| 0.50 | 1.00 | 0.00 | 1.00 | 1.00 |
| 0.60 | 1.00 | 0.00 | 1.00 | 1.00 |

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
  pipeline.py            # DetectionPipeline orchestrator
  cli.py                 # CLI entry point
  __main__.py            # python -m detection support
  tier1/                 # 8 Tier 1 detector implementations
  tier2/                 # 6 Tier 2 detector implementations
tests/
  conftest.py            # Shared fixtures (make_event, build_profile)
  test_models.py         # Data model tests
  test_pipeline.py       # Pipeline orchestration tests
  tier1/                 # 8 Tier 1 detector test files
  tier2/                 # 6 Tier 2 detector test files
  adversarial/           # 4 adversarial evaluation scenarios
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

# Run detection (API server)
python app.py
# GET /api/accounts — all accounts with scores
# GET /api/account/<id> — per-rule breakdown

# Run tests
pytest tests/ --cov=detection
```

## Test Coverage

92 tests, 94% coverage across all detection modules.

```
pytest tests/ -v --cov=detection --cov-report=term-missing
```

## API

### `GET /api/accounts`
Returns all scored accounts with composite scores, threat levels, and triggered rule counts.

### `GET /api/account/<account_id>`
Returns full per-rule breakdown with 14 detection results, diagnostic details, and top contributing signals.

## Known Limitations

1. **Single-signal evasion.** Token ratio normalization alone is sufficient to drop below the escalation threshold. Detection needs signal correlation bonuses.
2. **Blending blind spot.** Accounts mixing 90% legitimate / 10% attacker behavior score identically to power developers. Requires windowed or session-level scoring.
3. **Low-and-slow gap.** Distillation at normal rates is detected (0.41) but not escalated (threshold 0.66). Token + session signals lack sufficient combined weight.
4. **Synthetic data only.** All evaluation is on generated traffic with clean archetype boundaries. Real-world performance will differ.
5. **Batch-only scoring.** No streaming or real-time detection. Scores computed on full account history.

## Roadmap

- [x] 14-rule detection engine (Tier 1 + Tier 2)
- [x] Weighted composite scoring with confidence
- [x] Population baselines for cross-account analysis
- [x] Synthetic traffic generator (3 archetypes)
- [x] Flask API with per-rule breakdowns
- [x] Adversarial evaluation suite (4 scenarios)
- [x] 92 tests, 94% coverage
- [ ] Tier 0 signals (account age curve, IP clustering)
- [ ] Tier 3 signals (content-adjacent analysis)
- [ ] Windowed / session-level scoring
- [ ] Signal correlation bonuses
- [ ] Adaptive threshold tuning with feedback loop
- [ ] Streaming ingestion and real-time alerting
- [ ] Dashboard with live traffic feed and escalation queue

## License

MIT
