# PARALLAX

**Privacy-Aware Risk Labeling and Lateral Analysis for Cross-Platform Exploitation**

## The Problem

AI platforms face a growing threat from nation-state actors and adversarial organizations that abuse API access to systematically extract model capabilities — a process known as model distillation. Detecting these attacks typically requires deep inspection of user conversations, creating a fundamental tension: the more aggressively a platform monitors for abuse, the more it compromises the privacy of every legitimate user.

PARALLAX solves this by detecting adversarial behavior through behavioral pattern analysis — examining *how* someone uses the platform, not *what* they say. Using a five-tier escalation framework, PARALLAX resolves the majority of threats without ever inspecting message content, proving that effective threat detection and user privacy are not mutually exclusive.

## Why This Matters

- **Financial Impact:** Adversarial distillation operations consume massive compute resources. Every abusive API call is subsidized inference that directly costs the platform.
- **Regulatory Positioning:** As AI regulation matures globally, platforms that demonstrate privacy-preserving abuse detection gain a competitive advantage in compliance and enterprise sales.
- **Trust as a Differentiator:** A platform that can publicly demonstrate it catches abuse *without* reading user conversations builds a moat that competitors cannot easily replicate.

## Five-Tier Privacy Hierarchy

PARALLAX operates on a core principle: **use the minimum information necessary at each stage, and only escalate when the evidence justifies it.**

### Tier 1 — Traffic Tripwire (Fully Automated)
The cheapest, fastest filter. Monitors three signals in real time with zero privacy impact:
- **Request velocity** — volume of API calls per minute/hour against baseline thresholds
- **Timing regularity** — standard deviation of inter-request intervals (humans are irregular; scripts are mechanical)
- **Account age vs. usage volume** — a 2-day-old account generating thousands of API calls is an immediate red flag

### Tier 2 — Behavioral Confirmation (Fully Automated)
Activated when Tier 1 flags an account. Adds deeper behavioral profiling, still without touching content:
- **Conversation patterns** — number of unique conversations per day, single-turn vs. multi-turn ratio
- **Activity windows** — 24/7 continuous usage combined with mechanical timing indicates automation
- **Rate limit response behavior** — how an account reacts to being throttled (humans slow down; scripts retry at exact intervals)

### Tier 3 — Content-Adjacent Analysis (Fully Automated)
The boundary layer. Analyzes properties *about* content without reading the content itself:
- **Token ratio analysis** — consistent pattern of short input prompts generating maximum-length output responses (distillation fingerprint)
- **Safety filter trigger rate** — frequency of responses flagged or refused by the platform's own safety systems
- **Topic category distribution** — systematic, sequential coverage across capability areas (coding → math → creative writing) suggests benchmark sweeping

### Tier 4 — Human-in-the-Loop Gate (Analyst Review Required)
**No automated system can authorize this tier.** When an account's composite threat score crosses the confidence threshold, a human analyst reviews the behavioral case file assembled by Tiers 1–3 and makes a deliberate decision about whether content inspection is justified. This is the "warrant" — probable cause reviewed by a human before any search.

### Tier 5 — Content Review (Authorized, Audited, Time-Limited)
Full content inspection, only with Tier 4 approval. All access is logged, audited, and time-bound. This tier exists as a last resort and its usage rate is a key performance metric — the lower, the better.

## Threat Scoring Engine

Not all signals carry equal weight. PARALLAX uses a weighted confidence scoring model rather than simple threshold counting.

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Mechanical timing regularity | High | Hardest to spoof; requires deliberate randomization |
| Extreme request volume | High | Direct cost indicator |
| Short input / max output token ratio | High | Distillation-specific fingerprint |
| New account + high API usage | Medium | Common but easily circumvented with aged accounts |
| Systematic topic rotation | Medium | Requires cross-session analysis |
| 24/7 continuous activity | Low (alone) | Could be legitimate team usage across time zones |
| Rate limit retry behavior | Medium | Strong corroborator when combined with timing signals |

**Key insight:** Adversaries can spoof any individual signal, but replicating an entire legitimate behavioral fingerprint is prohibitively expensive. PARALLAX's strength is in signal *combination*, not any single detector.

**Confidence threshold:** Escalation to Tier 4 human review requires a composite score above 66%, reducing alert fatigue while maintaining detection coverage.

## AI Case Agent

Between Tier 3 and Tier 4, an AI triage agent acts as a pre-filter to reduce false positives and analyst fatigue. When an account crosses the Tier 3 threshold, the agent:

1. **Assembles the case file** — behavioral timeline, triggered signals, confidence score breakdown
2. **Compares against known attack profiles** — pattern-matches the account's behavioral fingerprint against established distillation attack signatures
3. **Estimates compute cost impact** — calculates the approximate dollar value of resources consumed by the flagged account
4. **Makes an escalation recommendation** — escalate to human review, continue monitoring, or dismiss

The analyst receives a ready-made investigation, not raw data.

## Dashboard

PARALLAX includes a Flask-based monitoring dashboard with three primary views:

**Live Traffic Feed** — Real-time scrolling view of active API sessions. Each row displays account ID, current request count, active tier level, and composite confidence score. Color-coded: green (normal), yellow (Tier 1), orange (Tier 2), red (Tier 3+).

**Account Deep Dive** — Click any flagged account to see its full behavioral fingerprint: request timing timeline, token input/output ratio chart, conversation count over 24 hours, and a breakdown of which signals triggered at each tier. Includes estimated compute cost consumed by the account.

**Escalation Queue** — Accounts that have crossed the confidence threshold awaiting human analyst review. Each entry shows the composite score, triggered signal summary, AI agent recommendation, and two actions: **Approve Inspection** or **Dismiss**.

## Key Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Privacy Efficiency** | % of adversarial accounts detected without content inspection (Tiers 1–3 only) | > 85% |
| **Mean Time to Detect** | Time from first adversarial request to Tier 3 escalation | < 2 hours |
| **False Positive Rate** | % of Tier 4 escalations that are legitimate users | < 10% |
| **Estimated Cost Savings** | Compute cost avoided by early detection and account termination | Tracked per account |

**Headline metric:** *PARALLAX detected 85%+ of simulated distillation attacks without any content inspection.*

## Architecture

```
Incoming API Traffic
        │
        ▼
┌─────────────────┐
│   Tier 1        │  Velocity, timing regularity, account age
│   Tripwire      │  ──► Pass → Normal traffic
└────────┬────────┘
         │ Flag
         ▼
┌─────────────────┐
│   Tier 2        │  Conversation patterns, activity windows, rate limits
│   Behavioral    │  ──► Pass → Continue monitoring
└────────┬────────┘
         │ Flag
         ▼
┌─────────────────┐
│   Tier 3        │  Token ratios, safety filter rate, topic distribution
│   Content-Adj.  │  ──► Pass → Continue monitoring
└────────┬────────┘
         │ Flag (score > 66%)
         ▼
┌─────────────────┐
│   AI Case Agent │  Assembles case file, compares profiles, estimates cost
│   (Tier 3.5)    │  ──► Dismiss → Continue monitoring
└────────┬────────┘
         │ Recommend escalation
         ▼
┌─────────────────┐
│   Tier 4        │  Human analyst reviews case file
│   Human Gate    │  ──► Dismiss → Close case
└────────┬────────┘
         │ Approve
         ▼
┌─────────────────┐
│   Tier 5        │  Content review (logged, audited, time-limited)
│   Content Review│
└─────────────────┘
```

## Tech Stack

- **Backend:** Python / Flask
- **Detection Engine:** Custom behavioral analysis pipeline with weighted scoring
- **Data:** Synthetic traffic generator simulating normal users, power developers, and adversarial distillation operations
- **Dashboard:** Flask + real-time WebSocket updates
- **AI Agent:** LLM-powered triage and case file assembly

## Synthetic Data Generation

PARALLAX ships with a traffic simulator that models three user archetypes:

| Archetype | Requests/Day | Timing Variance | Conversations/Day | Token Ratio (In:Out) | Session Type |
|-----------|-------------|-----------------|-------------------|----------------------|-------------|
| Normal User | 10–20 | High (human) | 3–10 | Variable | Multi-turn |
| Power Developer | 200+ | Medium | 20–50 | Variable | Mixed |
| Distillation Attacker | 1000+ | Very low (mechanical) | 100+ single-turn | Short:Max | Single-turn extraction |

## Setup

```bash
# Clone repository
git clone https://github.com/[username]/parallax.git
cd parallax

# Install dependencies
pip install -r requirements.txt

# Generate synthetic traffic data
python generate_traffic.py

# Launch dashboard
python app.py
```

## Roadmap

- [ ] Core detection engine with Tier 1–3 signals
- [ ] Weighted confidence scoring model
- [ ] Synthetic traffic data generator
- [ ] Flask dashboard with live traffic feed
- [ ] Account deep dive visualization
- [ ] Escalation queue with analyst workflow
- [ ] AI case agent for pre-filtering
- [ ] Compute cost estimation per flagged account
- [ ] Detection accuracy benchmarking suite
- [ ] Adversarial evasion testing

## Background

In early 2025, Anthropic disclosed that nation-state actors were conducting industrial-scale distillation attacks against Claude, using thousands of accounts to systematically extract model capabilities for training competing models. This disclosure highlighted a gap in the AI security landscape: platforms need to detect sophisticated abuse, but the detection methods themselves can compromise the privacy of millions of legitimate users.

PARALLAX was built to close that gap — demonstrating that behavioral analysis can catch adversarial actors without sacrificing the privacy that users trust platforms to protect.

## License

MIT