# PARALLAX — Claude Code Operating Instructions

## Project Summary
Privacy-preserving behavioral threat detection for AI platforms. Detects abuse through behavioral metadata patterns without content inspection ("see the pattern, not the content").

## Architecture

### Modules
- `detection/models.py` — Pydantic models: APIEvent, AccountProfile, DetectionResult, ThreatAssessment
- `detection/base.py` — BaseDetector ABC (all 14 rules inherit from this)
- `detection/baselines.py` — PopulationBaseline (cross-account stats for Tier 2)
- `detection/utils.py` — sigmoid_normalize, coefficient_of_variation, linear_scale
- `detection/pipeline.py` — DetectionPipeline orchestrator (loads traffic, builds profiles, runs detectors, computes composite scores)
- `detection/cli.py` + `detection/__main__.py` — CLI entry point (`python -m detection data/traffic.jsonl`)
- `detection/tier1/` — 8 Tier 1 detectors (T1-001 through T1-008, 72% total weight)
- `detection/tier2/` — 6 Tier 2 detectors (T2-001 through T2-006, 28% total weight)
- `app.py` — Flask API server (GET /api/accounts, GET /api/account/<id>)
- `traffic_generator.py` — Synthetic traffic generator (3 archetypes: normal_user, power_developer, attacker)
- `engine.py` — Legacy scoring engine (predates the modular detection/ package)

### Data Flow
1. JSONL events → `DetectionPipeline.load_traffic()` → parsed as `APIEvent` (Pydantic)
2. Events grouped by account → `AccountProfile` built per account
3. `PopulationBaseline` computed from all profiles (feeds Tier 2 detectors)
4. Each of 14 detectors runs independently → `DetectionResult` per rule per account
5. Weighted composite: `Σ(score × weight × confidence) / Σ(weight)` → `ThreatAssessment`
6. Threat levels: NONE (<0.25), LOW (0.25–0.49), MEDIUM (0.50–0.69), HIGH (0.70–0.84), CRITICAL (0.85+)

### Composite Scoring
```
composite = Σ(score × weight × confidence) / Σ(weight)
```
Escalation recommended above 0.66.

## Current State

### What works
- All 14 detection rules implemented and tested (8 Tier 1, 6 Tier 2)
- Pipeline orchestration: load → profile → detect → score
- Population baselines for cross-account statistical analysis
- Flask API with per-rule breakdowns
- 92 tests, 94% coverage
- Adversarial evaluation suite (4 scenarios: blended behavior, low-and-slow, signal ablation, threshold sensitivity)
- Perfect class separation at threshold 0.40 on standard archetypes (0 FP, 0 FN)

### What's stubbed / not yet built
- Tier 0 signals (account age curve, IP clustering)
- Tier 3 signals (content-adjacent analysis)
- Windowed / session-level scoring (needed for blended behavior detection)
- Signal correlation bonuses (needed to resist single-signal evasion)
- Adaptive threshold tuning with feedback loop
- Streaming ingestion / real-time alerting
- Dashboard with live traffic feed

### Known weaknesses
- Single-signal evasion: normalizing token ratio alone drops attacker below escalation threshold
- Blending blind spot: 90/10 legitimate/attacker mix is indistinguishable from power developers
- Low-and-slow gap: distillation at normal rates scores 0.41 but escalation threshold is 0.66
- All evaluation is on synthetic data with clean archetype boundaries

## Priority Queue (in order)
1. Windowed / session-level scoring to catch blended behavior attacks
2. Signal correlation bonuses to resist single-signal evasion
3. Adaptive threshold tuning with feedback loop
4. Replace synthetic data validation with real-adjacent dataset generation
5. Streaming ingestion and real-time alerting
6. Tier 0 signals (account age curve, IP clustering)
7. Tier 3 signals (content-adjacent analysis)

## Code Standards
- Python 3.11+, type hints on all function signatures
- Every public function gets a docstring
- pytest for all tests, minimum 80% coverage
- No print statements in production code — use logging
- Pydantic BaseModel for all external data (APIEvent, AccountProfile, DetectionResult, ThreatAssessment)
- Commit messages: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `perf:`, `ci:`

## Known Issues
- Circular validation problem: benchmarks validated against self-generated synthetic data
- `engine.py` (root) is the legacy scoring engine — `detection/` package supersedes it but both exist
- `traffic_generator.py` produces clean archetype boundaries that don't reflect real-world overlap
- Some `print()` statements remain in `engine.py` (legacy, not used by the main pipeline)

## Off-Limits
- Do not touch CI/CD config without explicit approval
- Do not refactor module boundaries without discussion
- Do not change detector weights without running the full adversarial evaluation suite

## Error Handling Philosophy: Fail Loud, Never Fake

Prefer a visible failure over a silent fallback.

- Never silently swallow errors to keep things "working."
  Surface the error. Don't substitute placeholder data.
- Fallbacks are acceptable only when disclosed. Show a
  banner, log a warning, annotate the output.
- Design for debuggability, not cosmetic stability.

Priority order:
1. Works correctly with real data
2. Falls back visibly — clearly signals degraded mode
3. Fails with a clear error message
4. Silently degrades to look "fine" — never do this
