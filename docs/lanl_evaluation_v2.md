# LANL Evaluation v2 — Host Fan-Out, Windowed Scoring, Auth Profile

**Date:** 2026-04-06
**Dataset:** LANL Cyber1 (partial — 296MB of 7.2GB auth.txt.gz)
**Sample:** 500 users (87 compromised, 413 normal), 16.9M auth events, 187K sessions

## Changes from v1

| Change | Description |
|--------|-------------|
| T1-009 Host Fan-Out | New Tier 1 detector for lateral movement via destination diversity |
| Windowed scoring | 4-hour sliding windows with 1-hour stride; reports peak score per account |
| Auth profile mode | Zeroes T1-003 (Token Ratio), T1-005 (Model Targeting), T1-006 (Context Exploitation) |
| Weight redistribution | T1-009 gets 0.10; freed 0.14 from dead-weight rules redistributed proportionally |

## Before vs After (Score Distributions)

### v1: Whole-Profile, Default Weights

| Group | Mean | Std | Min | Max |
|-------|------|-----|-----|-----|
| Compromised (n=66 visible) | 0.3841 | — | 0.3380 | 0.4313 |
| Normal (n=412 visible) | 0.3962 | — | 0.3427 | 0.4872 |

- Scores **inverted**: normal > compromised
- All accounts scored LOW, zero escalations
- 0% recall at any operationally useful threshold

### v2: Windowed + Auth Profile

| Group | Mean | Std | Min | Max |
|-------|------|-----|-----|-----|
| Compromised (n=87) | 0.4375 | 0.1774 | 0.0000 | 0.5838 |
| Normal (n=413) | 0.4961 | 0.0602 | 0.3251 | 0.6334 |

- Scores **still inverted on average** (normal mean 0.496 > compromised mean 0.438)
- But **variance** in compromised group is 3x larger (std 0.18 vs 0.06)
- Compromised max (0.58) approaches normal max (0.63)
- Some compromised users now score in the top decile

## Precision / Recall

| Threshold | TP | FP | FN | TN | Precision | Recall | F1 |
|-----------|----|----|----|----|-----------|--------|-----|
| 0.25 | 74 | 413 | 13 | 0 | 15.2% | 85.1% | 0.258 |
| 0.35 | 71 | 408 | 16 | 5 | 14.8% | 81.6% | 0.251 |
| 0.45 | 69 | 323 | 18 | 90 | 17.6% | 79.3% | 0.288 |
| **0.52 (best F1)** | **46** | **167** | **41** | **246** | **21.6%** | **52.9%** | **0.307** |
| 0.55 | 4 | 60 | 83 | 353 | 6.3% | 4.6% | 0.053 |

**Best F1: 0.307** at threshold 0.52 (precision 21.6%, recall 52.9%).

## ROC AUC

**AUC = 0.4797** (below 0.50 = random baseline)

The engine is slightly worse than a coin flip at ranking compromised vs normal users. This is because several high-weight detectors are **anti-correlated** with compromise on LANL data.

## Per-Detector Contribution to Separation

Sorted by absolute delta (compromised mean - normal mean):

| Detector | Weight | Comp Mean | Norm Mean | Delta | Direction |
|----------|--------|-----------|-----------|-------|-----------|
| T2-006 Behavioral Shift | 0.023 | 0.545 | 0.137 | **+0.408** | Correct |
| T2-005 Temporal Clustering | 0.047 | 0.019 | 0.268 | -0.249 | **Inverted** |
| T2-002 Entropy Analysis | 0.070 | 0.325 | 0.555 | -0.230 | **Inverted** |
| T2-001 Distribution Divergence | 0.070 | 0.573 | 0.789 | -0.216 | **Inverted** |
| T1-009 Host Fan-Out | 0.116 | 0.794 | 0.678 | **+0.116** | Correct |
| T1-001 Volume Anomaly | 0.140 | 0.917 | 1.000 | -0.084 | **Inverted** |
| T2-003 Cross-Account Corr | 0.070 | 0.885 | 0.964 | -0.079 | **Inverted** |
| T1-002 Automation Signature | 0.163 | 0.000 | 0.073 | -0.073 | **Inverted** |
| T1-008 Concurrent Sessions | 0.070 | 0.835 | 0.776 | +0.058 | Correct |
| T2-004 Power-Law Deviation | 0.047 | 0.164 | 0.215 | -0.051 | **Inverted** |
| T1-007 Error Pattern | 0.093 | 0.190 | 0.150 | +0.040 | Correct |
| T1-004 Session Anomaly | 0.093 | 0.158 | 0.118 | +0.039 | Correct |

### Key Takeaway

Only **5 of 12 active detectors** point in the right direction:
- **T2-006 Behavioral Shift (+0.41)** — the dominant positive signal by far
- **T1-009 Host Fan-Out (+0.12)** — new detector works as intended
- T1-008, T1-007, T1-004 — small positive contributions

**7 detectors are anti-correlated** — they score normal users higher than compromised users. The worst offenders:
- T2-005 Temporal Clustering (-0.25): normal LANL users have burstier patterns than compromised
- T2-002 Entropy Analysis (-0.23): normal users have more diverse behavior
- T2-001 Distribution Divergence (-0.22): normal users diverge more from population
- T1-001 Volume Anomaly (-0.08): adapter sampled top users by event count, so normal users are the highest-volume accounts

## Why It's Still Below Random

The anti-correlated detectors carry **0.607 total weight** (60.7%), drowning out the correctly-oriented signals at 0.393 weight (39.3%). The engine is actively penalizing the wrong group.

**Root cause**: The adapter samples normal users by descending event count. This means the most active users — those most likely to trigger volume, automation, temporal, and divergence detectors — are disproportionately normal. Compromised users are included regardless of activity level, so they're often lower-volume.

## Remaining Gaps and Next Steps

### Immediate wins (would flip AUC above 0.5)

1. **Zero or invert anti-correlated detectors for auth profile**: Extend `apply_auth_profile()` to also zero T2-005, T2-002, T2-001, T1-001, T2-003, T1-002 (or invert their contribution). This would let T2-006 and T1-009 dominate, which would immediately push AUC above 0.5.

2. **Increase T2-006 Behavioral Shift weight**: It has the strongest separation signal (+0.41 delta) but only 0.023 weight (2.3%). Boosting it to 0.10-0.15 would dramatically improve detection.

3. **Fix sampling bias**: Sample LANL users uniformly by event count rather than top-N. Current sampling over-represents high-activity normal users, which inflates their scores on volume-sensitive detectors.

### Medium-term improvements

4. **Window-level red team alignment**: The current evaluation marks a user as compromised across their entire timeline. LANL red team labels are timestamped — a user is compromised at specific moments. Aligning detection windows with compromise timestamps would be a fairer evaluation and would likely show higher AUC for the windowed approach.

5. **Session-level fan-out**: T1-009 uses topic_category as a host proxy (9 buckets). Adding the actual destination computer to the PARALLAX event schema (or using conversation_id patterns) would give finer-grained fan-out measurement.

6. **Auth failure sequences**: LANL lateral movement involves credential spraying — bursts of auth failures followed by a success on a new host. A dedicated detector for this pattern would be high-signal.

### Structural limitations

7. **LANL compromise != API abuse**: PARALLAX detectors model API platform abuse (token extraction, model distillation). LANL red team models Active Directory lateral movement. The threat models are fundamentally different. Full convergence requires either (a) LANL-specific detection rules, or (b) a real AI platform auth log dataset with labeled abuse.

8. **Partial data**: Only 4% of auth.txt.gz was processed. Full dataset (1.05B events) may show different distributions and stronger signals.

## Honest Assessment

The v2 changes are a step forward — T1-009 and windowed T2-006 generate real signal — but the engine still can't reliably distinguish compromised from normal users on LANL data. The core problem is that most detectors were designed for a different threat model and actively anti-correlate with the ground truth in this dataset.

Getting meaningful detection on LANL data requires aggressively pruning anti-correlated detectors for auth profiles (immediate), adding auth-specific rules like credential spray detection (medium-term), and addressing the sampling bias that inflates normal user scores (simple fix).

The path to AUC > 0.7 is visible: T2-006 alone provides +0.41 separation, and T1-009 adds +0.12. If the anti-correlated noise is silenced, these two signals would dominate and push well past random.
