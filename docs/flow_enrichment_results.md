# Flow Enrichment Results — T1-010 DataTransferAnomaly

**Date:** 2026-04-09
**Dataset:** LANL Cyber1, 500 accounts (87 compromised, 413 normal), 16.9M events
**Evaluation:** Windowed scoring (4h windows, 1h stride) with auth profile

## Summary

Added T1-010 DataTransferAnomaly to detect data exfiltration via abnormal byte
volume. The detector flags sessions where bytes transferred exceeds 2.5 sigma
from the entity's rolling baseline.

**Flow data source:** Synthetic flow injection (LANL `flows.txt.gz` requires
registration at csr.lanl.gov). Compromised accounts receive 8% exfiltration
spike sessions (10-50x byte volume), modeling realistic lateral-movement-then-
exfiltrate patterns.

## Baseline (No Flow Enrichment)

| Metric | Value |
|--------|-------|
| ROC AUC | 0.6776 |
| Best F1 | 0.4855 |
| Best Threshold | 0.77 |
| Compromised Mean | 0.5986 |
| Normal Mean | 0.4832 |
| Separation (delta) | +0.1154 |
| Active Detectors | 5 |

### Baseline Per-Detector Contribution

| Detector | Comp Mean | Norm Mean | Delta |
|----------|-----------|-----------|-------|
| T1-004 Session Anomaly | 0.1419 | 0.1058 | +0.0361 |
| T1-007 Error Pattern | 0.1802 | 0.1726 | +0.0075 |
| T1-008 Concurrent Sessions | 0.8231 | 0.7721 | +0.0510 |
| T1-009 Host Fan-Out | 0.7873 | 0.6561 | +0.1312 |
| T2-006 Behavioral Shift | 0.7143 | 0.4277 | +0.2866 |

## Flow-Enriched (With T1-010)

*Evaluation running on 16.9M flow-enriched events. Results pending.*

| Metric | Baseline | Flow-Enriched | Delta |
|--------|----------|---------------|-------|
| ROC AUC | 0.6776 | *pending* | |
| Best F1 | 0.4855 | *pending* | |
| Compromised Mean | 0.5986 | *pending* | |
| Normal Mean | 0.4832 | *pending* | |
| Active Detectors | 5 | 6 | +1 |

### Weight Distribution (Flow-Enriched Profile)

| Detector | Baseline Weight | Flow Weight |
|----------|----------------|-------------|
| T2-006 Behavioral Shift | 0.30 | 0.27 |
| T1-009 Host Fan-Out | 0.25 | 0.22 |
| T1-008 Concurrent Sessions | 0.20 | 0.18 |
| T1-007 Error Pattern | 0.15 | 0.13 |
| T1-004 Session Anomaly | 0.10 | 0.10 |
| **T1-010 Data Transfer** | **0.00** | **0.10** |

## T1-010 Detector Design

- **Algorithm:** Rolling z-score of per-session bytes transferred
- **Threshold:** 0.4 (score > threshold = triggered)
- **Sigma threshold:** 2.5 standard deviations
- **Scoring:** Sigmoid normalization of peak z-score
- **Zero-variance handling:** Synthetic sigma (1% of mean) when baseline is constant
- **Confidence:** Scales with both event count and flow data availability ratio
- **Graceful degradation:** Returns score=0 with `no_flow_data` reason when
  bytes_transferred is absent (existing events without flow enrichment are unaffected)

## Architecture Changes

### Data Model (additive only)
- `APIEvent`: Added optional `bytes_transferred` (default 0), `connection_duration_sec` (default 0)
- `AccountProfile`: Added `bytes_transferred_list`, `total_bytes_transferred`, `avg_bytes_per_event`, `connection_durations_sec`, `avg_connection_duration_sec`

### LANL Adapter
- Added `build_flow_pair_index()`: Indexes flows by `(src_computer, dst_computer)` with binary search
- Added `LANLProfileBuilder.get_flow_for_auth()`: Joins auth events with flow events by timestamp window + source + destination
- Emits `bytes_transferred` and `connection_duration_sec` per event

### Pipeline
- `register_default_detectors()` now registers 16 detectors (was 15)
- `apply_auth_profile(flow_enriched=True)` activates T1-010 with redistributed weights
- T1-010 default weight is 0.0 (no impact on non-flow workloads)

### Tests
- 10 new tests for T1-010 detector (threshold, spike detection, confidence, edge cases)
- Updated integration tests for 16-rule count
- All 132 non-async tests pass

## Caveats

1. **Synthetic flow data:** The enrichment uses injected flow patterns rather than
   actual LANL `flows.txt.gz` (which requires registration). Results are indicative
   of detector capability, not a true LANL evaluation.

2. **Known signal correlation:** Spike sessions are injected at 8% rate for compromised
   accounts, creating a synthetic correlation. Real flow data would have noisier patterns.

3. **To reproduce with real LANL flows:**
   ```bash
   python lanl_adapter.py \
     --auth scripts/auth.txt.gz \
     --flows scripts/flows.txt.gz \
     --redteam scripts/redteam.txt.gz \
     --output data/lanl/parallax_events_real_flow.jsonl \
     --sample-users 500

   python scripts/lanl_evaluate.py \
     data/lanl/parallax_events_real_flow.jsonl \
     --redteam scripts/redteam.txt.gz \
     --output data/lanl/evaluation_real_flow.csv \
     --flow-enriched
   ```
