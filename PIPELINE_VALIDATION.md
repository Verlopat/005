# Pipeline Update and Validation

Repository: https://github.com/Verlopat/005
Inspected baseline: `a5d4c03` (integrated three-phase pipeline)

This document records what was changed, what was verified by execution, and what
remains unverified. It is written to be read by a reviewer, so limitations are
stated rather than implied.

## 1. The problem this change fixes

Phase 2 and Phase 3 were written against a **different detector** from the one in
`Phase_1`:

| | Phase 1 (actual) | What Phases 2 and 3 assumed |
|---|---|---|
| Architecture | LightGBM multiclass | PyTorch binary classifier ("STAHN") |
| Dataset | NF-CSE-CIC-IDS2018-v2 (18,893,708 flows) | CICIoT2023 |
| Label space | 7 coarse categories | binary + CICIoT2023 families |
| Calibration | isotonic, ECE 8.14e-05 | recorded as *absent* |
| Reported accuracy | 0.9954 | 0.9862 |

A reviewer comparing the phases would have found the same framework described two
incompatible ways. Phase 1 was **not modified**; Phases 2 and 3 were retargeted
onto it.

## 2. What changed

### Phase 1 is now the single source of truth

`Phase2_Blockchain_Logging/src/detection_layer.py` reads the label space, feature
order, calibration method and ECE, per-class confidences, anchoring gate, class
thresholds and test metrics from Phase 1's own committed artefacts
(`model_card.json`, `metrics_table.csv`, `icr_per_class.csv`,
`calibration_metrics.csv`, `severity_map.json`). Nothing downstream restates a
detection figure, so a Phase 1 retrain cannot leave a stale number in a report.
Missing artefacts raise `DetectionLayerUnavailable` rather than substituting a
placeholder.

### Alert contract bumped to 2.0.0

- `threat_category` enum is now exactly Phase 1's seven categories. The
  CICIoT2023 families and the `Other` escape hatch are gone.
- `calibration` is required and reports `isotonic` with the measured ECE.
- New required `detection_contract` block carries the producer's own
  `event_hash`, `feature_digest`, gate tau and anchor decision, plus
  `digest_verified_by_consumer`.
- Severity is carried through from Phase 1's severity map, **not** re-derived
  from confidence — Phase 1 rates Infiltration `critical` despite measuring its
  mean confidence at 0.303, and a confidence-derived severity would silently
  overturn that.

### Independent cross-layer digest verification

`src/phase1_contract.py` re-implements Phase 1's frozen digest rules from the
specification and verifies itself against Phase 1's own fixed vectors. Importing
Phase 1's function would only prove a function equals itself; two independent
implementations agreeing on shared vectors is the actual evidentiary claim.
**Result: 6/6 vectors reproduced.**

### Class-aware anchoring floor, grounded in Phase 1's measurements

`config/anchoring-policy.example.yaml` now uses Phase 1's real gate
(tau = 0.9997655) and floors Infiltration at 0.002786 — the tau at which Phase 1's
own operating-point table reaches ICR 0.999, where Infiltration retains ICR 0.983.
The cost (higher on-chain volume for that category) is stated in the file.

### Comparative benchmark rebuilt on matched-dataset evidence

Own-framework figures are read from Phase 1's metrics table. Published
NF-CSE-CIC-IDS2018-v2 baselines were added, so the detection comparison is now
matched on dataset ([Scientific Reports 15:21158, 2025](https://www.nature.com/articles/s41598-025-08905-3), Table 10).

Three own-framework rows are emitted (weighted / macro / binary F1) because the
published baselines all report **weighted** F1 while this project optimises
**macro** F1. Reporting only macro against weighted baselines understates the
work; reporting only weighted overstates class-balanced performance.

### Cumulative phase execution

`python main.py phase2` now runs Phase 1 then Phase 2; `phase3` runs all three.
`--only` runs a single phase. Ordering is enforced by digest checks at each
handoff.

## 3. Two bugs found and fixed during this work

**(a) Synthetic events inherited the real model's calibration error.**
The adapter back-filled the deployed model's measured ECE whenever a caller passed
none, so a synthetic or uncalibrated event could carry a real measurement it did
not earn. Fixed: an uncalibrated score reports no calibration error. Regression
test added.

**(b) The claimed Python/Go digest agreement did not hold.**
`canonical.go` rendered floats with `strconv.FormatFloat(f, 'g', -1, 64)`, which
renders an integral `6.0` as `"6"` where Python's `repr` gives `"6.0"`, and `1e15`
as `"1e+15"` where Python gives `"1000000000000000.0"`. The existing v1 test
vector expects `6.0`, so the Go conformance test would have **failed** — the
cross-language claim was unverified because Go is not installed in this
environment. Feature vectors are full of integral floats, so this affected
ordinary alerts, not edge cases.

Fixed by implementing Python-`repr`-compatible formatting in `canonicalFloat`
(decimal notation for decimal exponents in [-4, 15] with a forced fractional
part, exponent notation with ≥2 exponent digits otherwise).

## 4. What was verified by execution

| Check | Result |
|---|---|
| Full test suite (`tests/`, Phase 2, Phase 3) | **192 passed** |
| Previously failing Phase 3 tests (missing CICIoT2023 file) | 11 now pass, unmodified |
| Cross-layer digest vectors (Phase 1 → Phase 2) | 6/6 reproduced |
| Go float algorithm vs Python `repr` | 20 boundary cases + 6,000 randomised values agree |
| Canonicalisation vectors self-consistency | 7/7 |
| `main.py phase1` / `phase2` / `phase3` / `--only phase3` | all succeed |
| Phase 2 demo, tamper demo | pass; tamper detected by audit *and* chain check |
| Phase 2 and Phase 3 report generators | both produce reports |

The Go algorithm was validated by transcribing `canonicalFloat` into Python and
testing it against `repr` across 6,000 values. A guard test fails if
`canonical.go` drifts from the transcribed rule.

## 5. Limitations — not yet validated

- **No real-data run.** `Phase_1/data/NF-CSE-CIC-IDS2018-v2.csv`,
  `detector_bundle.joblib` and `sample_alerts.jsonl` are absent from the
  repository (`Phase_1/.gitignore` excludes the last two). Every run here used
  explicitly-synthetic Phase 1-shaped alerts marked
  `SYNTHETIC-FIXTURE-NOT-A-DETECTION`. **No detection or performance figure
  produced in this environment is a research result.**
- **`go test` was not run.** Go is not installed here. The float fix is validated
  only through the Python transcription described above. Run
  `go test ./Phase2_Blockchain_Logging/chaincode/securitylog/` on a host with Go
  before claiming Python/Go digest agreement in the thesis.
- **MockLedger, not Fabric.** No consensus, endorsement policy, ordering service
  or network latency is measured. All latency and throughput figures are
  single-host software-layer measurements.
- **Provenance traceability is not demonstrated** without Phase 1's exported
  artifact; runs without it use a placeholder `model_digest` and say so.
- **Comparative latency is not matched protocol.** Only the detection comparison
  is dataset-matched.
- **Objective 3 metric 3c remains a measured gap** (~93% vs the >99% byte-volume
  target), reported rather than adjusted.

## 6. To validate on real data

```bash
# 1. Place the dataset (see https://staff.itee.uq.edu.au/marius/NIDS_datasets/)
#    at Phase_1/data/NF-CSE-CIC-IDS2018-v2.csv

# 2. Confirm prerequisites without running anything
python main.py phase3 --mode existing --check

# 3. Full training run, then logging, then replay (hours; stages 05/06 dominate)
python main.py phase3 --mode train --install

# 4. Or, if the bundle and alert stream already exist locally
python main.py phase3 --mode existing --install --limit 1000 --repeats 5

# 5. Cross-language digest conformance, on a host with Go
go test ./Phase2_Blockchain_Logging/chaincode/securitylog/
```
