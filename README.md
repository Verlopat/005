# Three-Phase Security Research Pipeline

The root `main.py` now orchestrates the current `Phase_1` LightGBM pipeline,
validates its exported alerts, runs Phase 2 evidence logging, and replays the
same events through Phase 3 synchronous/asynchronous experiments. It does not
invoke the removed STAHN submission or silently substitute predictions.

## Quick start

Use Python 3.11 or newer. The launcher works from any current directory.

```bash
# Safe first check: prints the full plan, creates/installs nothing.
python main.py all --mode train --dry-run

# Executable integration test, without the external dataset or trained model.
# These are SYNTHETIC fixtures, never detection or thesis performance results.
python main.py all --mode smoke --install --limit 100 --repeats 3

# Check that the exported real-data prerequisites are present.
python main.py all --mode existing --check

# Process real Phase 1 exports, then log and benchmark exactly those alerts.
python main.py all --mode existing --install --limit 1000 --repeats 5

# Run all ten training/evaluation/export stages, then Phases 2 and 3.
# Requires the external dataset; training can take hours.
python main.py all --mode train --install --limit 1000 --repeats 5
```

`--install` creates/reuses `.venv` and installs the selected dependency sets in
one pip invocation. Without it, the launcher reuses `.venv` if present, otherwise
the current interpreter. `--python /path/to/python` explicitly selects an existing
environment. Installation is opt-in and is not repeated on every run.

## Modes and prerequisites

| Mode | Phase 1 operation | Required local artifacts |
|---|---|---|
| `train` | Stages 01 through 10, in order, followed by handoff validation | `Phase_1/data/NF-CSE-CIC-IDS2018-v2.csv` |
| `existing` (default) | Validate already-exported alerts; no retraining | `outputs/09_model/detector_bundle.joblib`, `model_card.json`, `outputs/10_contract/sample_alerts.jsonl`, under `Phase_1` |
| `smoke` | Generate explicitly synthetic contract fixtures | Committed schema/model-card metadata; no trained model or raw dataset |

The raw dataset, model bundle, and full alert JSONL are not included in this
checkout. Committed metrics do not replace those artifacts. Existing mode can
read another full alert stream with `--alerts /path/to/sample_alerts.jsonl`.
It never loads untrusted joblib/pickle files: the bundle is hashed for provenance,
not deserialized by the adapter.

The ordered training sequence is:

```text
01_inspect -> 02_prepare -> 03_artifact_check -> 04_select_features
-> 05_compare_models -> 06_tune -> 07_metrics_report
-> 08_calibration_icr -> 09_export_model -> 10_alert_contract
-> validated handoff -> Phase 2 -> Phase 3
```

`11_demo.py` and interactive predictors are intentionally not in unattended runs.
The launcher does not change dataset splits, selected features, thresholds,
calibration fitting, model design, or either frozen alert schema.

## Individual phases

```bash
python main.py phase1 --mode train --install
python main.py phase2 --mode existing --install --run-dir runs/experiment-a
python main.py phase3 --mode existing --run-dir runs/experiment-a --repeats 5
```

For a standalone Phase 3 smoke replay, pass `--mode smoke` and the directory of
a completed Phase 2 smoke run. Phase 3 rejects mode mismatches and changed event
files. Output directories are exclusive: a repeat execution cannot silently
overwrite an earlier experiment. To retry a failed experiment, use a new run
directory; automatic resume is deliberately not offered for non-idempotent
training scripts.

## Cross-phase data contract

`pipeline/run_stage.py` is an explicit adapter between the two existing contracts.
It validates Phase 1 schema, event hash, feature digest, model-card version,
feature names, duplicate IDs, and verdict/category consistency before submission.
The mapping is `NORMAL -> BENIGN`, `ANOMALY -> ATTACK`, `Bot -> Botnet`,
`Web Attacks -> Web-based`; other shared categories retain their names.

Confidence remains isotonic-calibrated **P(attack)**, not multiclass correctness
or confidence in the predicted verdict. Phase 1's `anchor` boolean is preserved
exactly, including normal-verdict flows it elects to anchor. It is not recomputed
from rounded exported confidence/gate values. Critical anchored events submit
immediately; the remaining anchored events enter the existing Merkle batch path.
An absent resource ID becomes the explicitly unknown `unknown-resource`, not
a fabricated cloud inventory match.

Original alerts are kept in content-addressed evidence storage. `mapping.json`
records original event hashes, source content addresses, translated payload
digests, destination addresses, and anchor decisions. The new full-bundle
provenance digest includes the serialized calibrator through the bundle bytes;
it is distinct from Phase 1's model ID. The adapter checks card/alert association
but does not claim to independently reproduce predictions from supplied exports.
Run manifests and mappings are local audit records, not externally signed
experiment attestations.

## Results and reproducibility

Each run writes under `runs/<UTC timestamp>/` (or `--run-dir`):

- `manifest.json`: phase status, commands, interpreter selection, input/code hashes,
  timestamps, return codes, and elapsed times.
- `environment-info.log`: actual Python version and installed package versions.
- Per-step logs: combined stdout/stderr; a failed step prevents later phases.
- `phase1/`: validated source alerts and provenance metadata.
- `phase2/`: translated events, mapping, source evidence, handoff hashes, audit results.
- `phase3/`: independent paired sync/async trials with fresh stores and identities.

Phase 3 alternates trial order and measures the same inputs and policy in each
pair. It reports per-trial throughput, service-time p50/p99, async accounting,
and post-flush ledger audits. It does not assume asynchronous processing must
be faster. One async consumer avoids racing the existing mutable batch state.

These choices support inspectable and exercisable artifacts, consistent with
[ACM's software and data artifact guidance](https://www.acm.org/publications/artifacts).
They are not a claim of independent reproduction or an ACM badge.

## Research limits and legacy tooling

Both logging and replay currently use **MockLedger**, not deployed Hyperledger
Fabric. No Fabric consensus latency, Kafka durability, distributed scaling,
24-hour stability, new classification accuracy, or ground-truth ICR is established
by this launcher. Phase 3 service latency excludes queue residence and final
batch flush; total throughput includes drain/shutdown and flush, but excludes audit.
The existing Phase 2 batch implementation still writes one mock event record per
alert; a Merkle root here is not evidence of one real Fabric transaction per batch.

Old `generate_phase2_results.py`, `run_phase2_demo.py`, `run_load_test.py`, and
`generate_phase3_results.py` still describe or depend on removed STAHN/CICIoT2023
artifacts. They are legacy experiments, not this launcher's active execution path.
Their committed paper reports must not be presented as results from the new model.
The broad legacy load/stability suites also need dataset migration before they
can validate the new detection distribution.

Full training and real-data end-to-end validation require the missing artifacts.
Keep a pinned environment/lockfile from the machine that trained the model for
exact replay; the supplied requirements specify ranges, not a guaranteed
historical environment. Review held-out evaluation, statistical uncertainty, and
deployment evidence separately before making thesis claims.

## Tests

```bash
.venv/bin/python -m pytest tests/test_main_pipeline.py Phase2_Blockchain_Logging/tests -q
```

On Windows replace `.venv/bin/python` with `.venv\Scripts\python.exe`.
The root regression tests cover execution order, fail-fast behavior, missing
inputs, overwrite protection, digest/schema checks, category mapping, confidence
semantics, tampering, synthetic/real separation, and a complete subprocess smoke run.
