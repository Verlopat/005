# Pipeline Update and Validation

Repository: https://github.com/Verlopat/005

Inspected baseline: `10c2ff1ac5a6739f3b26f25cb1744bc4e35115be`

Local validation date: 17 September 2026

## Implemented

The root launcher now targets `Phase_1`, not the removed `Phase1_Submission`.
Training mode invokes the ten current scripts in their documented order and
then validates the exported handoff. Existing mode processes real exported alerts
without retraining. Smoke mode creates explicit synthetic fixtures.

The active Phase 2 path validates and translates the two frozen alert formats
without changing either schema, preserves the source anchoring decision, binds
the complete detector bundle to model provenance, records source/destination
evidence mappings, flushes batches, and verifies the mock ledger.

The active Phase 3 path replays the same Phase 2 events through independent
synchronous and asynchronous trials. It checks input hashes, drains the queue,
rejects dead letters/unaccounted submissions, flushes, audits, and records
per-trial metrics. It uses one consumer because the existing batching object
is not thread-safe.

Run manifests, input/code hashes, resolved package versions, logs, exclusive
output directories, fail-fast behavior, missing-input checks, and CI configuration
are included. Phase 1 requirements now include XGBoost, CatBoost, and
imbalanced-learn, which its comparison script imports.

## Executed validation

Local interpreter: Python 3.14.3 on Linux, isolated `.venv`.

| Check | Observed result |
|---|---|
| New root regression tests, Phase 2 tests, dataset-independent Phase 3 tests | 95 passed |
| All root, Phase 2, and Phase 3 tests together | 95 passed; 11 legacy failures |
| `all --mode smoke --limit 100 --repeats 3` | All three phases completed |
| Smoke Phase 1 | 100 synthetic full alerts validated |
| Smoke Phase 2 | 100 processed; 85 selected anchors verified; 15 off-chain-only |
| Smoke Phase 3 | Six independent replay trials completed and audited |
| Training dry run | Stages 01–10, handoff, Phase 2, Phase 3 in order |
| Real-artifact preflight | Correctly rejects missing bundle and alert stream |
| Patch whitespace validation | `git diff --check` passed |
| GitHub Actions | Workflow supplied; remote CI has not been executed |

The 11 legacy failures are in five load-generator tests, three scalability
tests, and three stability tests. All depend on the removed
`Phase1_Submission/CICIoT2023_Sample.csv`. These tests were not skipped, deleted,
or changed to force a pass. The current launcher does not call that generator;
its replacement integrated path has its own end-to-end regression tests.

## What remains unverified

- Full dataset training: the raw NF-CSE-CIC-IDS2018-v2 dataset is absent.
- Actual exported-model handoff: `detector_bundle.joblib` and
  `sample_alerts.jsonl` are absent.
- Real Fabric consensus, Kafka durability, distributed load, and 24-hour soak.
- Reproduction of historical model metrics or fresh ground-truth ICR.
- Windows execution and the configured Python 3.11/3.12 CI matrix.
- Migration of the old standalone report/load/stability scripts to the new data.

The new replay results are software integration evidence, not thesis-scale
performance evidence. Mock batching still calls the existing ledger once per
anchored event, so Merkle grouping must not be claimed as measured Fabric
transaction reduction. Existing static paper reports contain old-model assumptions
and must not be reused as new-model findings.

The bundle is hashed but not deserialized by the handoff adapter. Its association
with the supplied model card is recorded and alert versions are checked; this is
not independent verification that every supplied prediction came from that bundle.
The manifests/mappings are local records, not signed external attestations.

## Run commands

```bash
# First integration check
python main.py all --mode smoke --install

# Restore exported model bundle and full alert stream, then:
python main.py all --mode existing --check
python main.py all --mode existing --install --limit 1000 --repeats 5

# Or supply the raw dataset and run the entire training workflow:
python main.py all --mode train --install --limit 1000 --repeats 5
```

Default existing mode never fabricates predictions when inputs are unavailable.
For doctoral evaluation, supply the missing artifacts, run in a pinned environment,
review the real-data handoff and held-out metrics, and separately validate the
deployment-scale claims. This distinction between functional artifacts and
independently reproduced results follows the framing in
[ACM's artifact guidance](https://www.acm.org/publications/artifacts).
