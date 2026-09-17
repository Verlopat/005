# Phase 2 — Blockchain-Based Tamper-Proof Security Event Logging

## Current integrated entry point

Use `python main.py phase2 --mode existing --install --run-dir runs/experiment-a`
from the repository root for the current `Phase_1` exports. Use `--mode smoke`
for a clearly synthetic test without trained artifacts. See the root README
for the validated adapter and run-manifest format.

Phase 2 establishes the integrity and provenance layer for the Phase 1
intrusion-detection layer in `../Phase_1`, implementing **Objective 2** of the
project (see `Research_Objectives_Revised.docx`). Phase 1 classifies traffic;
Phase 2 creates cryptographically verifiable, tamper-evident evidence of
selected detection events and makes that evidence independently auditable.

## Status: Objective 2 complete for this phase

Everything below is implemented and tested in this repository, running
against a local mock ledger that requires no Docker, Go, or Fabric network
(`config/phase2.example.yaml`'s default, `ledger.enabled: false`).
Real Hyperledger Fabric deployment artifacts are provided for production
use once a suitable host is available — see "Two deployment targets"
below. Load testing, asynchronous Kafka pipelines, and comparative
benchmarking are **Objective 3** and are deliberately not built here.

## The detection layer of record

Phase 2 and Phase 3 are aligned to one detector, and it is the one in `../Phase_1`:

| Property | Value | Source |
|---|---|---|
| Architecture | LightGBM multiclass, 7 coarse threat categories | `Phase_1/outputs/09_model/model_card.json` |
| Dataset | NF-CSE-CIC-IDS2018-v2, 18,893,708 NetFlow records ([distribution](https://staff.itee.uq.edu.au/marius/NIDS_datasets/)) | Phase 1 `README.md`, `config.py` |
| Features | 25, identifiers excluded by construction | model card |
| Calibration | isotonic, fitted on the validation fold, measured ECE 8.14e-05 | `outputs/08_calibration_icr/` |
| Macro-F1 / accuracy | 0.8172 / 0.9954 (held-out test fold) | `outputs/07_metrics/metrics_table.csv` |
| Anchoring gate | tau = 0.9997655, ICR 0.9568, 88.6% write reduction | model card `anchoring_gate` |

No file in Phase 2 or Phase 3 restates these values. They are read at run time
from Phase 1's own committed artefacts by `src/detection_layer.py`, so a Phase 1
retrain cannot leave a stale figure behind in a downstream report. Phase 1 itself
is never modified by these phases.

### What changed, and why

Earlier revisions of Phase 2 and Phase 3 were written against a different
detector: a PyTorch binary classifier ("STAHN") trained on CICIoT2023 and
reported at 98.62% accuracy. That is not the detector in this repository -
different architecture, different dataset, different label space - so any figure
inherited from it was not a statement about this project. Concretely, the
following were corrected:

- The alert contract admitted CICIoT2023 categories (`Mirai`, `Recon`,
  `Spoofing`, `Web-based`, `Other`) that the deployed detector cannot emit. The
  enum is now exactly Phase 1's seven categories, and the contract version is
  bumped to **2.0.0**.
- Every event recorded `calibration.is_calibrated: false`. Phase 1 *is*
  isotonic-calibrated, and Objective 3's anchoring gate is only defensible
  against a calibrated score, so this understated the work.
- The provenance record named `stahn-phase1` / `stahn_v1_98.62_acc` and a
  CICIoT2023 training summary. It now carries Phase 1's own `model_id_sha256`,
  version label, feature order, label order, hyperparameters, per-class
  thresholds and dataset.
- The comparative benchmark reported this framework's accuracy as 0.9862 with
  attack precision 0.9959. Those were the other model's numbers.
- Phase 3's load generator read a `CICIoT2023_Sample.csv` that does not exist in
  this repository, which broke 11 tests.

### Two digests, deliberately

Phase 1 freezes its own cross-layer digest (`event_hash`: fixed field order,
pipe-joined, six-decimal floats) and its `CONTRACT.md` designates that value for
on-chain commitment. Phase 2 therefore **re-implements Phase 1's digest rules
independently** in `src/phase1_contract.py` and verifies itself against Phase 1's
own fixed test vectors (currently 6/6 reproduced). Importing Phase 1's function
instead would only prove that a function equals itself; two independent
implementations agreeing on shared vectors is the evidentiary claim Objective 2
needs.

So each event carries two digests with distinct scopes, both verified:

| Digest | Scope | Computed by | Anchored |
|---|---|---|---|
| `detection_contract.event_hash` | Phase 1's frozen field set | producer, re-verified by Phase 2 | yes |
| `payload_digest` | Phase 2's canonical-JSON envelope | Phase 2, mirrored by the Go chaincode | recorded |

A corrupted alert is rejected at ingestion rather than anchored.

## Evidence model

1. The detector emits a versioned alert conforming to
   `contracts/alert_event.schema.json` (`src/alert_builder.py`).
2. The alert is canonically serialised (`src/canonical.py`, per
   `docs/canonicalisation_spec.md`).
3. The canonical payload is hashed with SHA-256 (`src/digest.py`) and
   signed by the detection agent (`src/signing.py`, Ed25519).
4. The complete payload is persisted off-chain under a content-derived
   address (`src/evidence_store.py`).
5. A compact evidentiary record is committed to the ledger — individually
   or as a Merkle batch root under load (`src/merkle.py`,
   `src/anchoring_policy.py`, `src/pipeline.py`) — via a pluggable ledger
   client (`src/ledger/`: `MockLedger` locally, `FabricGatewayLedger` in
   production).
6. An auditor independently retrieves the payload, recomputes the digest,
   validates the signature, and queries the ledger's history
   (`src/audit.py`).

No claim of on-chain confirmation is valid unless a transaction ID and
committed status have been returned by the ledger (`LedgerReceipt`).

## Two deployment targets

| | Local development / this sandbox | Production |
|---|---|---|
| Ledger | `src/ledger/mock_ledger.py` — in-memory, hash-chained, tamper-evident, no external dependency | `src/ledger/fabric_gateway.py` against `network/` (2-org Fabric consortium, Raft ordering, Go chaincode) |
| Requires | Python 3.11+, `pip install -r requirements.txt` | + Docker, Go 1.21+, Fabric binaries/images (`network/scripts/network-up.sh`) |
| Switch via | `config/phase2.example.yaml`: `ledger.enabled: false` (default) | `ledger.enabled: true`, `ledger.backend: fabric`, valid `gateway_config` |

## Install Phase 2 Python dependencies

```bash
python -m pip install -r Phase2_Blockchain_Logging/requirements.txt
```

Fabric-only dependencies (grpc, the Fabric Gateway client, IPFS client) are
kept separate in `requirements-fabric.txt` so the default path never needs
them.

## Generate the paper results (single command)

```bash
python3 run_phase2.py
```

Run this from the repository root. It checks dependencies, then runs the
full pipeline over real rows of `../Phase1_Submission/CICIoT2023_Sample.csv`
and measures every metric in Objective 2's Success Metrics table
(throughput, commit latency, on-chain storage overhead, integrity
verification failure rate plus a live tamper-injection proof, Integrity
Coverage Ratio, canonical digest agreement, model provenance
traceability, non-repudiation). It prints the full report to the terminal
and writes it to:

- `Phase2_Blockchain_Logging/outputs/phase2_results.md` — a ready-to-paste
  Markdown table plus methodological notes for your paper's evaluation
  section (these are committed to the repo so the numbers are citable).
- `Phase2_Blockchain_Logging/outputs/phase2_results.json` — the same
  numbers as raw data, for plotting.

Tune the run with `python3 run_phase2.py --num-events 5000 --gate 0.95`
(more rows for tighter statistics; `--gate` sets the anchoring confidence
threshold the Integrity Coverage Ratio metric is reported at). The report
is explicit about which figures are genuine software-layer measurements
versus what still requires a deployed Fabric network, per the 'Two
deployment targets' section above and the report's own 'Methodological
notes' section, which should be read before citing a number in a paper.

## Run the end-to-end demo (no Docker/Fabric required)

```bash
python3 Phase2_Blockchain_Logging/scripts/run_phase2_demo.py
```

Consumes the alerts Phase 1 already emitted
(`../Phase_1/outputs/10_contract/sample_alerts.jsonl`), verifies each one's
producer digest, runs them through the full pipeline against a local
`MockLedger`, prints an Integrity Coverage Ratio sweep and the effect of
class-aware gate flooring, and ends with a compliance report.

Phase 2 does not re-run inference: re-deriving a verdict here would duplicate
Phase 1 while risking a different answer, and Objective 2's claims are about
evidence, not detection. If Phase 1's alert stream is absent - it is excluded
from version control by `Phase_1/.gitignore`, so a fresh clone will not have it -
the script falls back to explicitly-synthetic Phase 1-shaped alerts whose
`model_version` is `SYNTHETIC-FIXTURE-NOT-A-DETECTION`, and says so. The evidence
pipeline is exercised either way; only the detection figures differ.

```bash
python3 Phase2_Blockchain_Logging/scripts/tamper_demo.py
```

Anchors one event, corrupts the ledger's stored record directly (bypassing
every public API), and proves both the ledger's own chain-integrity check
and the independent audit workflow detect it.

```bash
python3 Phase2_Blockchain_Logging/scripts/audit_cli.py history --resource i-demo-0000
python3 Phase2_Blockchain_Logging/scripts/audit_cli.py verify <event_id>
python3 Phase2_Blockchain_Logging/scripts/audit_cli.py report
```

Auditor CLI, reading the state `run_phase2_demo.py` persisted under
`.phase2_runtime/` (git-ignored).

## Contract validation

```bash
python3 Phase2_Blockchain_Logging/scripts/validate_commit1.py
```

Validates both JSON Schemas and every canonical digest test vector. A
successful run ends with `Commit 1 contract validation passed.`

## Run the tests

```bash
python -m pytest Phase2_Blockchain_Logging/tests/ -v
```

56 tests covering canonicalisation/digest cross-checks against the shared
vector file, signing, content-addressed storage, Merkle batching and
inclusion proofs, the anchoring policy (including Integrity Coverage
Ratio and per-category gate flooring), the mock ledger's access control
and tamper-evidence, model provenance digesting, and the full pipeline +
audit workflow including a tampering scenario.

## Deploying the real Hyperledger Fabric network

Requires Docker, Go 1.21+, and the Fabric binaries/images on the host —
none of which are available in the sandbox this repository was built in,
so this path is provided as a complete deployment artifact rather than
something exercised automatically here.

```bash
cd Phase2_Blockchain_Logging/network
./scripts/network-up.sh        # cryptogen + configtxgen + docker compose up + channel create/join
./scripts/deploy-chaincode.sh   # package/install securitylog chaincode on both orgs
# then approve + commit the chaincode definition per the printed instructions
./scripts/network-down.sh      # tear down and clean generated artifacts
```

See `chaincode/securitylog/README.md` for the chaincode itself and
`docs/architecture.md` for the Hyperledger Fabric vs. private Ethereum
comparison Objective 2 calls for, plus the hybrid on-chain/off-chain
storage rationale.

## Documentation index

- `docs/canonicalisation_spec.md` — the normative cross-language digest
  specification (`src/canonical.py` / `chaincode/securitylog/canonical.go`).
- `docs/evidence_lifecycle.md` — the full lifecycle, step by step, with
  file references.
- `docs/architecture.md` — Fabric vs. Ethereum comparison; hybrid storage
  rationale; where Objective 3 picks up.
- `docs/compliance_mapping.md` — ISO 27001 / SOC 2 / NIST SP 800-92
  control-to-evidence mapping for `src/audit.py:compliance_report`.

## Repository layout

```
Phase2_Blockchain_Logging/
├── contracts/                  # frozen JSON Schemas + shared digest test vectors
├── config/                     # example configuration (no secrets)
├── docs/                       # normative specs and design rationale
├── src/                        # canonicalisation, signing, storage, policy,
│                                # Merkle batching, ledger clients, pipeline, audit
├── chaincode/securitylog/      # Go chaincode: LogSecurityEvent/VerifyEvent/
│                                # QueryEventHistory + model provenance
├── network/                    # Fabric consortium deployment artifacts
├── scripts/                    # validate_commit1, run_phase2_demo, tamper_demo, audit_cli
└── tests/                      # pytest suite (56 tests)
```

## Amendments arising from Phase I (Objective 2, as revised)

- **Merkle batching is a throughput dependency, not an optimisation.** At
  the measured 11.43% deployment gate and the 10,000 events/sec peak
  arrival rate specified in Objective 3, individual commitment requires
  ~1,143 transactions/sec against a 1,000 TPS target. A batch factor of
  100 brings this to ~12 tx/sec. `src/merkle.py:required_batch_factor_for_target_tps`
  makes this arithmetic reusable and testable rather than one-off prose.
- **Integrity Coverage Ratio is a success metric**, not assumed: a system
  that anchors nothing satisfies every throughput/latency/integrity target
  otherwise, so `src/anchoring_policy.py:integrity_coverage_ratio` and the
  demo's ICR sweep make evidentiary completeness explicit and measured.
