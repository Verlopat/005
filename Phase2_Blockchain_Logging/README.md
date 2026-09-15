# Phase 2 — Blockchain-Based Tamper-Proof Security Event Logging

Phase 2 establishes the integrity and provenance layer for the STAHN
intrusion-detection system in `../Phase1_Submission`, implementing
**Objective 2** of the project (see `Research_Objectives_Revised.docx`).
Phase 1 classifies traffic; Phase 2 creates cryptographically verifiable,
tamper-evident evidence of selected detection events and makes that
evidence independently auditable.

## Status: Objective 2 complete for this phase

Everything below is implemented and tested in this repository, running
against a local mock ledger that requires no Docker, Go, or Fabric network
(`config/phase2.example.yaml`'s default, `ledger.enabled: false`).
Real Hyperledger Fabric deployment artifacts are provided for production
use once a suitable host is available — see "Two deployment targets"
below. Load testing, asynchronous Kafka pipelines, and comparative
benchmarking are **Objective 3** and are deliberately not built here.

## A note on Phase 1 alignment

`Research_Objectives_Revised.docx` describes Objective 1's *registered,
revised* detection layer (a calibrated LightGBM cascade on
NF-CSE-CIC-IDS2018-v2, seven-category classification, isotonic
calibration). The code actually delivered in `../Phase1_Submission`
(`blockchain_handoff_document.md`, `blockchain_oracle_api.py`) is the
STAHN binary classifier on CICIoT2023 — the earlier architecture the
revision note says was discontinued. Phase 2's frozen contract
(`contracts/alert_event.schema.json`) is written to the *richer, revised*
specification, and `src/alert_builder.py` is the adapter that lets the
*actually delivered* STAHN oracle populate that contract honestly today
(`calibration.is_calibrated: false`, `threat_category: "Other"` where the
binary classifier cannot resolve a finer category) without blocking on a
Phase 1 rewrite. When/if Phase 1 is upgraded to the registered
LightGBM cascade, no Phase 2 code changes — only `alert_builder.py`'s
adapter logic becomes simpler.

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

## Run the end-to-end demo (no Docker/Fabric required)

```bash
python3 Phase2_Blockchain_Logging/scripts/run_phase2_demo.py
```

Reads real rows from `../Phase1_Submission/CICIoT2023_Sample.csv`, builds
contract-conformant alerts, runs them through the full pipeline against a
local `MockLedger`, prints an Integrity Coverage Ratio sweep, and ends with
a compliance report. If `torch` and the model artifact are available it
calls the real STAHN model; otherwise it uses a clearly-labelled simulated
oracle so the rest of the pipeline is still exercised honestly.

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
