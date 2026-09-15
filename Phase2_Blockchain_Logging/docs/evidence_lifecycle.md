# Evidence Lifecycle

This document describes the complete lifecycle of one piece of evidence
from detection to audit, and where in the codebase each step lives. It
supersedes the one-paragraph summary in the top-level README with full
detail, including the two amendments Phase I measurement required
(Merkle batching as a throughput dependency, and per-category anchoring).

## 1. Emission

The detection layer (`Phase1_Submission/blockchain_oracle_api.py` today;
the calibrated LightGBM cascade described in Objective 1's revised
formulation in the target architecture) emits a verdict, a confidence
score, and the triggering feature vector for a classified flow.
`src/alert_builder.py` adapts whichever of these the active detector
actually emits into a complete record shaped like
`contracts/alert_event.schema.json`.

## 2. Contract validation

`Phase2Pipeline.validate_contract` (`src/pipeline.py`) validates the record
against the frozen JSON Schema and independently recomputes its own
`payload_digest` before doing anything else. An event that fails either
check is rejected before it touches storage or the ledger — a malformed
event must never become "evidence" of anything.

## 3. Canonicalisation and digesting

`src/canonical.py` + `src/digest.py`, per
`docs/canonicalisation_spec.md`. Deterministic across languages by
construction, not by convention — see that document's cross-language
conformance procedure.

## 4. Signing

`src/signing.py`. The agent identity's Ed25519 private key signs the
32-byte digest (not the full payload), producing a signature that binds
the event's origin to a specific agent identity. In production this key
is issued and rotated via the Fabric Certificate Authority (`network/`);
locally, `load_or_create_agent_identity` persists a development key under
`.phase2_runtime/keys/` (git-ignored).

## 5. Off-chain persistence

`src/evidence_store.py`. The complete payload — including
`triggering_features` and `feature_attributions`, which are large and not
needed by every ledger read — is written to a content-addressed store
keyed by `sha256(payload)`. The default backend is the local filesystem
(`LocalContentAddressedStore`); `IPFSStore` is available for the
distributed deployment the Phase 1 handoff document directs for the model
artifact itself (`src/model_provenance.py`), and is the natural choice for
alert payloads too once a production IPFS cluster is provisioned.

## 6. Anchoring decision

`src/anchoring_policy.py`. Three outcomes, evaluated per event:

- `OFF_CHAIN_ONLY` — evidence is stored (step 5 already happened) but not
  anchored, e.g. a BENIGN verdict under `anchor_attack_only: true`, or an
  ATTACK verdict below its category's confidence gate.
- `IMMEDIATE` — anchored on its own transaction, for the highest-confidence
  events where batching latency is undesirable.
- `BATCH` — queued for the next Merkle batch window (default 100 events;
  configurable, see `src/merkle.py:required_batch_factor_for_target_tps`
  for the arithmetic behind that default at the measured Phase I
  operating point).

## 7. Ledger commitment

`src/pipeline.py` + `src/ledger/`. `LogSecurityEvent` commits
digest + essential metadata (never the full payload) either individually
(`IMMEDIATE`) or as one Merkle root covering a full batch (`BATCH`). The
receipt returned (`LedgerReceipt`) carries a transaction ID, a committed
flag, and a block number; per the top-level Phase 2 README, no claim of
on-chain confirmation is valid without all three.

## 8. Independent audit

`src/audit.py`. An auditor supplies an `event_id` and the agent's public
key; the workflow retrieves the off-chain payload by content address,
recomputes its digest, compares that digest against the ledger's stored
value, verifies the Ed25519 signature, and confirms the referenced model
is itself anchored. Any mismatch anywhere in that chain is reported as
`TAMPERED`, never silently corrected or ignored.
`scripts/tamper_demo.py` exercises this path against a deliberately
corrupted record to prove the detection actually fires.

## Retention and hierarchical storage

Objective 3 (not this phase) will add off-chain compression and
hierarchical retention to bound long-term storage growth. Phase 2's
storage interface (`EvidenceStore.get`/`put`/`exists`) is retention-policy
agnostic by design so that a future retention/tiering layer can be
inserted without touching the pipeline or the ledger clients.
