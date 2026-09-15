# Phase 2 — Blockchain-Based Tamper-Proof Security Event Logging

Phase 2 establishes the integrity and provenance layer for the STAHN intrusion-detection system in `../Phase1_Submission`. The phase is deliberately separated from Phase 1: Phase 1 classifies traffic; Phase 2 creates cryptographically verifiable evidence of selected detection events.

## Evidence model

A completed Phase 2 event will follow this sequence:

1. The detector emits a versioned alert conforming to `contracts/alert_event.schema.json`.
2. The entire alert payload is serialised by the rules in `docs/canonicalisation_spec.md`.
3. The canonical payload is hashed using SHA-256 and signed by the detection agent.
4. The complete payload is persisted off-chain under a content-derived address.
5. Only a compact evidentiary record is committed to the permissioned ledger: event ID, digest, content address, signature, identity reference, time, classification metadata, and model provenance reference.
6. An auditor independently retrieves the payload, recomputes the digest, validates its signature, and queries the ledger record and history.

No claim of on-chain confirmation is valid unless a Fabric transaction ID and committed status have been returned by the network.

## Commit 1 scope

This commit freezes the cross-layer contract before storage, chaincode, and integration are implemented. It contains:

- Versioned JSON Schemas for security alerts and model provenance.
- A normative canonical JSON and SHA-256 specification.
- Deterministic digest test vectors for independent implementation testing.
- Configuration templates that contain no private keys, certificates, passwords, or generated network identities.
- Phase-specific dependencies and ignore rules.

## Planned phases of implementation

- Commit 2: canonicalisation library, validation, cryptographic signing, and content-addressed evidence store.
- Commit 3: anchoring policy, receipts, local verification, and evidence lifecycle documentation.
- Commit 4: Fabric Go chaincode.
- Commit 5: two-organisation Fabric network, CAs, identities, policies, and deployment scripts.
- Commit 6: Fabric Gateway and Phase 1 detector integration.
- Commit 7: auditor workflow, reports, end-to-end tests, and tamper demonstration.

## Install Phase 2 Python dependencies

From the repository root with the project virtual environment active:

```bash
python -m pip install -r Phase2_Blockchain_Logging/requirements.txt
```

## Contract validation

Commit 1 does not require Docker, Fabric, Go, or a running ledger. Validate the schemas and canonical digest vector using:

```bash
python3 Phase2_Blockchain_Logging/scripts/validate_commit1.py
```

A successful run ends with `Commit 1 contract validation passed.`
