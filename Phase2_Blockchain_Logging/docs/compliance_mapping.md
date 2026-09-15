# Compliance Mapping

Objective 2: "Exportable reports will align with ISO 27001, SOC 2 and NIST
SP 800-92." This document maps each control family to the concrete
evidence this codebase produces, so a compliance officer running
`src/audit.py:compliance_report` can trace every field back to a control.

| Control family | Standard reference | What the control requires | Evidence this system produces |
|---|---|---|---|
| Logging and monitoring | ISO/IEC 27001:2022 Annex A.8.15 (Logging) | Event logs recording user activities, exceptions, faults, and security events; log protection against tampering and unauthorised access | `EventRecord` per anchored alert (`src/ledger/base.py`); tamper-evidence via on-chain digest + hash-chained ledger structure (`MockLedger.verify_chain_integrity`, and Fabric block immutability in production) |
| Monitoring activities | ISO/IEC 27001:2022 Annex A.8.16 | Networks, systems and applications monitored for anomalous behaviour | Objective 1's detection layer output is the monitored signal; Objective 2 makes its output tamper-evident and queryable |
| Non-repudiation | ISO/IEC 27001:2022 Annex A.5.28 (Collection of evidence — referenced practice) | Evidence must be attributable to its originator without possibility of denial | Ed25519 signature per event (`src/signing.py`), bound to a registered agent identity (`MockLedger._authenticate`, Fabric MSP in production) |
| System monitoring (CC7.2) | SOC 2 Trust Services Criteria, Security | Detection and monitoring procedures to identify security events and evaluate whether they represent a security incident | `src/anchoring_policy.py`'s severity classification and `src/audit.py:compliance_report`'s tampered/incomplete counts give a compliance officer a direct incident-review starting point |
| Change management / integrity | SOC 2 CC7.1, CC8.1 | Changes to the environment are authorised and their effects assessed; unauthorized modification is detectable | `model_provenance.schema.json` anchoring: every alert is attributable to an anchored model version, so an unauthorised model swap is detectable (closing the gap the Objective 2 explanation calls out: "an unaltered alert from an unidentified model is of limited forensic value") |
| Log management planning | NIST SP 800-92 §3 | Define log generation, storage, and retention policy consistently across systems | `contracts/alert_event.schema.json` is the single generation-time contract shared by every detection agent; `config/phase2.example.yaml` centralises storage backend and retention-relevant configuration |
| Log analysis and retention | NIST SP 800-92 §4–5 | Logs must be analysable and retained per policy, with integrity protected over the retention period | `src/audit.py:audit_event` performs the independent recomputation NIST 800-92 describes as the basis for log analysis; hierarchical retention (compression, tiering) is explicitly deferred to Objective 3 (see `docs/evidence_lifecycle.md`) and the storage interface is written to accept it without a breaking change |

## Report fields and their control relevance

`compliance_report()` (`src/audit.py`) returns, per resource or across all
resources:

- `total_events`, `verified`, `tampered`, `incomplete` — supports SOC 2
  CC7.2 evidence of ongoing monitoring effectiveness.
- `unbroken_chain_of_custody` — a single boolean an auditor can cite
  directly in a chain-of-custody attestation; it is `False` the instant any
  finding is `TAMPERED` or `INCOMPLETE`, never averaged or rounded away.
- `findings[].detail` — a human-readable reason string for every non-
  `VERIFIED` finding, satisfying the "explicit identification" expectation
  common to all three referenced frameworks (a report that says only
  "3 failed" without saying *how* is not sufficient for any of them).
