"""Auditor workflow: independent retrieval, recomputation, and compliance
reporting.

Objective 2: "A structured query interface will enable analysts and
compliance officers to retrieve complete, ordered and cryptographically
verifiable audit trails ... Exportable reports will align with ISO 27001,
SOC 2 and NIST SP 800-92." This module is that interface; see
docs/compliance_mapping.md for the control-to-evidence mapping and
scripts/audit_cli.py for the command-line entry point analysts actually run.
"""
from __future__ import annotations

from dataclasses import dataclass

from .digest import verify_event_digest
from .evidence_store import EvidenceStore, get_json
from .ledger.base import EventRecord, LedgerClient
from .signing import verify_signature


@dataclass
class AuditFinding:
    event_id: str
    digest_matches_ledger: bool
    payload_recomputation_matches_digest: bool
    signature_valid: bool
    model_provenance_found: bool
    verdict: str  # "VERIFIED" | "TAMPERED" | "INCOMPLETE"
    detail: str


def audit_event(
    ledger: LedgerClient,
    evidence_store: EvidenceStore,
    event_id: str,
    agent_public_key_hex: str,
) -> AuditFinding:
    """Independently verify one anchored event end to end:

    1. retrieve the full off-chain payload by its content address
    2. recompute payload_digest from that payload and compare to the
       digest committed on-chain (VerifyEvent)
    3. verify the Ed25519 signature over that digest against the
       recorded agent's public key
    4. confirm the referenced model_digest has an anchored provenance
       record, closing the accountability gap Objective 2 identifies:
       "an unaltered alert from an unidentified model is of limited
       forensic value"
    """
    history = ledger.query_event_history()
    record: EventRecord | None = next((r for r in history if r.event_id == event_id), None)
    if record is None:
        return AuditFinding(
            event_id=event_id,
            digest_matches_ledger=False,
            payload_recomputation_matches_digest=False,
            signature_valid=False,
            model_provenance_found=False,
            verdict="INCOMPLETE",
            detail=f"no ledger record found for event_id={event_id}",
        )

    try:
        payload = get_json(evidence_store, record.content_address)
    except Exception as exc:
        return AuditFinding(
            event_id=event_id,
            digest_matches_ledger=False,
            payload_recomputation_matches_digest=False,
            signature_valid=False,
            model_provenance_found=False,
            verdict="INCOMPLETE",
            detail=f"off-chain payload unavailable at {record.content_address}: {exc}",
        )

    payload_ok = verify_event_digest(payload)
    ledger_matches = record.payload_digest == payload.get("payload_digest")
    signature_ok = verify_signature(agent_public_key_hex, record.payload_digest, record.signature)
    provenance = ledger.get_model_provenance(record.model_digest)

    if payload_ok and ledger_matches and signature_ok:
        verdict = "VERIFIED"
        detail = "off-chain payload recomputes to the on-chain digest; signature valid."
    else:
        verdict = "TAMPERED"
        reasons = []
        if not payload_ok:
            reasons.append("off-chain payload digest does not match its own claimed payload_digest")
        if not ledger_matches:
            reasons.append("on-chain digest does not match the off-chain payload's digest")
        if not signature_ok:
            reasons.append("Ed25519 signature does not verify against the recorded agent identity")
        detail = "; ".join(reasons)

    return AuditFinding(
        event_id=event_id,
        digest_matches_ledger=ledger_matches,
        payload_recomputation_matches_digest=payload_ok,
        signature_valid=signature_ok,
        model_provenance_found=provenance is not None,
        verdict=verdict,
        detail=detail,
    )


def compliance_report(
    ledger: LedgerClient,
    evidence_store: EvidenceStore,
    agent_public_key_hex: str,
    resource_id: str | None = None,
) -> dict:
    """Generate a chain-of-custody report for every anchored event matching
    ``resource_id`` (or all events if None), suitable for export against
    ISO 27001 A.8.15/A.8.16 logging controls, SOC 2 CC7.2 monitoring, and
    NIST SP 800-92 log management guidance. See docs/compliance_mapping.md
    for the full control mapping.
    """
    history = ledger.query_event_history(resource_id=resource_id)
    findings = [audit_event(ledger, evidence_store, r.event_id, agent_public_key_hex) for r in history]
    verified = sum(1 for f in findings if f.verdict == "VERIFIED")
    tampered = sum(1 for f in findings if f.verdict == "TAMPERED")
    incomplete = sum(1 for f in findings if f.verdict == "INCOMPLETE")
    return {
        "resource_id": resource_id,
        "total_events": len(history),
        "verified": verified,
        "tampered": tampered,
        "incomplete": incomplete,
        "unbroken_chain_of_custody": tampered == 0 and incomplete == 0,
        "findings": [f.__dict__ for f in findings],
    }
