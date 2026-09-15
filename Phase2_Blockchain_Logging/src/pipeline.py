"""End-to-end Phase 2 evidence pipeline.

Wires together every module built for Objective 2 into the six-step
evidence model published in Phase2_Blockchain_Logging/README.md:

    1. detector emits an alert conforming to the frozen contract
    2. the alert is canonically serialised
    3. the canonical payload is hashed (SHA-256) and signed by the agent
    4. the complete payload is persisted off-chain, content-addressed
    5. a compact evidentiary record is committed to the ledger
       (individually, or batched into a Merkle root under load)
    6. an auditor retrieves, recomputes, verifies (src/audit.py)

This module is intentionally backend-agnostic: it depends only on
`LedgerClient` (base.py), so passing a `MockLedger` or a
`FabricGatewayLedger` produces identical evidentiary semantics.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import jsonschema

from .anchoring_policy import AnchoringDecision, AnchoringPolicy
from .digest import verify_event_digest
from .evidence_store import EvidenceStore, put_json
from .ledger.base import EventRecord, LedgerClient, LedgerReceipt, now_utc_iso
from .merkle import build_merkle_batch
from .signing import AgentIdentity, sign_digest

PHASE2_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class PipelineResult:
    event: dict
    decision: AnchoringDecision
    content_address: str | None
    receipt: LedgerReceipt | None
    merkle_root: str | None = None


class Phase2Pipeline:
    def __init__(
        self,
        evidence_store: EvidenceStore,
        ledger: LedgerClient,
        agent_identity: AgentIdentity,
        anchoring_policy: AnchoringPolicy,
        alert_schema: dict | None = None,
        batch_size: int = 100,
    ):
        self.evidence_store = evidence_store
        self.ledger = ledger
        self.agent_identity = agent_identity
        self.anchoring_policy = anchoring_policy
        self.alert_schema = alert_schema or self._load_default_schema()
        self.batch_size = batch_size
        self._pending_batch: list[tuple[dict, str]] = []  # (event, content_address)

    @staticmethod
    def _load_default_schema() -> dict:
        schema_path = PHASE2_ROOT / "contracts" / "alert_event.schema.json"
        return json.loads(schema_path.read_text(encoding="utf-8"))

    def validate_contract(self, event: dict) -> None:
        jsonschema.validate(instance=event, schema=self.alert_schema)
        if not verify_event_digest(event):
            raise ValueError(
                f"event {event.get('event_id')} failed self-digest verification "
                "before it ever reached the ledger — canonicalisation or transport corrupted it"
            )

    def submit(self, event: dict) -> PipelineResult:
        """Process one alert event through the full evidence pipeline."""
        self.validate_contract(event)

        # Step 4: persist the complete payload off-chain, content-addressed.
        stored = put_json(self.evidence_store, event)

        decision = self.anchoring_policy.decide(event)

        if decision == AnchoringDecision.OFF_CHAIN_ONLY:
            return PipelineResult(event=event, decision=decision, content_address=stored.content_address, receipt=None)

        # Step 3: sign the digest (already computed as event['payload_digest']).
        signature = sign_digest(self.agent_identity, event["payload_digest"])

        if decision == AnchoringDecision.IMMEDIATE:
            record = EventRecord(
                event_id=event["event_id"],
                payload_digest=event["payload_digest"],
                content_address=stored.content_address,
                resource_id=event["resource_id"],
                threat_category=event["threat_category"],
                severity=event["severity"],
                calibrated_confidence=event["calibrated_confidence"],
                model_digest=event["model"]["model_digest"],
                agent_id=self.agent_identity.agent_id,
                signature=signature,
                timestamp=event["timestamp"],
                transaction_id="",  # filled in by the ledger's receipt
                block_number=None,
            )
            receipt = self.ledger.log_security_event(record)
            return PipelineResult(event=event, decision=decision, content_address=stored.content_address, receipt=receipt)

        # decision == BATCH: queue for the next Merkle batch window.
        self._pending_batch.append((event, stored.content_address))
        result = PipelineResult(event=event, decision=decision, content_address=stored.content_address, receipt=None)
        if len(self._pending_batch) >= self.batch_size:
            self.flush_batch()
        return result

    def flush_batch(self) -> str | None:
        """Commit the pending batch as a single Merkle root, per the
        Objective 2 Phase I amendment's throughput dependency. Returns the
        root hex digest, or None if nothing was pending."""
        if not self._pending_batch:
            return None
        digests = [event["payload_digest"] for event, _ in self._pending_batch]
        batch = build_merkle_batch(digests)
        for event, content_address in self._pending_batch:
            signature = sign_digest(self.agent_identity, event["payload_digest"])
            record = EventRecord(
                event_id=event["event_id"],
                payload_digest=event["payload_digest"],
                content_address=content_address,
                resource_id=event["resource_id"],
                threat_category=event["threat_category"],
                severity=event["severity"],
                calibrated_confidence=event["calibrated_confidence"],
                model_digest=event["model"]["model_digest"],
                agent_id=self.agent_identity.agent_id,
                signature=signature,
                timestamp=event["timestamp"],
                transaction_id="",
                block_number=None,
                merkle_root=batch.root,
            )
            self.ledger.log_security_event(record)
        self._pending_batch.clear()
        return batch.root

    def close(self) -> str | None:
        """Flush any remaining batched events; call at shutdown so no event
        is left un-anchored merely because a batch window never filled."""
        return self.flush_batch()
