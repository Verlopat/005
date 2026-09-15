"""Ledger client interface.

Every backend (MockLedger for local dev/testing, FabricGatewayLedger for
production) implements this interface so `src/pipeline.py` and
`scripts/run_phase2_demo.py` never need to know which backend is active —
matching config/phase2.example.yaml's `ledger.backend` / `ledger.enabled`
switch. The three operations mirror the three chaincode functions specified
by Objective 2 and implemented in chaincode/securitylog/securitylog.go:
LogSecurityEvent, VerifyEvent, QueryEventHistory.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class LedgerReceipt:
    """Returned by ``log_security_event`` / ``anchor_batch``.

    ``committed`` distinguishes an accepted-and-final write from a
    submitted-but-unconfirmed one; per the Phase 2 README, "No claim of
    on-chain confirmation is valid unless a Fabric transaction ID and
    committed status have been returned by the network." A caller must
    branch on ``committed``, not merely on the absence of an exception.
    """

    transaction_id: str
    committed: bool
    block_number: int | None
    timestamp: str


@dataclass(frozen=True)
class EventRecord:
    """The on-chain record for one anchored event: digest + essential
    metadata only, per Objective 2's hybrid storage architecture. Full
    payloads live in the EvidenceStore and are never returned here."""

    event_id: str
    payload_digest: str
    content_address: str
    resource_id: str
    threat_category: str
    severity: str
    calibrated_confidence: float
    model_digest: str
    agent_id: str
    signature: str
    timestamp: str
    transaction_id: str
    block_number: int | None
    merkle_root: str | None = None  # set when anchored via batch, not individually


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LedgerError(RuntimeError):
    pass


class VerificationFailure(LedgerError):
    pass


class LedgerClient(ABC):
    """Interface implemented by every ledger backend.

    Access control (Objective 2: "only authenticated detection agents may
    write, while any authorised auditor may read") is enforced by whichever
    concrete backend is active — MockLedger enforces it against a
    configured allow-list; FabricGatewayLedger delegates it to chaincode
    and the Fabric MSP, per network/.
    """

    @abstractmethod
    def log_security_event(self, record: EventRecord) -> LedgerReceipt:
        """Chaincode: LogSecurityEvent. Commits digest + metadata for one
        event, or for one Merkle root representing a batch."""

    @abstractmethod
    def verify_event(self, event_id: str, payload_digest: str) -> bool:
        """Chaincode: VerifyEvent. True iff the ledger's stored digest for
        ``event_id`` equals ``payload_digest`` exactly."""

    @abstractmethod
    def query_event_history(
        self, resource_id: str | None = None, start_time: str | None = None, end_time: str | None = None
    ) -> list[EventRecord]:
        """Chaincode: QueryEventHistory. Ordered audit trail, optionally
        filtered by resource and/or time window."""

    @abstractmethod
    def anchor_model_provenance(self, provenance: dict) -> LedgerReceipt:
        """Anchors a model_provenance.schema.json record once per
        retraining cycle."""

    @abstractmethod
    def get_model_provenance(self, model_digest: str) -> dict | None:
        """Look up a previously anchored model provenance record by
        model_digest, enabling 'every alert attributable to an anchored
        model identifier' (Objective 2 success metric)."""
