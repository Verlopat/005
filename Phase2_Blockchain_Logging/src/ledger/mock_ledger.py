"""In-memory / on-disk mock ledger for local development and testing.

This is NOT a substitute for Hyperledger Fabric in production — it has no
decentralised consensus and no distributed replication, so it cannot by
itself satisfy Objective 2's "single point of failure" mitigation. Its
purpose is narrower and still real: it implements the exact
LedgerClient/EventRecord contract that chaincode/securitylog/securitylog.go
also implements, backed by an append-only, hash-chained structure that
IS tamper-evident against post-hoc modification of a single process's
storage — sufficient to develop and test the whole Phase 2 pipeline, the
anchoring policy, the Merkle batching, and the auditor workflow, entirely
offline, before a Fabric network is available (config/phase2.example.yaml
already anticipates this: ``ledger.enabled: false`` by default).

Switching to the real network requires only pointing
config/phase2.example.yaml's ``ledger.backend`` at ``fabric`` and setting
``ledger.enabled: true`` with a valid gateway_config; no caller code
changes, because both backends implement `src/ledger/base.py`.
"""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from pathlib import Path

from ..canonical import canonicalise
from ..digest import digest_bytes
from ..signing import verify_signature
from .base import EventRecord, LedgerClient, LedgerError, LedgerReceipt, VerificationFailure, now_utc_iso


class UnauthorisedAgentError(LedgerError):
    pass


class Block:
    __slots__ = ("index", "previous_hash", "timestamp", "records", "provenance", "hash")

    def __init__(self, index: int, previous_hash: str, timestamp: str, records: list[dict], provenance: list[dict]):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.records = records
        self.provenance = provenance
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        body = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "records": self.records,
            "provenance": self.provenance,
        }
        return digest_bytes(canonicalise(body).encode("utf-8"))

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "records": self.records,
            "provenance": self.provenance,
            "hash": self.hash,
        }


GENESIS_HASH = "0" * 64


class MockLedger(LedgerClient):
    def __init__(self, authorised_agents: dict[str, str] | None = None, persist_path: Path | None = None):
        """``authorised_agents`` maps agent_id -> hex Ed25519 public key.
        Enforces Objective 2's "only authenticated detection agents may
        write" — a write from an agent_id/signature pair that doesn't
        verify against this map is rejected, not silently accepted.
        """
        self._lock = threading.RLock()
        self._authorised_agents = dict(authorised_agents or {})
        self._chain: list[Block] = [Block(0, GENESIS_HASH, now_utc_iso(), [], [])]
        self._events_by_id: dict[str, EventRecord] = {}
        self._provenance_by_digest: dict[str, dict] = {}
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path and self._persist_path.is_file():
            self._load()

    def register_agent(self, agent_id: str, public_key_hex: str) -> None:
        self._authorised_agents[agent_id] = public_key_hex

    def _authenticate(self, agent_id: str, payload_digest: str, signature: str) -> None:
        public_key_hex = self._authorised_agents.get(agent_id)
        if public_key_hex is None:
            raise UnauthorisedAgentError(f"agent '{agent_id}' is not a registered authenticated agent")
        if not verify_signature(public_key_hex, payload_digest, signature):
            raise UnauthorisedAgentError(f"signature verification failed for agent '{agent_id}'")

    def log_security_event(self, record: EventRecord) -> LedgerReceipt:
        with self._lock:
            self._authenticate(record.agent_id, record.payload_digest, record.signature)
            if record.event_id in self._events_by_id:
                raise LedgerError(
                    f"event_id {record.event_id} is already committed; ledger records are "
                    "append-only and cannot be overwritten"
                )
            record_dict = asdict(record)
            prev = self._chain[-1]
            block = Block(prev.index + 1, prev.hash, now_utc_iso(), [record_dict], [])
            self._chain.append(block)
            stored = EventRecord(**{**record_dict, "transaction_id": block.hash, "block_number": block.index})
            self._events_by_id[record.event_id] = stored
            self._persist()
            return LedgerReceipt(
                transaction_id=block.hash, committed=True, block_number=block.index, timestamp=block.timestamp
            )

    def verify_event(self, event_id: str, payload_digest: str) -> bool:
        with self._lock:
            stored = self._events_by_id.get(event_id)
            if stored is None:
                return False
            return stored.payload_digest == payload_digest

    def query_event_history(
        self, resource_id: str | None = None, start_time: str | None = None, end_time: str | None = None
    ) -> list[EventRecord]:
        with self._lock:
            results = list(self._events_by_id.values())
        if resource_id is not None:
            results = [r for r in results if r.resource_id == resource_id]
        if start_time is not None:
            results = [r for r in results if r.timestamp >= start_time]
        if end_time is not None:
            results = [r for r in results if r.timestamp <= end_time]
        return sorted(results, key=lambda r: r.timestamp)

    def anchor_model_provenance(self, provenance: dict) -> LedgerReceipt:
        with self._lock:
            prev = self._chain[-1]
            block = Block(prev.index + 1, prev.hash, now_utc_iso(), [], [provenance])
            self._chain.append(block)
            self._provenance_by_digest[provenance["model_digest"]] = provenance
            self._persist()
            return LedgerReceipt(
                transaction_id=block.hash, committed=True, block_number=block.index, timestamp=block.timestamp
            )

    def get_model_provenance(self, model_digest: str) -> dict | None:
        with self._lock:
            return self._provenance_by_digest.get(model_digest)

    def verify_chain_integrity(self) -> bool:
        """Recompute every block hash and every previous_hash link. Returns
        False the instant any block has been altered after the fact — this
        is what makes the mock ledger tamper-evident rather than merely
        append-only in name; see scripts/tamper_demo.py for a live
        demonstration against this exact check."""
        with self._lock:
            for i, block in enumerate(self._chain):
                recomputed = block._compute_hash()
                if recomputed != block.hash:
                    return False
                if i > 0 and block.previous_hash != self._chain[i - 1].hash:
                    return False
            return True

    def _persist(self) -> None:
        if self._persist_path is None:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"chain": [b.to_dict() for b in self._chain], "authorised_agents": self._authorised_agents}
        self._persist_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def _load(self) -> None:
        data = json.loads(self._persist_path.read_text(encoding="utf-8"))
        self._authorised_agents.update(data.get("authorised_agents", {}))
        self._chain = []
        for b in data["chain"]:
            block = Block(b["index"], b["previous_hash"], b["timestamp"], b["records"], b["provenance"])
            self._chain.append(block)
            for rec in b["records"]:
                self._events_by_id[rec["event_id"]] = EventRecord(**rec)
            for prov in b["provenance"]:
                self._provenance_by_digest[prov["model_digest"]] = prov

    def tamper_with_stored_record_for_demo_only(self, event_id: str, new_payload_digest: str) -> None:
        """Directly mutate a stored record's digest, bypassing every
        integrity check, so scripts/tamper_demo.py can prove that
        verify_chain_integrity() and verify_event() both detect it. This
        method exists ONLY for the tamper demonstration and must never be
        reachable from LedgerClient's public interface or from the pipeline;
        a real ledger has no such method because Fabric's consensus and
        replication make an equivalent mutation infeasible for a single
        party, which is the entire point of Objective 2."""
        with self._lock:
            for block in self._chain:
                for rec in block.records:
                    if rec["event_id"] == event_id:
                        rec["payload_digest"] = new_payload_digest
                        self._events_by_id[event_id] = EventRecord(**rec)
                        return
            raise LedgerError(f"event_id {event_id} not found")
