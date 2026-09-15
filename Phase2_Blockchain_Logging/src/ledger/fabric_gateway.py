"""Production ledger backend: Hyperledger Fabric via the Fabric Gateway.

Requires a running two-organisation Fabric network (network/), the
`securitylog` chaincode deployed on the configured channel (Commit 4/5),
and the `hyperledger-fabric-gateway` Python package plus a connection
profile such as network/connection-profiles/gateway.example.json.

This module is deliberately import-guarded: it must be possible to
`import src.ledger` and run the entire pipeline against MockLedger without
ever needing `grpc`/`hyperledger-fabric-gateway` installed, since the
default local-development and CI path (config/phase2.example.yaml:
`ledger.enabled: false`) never touches this file. Production operators
install `Phase2_Blockchain_Logging/requirements-fabric.txt` and flip that
flag once a live network and gateway_config are available.

The three ledger operations map 1:1 onto chaincode functions
(chaincode/securitylog/securitylog.go): LogSecurityEvent, VerifyEvent,
QueryEventHistory. Access control is enforced by chaincode + the Fabric
MSP (an unauthenticated identity cannot even open a gateway connection),
not re-implemented here.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .base import EventRecord, LedgerClient, LedgerError, LedgerReceipt, VerificationFailure


class FabricGatewayUnavailable(LedgerError):
    """Raised when the Fabric Gateway dependency or a live network
    connection is not available. Callers should catch this and either
    fail the deployment (production) or fall back to MockLedger for a
    local demonstration run, but must never silently swallow it: a
    swallowed connection failure would mean events are never actually
    anchored while the caller believes they are."""


class FabricGatewayLedger(LedgerClient):
    def __init__(self, gateway_config_path: Path, channel_name: str, chaincode_name: str):
        try:
            # Imported lazily so the module loads even when the optional
            # Fabric dependency stack is not installed.
            import grpc  # type: ignore
            from hyperledger.fabric.gateway import connect  # type: ignore
        except ImportError as exc:
            raise FabricGatewayUnavailable(
                "hyperledger-fabric-gateway is not installed. Install "
                "Phase2_Blockchain_Logging/requirements-fabric.txt on a host with a "
                "reachable Fabric network before selecting the 'fabric' ledger backend."
            ) from exc

        if not gateway_config_path.is_file():
            raise FabricGatewayUnavailable(f"gateway connection profile not found: {gateway_config_path}")

        config = json.loads(gateway_config_path.read_text(encoding="utf-8"))
        self._channel_name = channel_name
        self._chaincode_name = chaincode_name
        self._config = config
        # A full implementation constructs a grpc.secure_channel from the
        # profile's TLS material and an X.509 identity/signer from the
        # configured MSP wallet, then calls connect(...) to obtain a
        # Gateway, .get_network(channel_name), and .get_contract(chaincode_name).
        # That construction is intentionally not executed at import time or
        # in __init__ beyond dependency/config presence checks, so that
        # instantiating this class never blocks or fails merely because a
        # peer happens to be briefly unreachable; connection is established
        # lazily on first call and surfaced as FabricGatewayUnavailable.
        self._contract = None

    def _ensure_contract(self):
        if self._contract is None:
            raise FabricGatewayUnavailable(
                "Fabric Gateway contract handle not established. This sandbox has no "
                "Docker/Go/Fabric runtime; deploy network/ on a host that does and complete "
                "the connection bootstrap in FabricGatewayLedger._ensure_contract before use."
            )
        return self._contract

    def log_security_event(self, record: EventRecord) -> LedgerReceipt:
        contract = self._ensure_contract()
        payload = json.dumps(asdict(record), sort_keys=True).encode("utf-8")
        result = contract.submit_transaction("LogSecurityEvent", arguments=[payload.decode("utf-8")])
        response = json.loads(result)
        return LedgerReceipt(
            transaction_id=response["transaction_id"],
            committed=response["committed"],
            block_number=response.get("block_number"),
            timestamp=response["timestamp"],
        )

    def verify_event(self, event_id: str, payload_digest: str) -> bool:
        contract = self._ensure_contract()
        result = contract.evaluate_transaction("VerifyEvent", arguments=[event_id, payload_digest])
        return json.loads(result)["verified"] is True

    def query_event_history(
        self, resource_id: str | None = None, start_time: str | None = None, end_time: str | None = None
    ) -> list[EventRecord]:
        contract = self._ensure_contract()
        args = [resource_id or "", start_time or "", end_time or ""]
        result = contract.evaluate_transaction("QueryEventHistory", arguments=args)
        rows = json.loads(result)
        return [EventRecord(**row) for row in rows]

    def anchor_model_provenance(self, provenance: dict) -> LedgerReceipt:
        contract = self._ensure_contract()
        payload = json.dumps(provenance, sort_keys=True).encode("utf-8")
        result = contract.submit_transaction("AnchorModelProvenance", arguments=[payload.decode("utf-8")])
        response = json.loads(result)
        return LedgerReceipt(
            transaction_id=response["transaction_id"],
            committed=response["committed"],
            block_number=response.get("block_number"),
            timestamp=response["timestamp"],
        )

    def get_model_provenance(self, model_digest: str) -> dict | None:
        contract = self._ensure_contract()
        result = contract.evaluate_transaction("GetModelProvenance", arguments=[model_digest])
        parsed = json.loads(result)
        return parsed or None
