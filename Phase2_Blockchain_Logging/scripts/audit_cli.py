#!/usr/bin/env python3
"""Command-line auditor workflow.

Objective 2: "A structured query interface will enable analysts and
compliance officers to retrieve complete, ordered and cryptographically
verifiable audit trails for any monitored asset over any specified
period." This CLI is that interface for the local MockLedger deployment;
a production deployment exposes the same operations through
src/ledger/fabric_gateway.py against the real network.

Usage (run from the repository root, after scripts/run_phase2_demo.py has
populated .phase2_runtime/):

    python3 Phase2_Blockchain_Logging/scripts/audit_cli.py history --resource i-demo-0000
    python3 Phase2_Blockchain_Logging/scripts/audit_cli.py verify <event_id>
    python3 Phase2_Blockchain_Logging/scripts/audit_cli.py report
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PHASE2_ROOT))

import yaml  # noqa: E402

from src.audit import audit_event, compliance_report  # noqa: E402
from src.evidence_store import LocalContentAddressedStore  # noqa: E402
from src.ledger.mock_ledger import MockLedger  # noqa: E402
from src.signing import load_agent_identity  # noqa: E402

RUNTIME_DIR = PHASE2_ROOT / ".phase2_runtime"


def load_runtime():
    config = yaml.safe_load((PHASE2_ROOT / "config" / "phase2.example.yaml").read_text(encoding="utf-8"))
    key_path = RUNTIME_DIR / "keys" / "detection_agent_ed25519.pem"
    if not key_path.is_file():
        sys.exit(
            "[!] No local runtime state found. Run scripts/run_phase2_demo.py first to "
            "populate .phase2_runtime/ with a ledger, evidence store, and agent identity."
        )
    identity = load_agent_identity(config["agent"]["id"], key_path)
    ledger_persist_path = RUNTIME_DIR / "ledger.json"
    ledger = MockLedger(
        authorised_agents={identity.agent_id: identity.public_key_hex()}, persist_path=ledger_persist_path
    )
    store = LocalContentAddressedStore(RUNTIME_DIR / "evidence")
    return identity, ledger, store


def cmd_history(args, identity, ledger, store) -> None:
    records = ledger.query_event_history(resource_id=args.resource)
    for r in records:
        print(f"{r.timestamp}  {r.event_id}  {r.threat_category:<20s} conf={r.calibrated_confidence:.3f}  tx={r.transaction_id[:16]}...")
    print(f"\n{len(records)} record(s).")


def cmd_verify(args, identity, ledger, store) -> None:
    finding = audit_event(ledger, store, args.event_id, identity.public_key_hex())
    print(json.dumps(finding.__dict__, indent=2))


def cmd_report(args, identity, ledger, store) -> None:
    report = compliance_report(ledger, store, identity.public_key_hex(), resource_id=args.resource)
    print(json.dumps(report, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2 auditor CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_history = sub.add_parser("history", help="query the ordered audit trail")
    p_history.add_argument("--resource", default=None)
    p_history.set_defaults(func=cmd_history)

    p_verify = sub.add_parser("verify", help="independently verify one event")
    p_verify.add_argument("event_id")
    p_verify.set_defaults(func=cmd_verify)

    p_report = sub.add_parser("report", help="generate a compliance report")
    p_report.add_argument("--resource", default=None)
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args()

    # Enable persistence so this CLI shares state with run_phase2_demo.py
    # across separate process invocations.
    global RUNTIME_DIR
    identity, ledger, store = load_runtime()
    args.func(args, identity, ledger, store)


if __name__ == "__main__":
    main()
