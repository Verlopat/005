#!/usr/bin/env python3
"""Live tamper demonstration.

Anchors one genuine event, then corrupts the mock ledger's stored record
directly (bypassing every public API — see
src/ledger/mock_ledger.py:tamper_with_stored_record_for_demo_only), and
shows that both `MockLedger.verify_chain_integrity()` and
`src/audit.py:audit_event` independently detect it. This is the concrete
demonstration behind Objective 2's premise: "The intrusion evidence
becomes mathematically permanent" is a claim this script actually tests,
not just asserts in prose.

Run from the repository root:

    python3 Phase2_Blockchain_Logging/scripts/tamper_demo.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PHASE2_ROOT))

from src.alert_builder import build_alert_from_oracle_response  # noqa: E402
from src.anchoring_policy import AnchoringPolicy  # noqa: E402
from src.audit import audit_event  # noqa: E402
from src.evidence_store import LocalContentAddressedStore  # noqa: E402
from src.ledger.mock_ledger import MockLedger  # noqa: E402
from src.pipeline import Phase2Pipeline  # noqa: E402
from src.signing import generate_agent_identity  # noqa: E402


def main() -> None:
    print("=" * 70)
    print("Tamper demonstration")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmp:
        store = LocalContentAddressedStore(Path(tmp) / "evidence")
        identity = generate_agent_identity("demo-agent-001")
        ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
        policy = AnchoringPolicy.from_dict({"anchor_attack_only": True, "confidence_threshold": 0.0})
        pipeline = Phase2Pipeline(store, ledger, identity, policy, batch_size=1)

        event = build_alert_from_oracle_response(
            oracle_response={"is_attack": True, "confidence_score": 0.995, "model_version": "demo"},
            feature_names=["Rate", "Protocol Type"],
            feature_values=[16251.95, 6.0],
            model_id="stahn-phase1",
            model_digest="a" * 64,
            resource_id="i-tamper-demo",
            inference_latency_ms=0.4,
        )
        result = pipeline.submit(event)
        print(f"[*] Anchored genuine event {event['event_id']} (decision={result.decision.value})")

        print()
        print("[*] BEFORE tampering:")
        finding = audit_event(ledger, store, event["event_id"], identity.public_key_hex())
        print(f"    audit verdict = {finding.verdict}  ({finding.detail})")
        print(f"    ledger chain integrity intact = {ledger.verify_chain_integrity()}")
        assert finding.verdict == "VERIFIED"
        assert ledger.verify_chain_integrity()

        print()
        print("[*] Attacker with local storage access corrupts the ledger's stored digest ...")
        forged_digest = "0" * 64
        ledger.tamper_with_stored_record_for_demo_only(event["event_id"], forged_digest)

        print()
        print("[*] AFTER tampering:")
        finding = audit_event(ledger, store, event["event_id"], identity.public_key_hex())
        print(f"    audit verdict = {finding.verdict}  ({finding.detail})")
        chain_intact = ledger.verify_chain_integrity()
        print(f"    ledger chain integrity intact = {chain_intact}")
        assert finding.verdict == "TAMPERED", "tamper demo FAILED: audit did not detect the corruption"
        assert not chain_intact, "tamper demo FAILED: chain integrity check did not detect the corruption"

        print()
        print("[ok] Tamper demonstration PASSED: both the audit workflow and the ledger's own")
        print("     chain-integrity check independently detected the corrupted record.")


if __name__ == "__main__":
    main()
