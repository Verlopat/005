#!/usr/bin/env python3
"""End-to-end Phase 2 demonstration: Phase 1 alerts -> evidence -> ledger -> audit.

Run from the repository root:

    python3 Phase2_Blockchain_Logging/scripts/run_phase2_demo.py

Uses MockLedger (``config/phase2.example.yaml``'s default, ``ledger.enabled:
false``), so it needs no Docker, Go or Fabric network. See ../README.md and
../docs/architecture.md for how this relates to the real Hyperledger Fabric
deployment under ../network/.

Detector input
--------------
The detection layer is Phase 1's LightGBM multiclass model over
NF-CSE-CIC-IDS2018-v2. This script consumes the alerts Phase 1 *already emitted*
(``Phase_1/outputs/10_contract/sample_alerts.jsonl``) rather than re-running
inference: Phase 2's responsibility is evidence, and re-deriving a verdict here
would duplicate Phase 1 while risking a different answer.

If that alert stream is absent - it is excluded from version control by
``Phase_1/.gitignore``, so a fresh clone will not have it - the script falls back
to explicitly-synthetic Phase 1-shaped alerts whose ``model_version`` is
``SYNTHETIC-FIXTURE-NOT-A-DETECTION``. The Phase 2 pipeline (schema validation,
cross-layer digest verification, canonicalisation, signing, off-chain storage,
anchoring policy, Merkle batching, ledger commit, audit) is exercised either way;
only the detection figures differ, and the script says which it used.
"""
from __future__ import annotations

import sys
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PHASE2_ROOT))

import yaml  # noqa: E402

from src.alert_builder import build_alert_from_phase1_alert  # noqa: E402
from src.anchoring_policy import AnchoringPolicy, integrity_coverage_ratio  # noqa: E402
from src.audit import compliance_report  # noqa: E402
from src.detection_layer import (  # noqa: E402
    SAMPLE_ALERTS_PATH,
    THREAT_CATEGORIES,
    DetectionLayerUnavailable,
    artifact_path,
    model_identity,
    per_class_confidence,
)
from src.evidence_store import LocalContentAddressedStore  # noqa: E402
from src.ledger.base import now_utc_iso  # noqa: E402
from src.ledger.mock_ledger import MockLedger  # noqa: E402
from src.model_provenance import build_provenance_from_phase1  # noqa: E402
from src.phase1_contract import (  # noqa: E402
    SYNTHETIC_MARKER,
    load_alerts,
    synthetic_alert,
    verify_against_phase1_vectors,
)
from src.pipeline import Phase2Pipeline  # noqa: E402
from src.signing import load_or_create_agent_identity  # noqa: E402

RUNTIME_DIR = PHASE2_ROOT / ".phase2_runtime"
DEMO_EVENTS = 60


def load_input_alerts(limit: int, gate_tau: float) -> tuple[list[dict], bool]:
    """Phase 1's real alerts if available, else synthetic ones. Returns (alerts, synthetic)."""
    if SAMPLE_ALERTS_PATH.is_file():
        return load_alerts(SAMPLE_ALERTS_PATH, limit=limit), False

    # Spread across every category, using Phase 1's *measured* per-class mean
    # confidences (icr_per_class.csv) rather than invented ones. This matters:
    # Phase 1's gate is 0.9997655, so a plausible-looking 0.999 would fall below
    # it and the demo would misleadingly show confident attacks going unanchored.
    measured = per_class_confidence()
    alerts = []
    for index in range(limit):
        category = THREAT_CATEGORIES[index % len(THREAT_CATEGORIES)]
        if category == "Benign":
            confidence = 0.02
        else:
            confidence = measured.get(category, {}).get("mean_confidence", 0.999)
        alerts.append(synthetic_alert(index, category, confidence, gate_tau=gate_tau))
    return alerts, True


def main() -> None:
    print("=" * 74)
    print("Phase 2 end-to-end demonstration")
    print("=" * 74)

    config = yaml.safe_load((PHASE2_ROOT / "config" / "phase2.example.yaml").read_text(encoding="utf-8"))
    policy_raw = yaml.safe_load(
        (PHASE2_ROOT / "config" / "anchoring-policy.example.yaml").read_text(encoding="utf-8")
    )
    policy = AnchoringPolicy.from_dict(policy_raw)

    # --- cross-layer digest agreement ------------------------------------------
    agreement = verify_against_phase1_vectors()
    print(f"[*] Cross-layer digest check: {agreement['vectors_agreeing']}/"
          f"{agreement['vectors_checked']} of Phase 1's own test vectors reproduced "
          f"by Phase 2's independent implementation.")

    # --- detection layer identity ----------------------------------------------
    try:
        identity = model_identity()
        print(f"[*] Detection layer: {identity.architecture}")
        print(f"    dataset={identity.dataset}  features={len(identity.features)}  "
              f"labels={len(identity.labels)}")
        print(f"    calibration={identity.calibration_method} "
              f"(ECE={identity.expected_calibration_error:.2e})  gate tau={identity.gate_tau:.7f}")
        print(f"    reported macro-F1={identity.reported_metrics.get('macro_f1'):.4f}  "
              f"accuracy={identity.reported_metrics.get('accuracy'):.4f}")
        gate_tau = identity.gate_tau
    except DetectionLayerUnavailable as exc:
        print(f"[!] {exc}")
        return

    evidence_store = LocalContentAddressedStore(RUNTIME_DIR / "evidence")
    agent = load_or_create_agent_identity(
        config["agent"]["id"], RUNTIME_DIR / "keys" / "detection_agent_ed25519.pem"
    )
    ledger = MockLedger(
        authorised_agents={agent.agent_id: agent.public_key_hex()},
        persist_path=RUNTIME_DIR / "ledger.json",
    )

    # --- anchor the model provenance record ------------------------------------
    try:
        provenance = build_provenance_from_phase1(now_utc_iso())
        receipt = ledger.anchor_model_provenance(provenance.to_dict())
        model_digest = provenance.model_digest
        print(f"[*] Anchored model provenance from {artifact_path().name}: "
              f"model_digest={model_digest[:16]}... tx={receipt.transaction_id[:16]}...")
    except DetectionLayerUnavailable:
        model_digest = "0" * 64
        print("[!] Phase 1's exported model artifact is absent; using a placeholder "
              "model_digest. Provenance traceability is NOT demonstrated in this run.")

    alerts, synthetic = load_input_alerts(DEMO_EVENTS, gate_tau)
    if synthetic:
        print(f"[!] {SAMPLE_ALERTS_PATH.name} not found.")
        print(f"    Using {len(alerts)} SYNTHETIC Phase 1-shaped alerts "
              f"(model_version={SYNTHETIC_MARKER}).")
        print("    The evidence pipeline is exercised end to end; the detection "
              "figures below are not measurements.")
    else:
        print(f"[*] Loaded {len(alerts)} real Phase 1 alerts from {SAMPLE_ALERTS_PATH.name}.")

    pipeline = Phase2Pipeline(
        evidence_store=evidence_store,
        ledger=ledger,
        agent_identity=agent,
        anchoring_policy=policy,
        batch_size=int(config.get("anchoring", {}).get("batch_size", 10)),
    )

    events = []
    for index, alert in enumerate(alerts):
        # The adapter re-verifies Phase 1's event_hash before the event is
        # admitted, so a corrupted alert cannot reach the ledger.
        event = build_alert_from_phase1_alert(
            alert, model_id=identity.model_id, model_digest=model_digest
        )
        result = pipeline.submit(event)
        events.append(event)
        if index < 5 or result.decision.value != "off_chain_only":
            print(f"[event {index:03d}] verdict={event['verdict']:7s} "
                  f"category={event['threat_category']:<13s} "
                  f"confidence={event['calibrated_confidence']:.4f} "
                  f"severity={event['severity']:<13s} decision={result.decision.value}")

    root = pipeline.close()
    if root:
        print(f"[*] Flushed final Merkle batch, root={root[:16]}...")

    # --- ICR sweep --------------------------------------------------------------
    print()
    print("-" * 74)
    print("Integrity Coverage Ratio sweep (Objective 1/3 diagnostic)")
    print("-" * 74)
    for gate in (0.0, 0.5, 0.9, 0.99, gate_tau):
        icr = integrity_coverage_ratio(events, gate=gate)
        if icr["integrity_coverage_ratio"] is not None:
            print(f"  gate={gate:.7f}  ICR={icr['integrity_coverage_ratio']:.4f}  "
                  f"on_chain_volume={icr['on_chain_volume']:.4f}  attacks={icr['attack_count']}")

    # --- class-aware flooring ---------------------------------------------------
    floors = policy.category_thresholds
    if floors:
        print()
        print("Class-aware gate flooring in effect:")
        for category, floor in sorted(floors.items()):
            anchored = sum(
                1 for e in events
                if e["threat_category"] == category and e["calibrated_confidence"] >= policy.gate_for(category)
            )
            total = sum(1 for e in events if e["threat_category"] == category)
            print(f"  {category:<13s} floor={floor:.7f}  anchored {anchored}/{total}")

    # --- audit -------------------------------------------------------------------
    print()
    print("-" * 74)
    print("Compliance report (src/audit.py)")
    print("-" * 74)
    report = compliance_report(ledger, evidence_store, agent.public_key_hex())
    print(f"  total_events={report['total_events']} verified={report['verified']} "
          f"tampered={report['tampered']} incomplete={report['incomplete']} "
          f"unbroken_chain_of_custody={report['unbroken_chain_of_custody']}")
    print(f"  ledger chain integrity intact: {ledger.verify_chain_integrity()}")
    print()
    print("Demo complete. Try scripts/tamper_demo.py next to see detection of a "
          "corrupted record.")


if __name__ == "__main__":
    main()
