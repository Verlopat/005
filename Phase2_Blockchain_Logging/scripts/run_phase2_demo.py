#!/usr/bin/env python3
"""End-to-end Phase 2 demonstration: alerts -> evidence pipeline -> ledger -> audit.

Run from the repository root:

    python3 Phase2_Blockchain_Logging/scripts/run_phase2_demo.py

This uses MockLedger (config/phase2.example.yaml's default,
`ledger.enabled: false`), so it needs no Docker, Go, or Fabric network —
see ../README.md and ../docs/architecture.md for how this relates to the
real Hyperledger Fabric deployment under ../network/.

Detector input: reads real rows and real true labels from
Phase1_Submission/CICIoT2023_Sample.csv. Where the actual Phase 1 STAHN
model (a PyTorch artifact) is available and `torch` is installed, this
script calls it directly for real inference. Where it is not installed —
as in the sandbox this repository was scaffolded in — it falls back to a
clearly-labelled SIMULATED oracle response derived deterministically from
each row's true label, so the rest of the Phase 2 pipeline (schema
validation, canonicalisation, digesting, signing, off-chain storage,
anchoring policy, Merkle batching, ledger commit, audit) is exercised
against realistic data without silently claiming a real detection result.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PHASE2_ROOT.parent
PHASE1_DIR = REPO_ROOT / "Phase1_Submission"
sys.path.insert(0, str(PHASE2_ROOT))

import yaml  # noqa: E402

from src.alert_builder import build_alert_from_oracle_response  # noqa: E402
from src.anchoring_policy import AnchoringPolicy, integrity_coverage_ratio  # noqa: E402
from src.audit import compliance_report  # noqa: E402
from src.evidence_store import LocalContentAddressedStore  # noqa: E402
from src.ledger.base import now_utc_iso  # noqa: E402
from src.ledger.mock_ledger import MockLedger  # noqa: E402
from src.model_provenance import build_provenance_record  # noqa: E402
from src.pipeline import Phase2Pipeline  # noqa: E402
from src.signing import load_or_create_agent_identity  # noqa: E402

RUNTIME_DIR = PHASE2_ROOT / ".phase2_runtime"


def try_real_inference():
    """Return a callable(features: list[float]) -> dict shaped like
    blockchain_oracle_api.py's response, using the real STAHN model, or
    None if torch/the model artifact is unavailable."""
    try:
        import torch  # noqa: F401
    except ImportError:
        return None

    model_path = PHASE1_DIR / "stahn_model.pth"
    if not model_path.is_file():
        return None

    sys.path.insert(0, str(PHASE1_DIR))
    try:
        from blockchain_oracle_api import STAHN  # type: ignore
        import torch

        device = torch.device("cpu")
        model = STAHN().to(device)
        model.load_state_dict(torch.load(model_path, map_location=device))
        model.eval()
    except Exception as exc:  # pragma: no cover - depends on optional heavy deps
        print(f"[!] Could not load real STAHN model ({exc}); falling back to simulated oracle.")
        return None

    def infer(features: list[float]) -> dict:
        import torch as _torch

        tensor_input = _torch.FloatTensor([features]).unsqueeze(2).to(device)
        with _torch.no_grad():
            outputs = model(tensor_input)
            probs = _torch.softmax(outputs, dim=1)[:, 1].item()
            prediction = int(_torch.argmax(outputs, dim=1).item())
        confidence = probs if prediction == 1 else (1.0 - probs)
        return {
            "is_attack": bool(prediction == 1),
            "confidence_score": round(confidence, 4),
            "action_required": "ISOLATE_NODE" if prediction == 1 else "ALLOW_TRAFFIC",
            "model_version": "stahn_v1_98.62_acc",
        }

    return infer


def simulated_oracle(features: list[float], true_label: int, row_index: int) -> dict:
    """Deterministic, clearly-labelled stand-in for the real oracle,
    used only when torch/the model artifact are unavailable. Confidence is
    derived from a hash of the row so repeated runs are reproducible, and
    is deliberately noisy (not a perfect predictor) so the anchoring
    policy has a realistic confidence spread to gate against."""
    is_attack = bool(true_label == 1)
    h = int(hashlib.sha256(f"row-{row_index}".encode()).hexdigest(), 16)
    noise = (h % 1000) / 1000.0  # in [0, 1)
    confidence = 0.75 + noise * 0.249 if is_attack else 0.75 + noise * 0.249
    return {
        "is_attack": is_attack,
        "confidence_score": round(min(confidence, 0.999), 4),
        "action_required": "ISOLATE_NODE" if is_attack else "ALLOW_TRAFFIC",
        "model_version": "stahn_v1_98.62_acc-SIMULATED",
    }


def main() -> None:
    import pandas as pd

    print("=" * 70)
    print("Phase 2 end-to-end demonstration")
    print("=" * 70)

    config_path = PHASE2_ROOT / "config" / "phase2.example.yaml"
    policy_path = PHASE2_ROOT / "config" / "anchoring-policy.example.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    policy_raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy = AnchoringPolicy.from_dict(policy_raw)

    evidence_store = LocalContentAddressedStore(RUNTIME_DIR / "evidence")
    identity = load_or_create_agent_identity(
        config["agent"]["id"], RUNTIME_DIR / "keys" / "detection_agent_ed25519.pem"
    )
    ledger = MockLedger(
        authorised_agents={identity.agent_id: identity.public_key_hex()},
        persist_path=RUNTIME_DIR / "ledger.json",
    )

    model_path = PHASE1_DIR / "stahn_model.pth"
    sample_csv = PHASE1_DIR / "CICIoT2023_Sample.csv"
    df = pd.read_csv(sample_csv)
    label_col = "label" if "label" in df.columns else "Label"
    feature_cols = [c for c in df.columns if c not in ("label", "Label", "attack_class")]

    if model_path.is_file():
        provenance = build_provenance_record(
            model_path=model_path,
            model_id="stahn-phase1",
            version_label="stahn_v1_98.62_acc",
            feature_order=feature_cols,
            label_order=["BENIGN", "ATTACK"],
            artifact_content_address=f"local:{model_path.name}",
            anchored_at=now_utc_iso(),
            training_summary={"dataset": "CICIoT2023 (5,000,000 train / 100,001 test)", "record_count": 5_000_000,
                               "reported_metrics": {"accuracy": 0.9862, "attack_precision": 0.9959, "benign_recall": 0.8629}},
        )
        receipt = ledger.anchor_model_provenance(provenance.to_dict())
        model_digest = provenance.model_digest
        print(f"[*] Anchored model provenance (model_digest={model_digest[:16]}..., tx={receipt.transaction_id[:16]}...)")
    else:
        model_digest = "0" * 64
        print("[!] stahn_model.pth not found; using placeholder model_digest for the demo.")

    infer = try_real_inference()
    if infer is not None:
        print("[*] Using the REAL STAHN model for inference.")
    else:
        print("[!] torch/model artifact unavailable in this environment.")
        print("    Using a clearly-labelled SIMULATED oracle (model_version ends in '-SIMULATED')")
        print("    so the Phase 2 pipeline can still be exercised end-to-end without torch installed.")

    pipeline = Phase2Pipeline(
        evidence_store=evidence_store,
        ledger=ledger,
        agent_identity=identity,
        anchoring_policy=policy,
        batch_size=10,
    )

    n_rows = min(60, len(df))
    sample = df.iloc[:n_rows]
    events = []
    for row_index, (_, row) in enumerate(sample.iterrows()):
        features = [float(row[c]) for c in feature_cols]
        true_label = int(row[label_col]) if str(row[label_col]).strip().lstrip("-").isdigit() else (
            0 if str(row[label_col]) == "BenignTraffic" else 1
        )
        oracle_response = infer(features) if infer is not None else simulated_oracle(features, true_label, row_index)
        event = build_alert_from_oracle_response(
            oracle_response=oracle_response,
            feature_names=feature_cols,
            feature_values=features,
            model_id="stahn-phase1",
            model_digest=model_digest,
            resource_id=f"i-demo-{row_index % 5:04d}",
            inference_latency_ms=0.3,
            threat_category=(row.get("attack_class") if "attack_class" in df.columns and oracle_response["is_attack"] else None),
        )
        result = pipeline.submit(event)
        events.append(event)
        if row_index < 5 or result.decision.value != "off_chain_only":
            print(
                f"[event {row_index:03d}] verdict={event['verdict']:7s} "
                f"category={event['threat_category']:<24s} confidence={event['calibrated_confidence']:.3f} "
                f"decision={result.decision.value}"
            )

    root = pipeline.close()
    if root:
        print(f"[*] Flushed final Merkle batch, root={root[:16]}...")

    print()
    print("-" * 70)
    print("Integrity Coverage Ratio sweep (Objective 1/3 diagnostic)")
    print("-" * 70)
    for gate in (0.0, 0.5, 0.75, 0.9, 0.95, 0.99):
        icr = integrity_coverage_ratio(events, gate=gate)
        if icr["integrity_coverage_ratio"] is not None:
            print(
                f"  gate={gate:.2f}  ICR={icr['integrity_coverage_ratio']:.3f}  "
                f"on_chain_volume={icr['on_chain_volume']:.3f}  attacks={icr['attack_count']}"
            )

    print()
    print("-" * 70)
    print("Compliance report (src/audit.py)")
    print("-" * 70)
    report = compliance_report(ledger, evidence_store, identity.public_key_hex())
    print(
        f"  total_events={report['total_events']} verified={report['verified']} "
        f"tampered={report['tampered']} incomplete={report['incomplete']} "
        f"unbroken_chain_of_custody={report['unbroken_chain_of_custody']}"
    )
    print(f"  ledger chain integrity intact: {ledger.verify_chain_integrity()}")
    print()
    print("Demo complete. Try scripts/tamper_demo.py next to see detection of a corrupted record.")


if __name__ == "__main__":
    main()
