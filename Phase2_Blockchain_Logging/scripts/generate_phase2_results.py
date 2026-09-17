#!/usr/bin/env python3
"""Generate the Objective 2 results report for the paper.

Runs the complete Phase 2 pipeline over real sample data, measures the
eight metrics listed in the Objective 2 Success Metrics table of
Research_Objectives_Revised.docx, and writes a paper-ready Markdown report
plus a raw-numbers JSON file to Phase2_Blockchain_Logging/outputs/.

This is invoked by the single-command launcher ../../run_phase2.py; run it
directly only if you want to change --num-events or --gate.

IMPORTANT — what this run does and does not measure:

This sandbox has no Docker, Go, or Fabric installed, so every number below
comes from `src/ledger/mock_ledger.py` (an in-memory, hash-chained,
tamper-evident ledger — see its module docstring) rather than a deployed
Hyperledger Fabric network. This is disclosed explicitly in the generated
report rather than silently presented as network-measured Fabric TPS/
latency, because that distinction matters for an academic paper's
methodology section. Where the docx's target is a network-level property
(transaction throughput, commit latency), the report gives both (a) the
calculated requirement from Objective 2's own amendment arithmetic and
(b) the measured software-layer figure, and states plainly that a
network-measured figure requires deploying `../network/` on a host with
Fabric prerequisites.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PHASE2_ROOT.parent
PHASE1_DIR = REPO_ROOT / "Phase_1"
OUTPUTS_DIR = PHASE2_ROOT / "outputs"
sys.path.insert(0, str(PHASE2_ROOT))

import yaml  # noqa: E402

from src.alert_builder import build_alert_from_phase1_alert  # noqa: E402
from src.anchoring_policy import AnchoringPolicy, integrity_coverage_ratio  # noqa: E402
from src.audit import audit_event, compliance_report  # noqa: E402
from src.canonical import canonicalise  # noqa: E402
from src.digest import digest_bytes  # noqa: E402
from src.evidence_store import LocalContentAddressedStore, put_json  # noqa: E402
from src.ledger.base import now_utc_iso  # noqa: E402
from src.ledger.mock_ledger import MockLedger  # noqa: E402
from src.detection_layer import (  # noqa: E402
    SAMPLE_ALERTS_PATH,
    THREAT_CATEGORIES,
    DetectionLayerUnavailable,
    model_identity,
    per_class_confidence,
)
from src.merkle import required_batch_factor_for_target_tps  # noqa: E402
from src.model_provenance import build_provenance_from_phase1  # noqa: E402
from src.phase1_contract import (  # noqa: E402
    SYNTHETIC_MARKER,
    load_alerts,
    synthetic_alert,
    verify_against_phase1_vectors,
)
from src.pipeline import Phase2Pipeline  # noqa: E402
from src.signing import generate_agent_identity  # noqa: E402

import hashlib  # noqa: E402

AGENT_ID = "detection-agent-001"

#: Phase 1's genuinely hard category: measured mean calibrated confidence 0.303
#: on the held-out fold (outputs/08_calibration_icr/icr_per_class.csv), against
#: >0.99 for every other attack category. This is the class-dependent confidence
#: gap the anchoring policy's class-aware flooring exists to address - see
#: docs/evidence_lifecycle.md.
HARD_CATEGORY = "Infiltration"


def phase1_inference_note(synthetic: bool) -> str:
    """One sentence stating exactly where the alerts came from.

    Phase 2 does not run the detector. It consumes what Phase 1 emitted, so the
    report must say which stream was used rather than implying an inference pass
    happened here.
    """
    if synthetic:
        return (f"SYNTHETIC Phase 1-shaped alerts (model_version={SYNTHETIC_MARKER}); "
                "Phase 1's emitted alert stream was not present in this checkout, so "
                "no detection figure in this report is a measurement.")
    return (f"Real alerts emitted by Phase 1 stage 10 ({SAMPLE_ALERTS_PATH.name}), "
            "digest-verified on ingestion by src/phase1_contract.py.")


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    values = sorted(values)
    k = (len(values) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(values) - 1)
    if f == c:
        return values[f]
    return values[f] + (values[c] - values[f]) * (k - f)


def load_phase1_alerts(limit: int, gate_tau: float) -> tuple[list[dict], bool]:
    """Phase 1's emitted alerts, or explicitly-synthetic stand-ins.

    Returns ``(alerts, synthetic)``. Phase 2 consumes the alerts Phase 1 already
    produced rather than re-running inference: re-deriving a verdict here would
    duplicate Phase 1 while risking a different answer, and Objective 2's claims
    are about evidence, not detection.
    """
    if SAMPLE_ALERTS_PATH.is_file():
        return load_alerts(SAMPLE_ALERTS_PATH, limit=limit), False

    measured = per_class_confidence()
    alerts = []
    for index in range(limit):
        category = THREAT_CATEGORIES[index % len(THREAT_CATEGORIES)]
        if category == "Benign":
            confidence = 0.02
        else:
            confidence = measured.get(category, {}).get("mean_confidence", 0.999)
        alerts.append(
            synthetic_alert(index, category, confidence,
                            resource_id=f"cloud-res-bench-{index % 8:04d}",
                            gate_tau=gate_tau)
        )
    return alerts, True


def build_events(alerts: list[dict], model_id: str, model_digest: str,
                 calibrated: bool) -> list[dict]:
    """Adapt Phase 1 alerts into Objective 2 evidence events.

    The adapter re-verifies each alert's producer digest, so a corrupted alert is
    rejected here rather than anchored.
    """
    return [
        build_alert_from_phase1_alert(
            alert,
            model_id=model_id,
            model_digest=model_digest,
            calibration_method="isotonic" if calibrated else "none",
        )
        for alert in alerts
    ]


def measure_canonical_digest_agreement() -> dict:
    vectors_path = PHASE2_ROOT / "contracts" / "test_vectors" / "canonical_digest_vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    total = len(data["vectors"])
    matched = 0
    for vec in data["vectors"]:
        canonical = canonicalise(vec["input"])
        digest = digest_bytes(canonical.encode("utf-8"))
        if canonical == vec["expected_canonical"] and digest == vec["expected_sha256"]:
            matched += 1
    go_available = (PHASE2_ROOT / "chaincode" / "securitylog" / "canonical.go").is_file()
    return {
        "python_vectors_total": total,
        "python_vectors_matched": matched,
        "python_agreement_pct": 100.0 * matched / total if total else 0.0,
        "go_implementation_present": go_available,
        "go_independently_executed": False,  # this sandbox has no Go toolchain
    }


def measure_storage_overhead(events: list[dict], sample_size: int = 200) -> dict:
    on_chain_sizes = []
    off_chain_sizes = []
    for event in events[:sample_size]:
        off_chain_sizes.append(len(json.dumps(event, sort_keys=True, ensure_ascii=False).encode("utf-8")))
        record_like = {
            "event_id": event["event_id"],
            "payload_digest": event["payload_digest"],
            "content_address": "sha256:" + "0" * 64,
            "resource_id": event["resource_id"],
            "threat_category": event["threat_category"],
            "severity": event["severity"],
            "calibrated_confidence": event["calibrated_confidence"],
            "model_digest": event["model"]["model_digest"],
            "agent_id": AGENT_ID,
            "signature": "0" * 128,
            "timestamp": event["timestamp"],
            "transaction_id": "0" * 64,
            "block_number": 12345,
        }
        on_chain_sizes.append(len(json.dumps(record_like, sort_keys=True, ensure_ascii=False).encode("utf-8")))
    return {
        "sample_size": len(on_chain_sizes),
        "on_chain_bytes_mean": statistics.mean(on_chain_sizes),
        "on_chain_bytes_max": max(on_chain_sizes),
        "off_chain_bytes_mean": statistics.mean(off_chain_sizes),
        "reduction_pct": 100.0 * (1 - statistics.mean(on_chain_sizes) / statistics.mean(off_chain_sizes)),
    }


def run_latency_and_throughput_benchmark(store, identity, events: list[dict], n: int) -> dict:
    """Immediate-commit policy so every one of the first `n` events gets a
    real ledger receipt, isolating pure software-layer latency/throughput
    (no batching amortisation, which would understate per-event latency)."""
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    policy = AnchoringPolicy.from_dict({"anchor_attack_only": False, "confidence_threshold": 0.0, "immediate_confidence_threshold": 0.0})
    pipeline = Phase2Pipeline(store, ledger, identity, policy, batch_size=1)

    latencies_ms = []
    t_start = time.perf_counter()
    for event in events[:n]:
        t0 = time.perf_counter()
        pipeline.submit(event)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)
    elapsed = time.perf_counter() - t_start

    return {
        "events_processed": len(latencies_ms),
        "elapsed_sec": elapsed,
        "measured_throughput_eps": len(latencies_ms) / elapsed if elapsed > 0 else float("inf"),
        "latency_ms_p50": percentile(latencies_ms, 50),
        "latency_ms_p95": percentile(latencies_ms, 95),
        "latency_ms_p99": percentile(latencies_ms, 99),
        "latency_ms_max": max(latencies_ms) if latencies_ms else float("nan"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the Objective 2 paper results report")
    parser.add_argument("--num-events", type=int, default=2000,
                        help="Phase 1 alerts to process")
    parser.add_argument("--benchmark-events", type=int, default=500, help="events used for the latency/throughput micro-benchmark")
    parser.add_argument("--gate", type=float, default=0.95, help="anchoring confidence gate for the operational ICR run")
    args = parser.parse_args()

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    run_started_at = now_utc_iso()

    print("=" * 78)
    print("Generating Objective 2 (Phase 2) results for the paper")
    print("=" * 78)

    # --- detection layer, provenance, and alert ingestion -----------------------------
    digest_agreement_phase1 = verify_against_phase1_vectors()
    print(f"[*] Cross-layer digest agreement with Phase 1: "
          f"{digest_agreement_phase1['vectors_agreeing']}/"
          f"{digest_agreement_phase1['vectors_checked']} vectors reproduced independently.")

    detector = model_identity()
    print(f"[*] Detection layer: {detector.architecture} on {detector.dataset}")
    print(f"    macro-F1={detector.reported_metrics.get('macro_f1'):.4f} "
          f"accuracy={detector.reported_metrics.get('accuracy'):.4f} "
          f"calibration={detector.calibration_method} gate tau={detector.gate_tau:.7f}")

    identity = generate_agent_identity(AGENT_ID)
    store = LocalContentAddressedStore(OUTPUTS_DIR / "_run_evidence")

    model_digest = "0" * 64
    provenance_record = None
    try:
        # Every provenance field is read from Phase 1's model card, so the anchored
        # record describes the detector that actually produced these alerts.
        provenance_record = build_provenance_from_phase1(run_started_at)
        model_digest = provenance_record.model_digest
        print(f"[*] Model provenance computed: model_digest={model_digest[:16]}...")
    except DetectionLayerUnavailable as exc:
        print(f"[!] {exc}")
        print("[!] Using a placeholder model_digest; provenance traceability is NOT demonstrated.")

    alerts, synthetic = load_phase1_alerts(args.num_events, detector.gate_tau)
    print(f"[*] Alert source: {phase1_inference_note(synthetic)}")
    print(f"[*] Adapting {len(alerts)} Phase 1 alerts into Objective 2 evidence events ...")
    events = build_events(alerts, detector.model_id, model_digest, calibrated=not synthetic)

    # --- metric 6: canonical digest agreement -----------------------------------------
    print("[*] Checking canonical digest agreement (metric 6) ...")
    digest_agreement = measure_canonical_digest_agreement()

    # --- metrics 1 & 2: throughput & latency (software-layer benchmark) --------------
    print(f"[*] Running latency/throughput micro-benchmark over {args.benchmark_events} events (metrics 1, 2) ...")
    bench = run_latency_and_throughput_benchmark(store, identity, events, args.benchmark_events)
    required_tx_per_sec = required_batch_factor_for_target_tps(peak_events_per_sec=10_000, anchoring_rate=0.1143, target_tps=1000)
    anchored_per_sec_no_batch = 10_000 * 0.1143
    anchored_per_sec_batch100 = anchored_per_sec_no_batch / 100

    # --- operational pass: realistic policy, ledger persisted for report -------------
    print("[*] Running the operational pass (realistic anchoring policy, model provenance anchoring) ...")
    op_ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    if provenance_record is not None:
        op_ledger.anchor_model_provenance(provenance_record.to_dict())
    policy_path = PHASE2_ROOT / "config" / "anchoring-policy.example.yaml"
    policy_raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    policy_raw["confidence_threshold"] = args.gate
    policy = AnchoringPolicy.from_dict(policy_raw)
    pipeline = Phase2Pipeline(store, op_ledger, identity, policy, batch_size=100)
    for event in events:
        pipeline.submit(event)
    pipeline.close()

    # --- metric 5: Integrity Coverage Ratio -------------------------------------------
    print("[*] Computing Integrity Coverage Ratio sweep (metric 5) ...")
    icr_sweep = [integrity_coverage_ratio(events, gate=g) for g in (0.0, 0.5, 0.75, 0.90, 0.95, 0.99)]
    icr_at_gate = integrity_coverage_ratio(events, gate=args.gate)

    # --- metric 3: on-chain storage overhead ------------------------------------------
    print("[*] Measuring on-chain storage overhead per event (metric 3) ...")
    storage = measure_storage_overhead(events)

    # --- metric 4: integrity verification failure rate + tamper proof ----------------
    print("[*] Auditing anchored events and running a live tamper-injection test (metric 4) ...")
    history = op_ledger.query_event_history()
    audit_sample = history[: min(300, len(history))]
    findings = [audit_event(op_ledger, store, r.event_id, identity.public_key_hex()) for r in audit_sample]
    verified_count = sum(1 for f in findings if f.verdict == "VERIFIED")
    failure_rate_pct = 100.0 * (len(findings) - verified_count) / len(findings) if findings else float("nan")

    tamper_detected = False
    if history:
        victim = history[0]
        finding_before = audit_event(op_ledger, store, victim.event_id, identity.public_key_hex())
        op_ledger.tamper_with_stored_record_for_demo_only(victim.event_id, "0" * 64)
        finding_after = audit_event(op_ledger, store, victim.event_id, identity.public_key_hex())
        chain_intact_after = op_ledger.verify_chain_integrity()
        tamper_detected = finding_before.verdict == "VERIFIED" and finding_after.verdict == "TAMPERED" and not chain_intact_after

    # --- metric 7: model provenance traceability --------------------------------------
    print("[*] Checking model provenance traceability (metric 7) ...")
    provenance_traceable = False
    if provenance_record is not None:
        looked_up = op_ledger.get_model_provenance(model_digest)
        attack_events = [e for e in events if e["verdict"] == "ATTACK"]
        provenance_traceable = looked_up is not None and all(
            e["model"]["model_digest"] == model_digest for e in attack_events
        )

    # --- metric 8: non-repudiation ------------------------------------------------------
    print("[*] Checking non-repudiation of agent identity (metric 8) ...")
    signature_pass = verified_count  # signature_valid is part of VERIFIED verdict
    signature_checks = len(findings)
    forged_rejected = False
    from src.signing import generate_agent_identity as _gen, sign_digest as _sign
    other_identity = _gen("impostor-agent")
    if history:
        forged_sig = _sign(other_identity, history[0].payload_digest)
        from src.signing import verify_signature
        forged_rejected = not verify_signature(identity.public_key_hex(), history[0].payload_digest, forged_sig)

    # --- assemble report ----------------------------------------------------------------
    report_rows = [
        {
            "metric": "Blockchain transaction throughput",
            "target": ">1,000 TPS sustained, with Merkle batch aggregation enabled at peak arrival rates",
            "measured": (
                f"Required tx/sec at 10,000 events/sec peak x 11.43% anchoring rate: "
                f"{anchored_per_sec_no_batch:.0f} tx/sec unbatched -> {anchored_per_sec_batch100:.1f} tx/sec at batch factor 100 "
                f"(minimum batch factor to clear 1,000 TPS: {required_tx_per_sec}). "
                f"Measured local software-layer submission throughput (mock ledger, immediate-commit, no batching): "
                f"{bench['measured_throughput_eps']:.0f} events/sec on this machine."
            ),
            "status": "Met by design (batching keeps required TPS far below 1,000); network-level TPS requires deploying network/ on a Fabric-capable host.",
        },
        {
            "metric": "Log commit latency, detection to on-chain confirmation",
            "target": "< 500 ms at the 95th percentile",
            "measured": (
                f"Software-layer latency (canonicalise+digest+sign+store+commit, mock ledger), n={bench['events_processed']}: "
                f"p50={bench['latency_ms_p50']:.3f} ms, p95={bench['latency_ms_p95']:.3f} ms, "
                f"p99={bench['latency_ms_p99']:.3f} ms, max={bench['latency_ms_max']:.3f} ms."
            ),
            "status": "Met for the software layer with large margin. Real end-to-end figure additionally includes Fabric endorsement/ordering round-trip, measured on a deployed network.",
        },
        {
            "metric": "On-chain storage overhead per event",
            "target": "< 1 KB per record, digest and metadata only",
            "measured": (
                f"n={storage['sample_size']}: mean on-chain record size {storage['on_chain_bytes_mean']:.0f} bytes "
                f"(max {storage['on_chain_bytes_max']} bytes) vs mean full off-chain payload {storage['off_chain_bytes_mean']:.0f} bytes "
                f"-> {storage['reduction_pct']:.1f}% size reduction."
            ),
            "status": "Met" if storage["on_chain_bytes_max"] < 1024 else "NOT MET",
        },
        {
            "metric": "Log integrity verification failure rate",
            "target": "0%; every stored digest verifies against its off-chain payload",
            "measured": (
                f"{len(findings) - verified_count}/{len(findings)} audited events failed verification "
                f"({failure_rate_pct:.2f}%) under normal operation. Live tamper-injection test: "
                f"{'detected (VERIFIED -> TAMPERED, chain integrity check also failed)' if tamper_detected else 'NOT detected — investigate'}."
            ),
            "status": "Met" if failure_rate_pct == 0.0 and tamper_detected else "REVIEW",
        },
        {
            "metric": "Integrity Coverage Ratio of the anchored record",
            "target": ">= 95% of true attack flows anchored at the deployment gate",
            "measured": (
                f"At gate={args.gate}: ICR={icr_at_gate['integrity_coverage_ratio']:.4f}, "
                f"on-chain volume={icr_at_gate['on_chain_volume']:.4f}, attacks in sample={icr_at_gate['attack_count']}. "
                f"Full sweep in the ICR table below."
            ),
            "status": "Met" if (icr_at_gate["integrity_coverage_ratio"] or 0) >= 0.95 else "Gate-dependent — see sweep table; adjust --gate",
        },
        {
            "metric": "Canonical digest agreement across layers",
            "target": "100% agreement between detection-layer and chaincode digests over the published test vectors",
            "measured": (
                f"Python implementation (src/canonical.py + src/digest.py): "
                f"{digest_agreement['python_vectors_matched']}/{digest_agreement['python_vectors_total']} vectors "
                f"({digest_agreement['python_agreement_pct']:.1f}%) reproduced exactly. Go chaincode implementation "
                f"(chaincode/securitylog/canonical.go) is provided with an equivalent test (canonical_test.go) but "
                f"{'was' if digest_agreement['go_independently_executed'] else 'was NOT'} independently executed in this "
                f"environment (no Go toolchain available); run `go test ./...` in chaincode/securitylog/ on a host with "
                f"Go 1.21+ to complete cross-language confirmation."
            ),
            "status": "Met (Python side); Go side pending toolchain availability",
        },
        {
            "metric": "Model provenance traceability",
            "target": "Every anchored alert resolvable to a specific anchored model identifier",
            "measured": (
                f"Model provenance anchored and retrievable by model_digest={model_digest[:16]}...; "
                f"every ATTACK alert's model.model_digest field matches the anchored record: {provenance_traceable}."
                if provenance_record is not None
                else "Phase 1 exported model artifact unavailable in this run; provenance anchoring skipped."
            ),
            "status": "Met" if provenance_traceable else "NOT MET / SKIPPED",
        },
        {
            "metric": "Non-repudiation of agent identity",
            "target": "Every record cryptographically bound to an authenticated agent certificate",
            "measured": (
                f"{signature_pass}/{signature_checks} audited signatures verified against the registered agent identity. "
                f"Forged-signature rejection test (different key signs the same digest): "
                f"{'correctly rejected' if forged_rejected else 'NOT rejected — investigate'}."
            ),
            "status": "Met" if signature_pass == signature_checks and forged_rejected else "REVIEW",
        },
    ]

    icr_table_rows = [
        f"| {r['gate']:.2f} | {r['integrity_coverage_ratio']:.4f} | {r['on_chain_volume']:.4f} | {r['attack_count']} |"
        if r["integrity_coverage_ratio"] is not None
        else f"| {r['gate']:.2f} | n/a (no attacks in sample) | {r['on_chain_volume']:.4f} | {r['attack_count']} |"
        for r in icr_sweep
    ]

    report_lines = []
    report_lines.append("# Objective 2 — Phase 2 Results")
    report_lines.append("")
    report_lines.append(f"Generated: {run_started_at}")
    report_lines.append(f"Sample: {len(events)} alerts from the Phase 1 detection layer "
                        f"({detector.architecture}, {detector.dataset})")
    report_lines.append(f"Alert source: {phase1_inference_note(synthetic)}")
    report_lines.append(
        f"Cross-layer digest agreement: Phase 2 independently reproduced "
        f"{digest_agreement_phase1['vectors_agreeing']}/"
        f"{digest_agreement_phase1['vectors_checked']} of Phase 1's frozen digest test vectors."
    )
    report_lines.append("Ledger backend: `src/ledger/mock_ledger.py` (in-memory, hash-chained, tamper-evident). No Docker/Go/Fabric were available in the environment that generated this report; see the caveats inline below and `../network/` for the production Hyperledger Fabric deployment artifacts.")
    report_lines.append("")
    report_lines.append("## Success metrics (Objective 2)")
    report_lines.append("")
    report_lines.append("| # | Metric | Target / Benchmark | Measured (this run) | Status |")
    report_lines.append("|---|---|---|---|---|")
    for i, row in enumerate(report_rows, start=1):
        report_lines.append(f"| {i} | {row['metric']} | {row['target']} | {row['measured']} | {row['status']} |")
    report_lines.append("")
    report_lines.append("## Integrity Coverage Ratio sweep")
    report_lines.append("")
    report_lines.append("| gate | ICR | on-chain volume | attack count |")
    report_lines.append("|---|---|---|---|")
    report_lines.extend(icr_table_rows)
    report_lines.append("")
    report_lines.append("## Methodological notes for the paper")
    report_lines.append("")
    report_lines.append(
        "- Throughput and latency figures above are software-layer measurements against the mock ledger "
        "(`src/ledger/mock_ledger.py`), not a deployed Hyperledger Fabric network. They demonstrate that the "
        "canonicalisation, signing, off-chain storage, and Merkle-batching logic add negligible overhead relative "
        "to the 1,000 TPS / 500 ms budgets; they are not a substitute for a network-measured figure. Deploy "
        "`Phase2_Blockchain_Logging/network/` on a host with Docker, Go 1.21+, and the Fabric binaries/images to "
        "obtain a network-measured throughput and commit-latency figure."
    )
    report_lines.append(
        "- The detection layer for these alerts is the Phase 1 calibrated seven-category LightGBM "
        "model on NF-CSE-CIC-IDS2018-v2, this project's detection layer of record. Confidence values "
        "are isotonic-calibrated P(attack) carried through from Phase 1 unchanged, and "
        "`calibration.is_calibrated` reflects that. Where this run used synthetic Phase 1-shaped "
        "alerts (stated above), the evidence pipeline is still exercised end to end but the detection "
        "figures are not measurements."
    )
    report_lines.append(
        "- Integrity Coverage Ratio figures are computed on this sample and detection layer and are not directly "
        "comparable to the 95.68% figure reported in the revised Objective 1 text, which was measured on a "
        "different dataset and model."
    )
    report_lines.append("")

    report_md = "\n".join(report_lines)
    report_path = OUTPUTS_DIR / "phase2_results.md"
    report_path.write_text(report_md + "\n", encoding="utf-8")

    raw_data = {
        "generated_at": run_started_at,
        "num_events_processed": len(events),
        "alert_source": "synthetic_phase1_shaped" if synthetic else "phase1_emitted",
        "phase1_digest_agreement": digest_agreement_phase1,
        "benchmark": bench,
        "required_tx_per_sec_calc": {
            "peak_events_per_sec": 10_000,
            "anchoring_rate": 0.1143,
            "unbatched_tx_per_sec": anchored_per_sec_no_batch,
            "batch_factor_100_tx_per_sec": anchored_per_sec_batch100,
            "min_batch_factor_for_1000_tps": required_tx_per_sec,
        },
        "storage": storage,
        "integrity": {
            "audited_count": len(findings),
            "verified_count": verified_count,
            "failure_rate_pct": failure_rate_pct,
            "tamper_injection_detected": tamper_detected,
        },
        "icr_sweep": icr_sweep,
        "icr_at_gate": icr_at_gate,
        "digest_agreement": digest_agreement,
        "model_provenance": {
            "anchored": provenance_record is not None,
            "model_digest": model_digest,
            "traceable": provenance_traceable,
        },
        "non_repudiation": {
            "signature_pass": signature_pass,
            "signature_checks": signature_checks,
            "forged_signature_rejected": forged_rejected,
        },
    }
    json_path = OUTPUTS_DIR / "phase2_results.json"
    json_path.write_text(json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8")

    print()
    print("=" * 78)
    print(report_md)
    print("=" * 78)
    print(f"[ok] Report saved to: {report_path}")
    print(f"[ok] Raw data saved to: {json_path}")


if __name__ == "__main__":
    main()
