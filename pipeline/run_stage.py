#!/usr/bin/env python3
"""Validated Phase 1 handoff and isolated MockLedger experiments.

No legacy STAHN fallback. Smoke fixtures are explicitly synthetic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "Phase2_Blockchain_Logging"),
                str(ROOT / "Phase3_Performance_Optimization"),
                str(ROOT / "Phase_1" / "outputs" / "10_contract")]
import jsonschema
from canonical_hash import event_hash, fmt
from src.alert_builder import build_alert_from_oracle_response
from src.anchoring_policy import AnchoringDecision
from src.audit import compliance_report
from src.digest import digest_event
from src.evidence_store import LocalContentAddressedStore, put_json
from src.ledger.mock_ledger import MockLedger
from src.model_provenance import build_provenance_record, sha256_file
from src.pipeline import Phase2Pipeline
from src.signing import load_or_create_agent_identity

CONTRACT = ROOT / "Phase_1" / "outputs" / "10_contract"
MODEL = ROOT / "Phase_1" / "outputs" / "09_model"
CATEGORIES = {"Benign": "BENIGN", "Bot": "Botnet", "Web Attacks": "Web-based",
              "DDoS": "DDoS", "DoS": "DoS", "BruteForce": "BruteForce",
              "Infiltration": "Infiltration"}


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def save_lines(path: Path, values) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for value in values:
            stream.write(json.dumps(value, allow_nan=False) + "\n")


def read_alerts(path: Path, limit: int) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                rows.append(json.loads(line))
            if len(rows) == limit:
                break
    if not rows:
        raise ValueError(f"Empty alert stream: {path}")
    if len({a["event_id"] for a in rows}) != len(rows):
        raise ValueError("Duplicate event IDs in selected alert stream")
    return rows


def feature_hash(features: dict) -> str:
    text = "|".join(f"{key}={fmt(features[key])}" for key in sorted(features))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_alert(alert: dict, schema: dict) -> None:
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(alert)
    if not alert.get("features"):
        raise ValueError("Full alerts with features are required, not on-chain projections")
    if feature_hash(alert["features"]) != alert["feature_digest"]:
        raise ValueError("Phase 1 feature digest mismatch")
    if event_hash(alert) != alert["event_hash"]:
        raise ValueError("Phase 1 event hash mismatch")
    if (alert["verdict"] == "NORMAL") != (alert["threat_class"] == "Benign"):
        raise ValueError("Inconsistent verdict and threat class")


def adapt(alert: dict, model_digest: str, *, synthetic: bool = False) -> dict:
    """Retain P(attack), not P(predicted class); source anchor flag is authoritative."""
    event = build_alert_from_oracle_response(
        {"is_attack": alert["verdict"] == "ANOMALY",
         "confidence_score": alert["confidence"], "model_version": alert["model_version"]},
        list(alert["features"]), list(alert["features"].values()),
        "nf-cse-cic-ids2018-lightgbm" if not synthetic else "SYNTHETIC-SMOKE",
        model_digest, alert["cloud_resource_id"] or "unknown-resource",
        alert["inference_latency_ms"],
        source_address=address(alert.get("src_ip"), alert.get("src_port")),
        destination_address=address(alert.get("dst_ip"), alert.get("dst_port")),
        threat_category=CATEGORIES[alert["threat_class"]],
        feature_attributions=[{"feature": item["feature"], "contribution": item["shap"]}
                              for item in alert.get("top_contributing_features", [])],
        event_id=alert["event_id"], timestamp=alert["timestamp"],
    )
    event["severity"] = {"NONE": "informational", "LOW": "low", "MEDIUM": "medium",
                         "HIGH": "high", "CRITICAL": "critical"}[alert["severity"]]
    event["calibration"] = {"is_calibrated": not synthetic,
                            "method": "none" if synthetic else "isotonic"}
    event["payload_digest"] = digest_event(event)
    return event


def address(ip, port) -> str | None:
    if ip is None:
        return None
    return str(ip) if port is None else f"[{ip}]:{port}"


class SourceAnchorPolicy:
    """Preserve the producer's decision; rounding cannot alter the gate outcome."""
    def __init__(self, anchors: dict[str, bool]):
        self.anchors = anchors

    def decide(self, event):
        if not self.anchors[event["event_id"]]:
            return AnchoringDecision.OFF_CHAIN_ONLY
        return (AnchoringDecision.IMMEDIATE if event["severity"] == "critical"
                else AnchoringDecision.BATCH)


def fixture(limit: int) -> list[dict]:
    features = json.loads((MODEL / "model_card.json").read_text())["features"]
    rows = []
    for i in range(limit):
        category = list(CATEGORIES)[i % len(CATEGORIES)]
        values = {key: float((i + j) % 13) for j, key in enumerate(features)}
        alert = {
            "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"synthetic-smoke/{i}")),
            "schema_version": "1.0.0", "timestamp": "2026-01-01T00:00:00.000Z",
            "verdict": "NORMAL" if category == "Benign" else "ANOMALY",
            "threat_class": category, "severity": "NONE" if category == "Benign" else "HIGH",
            "confidence": 0.1 if category == "Benign" else 0.99,
            "model_version": "SYNTHETIC-SMOKE-NOT-A-DETECTOR",
            "cloud_resource_id": f"synthetic-{i % 5}",
            "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None,
            "features": values, "feature_digest": feature_hash(values),
            "anchor": category != "Benign", "anchor_gate_tau": 0.95,
            "inference_latency_ms": 0.0,
        }
        alert["event_hash"] = event_hash(alert)
        rows.append(alert)
    return rows


def prepare(args) -> tuple[list[dict], dict]:
    synthetic = args.mode == "smoke"
    source = args.run_dir / "phase1" / "alerts.jsonl"
    if synthetic:
        rows = fixture(args.limit)
        artifact = args.run_dir / "phase1" / "synthetic-artifact.json"
        save(artifact, {"purpose": "SYNTHETIC TEST FIXTURE, NOT TRAINED MODEL", "version": 1})
        card = {"features": list(rows[0]["features"]), "labels": list(CATEGORIES),
                "model_version": rows[0]["model_version"]}
    else:
        rows = read_alerts(args.alerts, args.limit)
        artifact = MODEL / "detector_bundle.joblib"
        card = json.loads((MODEL / "model_card.json").read_text(encoding="utf-8"))
        if not artifact.is_file():
            raise FileNotFoundError(f"Missing trained bundle: {artifact}")
        if not str(card.get("calibration", "")).startswith("isotonic"):
            raise ValueError("Adapter requires documented isotonic P(attack) calibration")
    schema = json.loads((CONTRACT / "alert_schema.json").read_text())
    for alert in rows:
        validate_alert(alert, schema)
        if alert["model_version"] != card["model_version"]:
            raise ValueError("Alert model version does not match model card")
        if set(alert["features"]) != set(card["features"]):
            raise ValueError("Alert features do not match model card")
    save_lines(source, rows)
    provenance = build_provenance_record(
        artifact, "SYNTHETIC-SMOKE" if synthetic else "nf-cse-cic-ids2018-lightgbm",
        card["model_version"], card["features"], card["labels"],
        f"sha256:{sha256_file(artifact)}", rows[0]["timestamp"],
        hyperparameters=card.get("hyperparameters", {}),
        thresholds={"class_thresholds": card.get("class_thresholds", {}),
                    "anchoring_gate": card.get("anchoring_gate", {})},
        training_summary={"synthetic": synthetic, "source_model_card": card},
    ).to_dict()
    metadata = {
        "adapter_version": "1.0.0", "synthetic": synthetic, "backend": "MockLedger",
        "source_alerts_sha256": sha256_file(source),
        "artifact_sha256": sha256_file(artifact), "provenance": provenance,
        "confidence_semantics": "P(attack), not multiclass correctness",
        "anchor_policy": "preserve Phase 1 anchor flag; critical immediate, others batched",
        "category_mapping": CATEGORIES, "source": str(args.alerts) if not synthetic else "synthetic fixture",
        "limitations": [
            "No Fabric consensus or distributed deployment measured.",
            "No new detection accuracy or ground-truth ICR is computed.",
            "Source event_hash excludes some fields; whole source file is separately hashed.",
            "Model version/card association checked; inference is not recomputed from alerts.",
            "Existing Phase2Pipeline batches still write one mock event record per alert; "
            "do not interpret this as one Fabric transaction per Merkle batch.",
        ],
    }
    save(args.run_dir / "phase1" / "handoff.json", metadata)
    return rows, metadata


def make_pipeline(directory: Path, metadata: dict, anchors: dict):
    directory.mkdir(parents=True, exist_ok=False)
    store = LocalContentAddressedStore(directory / "evidence")
    identity = load_or_create_agent_identity("integrated-agent", directory / "keys" / "agent.pem")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()},
                        persist_path=directory / "ledger.json")
    ledger.anchor_model_provenance(metadata["provenance"])
    pipeline = Phase2Pipeline(store, ledger, identity, SourceAnchorPolicy(anchors), batch_size=100)
    return pipeline, ledger, store, identity


def audit(pipeline, ledger, store, identity, expected: int) -> dict:
    pipeline.close()
    result = compliance_report(ledger, store, identity.public_key_hex())
    if (not ledger.verify_chain_integrity() or result["verified"] != expected
            or result["tampered"] or result["incomplete"]):
        raise ValueError(f"Ledger audit failed: {result}, expected {expected} anchored events")
    return result


def phase2(args) -> None:
    source = args.run_dir / "phase1" / "alerts.jsonl"
    handoff = args.run_dir / "phase1" / "handoff.json"
    if handoff.exists():
        metadata = json.loads(handoff.read_text())
        if metadata["synthetic"] != (args.mode == "smoke"):
            raise ValueError("Phase 2 mode does not match Phase 1 provenance")
        if sha256_file(source) != metadata["source_alerts_sha256"]:
            raise ValueError("Phase 1 -> Phase 2 handoff digest mismatch")
        rows = read_alerts(source, args.limit)
        schema = json.loads((CONTRACT / "alert_schema.json").read_text())
        for alert in rows:
            validate_alert(alert, schema)
    else:
        rows, metadata = prepare(args)
    directory = args.run_dir / "phase2"
    anchors = {a["event_id"]: a["anchor"] for a in rows}
    events = [adapt(a, metadata["provenance"]["model_digest"], synthetic=metadata["synthetic"])
              for a in rows]
    pipeline, ledger, store, identity = make_pipeline(directory, metadata, anchors)
    mappings = []
    start = time.perf_counter()
    for source, event in zip(rows, events):
        stored_source = put_json(store, source)
        result = pipeline.submit(event)
        mappings.append({"event_id": event["event_id"], "phase1_event_hash": source["event_hash"],
                         "phase1_content_address": stored_source.content_address,
                         "phase2_payload_digest": event["payload_digest"],
                         "phase2_content_address": result.content_address,
                         "anchor": source["anchor"]})
    report = audit(pipeline, ledger, store, identity, sum(anchors.values()))
    save_lines(directory / "events.jsonl", events)
    save(directory / "mapping.json", mappings)
    metadata.update({"events_sha256": sha256_file(directory / "events.jsonl"),
                     "anchors": anchors, "mapping_sha256": sha256_file(directory / "mapping.json")})
    save(directory / "handoff.json", metadata)
    save(directory / "results.json", {
        "synthetic": metadata["synthetic"], "backend": "MockLedger",
        "processed": len(events), "anchored": sum(anchors.values()),
        "off_chain_only": len(events) - sum(anchors.values()),
        "elapsed_seconds_including_audit": time.perf_counter() - start, "audit": report,
    })
    print(f"Phase 2: {len(events)} alerts processed; {sum(anchors.values())} anchors verified.")


def phase3(args) -> None:
    from perf.async_pipeline import AsyncSubmissionService, InMemoryQueueBackend
    previous = args.run_dir / "phase2"
    metadata = json.loads((previous / "handoff.json").read_text())
    if metadata["synthetic"] != (args.mode == "smoke"):
        raise ValueError("Phase 3 mode does not match Phase 2 provenance")
    if sha256_file(previous / "events.jsonl") != metadata["events_sha256"]:
        raise ValueError("Phase 2 -> Phase 3 handoff digest mismatch")
    if sha256_file(previous / "mapping.json") != metadata["mapping_sha256"]:
        raise ValueError("Phase 2 mapping digest mismatch")
    events = read_alerts(previous / "events.jsonl", args.limit)
    anchors = {e["event_id"]: metadata["anchors"][e["event_id"]] for e in events}
    trials = []
    out = args.run_dir / "phase3"
    out.mkdir(parents=True, exist_ok=False)
    for repeat in range(args.repeats):
        # Alternate ordering to reduce systematic warm-cache/order bias.
        for mode in (("sync", "async") if repeat % 2 == 0 else ("async", "sync")):
            pipeline, ledger, store, identity = make_pipeline(out / f"{repeat}-{mode}", metadata, anchors)
            latencies = []
            def submit(event):
                start = time.perf_counter()
                pipeline.submit(event)
                latencies.append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            stats = None
            if mode == "async":
                # One consumer: Phase2Pipeline's mutable Merkle batch is not thread-safe.
                service = AsyncSubmissionService(InMemoryQueueBackend(), submit, num_workers=1)
                service.start()
                try:
                    for event in events:
                        service.enqueue(event)
                finally:
                    stopped = service.stop(drain=True, drain_timeout_sec=300)
                stats = service.stats.snapshot()
                if not stopped or not stats["zero_loss"] or stats["dead_lettered"]:
                    raise ValueError(f"Async replay failed: {stats}")
            else:
                for event in events:
                    submit(event)
            pipeline.close()
            elapsed = time.perf_counter() - start
            report = audit(pipeline, ledger, store, identity, sum(anchors.values()))
            ordered = sorted(latencies)
            trials.append({
                "repeat": repeat, "mode": mode, "events": len(events),
                "elapsed_seconds_including_drain_and_flush": elapsed,
                "processed_events_per_second": len(events) / elapsed,
                "submit_service_ms_p50": statistics.median(ordered),
                "submit_service_ms_p99": ordered[max(0, (99 * len(ordered) + 99) // 100 - 1)],
                "audit": report, "async_stats": stats,
            })
    save(out / "results.json", {
        "synthetic": metadata["synthetic"], "backend": "MockLedger",
        "experiment": "paired synchronous/asynchronous replay of Phase 2 alerts",
        "input_sha256": metadata["events_sha256"], "trials": trials,
        "limitations": metadata["limitations"] + [
            "Service latency excludes queue residence and final batch flush.",
            "Throughput includes queue drain/shutdown and final flush, excludes audit.",
            "Single consumer, local evidence store; no distributed scalability claim.",
            "Async is not assumed faster; report the measurements without forcing a speedup.",
        ],
    })
    print(f"Phase 3: {len(trials)} replay trials completed and audited.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("phase1", "phase2", "phase3"))
    parser.add_argument("--mode", choices=("train", "existing", "smoke"), required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.limit < 1 or args.repeats < 1:
        parser.error("--limit and --repeats must be positive")
    if args.phase == "phase1":
        rows, metadata = prepare(args)
        print(f"Phase 1: {len(rows)} validated alerts; synthetic={metadata['synthetic']}")
    elif args.phase == "phase2":
        phase2(args)
    else:
        phase3(args)


if __name__ == "__main__":
    main()
