"""Builds contract-conformant alert events from the Phase 1 detection layer.

The detection layer of record is the Phase 1 LightGBM multiclass detector
(``Phase_1/``): 25 NetFlow features, seven coarse threat categories, isotonic
calibration fitted on the validation fold, trained and evaluated on
NF-CSE-CIC-IDS2018-v2. Phase 1 already emits a frozen alert contract
(``Phase_1/outputs/10_contract/``); this module adapts that contract into the
Objective 2 evidence contract (``contracts/alert_event.schema.json``).

What this module does and does not do
------------------------------------
It *translates and verifies*. It never re-derives a detection result:

* ``threat_category``, ``calibrated_confidence`` and the feature vector are
  carried through from Phase 1 unchanged.
* ``severity`` is Phase 1's own severity decision, renamed to Phase 2's
  lowercase vocabulary (``src/detection_layer.py:SEVERITY_TRANSLATION``). It is
  *not* recomputed from confidence, because Phase 1 deliberately rates
  Infiltration CRITICAL despite its low mean confidence (0.303) - a
  confidence-derived severity would silently overturn that decision.
* ``calibration`` records the method Phase 1 documents, with the measured
  expected calibration error. Objective 3's anchoring gate is a probability
  threshold and is only defensible against a calibrated score, so this field
  must reflect reality rather than a conservative default.
* ``detection_contract`` carries Phase 1's own ``event_hash`` and
  ``feature_digest``, each independently recomputed here before the event is
  admitted (``src/phase1_contract.py``). Phase 1's CONTRACT.md designates
  ``event_hash`` as the value committed on-chain, so it travels with the event
  rather than being discarded in favour of Phase 2's envelope digest.

Historical note
---------------
Earlier revisions of this module adapted a ``blockchain_oracle_api.py``
response from a PyTorch binary classifier ("STAHN", CICIoT2023, reported
98.62% accuracy) and recorded ``calibration.is_calibrated = False``. That
detector is not the Phase 1 model in this repository - different architecture,
dataset and label space - so that adapter has been removed rather than kept as
a second, contradictory description of the detection layer.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from .detection_layer import (
    SEVERITY_TRANSLATION,
    THREAT_CATEGORIES,
    model_identity,
    severity_for,
    verdict_for,
)
from .digest import digest_event
from .phase1_contract import PHASE1_SCHEMA_VERSION, verify_alert

DEFAULT_CONTRACT_VERSION = "2.0.0"

PHASE1_PRODUCER = "Phase_1/10_alert_contract.py"

#: Phase 1's verdict vocabulary -> Objective 2's.
VERDICT_TRANSLATION = {"ANOMALY": "ATTACK", "NORMAL": "BENIGN"}


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_alert_event(
    threat_category: str,
    calibrated_confidence: float,
    feature_names: Sequence[str],
    feature_values: Sequence[float],
    model_id: str,
    model_digest: str,
    version_label: str,
    resource_id: str,
    inference_latency_ms: float,
    *,
    calibration_method: str = "isotonic",
    expected_calibration_error: float | None = None,
    source_address: str | None = None,
    destination_address: str | None = None,
    feature_attributions: list[dict] | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
    detection_contract: dict | None = None,
    severity: str | None = None,
) -> dict:
    """Assemble a complete, schema-conformant, digested alert event.

    This is the single constructor for Objective 2 alert events. Phase 1 alerts
    reach it through :func:`build_alert_from_phase1_alert`; Phase 3's synthetic
    load generator calls it directly with an explicitly synthetic
    ``version_label`` so a generated event can never be mistaken for a
    measured detection.
    """
    if len(feature_names) != len(feature_values):
        raise ValueError(
            f"feature_names ({len(feature_names)}) and feature_values "
            f"({len(feature_values)}) length mismatch"
        )
    if not feature_names:
        raise ValueError("an alert must carry at least one feature for off-chain evidence")
    if threat_category not in THREAT_CATEGORIES:
        raise ValueError(
            f"threat_category {threat_category!r} is outside Phase 1's label space "
            f"{THREAT_CATEGORIES}. Phase 2 does not invent categories the detector "
            "cannot emit."
        )
    if not 0.0 <= float(calibrated_confidence) <= 1.0:
        raise ValueError(f"calibrated_confidence {calibrated_confidence!r} is not a probability")
    if calibration_method not in ("isotonic", "platt", "none"):
        raise ValueError(f"unknown calibration method {calibration_method!r}")

    calibration: dict = {
        "is_calibrated": calibration_method != "none",
        "method": calibration_method,
    }
    if expected_calibration_error is not None:
        calibration["expected_calibration_error"] = float(expected_calibration_error)

    event: dict = {
        "contract_version": DEFAULT_CONTRACT_VERSION,
        "event_id": event_id or str(uuid.uuid4()),
        "timestamp": timestamp or _utc_timestamp(),
        "verdict": verdict_for(threat_category),
        "threat_category": threat_category,
        "severity": severity or severity_for(threat_category),
        "calibrated_confidence": float(calibrated_confidence),
        "calibration": calibration,
        "source_address": source_address,
        "destination_address": destination_address,
        "resource_id": resource_id,
        "triggering_features": {
            name: float(value) for name, value in zip(feature_names, feature_values)
        },
        "model": {
            "model_id": model_id,
            "model_digest": model_digest,
            "version_label": version_label,
        },
        "feature_attributions": feature_attributions or [],
        "inference_latency_ms": float(inference_latency_ms),
    }
    if detection_contract is not None:
        event["detection_contract"] = detection_contract
    event["payload_digest"] = digest_event(event)
    return event


def build_alert_from_phase1_alert(
    phase1_alert: dict,
    *,
    model_id: str,
    model_digest: str,
    verify: bool = True,
    calibration_method: str | None = None,
    expected_calibration_error: float | None = None,
) -> dict:
    """Adapt one Phase 1 alert into an Objective 2 evidence event.

    ``phase1_alert`` is a record from Phase 1's ``sample_alerts.jsonl``,
    conforming to ``Phase_1/outputs/10_contract/alert_schema.json``.

    With ``verify=True`` (the default) the producer's ``event_hash`` and
    ``feature_digest`` are recomputed from Phase 1's frozen canonical rules
    before anything is built, so an altered alert is rejected here rather than
    anchored as evidence.
    """
    if verify:
        verify_alert(phase1_alert)

    identity = None
    if calibration_method is None or expected_calibration_error is None:
        try:
            identity = model_identity()
        except Exception:  # noqa: BLE001 - model card absent (e.g. synthetic run)
            identity = None
    if calibration_method is None:
        calibration_method = identity.calibration_method if identity else "none"
    if calibration_method == "none":
        # An uncalibrated score has no calibration error to report. Inheriting
        # the deployed model's measured ECE here would let a synthetic or
        # uncalibrated event carry a real measurement it did not earn.
        expected_calibration_error = None
    elif expected_calibration_error is None and identity is not None:
        expected_calibration_error = identity.expected_calibration_error

    threat_category = phase1_alert["threat_class"]
    attributions = [
        {"feature": item["feature"], "contribution": float(item["shap"])}
        for item in phase1_alert.get("top_contributing_features") or []
    ]

    detection_contract = {
        "producer": PHASE1_PRODUCER,
        "schema_version": phase1_alert.get("schema_version", PHASE1_SCHEMA_VERSION),
        "event_hash": phase1_alert["event_hash"],
        "feature_digest": phase1_alert["feature_digest"],
        "producer_anchor_decision": bool(phase1_alert.get("anchor", False)),
        "digest_verified_by_consumer": bool(verify),
    }
    if phase1_alert.get("anchor_gate_tau") is not None:
        detection_contract["anchor_gate_tau"] = float(phase1_alert["anchor_gate_tau"])

    # Carry the producer's own severity through, only renaming the vocabulary.
    # Re-deriving it from the category (or from confidence) would let Phase 2
    # overrule a decision that belongs to the detection layer.
    producer_severity = phase1_alert.get("severity")
    severity = SEVERITY_TRANSLATION.get(producer_severity) if producer_severity else None
    if producer_severity and severity is None:
        raise ValueError(
            f"Alert {phase1_alert['event_id']} carries severity {producer_severity!r}, "
            f"which has no Phase 2 equivalent. Known: {sorted(SEVERITY_TRANSLATION)}"
        )

    features = phase1_alert["features"]
    return build_alert_event(
        threat_category=threat_category,
        # Phase 1's `confidence` is calibrated P(attack), not P(argmax class);
        # carried through unchanged so the anchoring gate keeps its meaning.
        calibrated_confidence=phase1_alert["confidence"],
        feature_names=list(features),
        feature_values=list(features.values()),
        model_id=model_id,
        model_digest=model_digest,
        version_label=phase1_alert["model_version"],
        resource_id=phase1_alert.get("cloud_resource_id") or "unmapped-resource",
        inference_latency_ms=phase1_alert.get("inference_latency_ms", 0.0),
        calibration_method=calibration_method,
        expected_calibration_error=expected_calibration_error,
        source_address=format_address(phase1_alert.get("src_ip"), phase1_alert.get("src_port")),
        destination_address=format_address(phase1_alert.get("dst_ip"), phase1_alert.get("dst_port")),
        feature_attributions=attributions,
        event_id=phase1_alert["event_id"],
        timestamp=phase1_alert["timestamp"],
        detection_contract=detection_contract,
        severity=severity,
    )


def format_address(ip: str | None, port: int | None) -> str | None:
    """Render nullable IP/port metadata as a single address string.

    Identifiers never enter the feature vector (Phase 1's central rule); they
    travel here as metadata so an analyst can act on an alert without the model
    having trained on them.
    """
    if ip is None:
        return None
    if port is None:
        return str(ip)
    return f"{ip}:{port}"
