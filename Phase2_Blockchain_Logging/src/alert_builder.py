"""Builds a frozen-contract alert event from Phase 1 detector output.

The actual Phase 1 STAHN artifact is delivered as a binary classifier via
``Phase1_Submission/blockchain_oracle_api.py``'s ``/verify_transaction``
endpoint, which returns::

    {"is_attack": bool, "confidence_score": float, "action_required": str,
     "model_version": str}

Objective 2's frozen alert contract (contracts/alert_event.schema.json) is
richer than this: seven-category threat_category, explicit calibration
provenance, model_digest, feature attributions, per-flow latency. This
module is the adapter between what Phase 1 actually emits today and what
the Objective 2 contract requires, so Phase 2 does not have to wait for a
Phase 1 rewrite to be useful, and so the contract never silently degrades
to whatever the easiest producer happens to emit.

Where Phase 1's binary oracle cannot supply a field the Objective 2 contract
requires, this module fills it with an explicit, honestly-labelled default
(``threat_category="Other"``, ``calibration.is_calibrated=False``,
``feature_attributions=[]``) rather than fabricating a value — an auditor
reading calibration.is_calibrated=False knows exactly how much trust the
calibrated_confidence field deserves upstream of Objective 3's anchoring
gate.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from .digest import digest_event

DEFAULT_CONTRACT_VERSION = "1.0.0"


def _severity_for(verdict: str, confidence: float) -> str:
    if verdict == "BENIGN":
        return "informational"
    if confidence >= 0.99:
        return "critical"
    if confidence >= 0.90:
        return "high"
    if confidence >= 0.70:
        return "medium"
    return "low"


def build_alert_from_oracle_response(
    oracle_response: dict,
    feature_names: Sequence[str],
    feature_values: Sequence[float],
    model_id: str,
    model_digest: str,
    resource_id: str,
    inference_latency_ms: float,
    source_address: str | None = None,
    destination_address: str | None = None,
    threat_category: str | None = None,
    feature_attributions: list[dict] | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
) -> dict:
    """Adapt a ``blockchain_oracle_api.py`` JSON response into a complete,
    schema-conformant, digested alert event.

    ``oracle_response`` is exactly the dict returned by
    ``POST /verify_transaction`` (``is_attack``, ``confidence_score``,
    ``model_version``); see Phase1_Submission/blockchain_oracle_api.py.
    """
    if len(feature_names) != len(feature_values):
        raise ValueError(
            f"feature_names ({len(feature_names)}) and feature_values "
            f"({len(feature_values)}) length mismatch"
        )

    is_attack = bool(oracle_response["is_attack"])
    verdict = "ATTACK" if is_attack else "BENIGN"
    confidence = float(oracle_response["confidence_score"])
    resolved_category = threat_category or ("Other" if is_attack else "BENIGN")

    event: dict = {
        "contract_version": DEFAULT_CONTRACT_VERSION,
        "event_id": event_id or str(uuid.uuid4()),
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "verdict": verdict,
        "threat_category": resolved_category,
        "severity": _severity_for(verdict, confidence),
        "calibrated_confidence": confidence,
        "calibration": {
            # The delivered Phase 1 STAHN artifact reports raw softmax
            # output; it has not been through Objective 1's isotonic
            # calibration step. Recorded honestly rather than implied.
            "is_calibrated": False,
            "method": "none",
        },
        "source_address": source_address,
        "destination_address": destination_address,
        "resource_id": resource_id,
        "triggering_features": {
            name: float(value) for name, value in zip(feature_names, feature_values)
        },
        "model": {
            "model_id": model_id,
            "model_digest": model_digest,
            "version_label": str(oracle_response.get("model_version", "unknown")),
        },
        "feature_attributions": feature_attributions or [],
        "inference_latency_ms": float(inference_latency_ms),
    }
    event["payload_digest"] = digest_event(event)
    return event
