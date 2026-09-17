"""Independent re-implementation of Phase 1's frozen alert digest.

Phase 1 freezes its cross-layer interface in
``Phase_1/outputs/10_contract/CONTRACT.md``: an alert's ``event_hash`` is
SHA-256 over a *canonical string* (not over JSON), built from a fixed field
order, pipe-joined, with floats at fixed six decimals and ``null`` rendered as
the single byte 0x00. Phase 1 ships a reference implementation
(``canonical_hash.py``) and fixed test vectors (``hash_test_vectors.json``).

This module re-implements those rules from the specification and verifies
itself against Phase 1's vectors. That is deliberate, and it is the point:

* Phase 2 must be able to state that an alert's digest is correct *without*
  trusting the producer's own code path. Two independent implementations
  agreeing on shared vectors is the evidentiary claim Objective 2 needs;
  importing Phase 1's function would only prove that a function equals itself.
* Phase 1 stays untouched. This module reads its vectors; it never edits them.

Scope of the two digests in this project
---------------------------------------
``event_hash`` (here)     - the producer's digest over the fields Phase 1
                            freezes. This is the value Phase 1's CONTRACT.md
                            designates for on-chain commitment, so it is the
                            value Phase 2 anchors.
``payload_digest``        - Phase 2's canonical-JSON digest over its own,
(``src/digest.py``)         richer envelope (``docs/canonicalisation_spec.md``),
                            mirrored by the Go chaincode. Internal to Phase 2.

Both are carried and both are verified; neither is silently substituted for the
other.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Iterator

from .detection_layer import (
    ALERT_SCHEMA_PATH,
    HASH_VECTORS_PATH,
    SAMPLE_ALERTS_PATH,
    DetectionLayerUnavailable,
)

#: Fixed field order from Phase 1's CONTRACT.md. Not sorted, not derived from
#: the payload - reordering this list is a breaking change to Phase 1's
#: contract and would invalidate every previously anchored digest.
DIGEST_FIELDS: tuple[str, ...] = (
    "event_id",
    "schema_version",
    "timestamp",
    "verdict",
    "threat_class",
    "confidence",
    "model_version",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "cloud_resource_id",
    "feature_digest",
)

NULL_RENDERING = "\x00"
FLOAT_DECIMALS = 6

PHASE1_SCHEMA_VERSION = "1.0.0"


class Phase1ContractError(ValueError):
    """Raised when an alert does not satisfy Phase 1's frozen contract."""


def render(value: Any) -> str:
    """Render one value as Phase 1's canonical string fragment.

    Rules, verbatim from Phase 1's CONTRACT.md:
    ``null`` -> single byte 0x00 (distinct from the empty string); bools ->
    ``true``/``false``; floats -> fixed six decimals (chosen because Python
    ``repr`` and Go ``strconv`` disagree on shortest round-trip forms);
    integers -> decimal; everything else -> ``str``.
    """
    if value is None:
        return NULL_RENDERING
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.{FLOAT_DECIMALS}f}"
    if isinstance(value, int):
        return str(value)
    return str(value)


def canonical_string(alert: dict) -> str:
    """Phase 1's canonical string for an alert: fixed order, pipe-joined."""
    return "|".join(f"{field}={render(alert.get(field))}" for field in DIGEST_FIELDS)


def event_hash(alert: dict) -> str:
    """SHA-256 of Phase 1's canonical string, lowercase hex."""
    return hashlib.sha256(canonical_string(alert).encode("utf-8")).hexdigest()


def feature_digest(features: dict) -> str:
    """Phase 1's digest over the feature vector alone.

    Sorted by key (unlike the event digest's fixed order) so the on-chain
    record can commit to the features without carrying them.
    """
    payload = "|".join(f"{key}={render(features[key])}" for key in sorted(features))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_against_phase1_vectors() -> dict:
    """Check this implementation against Phase 1's fixed test vectors.

    Returns a summary suitable for a results table. Raises if any vector
    disagrees - a mismatch means the two layers would anchor different digests
    for the same alert, which is a contract break, not a warning.
    """
    if not HASH_VECTORS_PATH.is_file():
        raise DetectionLayerUnavailable(
            f"Missing Phase 1 digest vectors: {HASH_VECTORS_PATH}"
        )
    document = json.loads(HASH_VECTORS_PATH.read_text(encoding="utf-8"))
    vectors = document.get("vectors", document)
    if not vectors:
        raise Phase1ContractError(f"{HASH_VECTORS_PATH} contains no vectors")

    mismatches = []
    for index, vector in enumerate(vectors):
        alert = vector["alert"]
        expected = vector["expected_sha256"]
        computed = event_hash(alert)
        if computed != expected:
            mismatches.append(
                {
                    "index": index,
                    "event_id": alert.get("event_id"),
                    "expected": expected,
                    "computed": computed,
                }
            )
    if mismatches:
        raise Phase1ContractError(
            "Phase 2's re-implementation of Phase 1's digest disagrees with "
            f"Phase 1's own test vectors: {mismatches}"
        )
    return {
        "vector_source": str(HASH_VECTORS_PATH),
        "spec_version": document.get("schema_version", PHASE1_SCHEMA_VERSION),
        "vectors_checked": len(vectors),
        "vectors_agreeing": len(vectors),
        "independent_implementations_agree": True,
        "digest_fields": list(DIGEST_FIELDS),
    }


def verify_alert(alert: dict, *, require_features: bool = True) -> None:
    """Verify one Phase 1 alert against Phase 1's frozen contract.

    Checks the producer's own digests by recomputation, plus the internal
    consistency the contract implies. Raises ``Phase1ContractError`` on any
    violation; a caller that swallows this exception would be anchoring
    evidence it has not verified.
    """
    missing = [field for field in ("event_id", "event_hash", "feature_digest") if field not in alert]
    if missing:
        raise Phase1ContractError(f"Alert is missing required field(s): {missing}")

    if alert.get("schema_version") != PHASE1_SCHEMA_VERSION:
        raise Phase1ContractError(
            f"Alert {alert['event_id']} declares schema_version "
            f"{alert.get('schema_version')!r}; this consumer implements "
            f"{PHASE1_SCHEMA_VERSION!r} and must not guess at field semantics."
        )

    if require_features:
        features = alert.get("features")
        if not features:
            raise Phase1ContractError(
                f"Alert {alert['event_id']} carries no feature vector. This looks "
                "like the on-chain projection (onchain_records.jsonl) rather than "
                "a full alert (sample_alerts.jsonl); Phase 2 needs the full payload "
                "to store off-chain evidence."
            )
        recomputed_features = feature_digest(features)
        if recomputed_features != alert["feature_digest"]:
            raise Phase1ContractError(
                f"Alert {alert['event_id']}: feature_digest mismatch "
                f"(carried {alert['feature_digest']}, recomputed {recomputed_features})."
            )

    recomputed = event_hash(alert)
    if recomputed != alert["event_hash"]:
        raise Phase1ContractError(
            f"Alert {alert['event_id']}: event_hash mismatch "
            f"(carried {alert['event_hash']}, recomputed {recomputed}). The alert "
            "was altered in transit, or the producer and consumer disagree on the "
            "canonical form."
        )

    verdict = alert.get("verdict")
    threat_class = alert.get("threat_class")
    if verdict not in ("NORMAL", "ANOMALY"):
        raise Phase1ContractError(f"Alert {alert['event_id']}: unknown verdict {verdict!r}")
    if (verdict == "NORMAL") != (threat_class == "Benign"):
        raise Phase1ContractError(
            f"Alert {alert['event_id']}: verdict {verdict!r} is inconsistent with "
            f"threat_class {threat_class!r}."
        )

    confidence = alert.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        raise Phase1ContractError(
            f"Alert {alert['event_id']}: confidence {confidence!r} is not a probability."
        )


def load_alert_schema() -> dict:
    """Phase 1's own JSON Schema for its alerts."""
    if not ALERT_SCHEMA_PATH.is_file():
        raise DetectionLayerUnavailable(f"Missing Phase 1 alert schema: {ALERT_SCHEMA_PATH}")
    return json.loads(ALERT_SCHEMA_PATH.read_text(encoding="utf-8"))


def iter_alerts(path: Path | None = None, limit: int | None = None) -> Iterator[dict]:
    """Stream Phase 1 alerts from a JSONL file, verifying each one."""
    source = Path(path) if path is not None else SAMPLE_ALERTS_PATH
    if not source.is_file():
        raise DetectionLayerUnavailable(
            f"Missing Phase 1 alert stream: {source}\n"
            "Phase 1 writes it in stage 10 (10_alert_contract.py). It is excluded "
            "from version control by Phase_1/.gitignore, so a fresh clone will not "
            "contain it."
        )
    emitted = 0
    with source.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError as exc:
                raise Phase1ContractError(f"{source}:{line_number}: invalid JSON ({exc})") from exc
            verify_alert(alert)
            yield alert
            emitted += 1
            if limit is not None and emitted >= limit:
                return


def load_alerts(path: Path | None = None, limit: int | None = None) -> list[dict]:
    """Read and verify Phase 1 alerts, rejecting duplicate event IDs."""
    alerts = list(iter_alerts(path, limit))
    if not alerts:
        raise Phase1ContractError(f"No alerts read from {path or SAMPLE_ALERTS_PATH}")
    identifiers = {alert["event_id"] for alert in alerts}
    if len(identifiers) != len(alerts):
        raise Phase1ContractError(
            f"Duplicate event_id values in {path or SAMPLE_ALERTS_PATH}: "
            f"{len(alerts)} alerts, {len(identifiers)} distinct identifiers."
        )
    return alerts


SYNTHETIC_MARKER = "SYNTHETIC-FIXTURE-NOT-A-DETECTION"


def synthetic_alert(
    index: int,
    threat_class: str,
    confidence: float,
    *,
    features: dict | None = None,
    resource_id: str | None = None,
    gate_tau: float = 0.0,
) -> dict:
    """Build an explicitly-synthetic alert in Phase 1's contract shape.

    For demonstrations and smoke runs on a clone that does not contain Phase 1's
    (gitignored) alert stream. ``model_version`` carries
    ``SYNTHETIC-FIXTURE-NOT-A-DETECTION`` so no figure derived from these alerts
    can be mistaken for a measured detection result.

    Feature values are arbitrary; only the contract shape and the digests are
    meaningful. This helper lives here so the demo scripts, the smoke fixture and
    the load generator all agree on one definition of "Phase 1-shaped".
    """
    from .detection_layer import load_severity_map

    resolved = dict(features or {f"FEATURE_{i:02d}": float((index + i) % 97) for i in range(6)})
    alert = {
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"synthetic-phase1/{index}")),
        "schema_version": PHASE1_SCHEMA_VERSION,
        "timestamp": "2026-01-01T00:00:00.000Z",
        "verdict": "NORMAL" if threat_class == "Benign" else "ANOMALY",
        "threat_class": threat_class,
        "severity": load_severity_map()[threat_class],
        "confidence": round(float(confidence), 6),
        "model_version": SYNTHETIC_MARKER,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "cloud_resource_id": resource_id or f"synthetic-res-{index % 5:04d}",
        "features": resolved,
        "feature_digest": feature_digest(resolved),
        "anchor": threat_class != "Benign" and float(confidence) >= gate_tau,
        "anchor_gate_tau": float(gate_tau),
        "inference_latency_ms": 0.0,
    }
    alert["event_hash"] = event_hash(alert)
    return alert


if __name__ == "__main__":  # pragma: no cover - convenience check
    print(json.dumps(verify_against_phase1_vectors(), indent=2))
