import sys
import uuid
from pathlib import Path

import pytest

PHASE2_ROOT = Path(__file__).resolve().parent.parent
if str(PHASE2_ROOT) not in sys.path:
    sys.path.insert(0, str(PHASE2_ROOT))

from src.phase1_contract import event_hash, feature_digest  # noqa: E402

#: A representative subset of Phase 1's 25 NetFlow features. Tests do not need
#: the full vector, only a contract-valid one.
SAMPLE_FEATURES = {
    "IN_BYTES": 1480.0,
    "OUT_BYTES": 640.0,
    "LONGEST_FLOW_PKT": 1500.0,
    "FLOW_DURATION_MILLISECONDS": 132.0,
    "TCP_WIN_MAX_IN": 65535.0,
}

PHASE1_MODEL_VERSION = "flat_tuned_tau-fa8d2667cc39"

#: Phase 1's deployment gate (model_card.json:anchoring_gate.tau).
PHASE1_GATE_TAU = 0.9997655153274536

#: Phase 1's severity map (outputs/10_contract/severity_map.json).
PHASE1_SEVERITY = {
    "Benign": "NONE",
    "DDoS": "HIGH",
    "DoS": "HIGH",
    "Bot": "HIGH",
    "BruteForce": "MEDIUM",
    "Infiltration": "CRITICAL",
    "Web Attacks": "HIGH",
}


def make_phase1_alert(
    threat_class: str = "DDoS",
    confidence: float = 0.995,
    *,
    resource_id: str = "cloud-res-000000000001",
    features: dict | None = None,
    event_id: str | None = None,
    src_ip: str | None = "10.0.0.7",
    src_port: int | None = 44321,
    dst_ip: str | None = "10.0.1.9",
    dst_port: int | None = 443,
    attributions: bool = True,
    latency_ms: float = 0.42,
) -> dict:
    """Build a valid alert in Phase 1's frozen contract shape.

    Digests are computed with Phase 1's canonical rules, so the result passes
    ``src.phase1_contract.verify_alert``. This mirrors what
    ``Phase_1/10_alert_contract.py`` emits, letting Phase 2 be tested without
    requiring the (gitignored) real alert stream.
    """
    resolved_features = dict(features if features is not None else SAMPLE_FEATURES)
    alert = {
        "event_id": event_id or str(uuid.uuid4()),
        "schema_version": "1.0.0",
        "timestamp": "2026-09-15T18:04:12.501Z",
        "verdict": "NORMAL" if threat_class == "Benign" else "ANOMALY",
        "threat_class": threat_class,
        "severity": PHASE1_SEVERITY[threat_class],
        "confidence": confidence,
        "model_version": PHASE1_MODEL_VERSION,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "cloud_resource_id": resource_id,
        "features": resolved_features,
        "feature_digest": feature_digest(resolved_features),
        "anchor": confidence >= PHASE1_GATE_TAU and threat_class != "Benign",
        "anchor_gate_tau": PHASE1_GATE_TAU,
        "inference_latency_ms": latency_ms,
    }
    if attributions:
        alert["top_contributing_features"] = [
            {"feature": "IN_BYTES", "value": 1480.0, "shap": 0.412},
            {"feature": "LONGEST_FLOW_PKT", "value": 1500.0, "shap": -0.108},
        ]
    alert["event_hash"] = event_hash(alert)
    return alert


@pytest.fixture
def phase1_alert():
    """Factory fixture for Phase 1-shaped alerts."""
    return make_phase1_alert
