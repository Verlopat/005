"""Contract tests for the Phase 1 -> Phase 2 alert adapter.

These assert the properties that make the cross-layer handoff auditable: the
event validates against the Objective 2 schema, the producer's digest is
independently verified, calibration is reported truthfully, and the label space
is exactly Phase 1's.
"""
import json
from pathlib import Path

import jsonschema
import pytest

from conftest import PHASE1_GATE_TAU, make_phase1_alert
from src.alert_builder import (
    DEFAULT_CONTRACT_VERSION,
    build_alert_event,
    build_alert_from_phase1_alert,
)
from src.detection_layer import THREAT_CATEGORIES
from src.digest import verify_event_digest
from src.phase1_contract import (
    Phase1ContractError,
    event_hash,
    verify_against_phase1_vectors,
)

PHASE2_ROOT = Path(__file__).resolve().parent.parent
ALERT_SCHEMA = json.loads((PHASE2_ROOT / "contracts" / "alert_event.schema.json").read_text(encoding="utf-8"))
PROVENANCE_SCHEMA = json.loads((PHASE2_ROOT / "contracts" / "model_provenance.schema.json").read_text(encoding="utf-8"))

MODEL_ID = "fa8d2667cc39cea50abe78f813133ead89e9dea3a317da436c14dcfc41fbf820"
MODEL_DIGEST = "a" * 64


def adapt(alert, **kwargs):
    return build_alert_from_phase1_alert(
        alert, model_id=MODEL_ID, model_digest=MODEL_DIGEST, **kwargs
    )


def test_attack_alert_validates_against_contract():
    event = adapt(make_phase1_alert("DDoS", 0.9999))
    jsonschema.validate(instance=event, schema=ALERT_SCHEMA)
    assert verify_event_digest(event)
    assert event["contract_version"] == DEFAULT_CONTRACT_VERSION
    assert event["verdict"] == "ATTACK"
    assert event["threat_category"] == "DDoS"
    assert event["severity"] == "high"


def test_benign_alert_validates_and_maps_to_informational():
    event = adapt(make_phase1_alert("Benign", 0.0001))
    jsonschema.validate(instance=event, schema=ALERT_SCHEMA)
    assert event["verdict"] == "BENIGN"
    assert event["threat_category"] == "Benign"
    assert event["severity"] == "informational"


def test_calibration_is_reported_as_isotonic_not_absent():
    """Phase 1 fits isotonic calibration; the contract must say so.

    Objective 3's anchoring gate is a threshold on a probability, so recording
    calibration as absent would understate the evidence the gate rests on.
    """
    event = adapt(make_phase1_alert("DoS", 0.998))
    assert event["calibration"]["is_calibrated"] is True
    assert event["calibration"]["method"] == "isotonic"
    assert event["calibration"]["expected_calibration_error"] == pytest.approx(8.136e-05, rel=1e-3)


def test_uncalibrated_event_does_not_inherit_the_models_measured_ece():
    '''An uncalibrated score must not carry a calibration error it did not earn.

    Regression test: the adapter previously back-filled the deployed model's
    measured ECE whenever the caller passed none, so a synthetic or uncalibrated
    event could claim a real measurement.
    '''
    event = adapt(make_phase1_alert('DDoS', 0.9999), calibration_method='none')
    assert event['calibration']['is_calibrated'] is False
    assert event['calibration']['method'] == 'none'
    assert 'expected_calibration_error' not in event['calibration']
    jsonschema.validate(instance=event, schema=ALERT_SCHEMA)


def test_producer_severity_is_carried_not_rederived():
    '''Phase 2 renames the producer's severity; it does not recompute it.

    BruteForce is MEDIUM in Phase 1's map even though its confidence is very
    high, so a confidence-derived severity would disagree with the producer.
    '''
    event = adapt(make_phase1_alert('BruteForce', 0.99998))
    assert event['severity'] == 'medium'


def test_unknown_producer_severity_is_rejected():
    alert = make_phase1_alert('DDoS', 0.9999)
    alert['severity'] = 'EXTREME'
    alert['event_hash'] = event_hash(alert)
    with pytest.raises(ValueError, match='no Phase 2 equivalent'):
        adapt(alert)


def test_infiltration_keeps_producer_severity_despite_low_confidence():
    """Severity must not be re-derived from confidence.

    Phase 1 rates Infiltration CRITICAL although it measures its mean
    confidence at 0.303, because a missed post-compromise intrusion costs more
    than a missed flood. A confidence-derived severity would silently downgrade
    exactly the class that most needs evidence.
    """
    event = adapt(make_phase1_alert("Infiltration", 0.31))
    assert event["severity"] == "critical"
    assert event["calibrated_confidence"] == pytest.approx(0.31)


def test_producer_digest_is_carried_and_verified():
    alert = make_phase1_alert("Bot", 0.9998)
    event = adapt(alert)
    contract = event["detection_contract"]
    assert contract["event_hash"] == alert["event_hash"]
    assert contract["feature_digest"] == alert["feature_digest"]
    assert contract["digest_verified_by_consumer"] is True
    assert contract["anchor_gate_tau"] == pytest.approx(PHASE1_GATE_TAU)
    assert contract["producer_anchor_decision"] == alert["anchor"]


def test_tampered_alert_is_rejected_before_it_can_be_anchored():
    alert = make_phase1_alert("DDoS", 0.9999)
    alert["confidence"] = 0.10  # alter the payload, leave the digest untouched
    with pytest.raises(Phase1ContractError, match="event_hash mismatch"):
        adapt(alert)


def test_tampered_feature_vector_is_rejected():
    alert = make_phase1_alert("DoS", 0.999)
    alert["features"]["IN_BYTES"] = 999999.0
    with pytest.raises(Phase1ContractError, match="feature_digest mismatch"):
        adapt(alert)


def test_on_chain_projection_without_features_is_rejected():
    """The on-chain projection is not sufficient input for evidence logging."""
    alert = make_phase1_alert("DDoS", 0.9999)
    del alert["features"]
    with pytest.raises(Phase1ContractError, match="no feature vector"):
        adapt(alert)


def test_inconsistent_verdict_and_class_is_rejected():
    alert = make_phase1_alert("Benign", 0.01)
    alert["verdict"] = "ANOMALY"
    # Re-digest so the alert is internally consistent apart from the very
    # contradiction under test.
    alert["event_hash"] = event_hash(alert)
    with pytest.raises(Phase1ContractError, match="inconsistent"):
        adapt(alert)


def test_schema_label_space_is_exactly_phase1s():
    enum = ALERT_SCHEMA["properties"]["threat_category"]["enum"]
    assert enum == list(THREAT_CATEGORIES)
    # Categories belonging to the previously-referenced CICIoT2023 detector must
    # not be admitted by a contract whose producer cannot emit them.
    for absent in ("Mirai", "Recon", "Spoofing", "Web-based", "Botnet", "Other"):
        assert absent not in enum


def test_category_outside_label_space_is_rejected():
    with pytest.raises(ValueError, match="outside Phase 1's label space"):
        build_alert_event(
            threat_category="Spoofing",
            calibrated_confidence=0.9,
            feature_names=["IN_BYTES"],
            feature_values=[1.0],
            model_id=MODEL_ID,
            model_digest=MODEL_DIGEST,
            version_label="v",
            resource_id="i-001",
            inference_latency_ms=1.0,
        )


def test_mismatched_feature_lengths_raise():
    with pytest.raises(ValueError, match="length mismatch"):
        build_alert_event(
            threat_category="DDoS",
            calibrated_confidence=0.9,
            feature_names=["a", "b"],
            feature_values=[1.0],
            model_id=MODEL_ID,
            model_digest=MODEL_DIGEST,
            version_label="v",
            resource_id="i-001",
            inference_latency_ms=1.0,
        )


def test_nullable_source_destination_accepted_by_schema():
    event = adapt(
        make_phase1_alert("DDoS", 0.9999, src_ip=None, src_port=None, dst_ip=None, dst_port=None)
    )
    assert event["source_address"] is None
    assert event["destination_address"] is None
    jsonschema.validate(instance=event, schema=ALERT_SCHEMA)


def test_address_metadata_is_formatted_from_identifiers():
    event = adapt(make_phase1_alert("DDoS", 0.9999))
    assert event["source_address"] == "10.0.0.7:44321"
    assert event["destination_address"] == "10.0.1.9:443"
    # Identifiers must never appear among the model's features.
    for identifier in ("src_ip", "dst_ip", "L4_DST_PORT", "IPV4_SRC_ADDR"):
        assert identifier not in event["triggering_features"]


def test_feature_attributions_are_translated():
    event = adapt(make_phase1_alert("DDoS", 0.9999))
    assert event["feature_attributions"][0] == {"feature": "IN_BYTES", "contribution": 0.412}


def test_phase2_independently_reproduces_phase1_digest_vectors():
    """Cross-layer digest agreement on Phase 1's own fixed vectors."""
    summary = verify_against_phase1_vectors()
    assert summary["independent_implementations_agree"] is True
    assert summary["vectors_checked"] == summary["vectors_agreeing"]
    assert summary["vectors_checked"] >= 1


def test_model_provenance_schema_accepts_a_realistic_record():
    record = {
        "contract_version": "1.0.0",
        "model_id": MODEL_ID,
        "model_digest": "a" * 64,
        "version_label": "flat_tuned_tau-fa8d2667cc39",
        "artifact_content_address": "sha256:" + "b" * 64,
        "feature_order": ["SRC_TO_DST_SECOND_BYTES", "LONGEST_FLOW_PKT"],
        "label_order": list(THREAT_CATEGORIES),
        "hyperparameters": {"n_estimators": 300, "num_leaves": 69},
        "thresholds": {"class_thresholds": {"Benign": 0.7}, "anchoring_gate": {"tau": PHASE1_GATE_TAU}},
        "training_summary": {
            "dataset": "NF-CSE-CIC-IDS2018-v2",
            "record_count": 18_893_708,
            "reported_metrics": {"macro_f1": 0.8171522873728747, "accuracy": 0.995360224377559},
        },
        "anchored_at": "2026-09-15T18:00:00.000Z",
    }
    jsonschema.validate(instance=record, schema=PROVENANCE_SCHEMA)
