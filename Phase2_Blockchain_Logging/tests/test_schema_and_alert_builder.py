import json
from pathlib import Path

import jsonschema
import pytest

from src.alert_builder import build_alert_from_oracle_response
from src.digest import verify_event_digest

PHASE2_ROOT = Path(__file__).resolve().parent.parent
ALERT_SCHEMA = json.loads((PHASE2_ROOT / "contracts" / "alert_event.schema.json").read_text(encoding="utf-8"))
PROVENANCE_SCHEMA = json.loads((PHASE2_ROOT / "contracts" / "model_provenance.schema.json").read_text(encoding="utf-8"))


def test_alert_from_attack_oracle_response_validates():
    event = build_alert_from_oracle_response(
        oracle_response={"is_attack": True, "confidence_score": 0.987, "model_version": "stahn_v1_98.62_acc"},
        feature_names=["Rate", "Protocol Type"],
        feature_values=[16251.95, 6.0],
        model_id="stahn-phase1",
        model_digest="a" * 64,
        resource_id="i-001",
        inference_latency_ms=0.31,
    )
    jsonschema.validate(instance=event, schema=ALERT_SCHEMA)
    assert verify_event_digest(event)
    assert event["verdict"] == "ATTACK"
    assert event["calibration"]["is_calibrated"] is False


def test_alert_from_benign_oracle_response_validates():
    event = build_alert_from_oracle_response(
        oracle_response={"is_attack": False, "confidence_score": 0.91, "model_version": "stahn_v1_98.62_acc"},
        feature_names=["Rate"],
        feature_values=[100.0],
        model_id="stahn-phase1",
        model_digest="a" * 64,
        resource_id="i-002",
    inference_latency_ms=0.2,
    )
    jsonschema.validate(instance=event, schema=ALERT_SCHEMA)
    assert event["verdict"] == "BENIGN"
    assert event["threat_category"] == "BENIGN"
    assert event["severity"] == "informational"


def test_mismatched_feature_lengths_raise():
    with pytest.raises(ValueError):
        build_alert_from_oracle_response(
            oracle_response={"is_attack": True, "confidence_score": 0.9},
            feature_names=["a", "b"],
            feature_values=[1.0],
            model_id="m",
            model_digest="a" * 64,
            resource_id="i-001",
            inference_latency_ms=1.0,
        )


def test_nullable_source_destination_accepted_by_schema():
    event = build_alert_from_oracle_response(
        oracle_response={"is_attack": True, "confidence_score": 0.99},
        feature_names=["Rate"],
        feature_values=[1.0],
        model_id="m",
        model_digest="a" * 64,
        resource_id="i-001",
        inference_latency_ms=1.0,
        source_address=None,
        destination_address=None,
    )
    jsonschema.validate(instance=event, schema=ALERT_SCHEMA)


def test_model_provenance_schema_accepts_a_realistic_record():
    record = {
        "contract_version": "1.0.0",
        "model_id": "stahn-phase1",
        "model_digest": "a" * 64,
        "version_label": "stahn_v1_98.62_acc",
        "artifact_content_address": "sha256:" + "b" * 64,
        "feature_order": ["Rate", "Protocol Type"],
        "label_order": ["BENIGN", "ATTACK"],
        "hyperparameters": {},
        "thresholds": {},
        "training_summary": {"dataset": "CICIoT2023", "record_count": 5_000_000, "reported_metrics": {"accuracy": 0.9862}},
        "anchored_at": "2026-09-15T18:00:00.000Z",
    }
    jsonschema.validate(instance=record, schema=PROVENANCE_SCHEMA)
