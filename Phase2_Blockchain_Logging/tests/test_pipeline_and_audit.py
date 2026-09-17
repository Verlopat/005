import pytest

from conftest import make_phase1_alert
from src.alert_builder import build_alert_from_phase1_alert
from src.anchoring_policy import AnchoringPolicy
from src.audit import audit_event, compliance_report
from src.evidence_store import LocalContentAddressedStore
from src.ledger.mock_ledger import MockLedger
from src.pipeline import Phase2Pipeline
from src.signing import generate_agent_identity


def make_event(is_attack=True, confidence=0.995, resource_id="i-001", threat_class=None):
    """An Objective 2 event built through the real Phase 1 adapter.

    Using the production path here means these pipeline/audit tests also cover
    cross-layer digest verification, rather than a shortcut constructor that
    could diverge from what Phase 1 actually emits.
    """
    if threat_class is None:
        threat_class = "DDoS" if is_attack else "Benign"
    alert = make_phase1_alert(threat_class, confidence, resource_id=resource_id)
    return build_alert_from_phase1_alert(
        alert,
        model_id="fa8d2667cc39cea50abe78f813133ead89e9dea3a317da436c14dcfc41fbf820",
        model_digest="a" * 64,
    )


@pytest.fixture
def pipeline(tmp_path):
    store = LocalContentAddressedStore(tmp_path / "evidence")
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    policy = AnchoringPolicy.from_dict({"anchor_attack_only": True, "confidence_threshold": 0.5})
    p = Phase2Pipeline(store, ledger, identity, policy, batch_size=3)
    return p, ledger, store, identity


def test_high_confidence_event_is_anchored_immediately(pipeline):
    p, ledger, store, identity = pipeline
    event = make_event(confidence=0.995)
    result = p.submit(event)
    assert result.decision.value == "immediate"
    assert result.receipt is not None
    assert result.receipt.committed
    assert ledger.verify_event(event["event_id"], event["payload_digest"])


def test_benign_event_is_stored_but_not_anchored(pipeline):
    p, ledger, store, identity = pipeline
    event = make_event(is_attack=False, confidence=0.99)
    result = p.submit(event)
    assert result.decision.value == "off_chain_only"
    assert result.receipt is None
    assert store.exists(result.content_address)  # still preserved off-chain


def test_batched_events_flush_at_batch_size(pipeline):
    p, ledger, store, identity = pipeline
    events = [make_event(confidence=0.6) for _ in range(3)]  # below immediate threshold, above gate
    for e in events:
        p.submit(e)
    # batch_size=3, so the third submit() should have auto-flushed.
    for e in events:
        assert ledger.verify_event(e["event_id"], e["payload_digest"])


def test_close_flushes_partial_batch(pipeline):
    p, ledger, store, identity = pipeline
    event = make_event(confidence=0.6)
    p.submit(event)
    assert not ledger.verify_event(event["event_id"], event["payload_digest"])  # not yet flushed
    root = p.close()
    assert root is not None
    assert ledger.verify_event(event["event_id"], event["payload_digest"])


def test_rejects_event_with_bad_digest(pipeline):
    p, ledger, store, identity = pipeline
    event = make_event()
    event["payload_digest"] = "0" * 64  # corrupt before submission
    with pytest.raises(ValueError):
        p.submit(event)


def test_audit_verified_for_untampered_event(pipeline):
    p, ledger, store, identity = pipeline
    event = make_event(confidence=0.995)
    p.submit(event)
    finding = audit_event(ledger, store, event["event_id"], identity.public_key_hex())
    assert finding.verdict == "VERIFIED"


def test_audit_tampered_when_ledger_record_corrupted(pipeline):
    p, ledger, store, identity = pipeline
    event = make_event(confidence=0.995)
    p.submit(event)
    ledger.tamper_with_stored_record_for_demo_only(event["event_id"], "0" * 64)
    finding = audit_event(ledger, store, event["event_id"], identity.public_key_hex())
    assert finding.verdict == "TAMPERED"


def test_compliance_report_reflects_tampering(pipeline):
    p, ledger, store, identity = pipeline
    event = make_event(confidence=0.995)
    p.submit(event)
    ledger.tamper_with_stored_record_for_demo_only(event["event_id"], "0" * 64)
    report = compliance_report(ledger, store, identity.public_key_hex())
    assert report["tampered"] == 1
    assert report["unbroken_chain_of_custody"] is False
