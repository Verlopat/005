import pytest

from src.digest import digest_bytes
from src.ledger.base import EventRecord
from src.ledger.mock_ledger import MockLedger, UnauthorisedAgentError
from src.signing import generate_agent_identity, sign_digest


def make_record(identity, event_id="evt-1", resource_id="i-001", timestamp="2026-09-15T18:00:00.000Z"):
    payload_digest = digest_bytes(f"payload-for-{event_id}".encode())
    signature = sign_digest(identity, payload_digest)
    return EventRecord(
        event_id=event_id,
        payload_digest=payload_digest,
        content_address=f"sha256:{payload_digest}",
        resource_id=resource_id,
        threat_category="DDoS",
        severity="high",
        calibrated_confidence=0.99,
        model_digest="a" * 64,
        agent_id=identity.agent_id,
        signature=signature,
        timestamp=timestamp,
        transaction_id="",
        block_number=None,
    )


def test_log_and_verify_event():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    record = make_record(identity)
    receipt = ledger.log_security_event(record)
    assert receipt.committed
    assert receipt.transaction_id
    assert ledger.verify_event(record.event_id, record.payload_digest)
    assert not ledger.verify_event(record.event_id, "0" * 64)


def test_unauthorised_agent_cannot_write():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={})  # agent not registered
    record = make_record(identity)
    with pytest.raises(UnauthorisedAgentError):
        ledger.log_security_event(record)


def test_duplicate_event_id_is_rejected():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    record = make_record(identity)
    ledger.log_security_event(record)
    with pytest.raises(Exception):
        ledger.log_security_event(record)


def test_query_event_history_filters_by_resource():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    ledger.log_security_event(make_record(identity, event_id="evt-1", resource_id="i-001"))
    ledger.log_security_event(make_record(identity, event_id="evt-2", resource_id="i-002"))
    results = ledger.query_event_history(resource_id="i-001")
    assert len(results) == 1
    assert results[0].event_id == "evt-1"


def test_chain_integrity_detects_tampering():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    ledger.log_security_event(make_record(identity))
    assert ledger.verify_chain_integrity()
    ledger.tamper_with_stored_record_for_demo_only("evt-1", "0" * 64)
    assert not ledger.verify_chain_integrity()


def test_model_provenance_roundtrip():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    provenance = {
        "contract_version": "1.0.0",
        "model_id": "fa8d2667cc39cea50abe78f813133ead89e9dea3a317da436c14dcfc41fbf820",
        "model_digest": "b" * 64,
        "anchored_at": "2026-09-15T18:00:00.000Z",
    }
    receipt = ledger.anchor_model_provenance(provenance)
    assert receipt.committed
    assert ledger.get_model_provenance("b" * 64) == provenance
    assert ledger.get_model_provenance("c" * 64) is None


def test_persistence_roundtrip(tmp_path):
    identity = generate_agent_identity("agent-001")
    persist_path = tmp_path / "ledger.json"
    ledger1 = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()}, persist_path=persist_path)
    ledger1.log_security_event(make_record(identity))

    ledger2 = MockLedger(persist_path=persist_path)
    assert ledger2.verify_event("evt-1", digest_bytes(b"payload-for-evt-1"))
    assert ledger2.verify_chain_integrity()
