import sys
import time

from perf._phase2_bridge import ensure_phase2_importable
from perf.local_cache import LocalStateCache

ensure_phase2_importable()

from src.digest import digest_bytes
from src.ledger.base import EventRecord
from src.ledger.mock_ledger import MockLedger
from src.signing import generate_agent_identity, sign_digest


def make_record(identity, event_id, resource_id):
    payload_digest = digest_bytes(f"payload-{event_id}".encode())
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
        timestamp="2026-09-15T18:00:00.000Z",
        transaction_id="",
        block_number=None,
    )


def test_sync_once_populates_cache():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    ledger.log_security_event(make_record(identity, "e1", "i-001"))
    ledger.log_security_event(make_record(identity, "e2", "i-002"))

    cache = LocalStateCache(ledger, sync_interval_sec=0.1)
    count = cache.sync_once()
    assert count == 2
    assert cache.get_by_event_id("e1").resource_id == "i-001"
    assert len(cache.get_by_resource_id("i-002")) == 1
    assert cache.get_by_event_id("missing") is None


def test_background_sync_picks_up_new_events():
    identity = generate_agent_identity("agent-001")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
    cache = LocalStateCache(ledger, sync_interval_sec=0.05)
    cache.start_background_sync()
    try:
        ledger.log_security_event(make_record(identity, "e1", "i-001"))
        time.sleep(0.3)
        assert cache.get_by_event_id("e1") is not None
        assert cache.staleness_sec() is not None
        assert cache.staleness_sec() < 1.0
    finally:
        cache.stop_background_sync()


def test_writes_never_go_through_the_cache():
    """The cache has no put()/write method at all -- writes must go
    through Phase2Pipeline.submit() -> the ledger directly."""
    assert not hasattr(LocalStateCache, "put")
    assert not hasattr(LocalStateCache, "write")
