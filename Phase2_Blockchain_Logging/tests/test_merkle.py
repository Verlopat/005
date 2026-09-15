import hashlib

import pytest

from src.merkle import build_merkle_batch, required_batch_factor_for_target_tps, verify_inclusion


def _digest(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_single_leaf_batch():
    d = _digest("only-event")
    batch = build_merkle_batch([d])
    assert batch.root == d  # a single-leaf tree's root is the leaf itself


def test_inclusion_proof_verifies_for_every_leaf():
    digests = [_digest(f"event-{i}") for i in range(7)]  # odd count exercises padding
    batch = build_merkle_batch(digests)
    for i in range(len(digests)):
        proof = batch.inclusion_proof(i)
        assert verify_inclusion(batch.root, proof)


def test_inclusion_proof_fails_for_wrong_root():
    digests = [_digest(f"event-{i}") for i in range(5)]
    batch = build_merkle_batch(digests)
    proof = batch.inclusion_proof(2)
    assert not verify_inclusion(_digest("some-other-root"), proof)


def test_empty_batch_raises():
    with pytest.raises(ValueError):
        build_merkle_batch([])


def test_required_batch_factor_matches_objective2_amendment_arithmetic():
    # 10,000 events/sec * 11.43% anchoring rate ≈ 1,143 tx/sec, which exceeds
    # the 1,000 TPS target under individual commitment; the smallest batch
    # factor that brings it back under budget is 2 (≈572 tx/sec).
    factor = required_batch_factor_for_target_tps(
        peak_events_per_sec=10_000, anchoring_rate=0.1143, target_tps=1000
    )
    assert factor == 2

    # A batch factor of 100 (the operational default) comfortably clears
    # the same budget, at roughly 12 tx/sec, matching Objective 2's
    # published amendment arithmetic.
    anchored_per_sec = 10_000 * 0.1143
    assert anchored_per_sec / 100 < 15

