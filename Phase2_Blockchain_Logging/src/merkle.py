"""Merkle batch aggregation.

Objective 2's Phase I amendment: at the measured 11.43% anchoring gate and
the 10,000 events/sec peak arrival rate specified in Objective 3, individual
commitment requires ~1,143 transactions/sec, exceeding the 1,000 TPS
target. A batch factor of 100 events per root reduces this to ~12
transactions/sec. This module builds that Merkle tree, so a submission
service can commit one root per batch window while every individual event
digest remains independently verifiable via its inclusion proof.

Implemented from scratch (SHA-256, binary tree, duplicate-last-node padding
for odd levels) rather than depending on `pymerkle`'s on-disk log format,
because the batching unit here is an in-memory list of already-computed
`payload_digest` values, not an append-only external log.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    leaf_digest: str
    siblings: list[str]  # hex digests, ordered leaf -> root
    directions: list[str]  # "L" or "R": is the sibling to the left or right of the running hash


@dataclass(frozen=True)
class MerkleBatch:
    root: str  # hex
    leaves: list[str]  # hex digests, order preserved (this order is authoritative for indices)

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        if not 0 <= leaf_index < len(self.leaves):
            raise IndexError(f"leaf_index {leaf_index} out of range for batch of {len(self.leaves)}")
        level = [bytes.fromhex(h) for h in self.leaves]
        siblings: list[str] = []
        directions: list[str] = []
        idx = leaf_index
        while len(level) > 1:
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            if idx % 2 == 0:
                sibling_idx = idx + 1
                directions.append("R")
            else:
                sibling_idx = idx - 1
                directions.append("L")
            siblings.append(level[sibling_idx].hex())
            next_level = []
            for i in range(0, len(level), 2):
                next_level.append(_hash_pair(level[i], level[i + 1]))
            level = next_level
            idx //= 2
        return InclusionProof(
            leaf_index=leaf_index,
            leaf_digest=self.leaves[leaf_index],
            siblings=siblings,
            directions=directions,
        )


def build_merkle_batch(payload_digests: list[str]) -> MerkleBatch:
    if not payload_digests:
        raise ValueError("cannot build a Merkle batch from an empty list of digests")
    level = [bytes.fromhex(h) for h in payload_digests]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return MerkleBatch(root=level[0].hex(), leaves=list(payload_digests))


def verify_inclusion(root_hex: str, proof: InclusionProof) -> bool:
    running = bytes.fromhex(proof.leaf_digest)
    for sibling_hex, direction in zip(proof.siblings, proof.directions):
        sibling = bytes.fromhex(sibling_hex)
        running = _hash_pair(running, sibling) if direction == "R" else _hash_pair(sibling, running)
    return running.hex() == root_hex


def required_batch_factor_for_target_tps(
    peak_events_per_sec: float, anchoring_rate: float, target_tps: float
) -> int:
    """Smallest integer batch factor that keeps anchoring transactions/sec
    at or below ``target_tps``, given the measured anchoring rate. Encodes
    the Objective 2 amendment's arithmetic (10,000 * 0.1143 / 100 ≈ 12)
    as a reusable, testable function rather than a one-off calculation in
    prose.
    """
    anchored_per_sec = peak_events_per_sec * anchoring_rate
    if anchored_per_sec <= target_tps:
        return 1
    import math

    return math.ceil(anchored_per_sec / target_tps)
