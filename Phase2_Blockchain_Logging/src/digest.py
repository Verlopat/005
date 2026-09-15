"""SHA-256 digesting over canonical JSON.

Objective 2: "a canonical digest of the payload" travels in every alert and
is the value committed to the ledger. This module produces and verifies
that digest. See docs/canonicalisation_spec.md rule 8.
"""
from __future__ import annotations

import hashlib

from .canonical import canonicalise

HEX_DIGEST_PATTERN_LENGTH = 64


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_event(event: dict) -> str:
    """Compute payload_digest for an alert event.

    ``event`` may or may not already contain a ``payload_digest`` key; if
    present it is ignored/stripped (rule 1), never fed into the digest.
    """
    stripped = {k: v for k, v in event.items() if k != "payload_digest"}
    canonical = canonicalise(stripped)
    return digest_bytes(canonical.encode("utf-8"))


def verify_event_digest(event: dict) -> bool:
    """Return True iff event['payload_digest'] matches a fresh recomputation."""
    claimed = event.get("payload_digest")
    if not isinstance(claimed, str) or len(claimed) != HEX_DIGEST_PATTERN_LENGTH:
        return False
    recomputed = digest_event(event)
    return claimed.lower() == recomputed
