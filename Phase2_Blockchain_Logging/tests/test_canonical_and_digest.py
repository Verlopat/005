import json
import math
from pathlib import Path

import pytest

from src.canonical import CanonicalisationError, canonicalise
from src.digest import digest_event, verify_event_digest

VECTORS_PATH = Path(__file__).resolve().parent.parent / "contracts" / "test_vectors" / "canonical_digest_vectors.json"


def load_vectors():
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v["name"])
def test_vector_canonical_and_digest(vector):
    canonical = canonicalise(vector["input"])
    assert canonical == vector["expected_canonical"]
    event_with_digest = dict(vector["input"])
    event_with_digest["payload_digest"] = vector["expected_sha256"]
    assert verify_event_digest(event_with_digest)


def test_key_ordering_is_byte_sequence():
    assert canonicalise({"b": 1, "a": 2, "Z": 3}) == '{"Z":3,"a":2,"b":1}'  # 'Z' (0x5A) < 'a' (0x61)


def test_nan_and_infinity_are_rejected():
    with pytest.raises(CanonicalisationError):
        canonicalise({"x": float("nan")})
    with pytest.raises(CanonicalisationError):
        canonicalise({"x": float("inf")})


def test_payload_digest_must_be_excluded_before_canonicalisation():
    with pytest.raises(CanonicalisationError):
        canonicalise({"payload_digest": "a" * 64, "x": 1})


def test_digest_event_strips_existing_payload_digest():
    event = {"a": 1, "payload_digest": "deadbeef"}
    d1 = digest_event(event)
    d2 = digest_event({"a": 1})
    assert d1 == d2


def test_verify_event_digest_detects_tampering():
    event = {"a": 1}
    event["payload_digest"] = digest_event(event)
    assert verify_event_digest(event)
    tampered = dict(event)
    tampered["a"] = 2
    assert not verify_event_digest(tampered)  # digest no longer matches mutated content
