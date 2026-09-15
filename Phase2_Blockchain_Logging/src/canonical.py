"""Canonical JSON serialisation.

Implements docs/canonicalisation_spec.md v1.0.0 exactly. This module is one
half of the cross-layer digest agreement required by Objective 2; the other
half is chaincode/securitylog/canonical.go. Both MUST produce byte-identical
output for the shared test vectors in
contracts/test_vectors/canonical_digest_vectors.json.

Deliberately dependency-free (standard library only) so it can be read and
re-implemented in Go without hidden behaviour from a third-party JSON
encoder.
"""
from __future__ import annotations

import math
from typing import Any


class CanonicalisationError(ValueError):
    """Raised when a value cannot be canonicalised under the frozen spec."""


def _canonical_number(value: float | int) -> str:
    if isinstance(value, bool):  # bool is a subclass of int in Python
        raise CanonicalisationError("booleans are not numbers under this spec")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalisationError(
                f"NaN/Infinity is forbidden in a canonicalised alert event: {value!r}"
            )
        if value.is_integer() and abs(value) < 1e16:
            # Still a float type per JSON Schema "number", but render as the
            # shortest round-tripping form; Python repr already does this
            # (e.g. 2.0 -> '2.0'), and Go's %g on an integral float64 of
            # this magnitude also renders with a trailing '.0'-equivalent
            # is NOT guaranteed, so we keep the '.0' explicit here and the
            # Go implementation matches it explicitly (see canonical.go).
            return repr(value)
        return repr(value)
    raise CanonicalisationError(f"unsupported numeric type: {type(value)!r}")


def _canonical_string(value: str) -> str:
    out = ['"']
    for ch in value:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canonical_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _canonical_number(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, dict):
        return _canonical_object(value)
    if isinstance(value, (list, tuple)):
        return _canonical_array(value)
    raise CanonicalisationError(f"unsupported type for canonicalisation: {type(value)!r}")


def _canonical_object(obj: dict) -> str:
    # Rule 2: keys sorted by raw UTF-8 byte sequence (ordinal order).
    items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-8"))
    parts = [f"{_canonical_string(k)}:{_canonical_value(v)}" for k, v in items]
    return "{" + ",".join(parts) + "}"


def _canonical_array(arr) -> str:
    # Rule 7: array order is preserved, never re-sorted.
    return "[" + ",".join(_canonical_value(v) for v in arr) + "]"


def canonicalise(event: dict) -> str:
    """Return the canonical JSON string for ``event`` per the frozen spec.

    ``event`` MUST NOT include ``payload_digest`` (rule 1); callers should
    pass the event with that key already removed. This function does not
    strip it automatically so that omission is explicit and auditable at
    the call site — see ``digest.py:digest_event`` which performs the strip
    and calls this function.
    """
    if not isinstance(event, dict):
        raise CanonicalisationError("top-level canonicalised value must be an object")
    if "payload_digest" in event:
        raise CanonicalisationError(
            "payload_digest must be excluded before canonicalisation (spec rule 1)"
        )
    return _canonical_object(event)


def canonical_bytes(event: dict) -> bytes:
    return canonicalise(event).encode("utf-8")
