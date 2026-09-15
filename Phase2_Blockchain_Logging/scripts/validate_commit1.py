#!/usr/bin/env python3
"""Validate Commit 1 of Phase 2: schemas + canonicalisation + digest vectors.

Run from the repository root:

    python3 Phase2_Blockchain_Logging/scripts/validate_commit1.py

Exits non-zero on any failure. Requires no Docker, Fabric, Go, or running
ledger — this validates only the frozen contract, per the Phase 2 README.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PHASE2_ROOT))

from src.canonical import canonicalise  # noqa: E402
from src.digest import digest_bytes  # noqa: E402

try:
    import jsonschema
except ImportError:
    print("[!] jsonschema is required: pip install -r Phase2_Blockchain_Logging/requirements.txt")
    sys.exit(1)


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def check_schema_is_valid_json_schema(path: Path) -> dict:
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    print(f"[ok] {path.relative_to(PHASE2_ROOT)} is a valid Draft 2020-12 JSON Schema")
    return schema


def check_digest_vectors() -> None:
    vectors_path = PHASE2_ROOT / "contracts" / "test_vectors" / "canonical_digest_vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    if not vectors:
        fail("no test vectors found")
    for vec in vectors:
        name = vec["name"]
        recomputed_canonical = canonicalise(vec["input"])
        if recomputed_canonical != vec["expected_canonical"]:
            fail(
                f"vector '{name}': canonical form mismatch\n"
                f"  expected: {vec['expected_canonical']}\n"
                f"  got:      {recomputed_canonical}"
            )
        recomputed_digest = digest_bytes(recomputed_canonical.encode("utf-8"))
        if recomputed_digest != vec["expected_sha256"]:
            fail(
                f"vector '{name}': digest mismatch\n"
                f"  expected: {vec['expected_sha256']}\n"
                f"  got:      {recomputed_digest}"
            )
        if len(recomputed_digest) != 64:
            fail(f"vector '{name}': digest is not 64 hex characters: {recomputed_digest}")
        print(f"[ok] digest vector '{name}' reproduced exactly ({recomputed_digest})")
    print(f"[ok] all {len(vectors)} canonical digest vectors reproduced exactly")


def check_realistic_alert_against_schema(alert_schema: dict) -> None:
    vectors_path = PHASE2_ROOT / "contracts" / "test_vectors" / "canonical_digest_vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    realistic = next(v for v in data["vectors"] if v["name"] == "realistic_alert_event_v1")
    event = dict(realistic["input"])
    event["payload_digest"] = realistic["expected_sha256"]
    jsonschema.validate(instance=event, schema=alert_schema)
    print("[ok] realistic_alert_event_v1 + its digest validates against alert_event.schema.json")


def main() -> None:
    print("=" * 70)
    print("Phase 2 Commit 1 contract validation")
    print("=" * 70)

    alert_schema = check_schema_is_valid_json_schema(
        PHASE2_ROOT / "contracts" / "alert_event.schema.json"
    )
    check_schema_is_valid_json_schema(
        PHASE2_ROOT / "contracts" / "model_provenance.schema.json"
    )
    check_digest_vectors()
    check_realistic_alert_against_schema(alert_schema)

    print("=" * 70)
    print("Commit 1 contract validation passed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
