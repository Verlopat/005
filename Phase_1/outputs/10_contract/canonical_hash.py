"""Shared digest implementation. Layer 2 must reproduce this exactly.
Verify a port against hash_test_vectors.json before integrating."""
import hashlib

DIGEST_FIELDS = ['event_id', 'schema_version', 'timestamp', 'verdict', 'threat_class', 'confidence', 'model_version', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'cloud_resource_id', 'feature_digest']


def fmt(v):
    if v is None:
        return "\x00"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return f"{v:.6f}"
    if isinstance(v, int):
        return str(v)
    return str(v)


def canonical_string(alert):
    return "|".join(f"{k}={fmt(alert.get(k))}" for k in DIGEST_FIELDS)


def event_hash(alert):
    return hashlib.sha256(canonical_string(alert).encode("utf-8")).hexdigest()


if __name__ == "__main__":
    import json, pathlib
    v = json.loads((pathlib.Path(__file__).parent /
                    "hash_test_vectors.json").read_text())
    ok = sum(event_hash(t["alert"]) == t["expected_sha256"] for t in v["vectors"])
    print(f"{ok}/{len(v['vectors'])} test vectors pass")
