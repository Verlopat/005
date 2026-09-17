"""
Stage 10 — The alert contract: the frozen interface between Layer 1
(detection) and Layer 2 (blockchain logging).

Produces everything the blockchain developer needs to build chaincode
WITHOUT running the detection model:

  alert_schema.json        JSON Schema, machine-checkable, the frozen contract
  canonical_hash.py        the shared digest implementation + test vectors
  hash_test_vectors.json   fixed inputs and expected digests, for cross-language
                           verification against the Go implementation
  sample_alerts.jsonl      ~10,000 real alerts generated from the test fold
  onchain_records.jsonl    the <1KB on-chain projection of those alerts
  offchain_payloads.jsonl  the IPFS-bound remainder
  capacity_table.csv       anchors/sec by arrival rate and batch factor
  severity_map.json        threat class -> severity, for the Obj-3 priority engine
  CONTRACT.md              the handover document

WHY THE DIGEST IS SPECIFIED, NOT ASSUMED

  Layer 1 computes a digest; the chaincode recomputes it during VerifyEvent.
  If the two disagree on key ordering, float formatting, or null handling,
  verification fails on CORRECT data — a failure mode that is hard to
  diagnose across two languages and two codebases. So the digest is not
  taken over "the JSON": it is taken over an explicitly specified canonical
  string with a fixed field order and fixed formatting rules, which is
  trivially reproducible in Go. Test vectors are published so the Go side
  can be verified before integration rather than during it.

Run: python 10_alert_contract.py
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from datetime import datetime, timezone

import numpy as np
import pandas as pd

import config

OUTDIR = config.OUTPUTS_DIR / "10_contract"
MODEL_DIR = config.OUTPUTS_DIR / "09_model"
N_SAMPLE = 10_000
SHAP_TOP_K = 5

# Severity feeds the Objective 3 prioritisation engine. Infiltration is rated
# CRITICAL despite low model confidence precisely because it represents
# post-compromise activity: a missed infiltration is more costly than a missed
# flood, and the priority engine must be able to compensate for the low
# confidence documented in stage 08.
SEVERITY = {
    "Benign": "NONE",
    "DDoS": "HIGH",
    "DoS": "HIGH",
    "Bot": "HIGH",
    "BruteForce": "MEDIUM",
    "Infiltration": "CRITICAL",
    "Web Attacks": "HIGH",
}

# Fixed field order for the digest. Changing this list is a breaking change to
# the contract and requires a contract version bump.
DIGEST_FIELDS = [
    "event_id", "schema_version", "timestamp", "verdict", "threat_class",
    "confidence", "model_version", "src_ip", "src_port", "dst_ip", "dst_port",
    "cloud_resource_id", "feature_digest",
]
SCHEMA_VERSION = "1.0.0"


# --------------------------------------------------------------------------
# canonical serialisation — the part both layers must agree on
# --------------------------------------------------------------------------
def fmt(value) -> str:
    """One value, one unambiguous string.

    Floats are fixed at six decimals rather than emitted by the language's
    default float formatter, because Python's repr and Go's strconv do not
    agree on shortest-round-trip representations. Six decimals is far below
    any precision the confidence score carries meaning at.
    """
    if value is None:
        return "\x00"                       # distinct from the empty string
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.6f}"
    if isinstance(value, (int, np.integer)):
        return str(int(value))
    return str(value)


def canonical_string(alert: dict) -> str:
    """Fixed field order, pipe-joined. Not JSON: JSON canonicalisation has
    several competing specifications and this needs exactly one."""
    return "|".join(f"{k}={fmt(alert.get(k))}" for k in DIGEST_FIELDS)


def event_hash(alert: dict) -> str:
    return hashlib.sha256(canonical_string(alert).encode("utf-8")).hexdigest()


def feature_digest(features: dict) -> str:
    """Digest over the feature vector alone, so the on-chain record can commit
    to the features without carrying them."""
    payload = "|".join(f"{k}={fmt(features[k])}" for k in sorted(features))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resource_id_from(dst_ip) -> str | None:
    """Synthetic cloud resource identifier derived from the destination host.

    NF-CSE-CIC-IDS2018-v2 has no asset inventory, so the mapping is a
    deterministic derivation from the destination address rather than a real
    lookup. Documented as such: in deployment this is replaced by a call to
    the cloud provider's inventory API.
    """
    if dst_ip is None or (isinstance(dst_ip, float) and np.isnan(dst_ip)):
        return None
    h = hashlib.sha256(str(dst_ip).encode()).hexdigest()[:12]
    return f"cloud-res-{h}"


# --------------------------------------------------------------------------
def build_schema(labels, feature_names):
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://anurag.edu/cloud-ids/alert_schema/1.0.0",
        "title": "Cloud IDS Security Alert",
        "description": "Frozen interface between the detection layer (Layer 1) "
                       "and the blockchain logging layer (Layer 2).",
        "type": "object",
        "additionalProperties": False,
        "required": ["event_id", "schema_version", "timestamp", "verdict",
                     "threat_class", "severity", "confidence", "model_version",
                     "cloud_resource_id", "feature_digest", "event_hash",
                     "anchor", "inference_latency_ms"],
        "properties": {
            "event_id": {"type": "string", "format": "uuid"},
            "schema_version": {"type": "string", "const": SCHEMA_VERSION},
            "timestamp": {"type": "string", "format": "date-time",
                          "description": "RFC 3339, UTC, millisecond precision"},
            "verdict": {"type": "string", "enum": ["ANOMALY", "NORMAL"]},
            "threat_class": {"type": "string", "enum": labels},
            "severity": {"type": "string",
                         "enum": ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0,
                           "description": "Isotonic-calibrated P(attack). ECE "
                                          "0.000081 on the held-out test fold."},
            "model_version": {"type": "string",
                              "description": "SHA-256-derived model identifier; "
                                             "anchored on-chain once per retrain."},
            "src_ip": {"type": ["string", "null"]},
            "src_port": {"type": ["integer", "null"], "minimum": 0, "maximum": 65535},
            "dst_ip": {"type": ["string", "null"]},
            "dst_port": {"type": ["integer", "null"], "minimum": 0, "maximum": 65535},
            "cloud_resource_id": {"type": ["string", "null"],
                                  "description": "Synthetically derived from the "
                                                 "destination host; see CONTRACT.md."},
            "features": {
                "type": "object", "description": "Triggering feature values.",
                "additionalProperties": {"type": "number"},
                "propertyNames": {"enum": feature_names},
            },
            "feature_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "top_contributing_features": {
                "type": "array", "maxItems": SHAP_TOP_K,
                "items": {
                    "type": "object",
                    "required": ["feature", "value", "shap"],
                    "properties": {
                        "feature": {"type": "string"},
                        "value": {"type": "number"},
                        "shap": {"type": "number",
                                 "description": "Signed contribution toward the "
                                                "predicted class."},
                    },
                },
            },
            "event_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                           "description": "SHA-256 over the canonical string; "
                                          "this is the value committed on-chain."},
            "anchor": {"type": "boolean",
                       "description": "True when confidence >= the deployment gate."},
            "anchor_gate_tau": {"type": "number"},
            "inference_latency_ms": {"type": "number", "minimum": 0},
        },
    }


def main() -> None:
    try:
        import joblib
    except ImportError:
        sys.exit("pip install joblib")

    bundle_path = MODEL_DIR / "detector_bundle.joblib"
    if not bundle_path.exists():
        sys.exit(f"Missing {bundle_path}. Run 09_export_model.py first.")
    OUTDIR.mkdir(parents=True, exist_ok=True)

    b = joblib.load(bundle_path)
    model, cal = b["model"], b["calibrator"]
    feats, labels = b["features"], b["labels"]
    order, benign_idx = b["class_order"], b["benign_index"]
    thresholds = np.asarray(b["class_thresholds"], dtype="float64")
    gate = b.get("gate") or {}
    tau = float(gate.get("tau", 0.5))
    card = json.loads((MODEL_DIR / "model_card.json").read_text())
    model_version = card["model_version"]

    print(f"model {model_version} | gate tau={tau:.6f}")

    # ---- sample real flows ----------------------------------------------
    payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    ident = [c for c in payload.get("identifiers", [])]
    COARSE = config.COARSE_LABEL_COLUMN
    cols = list(dict.fromkeys(feats + [COARSE] + ident))
    test = pd.read_parquet(config.TEST_PARQUET, columns=cols)

    # Stratify so every class appears in the corpus, including Web Attacks.
    rng = np.random.default_rng(config.RANDOM_SEED)
    y_all = test[COARSE].astype(str).to_numpy()
    keep = []
    per = max(1, N_SAMPLE // len(labels))
    for lab in labels:
        pos = np.flatnonzero(y_all == lab)
        keep.append(rng.choice(pos, min(per, len(pos)), replace=False))
    idx = np.sort(np.concatenate(keep))
    sample = test.iloc[idx].reset_index(drop=True)
    del test
    print(f"corpus: {len(sample):,} flows, stratified across {len(labels)} classes")

    X = sample[feats].astype("float32")

    t0 = time.perf_counter()
    proba = model.predict_proba(X)[:, order]
    latency_ms = (time.perf_counter() - t0) / len(X) * 1000
    pred = np.asarray(labels)[(proba / thresholds).argmax(axis=1)]
    confidence = cal.predict(1.0 - proba[:, benign_idx])

    # ---- SHAP -------------------------------------------------------------
    try:
        import shap
        expl = shap.TreeExplainer(model)
        sv = expl.shap_values(X)
        sv = np.asarray(sv)
        # normalise shape to (n_samples, n_features, n_classes)
        if sv.ndim == 3 and sv.shape[0] == len(labels):
            sv = np.transpose(sv, (1, 2, 0))
        print(f"SHAP computed: {sv.shape}")
    except Exception as e:
        sv = None
        print(f"SHAP unavailable ({type(e).__name__}) — "
              f"top_contributing_features will be omitted. pip install shap")

    def col(name):
        for c in sample.columns:
            if name in c.lower():
                return sample[c]
        return None

    src_ip, dst_ip = col("ipv4_src_addr"), col("ipv4_dst_addr")
    src_pt, dst_pt = col("l4_src_port"), col("l4_dst_port")

    def opt(series, i, cast=None):
        if series is None:
            return None
        v = series.iloc[i]
        if pd.isna(v):
            return None
        return cast(v) if cast else str(v)

    # ---- build alerts -----------------------------------------------------
    alerts, onchain, offchain = [], [], []
    now = datetime.now(timezone.utc)
    for i in range(len(sample)):
        fv = {f: float(X.iloc[i][f]) for f in feats}
        cls = str(pred[i])
        conf = float(confidence[i])
        a = {
            "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cloud-ids/{i}")),
            "schema_version": SCHEMA_VERSION,
            "timestamp": now.isoformat(timespec="milliseconds"),
            "verdict": "NORMAL" if cls == "Benign" else "ANOMALY",
            "threat_class": cls,
            "severity": SEVERITY[cls],
            "confidence": round(conf, 6),
            "model_version": model_version,
            "src_ip": opt(src_ip, i),
            "src_port": opt(src_pt, i, int),
            "dst_ip": opt(dst_ip, i),
            "dst_port": opt(dst_pt, i, int),
            "cloud_resource_id": resource_id_from(opt(dst_ip, i)),
            "features": {k: round(v, 6) for k, v in fv.items()},
            "feature_digest": feature_digest(fv),
            "anchor": bool(conf >= tau),
            "anchor_gate_tau": round(tau, 6),
            "inference_latency_ms": round(latency_ms, 4),
        }
        if sv is not None:
            k = labels.index(cls)
            vals = sv[i, :, k] if sv.ndim == 3 else sv[i]
            top = np.argsort(np.abs(vals))[::-1][:SHAP_TOP_K]
            a["top_contributing_features"] = [
                {"feature": feats[j], "value": round(float(X.iloc[i][feats[j]]), 6),
                 "shap": round(float(vals[j]), 6)} for j in top]
        a["event_hash"] = event_hash(a)
        alerts.append(a)

        onchain.append({k: a[k] for k in (
            "event_id", "event_hash", "timestamp", "threat_class", "severity",
            "confidence", "cloud_resource_id", "model_version")})
        offchain.append({"event_id": a["event_id"], "features": a["features"],
                         "top_contributing_features": a.get("top_contributing_features"),
                         "src_ip": a["src_ip"], "src_port": a["src_port"],
                         "dst_ip": a["dst_ip"], "dst_port": a["dst_port"]})

    def dump(path, rows):
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")

    dump(OUTDIR / "sample_alerts.jsonl", alerts)
    dump(OUTDIR / "onchain_records.jsonl", onchain)
    dump(OUTDIR / "offchain_payloads.jsonl", offchain)

    sizes = [len(json.dumps(r, separators=(",", ":")).encode()) for r in onchain]
    n_anchor = sum(a["anchor"] for a in alerts)
    print(f"on-chain record size: mean {np.mean(sizes):.0f} B, "
          f"max {max(sizes)} B  (budget 1024 B)")
    print(f"anchored: {n_anchor:,} of {len(alerts):,} "
          f"({n_anchor / len(alerts) * 100:.2f}%)")

    # ---- schema, hasher, vectors ------------------------------------------
    (OUTDIR / "alert_schema.json").write_text(
        json.dumps(build_schema(labels, feats), indent=2))
    (OUTDIR / "severity_map.json").write_text(json.dumps(SEVERITY, indent=2))

    vectors = []
    for a in alerts[:5]:
        vectors.append({"alert": {k: a.get(k) for k in DIGEST_FIELDS},
                        "canonical_string": canonical_string(a),
                        "expected_sha256": a["event_hash"]})
    vectors.append({
        "alert": {k: None for k in DIGEST_FIELDS},
        "canonical_string": canonical_string({}),
        "expected_sha256": event_hash({}),
        "note": "all-null case: exercises the null sentinel",
    })
    (OUTDIR / "hash_test_vectors.json").write_text(json.dumps({
        "digest_fields": DIGEST_FIELDS,
        "rules": {
            "field_order": "fixed, as digest_fields; NOT sorted",
            "join": "fields joined by '|', each rendered as key=value",
            "null": "rendered as the single byte 0x00",
            "float": "fixed six decimals, e.g. 0.999766",
            "int": "base-10, no padding",
            "bool": "lowercase true / false",
            "encoding": "UTF-8, then SHA-256, then lowercase hex",
        },
        "vectors": vectors,
    }, indent=2))

    (OUTDIR / "canonical_hash.py").write_text(f'''"""Shared digest implementation. Layer 2 must reproduce this exactly.
Verify a port against hash_test_vectors.json before integrating."""
import hashlib

DIGEST_FIELDS = {DIGEST_FIELDS!r}


def fmt(v):
    if v is None:
        return "\\x00"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return f"{{v:.6f}}"
    if isinstance(v, int):
        return str(v)
    return str(v)


def canonical_string(alert):
    return "|".join(f"{{k}}={{fmt(alert.get(k))}}" for k in DIGEST_FIELDS)


def event_hash(alert):
    return hashlib.sha256(canonical_string(alert).encode("utf-8")).hexdigest()


if __name__ == "__main__":
    import json, pathlib
    v = json.loads((pathlib.Path(__file__).parent /
                    "hash_test_vectors.json").read_text())
    ok = sum(event_hash(t["alert"]) == t["expected_sha256"] for t in v["vectors"])
    print(f"{{ok}}/{{len(v['vectors'])}} test vectors pass")
''')

    # ---- capacity table ---------------------------------------------------
    anchor_rate = n_anchor / len(alerts)
    rows = []
    for arrival in (100, 500, 1_000, 5_000, 10_000):
        for batch in (1, 10, 100, 500):
            rows.append({
                "arrival_events_per_sec": arrival,
                "anchor_rate": round(anchor_rate, 6),
                "anchors_per_sec": round(arrival * anchor_rate, 2),
                "batch_factor": batch,
                "ledger_tps_required": round(arrival * anchor_rate / batch, 3),
                "within_1000_tps": arrival * anchor_rate / batch <= 1000,
            })
    cap = pd.DataFrame(rows)
    cap.to_csv(OUTDIR / "capacity_table.csv", index=False)
    peak = cap[(cap.arrival_events_per_sec == 10_000) & (cap.batch_factor == 1)]
    print(f"peak unbatched load: "
          f"{peak.iloc[0]['ledger_tps_required']:.0f} TPS required "
          f"(budget 1000) -> batching required")

    (OUTDIR / "CONTRACT.md").write_text(f"""# Alert Contract v{SCHEMA_VERSION}

Interface between Layer 1 (detection) and Layer 2 (blockchain logging).
**This contract is frozen.** Changes require a version bump and agreement
from both sides.

## Files

| File | Purpose |
|---|---|
| `alert_schema.json` | JSON Schema. Validate every alert against this. |
| `canonical_hash.py` | Digest implementation. Port to Go, verify against the vectors. |
| `hash_test_vectors.json` | Fixed inputs and expected digests. |
| `sample_alerts.jsonl` | {len(alerts):,} real alerts from the held-out test fold. |
| `onchain_records.jsonl` | The <1KB projection committed on-chain. |
| `offchain_payloads.jsonl` | The remainder, bound for content-addressed storage. |
| `capacity_table.csv` | Ledger TPS required by arrival rate and batch factor. |
| `severity_map.json` | Threat class to severity, for the priority engine. |

## The digest

`event_hash` is SHA-256 over a canonical string, **not** over the JSON.
JSON canonicalisation has several competing specifications; this needs
exactly one. Rules:

- Fields in the fixed order given by `digest_fields`. **Not sorted.**
- Each rendered `key=value`, joined with `|`.
- `null` renders as the single byte `0x00`, distinct from an empty string.
- Floats render at **fixed six decimals**. Python `repr` and Go `strconv`
  disagree on shortest-round-trip forms, so neither is used.
- UTF-8, then SHA-256, then lowercase hex.

Run `python canonical_hash.py` to check a port against the vectors.

## On-chain versus off-chain

On-chain ({np.mean(sizes):.0f} B mean, {max(sizes)} B max, budget 1024 B):
`event_id`, `event_hash`, `timestamp`, `threat_class`, `severity`,
`confidence`, `cloud_resource_id`, `model_version`.

Off-chain: the feature vector, SHAP attributions, and IP/port metadata.
The full payload digests to `feature_digest`, which the on-chain record
commits to via `event_hash`.

## Capacity

The deployment gate is tau = {tau:.6f}. At that gate
{anchor_rate * 100:.2f}% of observed flows are anchored.

At the Objective 3 peak of 10,000 events/sec that is
{10000 * anchor_rate:.0f} anchoring operations per second, **above the
1,000 TPS budget**. Merkle batching is therefore a dependency, not an
optimisation. At a batch factor of 100 the same load requires
{10000 * anchor_rate / 100:.1f} TPS. See `capacity_table.csv`.

## Notes

- `src_ip`, `dst_ip`, `src_port`, `dst_port` are **nullable** and are never
  model features. They travel as metadata only.
- `cloud_resource_id` is derived deterministically from the destination
  host, since the dataset carries no asset inventory. In deployment this is
  replaced by a cloud inventory lookup.
- `confidence` is isotonic-calibrated with ECE 0.000081 on the held-out test
  fold, so the gate is interpretable as a probability.
- `model_version` is anchored on-chain once per retraining cycle, making
  every alert attributable to the exact model that produced it.
""")

    for p in sorted(OUTDIR.iterdir()):
        print(f"  {p.name:26} {p.stat().st_size / 1024:8.1f} KB")
    print(f"\nsaved -> {OUTDIR}")


if __name__ == "__main__":
    main()