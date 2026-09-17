# Alert Contract v1.0.0

Interface between Layer 1 (detection) and Layer 2 (blockchain logging).
**This contract is frozen.** Changes require a version bump and agreement
from both sides.

## Files

| File | Purpose |
|---|---|
| `alert_schema.json` | JSON Schema. Validate every alert against this. |
| `canonical_hash.py` | Digest implementation. Port to Go, verify against the vectors. |
| `hash_test_vectors.json` | Fixed inputs and expected digests. |
| `sample_alerts.jsonl` | 9,233 real alerts from the held-out test fold. |
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

On-chain (326 B mean, 340 B max, budget 1024 B):
`event_id`, `event_hash`, `timestamp`, `threat_class`, `severity`,
`confidence`, `cloud_resource_id`, `model_version`.

Off-chain: the feature vector, SHAP attributions, and IP/port metadata.
The full payload digests to `feature_digest`, which the on-chain record
commits to via `event_hash`.

## Capacity

The deployment gate is tau = 0.999766. At that gate
70.95% of observed flows are anchored.

At the Objective 3 peak of 10,000 events/sec that is
7095 anchoring operations per second, **above the
1,000 TPS budget**. Merkle batching is therefore a dependency, not an
optimisation. At a batch factor of 100 the same load requires
71.0 TPS. See `capacity_table.csv`.

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
