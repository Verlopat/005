# Cloud-IDS — Detection Layer (Objective 1)

This is the Detection Layer (Objective 1) of a PhD project:

1. **Detection Layer** — ML anomaly/attack detection  ← THIS REPO
2. **Blockchain Layer** — Hyperledger Fabric, tamper-proof alert logging
3. **Optimization Layer** — selective logging, off-chain storage, batching

Layers 2 and 3 are built by a DIFFERENT developer in parallel. The alert JSON
is a contract between two people. **Changing a field means renegotiating it —
stop and ask before touching it.**

## History

A CNN-LSTM-Transformer hybrid was tried and abandoned (sequence model on
tabular flow records). No metrics were saved. Do not propose rebuilding it.
Do not propose restarting or re-architecting — we debug, we don't start over.

## Dataset

NF-CSE-CIC-IDS2018-v2, 43 extended NetFlow features from the AWS-generated
CSE-CIC-IDS2018 PCAPs, 18,893,708 flows.

| Class      | Count      | Ratio vs benign |
|------------|-----------:|-----------------|
| Benign     | 16,635,567 | —                |
| DDoS       | 1,390,270  | ~1:12            |
| DoS        | 483,999    | ~1:34            |
| Bot        | 143,097    | ~1:116           |
| BruteForce | 120,912    | ~1:138           |
| Infiltration | 116,361  | ~1:143           |
| Web Attacks | 3,502     | ~1:4,750         |

Web Attacks is ~1 in 4,750 vs benign — expect it to be the weak class.

Cite: Sarhan, Layeghy & Portmann, *Mobile Networks and Applications* 103,
108379, 2022.

## Threat category mapping (fine-grained -> coarse)

The raw `Attack` column has 15 fine-grained values; the 7 coarse categories
above are what `threat_class` in the alert contract and every downstream
metric (macro-F1, per-class P/R/F1, confusion matrix) are computed on.
`config.ATTACK_MAP` is the single source of truth for this mapping —
`config.map_to_coarse_category()` raises if it ever sees a raw value that
isn't listed here, rather than letting an unmapped label silently become
NaN. `02_prepare.py` writes the coarse category to a new `THREAT_CATEGORY`
column and keeps the original fine-grained `Attack` column alongside it in
every split, so per-variant performance can still be broken out later.

| Raw `Attack` value | Coarse category |
|---------------------|------------------|
| Benign | Benign |
| DDOS attack-HOIC | DDoS |
| DDoS attacks-LOIC-HTTP | DDoS |
| DDOS attack-LOIC-UDP | DDoS |
| DoS attacks-Hulk | DoS |
| DoS attacks-GoldenEye | DoS |
| DoS attacks-SlowHTTPTest | DoS |
| DoS attacks-Slowloris | DoS |
| Bot | Bot |
| Infilteration *(dataset's spelling)* | Infiltration |
| SSH-Bruteforce | BruteForce |
| FTP-BruteForce | BruteForce |
| Brute Force -Web | **Web Attacks** (not BruteForce) |
| Brute Force -XSS | **Web Attacks** (not BruteForce) |
| SQL Injection | Web Attacks |

`Brute Force -Web` and `Brute Force -XSS` map to Web Attacks despite the
name — they're web-application attacks, not the credential brute-forcing
that BruteForce (SSH/FTP) covers. The naming collision is a dataset
artifact, not a hint that they belong together.

## The rule that matters most

Identifiers travel ALONGSIDE the feature vector, never inside it.
`IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT` go into the
alert as metadata and must never reach the model. Destination port alone
reaches 70-100% accuracy on these datasets (D'hooge et al.) — hold it out by
default, and support an ablation flag that includes it.

## Alert contract (frozen)

```json
{
  "event_id": "",
  "timestamp_utc": "",
  "verdict": "NORMAL|ANOMALY",
  "threat_class": "",
  "confidence": 0.0,
  "risk_tier": "LOW|MEDIUM|HIGH|CRITICAL",
  "source": {
    "src_ip": "",
    "dst_ip": "",
    "dst_port": 0,
    "protocol": "",
    "cloud_resource_id": ""
  },
  "triggering_features": {},
  "top_contributing_features": [],
  "detector": {
    "model_version": "",
    "pipeline_version": "",
    "calibrated": true
  },
  "raw_event_hash": "",
  "inference_latency_ms": 0.0
}
```

`cloud_resource_id` is derived: destination IP -> synthetic resource ID from
a config mapping. Documented, not hidden.

## Hard requirements

- p99 inference latency < 50 ms, single event, CPU only
- MACRO-F1 is the target, not accuracy. Report both, plus per-class P/R/F1,
  confusion matrix, AUC-ROC, AUC-PR
- Confidence must be calibrated (isotonic + reliability diagram)
- Splits follow CAPTURE ORDER. Never shuffle before splitting
- Resampling (SMOTE etc.) inside the training fold only

## Environment

Windows laptop, CPU only, no GPU. Chunked reads, float32/int32 downcast,
convert to Parquet once, develop on a stratified subsample.

## Pipeline status

- [ ] 01 Inspect raw data (`01_inspect.py`)
- [ ] 02 Prepare / split (`02_prepare.py`)
- [ ] 03 Artifact / leakage check (`03_artifact_check.py`)
- [ ] 04 Feature selection (`04_select_features.py`)
- [ ] 05 Train baseline model (not yet built)
- [ ] 06 Calibrate confidence (not yet built)
- [ ] 07 Full evaluation report (not yet built)
- [ ] 08 Alert-emitting inference service (not yet built)
