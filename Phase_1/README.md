# Blockchain-Enabled Cloud Anomaly Detection — Layer 1 (Detection)

PhD research, Anurag University. Detection layer for a three-layer system:
ML detection -> Hyperledger Fabric logging -> selective-anchoring optimisation.

## Dataset (not included)

NF-CSE-CIC-IDS2018-v2, 18,893,708 NetFlow records.
Download from https://staff.itee.uq.edu.au/marius/NIDS_datasets/
Place `NF-CSE-CIC-IDS2018-v2.csv` in `data/`.

## Pipeline — run in order

`01_inspect` -> `02_prepare` -> `03_artifact_check` -> `04_select_features`
-> `05_compare_models` -> `06_tune` -> `07_metrics_report`
-> `08_calibration_icr` -> `09_export_model` -> `10_alert_contract`

All paths come from `config.py`. Stage 02 takes ~30 min; 05 and 06 take hours.

## Results (held-out test fold, 3,778,631 records, natural 88% benign prior)

| Metric | Value |
|---|---|
| Macro-F1 | 0.8172 |
| Accuracy | 0.9954 |
| Binary F1 | 0.9809 |
| False positive rate | 0.0003 |
| Expected calibration error | 0.000081 |
| Integrity Coverage Ratio | 0.9568 |
| Ledger write reduction | 88.6% |

## Demo

`python predict_csv.py demo_final.csv --names` — 25 fixed records, 24 correct.

## Notes

Splits are capture-ordered, not shuffled. Benign downsampling is applied to the
training fold only. Identifiers (IPs, ports) are never model features.
Infiltration and Web Attacks recall poorly by design of the dataset — see
`Project_Overview.docx`.
