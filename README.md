# Blockchain-Enabled Cloud Anomaly Detection

A phased research/engineering project building a machine-learning intrusion
detection layer and a blockchain-based tamper-proof evidence logging layer
around it. See `Research_Objectives_Revised.docx` for the full academic
objectives; each phase folder below corresponds to one research objective.

## Phases

| Folder | Objective | Status |
|---|---|---|
| `Phase1_Submission/` | Objective 1 — ML detection layer (STAHN model on CICIoT2023) | Delivered |
| `Phase2_Blockchain_Logging/` | Objective 2 — blockchain-based tamper-proof security event logging | Complete for this phase — see its README |
| Phase 3 (not yet started) | Objective 3 — performance optimisation, scalability validation, comparative benchmarking | Planned |

## Quick start

```bash
git clone <repo-link>
cd 005
python3 -m pip install -r Phase1_Submission/requirements.txt
python3 run.py                 # interactive Phase 1 STAHN inference
```

```bash
python3 -m pip install -r Phase2_Blockchain_Logging/requirements.txt
python3 Phase2_Blockchain_Logging/scripts/run_phase2_demo.py     # end-to-end evidence pipeline demo
python3 Phase2_Blockchain_Logging/scripts/tamper_demo.py         # live tamper-detection proof
python -m pytest Phase2_Blockchain_Logging/tests/ -v             # 56 tests
```

See `Phase2_Blockchain_Logging/README.md` for the full Phase 2 documentation,
including how to deploy the real Hyperledger Fabric network once Docker/Go
are available.
