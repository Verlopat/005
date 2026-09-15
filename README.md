# Three-Phase Security Pipeline

This repository contains a three-stage project:

- **Phase 1 — Submission:** STAHN model inference and evaluation assets.
- **Phase 2 — Blockchain Logging:** audit logging and blockchain demonstration tooling.
- **Phase 3 — Performance Optimization:** load and stability testing tooling.

## Quick start

Run the unified launcher from the repository root with Python 3:

```bash
python main.py phase1
python main.py phase2
python main.py phase3
python main.py all
```

On first use, `main.py` creates (or reuses) `.venv`, upgrades `pip`, installs the selected phase's `requirements.txt`, and launches that phase's primary script. It installs dependencies only for the phase being run; `all` processes the phases in order.

## What each command runs

| Command | Requirements | Entry point |
| --- | --- | --- |
| `phase1` | `Phase1_Submission/requirements.txt` | `Phase1_Submission/interactive_inference.py` |
| `phase2` | `Phase2_Blockchain_Logging/requirements.txt` | `Phase2_Blockchain_Logging/scripts/run_phase2_demo.py` |
| `phase3` | `Phase3_Performance_Optimization/requirements.txt` | `Phase3_Performance_Optimization/scripts/run_load_test.py` |

## Additional dependencies

Phase 2 and Phase 3 include optional environment-specific dependency files (`requirements-fabric.txt` and `requirements-kafka.txt`). Install them manually only when working with their respective Fabric or Kafka integrations:

```bash
.venv/bin/python -m pip install -r Phase2_Blockchain_Logging/requirements-fabric.txt
.venv/bin/python -m pip install -r Phase3_Performance_Optimization/requirements-kafka.txt
```

On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.

## Repository layout

```text
Phase1_Submission/                 Model submission, inference, and evaluation
Phase2_Blockchain_Logging/         Blockchain audit logging implementation
Phase3_Performance_Optimization/   Performance test implementation
main.py                            Unified environment and phase launcher
```

The older root launch scripts have been consolidated into `main.py`.
