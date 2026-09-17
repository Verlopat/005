# Phase 3 — Performance Optimisation, Scalability Validation, and Comparative Benchmarking

## Current integrated entry point

Use `python main.py phase3 --mode existing --run-dir runs/experiment-a`
after completing Phase 2 in that directory. The current experiment replays the
validated Phase 2 events in paired synchronous/asynchronous MockLedger trials.
See the root README for metrics, limitations, and the complete three-phase command.

The STAHN/CICIoT2023 load generator, retired root scripts, and historical paper
results described below are not the new integrated execution path. Their legacy
load/stability tests require a separate dataset migration.

Phase 3 implements **Objective 3**: the holistic optimisation and
validation of the integrated framework (Phase 1 detection + Phase 2
blockchain evidence logging) against the performance requirements of a
production cloud security deployment.

## What's implemented

| Objective 3 sub-component | Module | Status |
|---|---|---|
| Calibrated selective logging and event prioritisation | `Phase2_Blockchain_Logging/src/anchoring_policy.py` | Already built in Phase 2 |
| Class-aware gate flooring | `Phase2_Blockchain_Logging/src/anchoring_policy.py` (`category_thresholds`) | Already built in Phase 2; **exercised and measured here** in the per-category ICR breakdown |
| Batch processing with Merkle tree aggregation | `Phase2_Blockchain_Logging/src/merkle.py` | Already built in Phase 2 (recorded there as a throughput dependency) |
| Asynchronous logging pipeline and local caching | `perf/async_pipeline.py`, `perf/local_cache.py` | Built in this phase |
| Scalability testing and load profiling | `perf/load_generator.py`, `perf/scalability_harness.py` | Built in this phase |
| Comparative analysis against existing solutions | `perf/comparative_benchmark.py` | Built in this phase, with real literature citations |
| System stability under sustained load | `perf/stability_test.py` | Built in this phase (short representative run in this sandbox; full 24h harness ready for a dedicated host) |

## Environment honesty

This framework was built and measured on a **2 vCPU / 8 GB RAM single
host** with no Docker, Kafka broker, Kubernetes, or Locust/k6 available.
Every number this phase produces is disclosed as exactly what it is: a
single-process, software-layer measurement against
`Phase2_Blockchain_Logging/src/ledger/mock_ledger.py`. See
`docs/scalability_methodology.md` for what this does and does not
demonstrate, and `Phase2_Blockchain_Logging/README.md`'s "Two deployment
targets" section for how to point the same pipeline at a real
Hyperledger Fabric network.

## Install dependencies

```bash
python3 -m pip install -r Phase3_Performance_Optimization/requirements.txt
```

Kafka is optional and kept separate in `requirements-kafka.txt` — see
`docs/async_pipeline.md` for validating `KafkaBackend` against a real
broker on a host with Docker.

## Generate the paper results (single command)

```bash
python3 run_phase3.py
```

Run from the repository root (requires `Phase2_Blockchain_Logging/outputs/phase2_results.json` to already exist — run `python3 run_phase2.py` first if you haven't). This measures every metric in Objective 3's Success Metrics table and writes:

- `Phase3_Performance_Optimization/outputs/phase3_results.md` — the
  ready-to-paste report for your paper's Objective 3 evaluation section.
- `Phase3_Performance_Optimization/outputs/phase3_results.json` — the
  same data as raw numbers.

Tune it with `--num-events`, `--instance-counts`, `--arrival-rates`,
`--icr-gate`, etc. — run `python3 Phase3_Performance_Optimization/scripts/generate_phase3_results.py --help`.

## Run the full 24-hour stability soak

```bash
python3 Phase3_Performance_Optimization/scripts/run_stability_test.py \
    --duration-hours 24 --arrival-rate 1000 --failure-probability 0.05
```

On a host that can stay up for 24 continuous hours. Checkpoints every 5
minutes to `.phase3_runtime/stability_checkpoint.json`; see
`docs/stability_test.md`.

## Run the tests

```bash
python -m pytest Phase3_Performance_Optimization/tests/ -v
```

27 tests covering the async submission service's retry/dead-letter/zero-
loss guarantees, the local cache's read-only contract, the synthetic load
generator's schema conformance and determinism, the resource profiler's
CPU/memory accounting, both scalability sweeps, the stability harness, and
the comparative benchmark table's citation integrity.

## An honestly-reported gap: metric 3c

Objective 3's own Success Metrics table targets ">99% of byte volume
against full on-chain logging" for the combined effect of selective
logging + batching + off-chain payload placement. Measured against this
project's actual ~1.4 KB structured alert payload, the combined figure
reaches roughly 93.7% (at the registered 11.43% anchoring rate) — short of
the >99% target. `outputs/phase3_results.md`'s methodological notes walk
through the exact arithmetic and the likely reason (the target was most
plausibly calibrated for a larger raw-evidence payload than this
project's compact JSON alert contract). This is reported as a measured
gap, not adjusted to force a passing number.

## Documentation index

- `docs/async_pipeline.md` — asynchronous pipeline design, the zero-event-
  loss invariant, and how to validate `KafkaBackend` against a real broker.
- `docs/scalability_methodology.md` — what the two load-test sweeps
  measure and what they explicitly do not (a distributed 10,000-node claim).
- `docs/comparative_benchmark.md` — the six cited prior-work sources and
  every protocol difference that must be disclosed alongside the table.
- `docs/stability_test.md` — the sustained-load harness and how to run the
  full 24-hour soak on a dedicated host.

## Repository layout

```
Phase3_Performance_Optimization/
├── perf/                        # async pipeline, local cache, load generator,
│                                 # resource profiler, scalability harness,
│                                 # stability test, comparative benchmark
├── docs/                        # methodology and design rationale
├── scripts/                     # generate_phase3_results, run_load_test,
│                                 # run_stability_test
├── tests/                       # pytest suite (27 tests)
└── outputs/                     # phase3_results.md / .json (committed)
```
