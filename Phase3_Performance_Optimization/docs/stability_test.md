# Sustained-Load Stability Testing

Objective 3 success metric: "System stability under sustained load | Zero
event loss and zero service failure across a 24-hour continuous stress
test at peak load."

## What `perf/stability_test.py` actually runs

`run_stability_test(duration_sec, arrival_rate_eps, transient_failure_probability, num_workers)`:

1. Starts an `AsyncSubmissionService` with a configurable number of worker
   threads against a `MockLedger` + local content-addressed store.
2. Paces synthetic event generation as a Poisson process at
   `arrival_rate_eps` for `duration_sec` wall-clock seconds.
3. Injects a transient commit failure with probability
   `transient_failure_probability` on every commit attempt — simulating
   "transient network or consensus delay" in Objective 3's own words —
   so retry/dead-letter handling is exercised under real failure
   conditions, not a failure-free happy path.
4. Verifies, after a clean drain and shutdown:
   - **Zero event loss**: `committed + dead_lettered == submitted`.
   - **Zero service failure**: every worker thread joined cleanly within
     its shutdown timeout (a hung/crashed worker would fail this).
   - Records `injected_transient_failures` (so a reviewer can confirm the
     test was not accidentally failure-free) and
     `max_consecutive_dead_letters` (a proxy for "did failures cluster
     badly at any point").

## Running the full 24-hour soak test

This sandbox's session lifetime does not support a genuine unattended
24-hour run, so `scripts/run_stability_test.py` defaults to a short
representative duration and prints the exact command for the full run:

```bash
python3 Phase3_Performance_Optimization/scripts/run_stability_test.py \
    --duration-hours 24 --arrival-rate 1000 --failure-probability 0.05
```

Run this on a host that can stay up for 24 continuous hours (a small VM is
sufficient — the workload is CPU-light and disk-light at 1,000 events/sec
with `LocalContentAddressedStore`). The script writes a checkpoint every
five minutes to `.phase3_runtime/stability_checkpoint.json` so a reviewer
can confirm the run's progress without waiting for completion, and prints
a final pass/fail summary against both invariants above.

## Relationship to the mock ledger

Like every other Phase 2/3 measurement in this repository, this runs
against `MockLedger`, not a deployed Fabric network — see
`Phase2_Blockchain_Logging/README.md`'s "Two deployment targets" section.
The stability *properties* being tested (retry/dead-letter correctness,
zero event loss, clean shutdown under sustained load) are properties of
this project's own submission-service code and hold regardless of ledger
backend; a Fabric-backed 24-hour run would additionally need to tolerate
real network partitions and peer/orderer restarts, which
`transient_failure_probability` approximates but does not reproduce
exactly.
