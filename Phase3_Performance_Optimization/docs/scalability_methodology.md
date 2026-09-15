# Scalability Testing Methodology

Objective 3: "Systematic load testing evaluates performance across
simulated instance counts from 100 to 10,000, arrival rates from 100 to
10,000 events per second, and varying anomalous-to-normal ratios.
Detection latency, ledger throughput, processor and memory utilisation,
and network bandwidth are continuously profiled. Scaling behaviour is
modelled to identify degradation thresholds and infrastructure
requirements."

## Environment honesty

The environment this framework was built and measured in is a single host
with **2 vCPUs and 8 GB RAM**, with no Locust/k6 distributed load
generators, no Kafka broker, and no Kubernetes cluster available. Every
number this methodology produces is a **single-process, single-host**
measurement. It is reported as exactly that — never re-labelled as a
distributed 10,000-node result — and the report this framework generates
says so explicitly. Network bandwidth profiling is out of scope for the
same reason: there is no multi-host network path to measure on one
machine.

## Two sweeps, two different questions

### 1. Instance-count sweep (`perf.scalability_harness.run_instance_count_sweep`)

**Question:** does the software layer (canonicalisation, digesting,
signing, off-chain storage, ledger commit) have any hidden dependency on
the *number of distinct simulated cloud resources* being monitored — e.g.
an accidental O(n) structure keyed by resource cardinality?

**Method:** for each instance count in `{100, ..., 10,000}`, generate a
fixed-size batch of events tagged with `resource_id` drawn from that many
distinct simulated instances (`perf.load_generator.SyntheticEventStream`),
submit them through `Phase2Pipeline` with immediate (unbatched) anchoring,
and measure throughput, p50/p95 latency, and CPU/memory
(`perf.resource_profiler`). "Linear scalability" here means throughput and
latency are **flat** across instance counts — a *lack* of degradation as
cardinality grows, not a claim about total system capacity.

### 2. Arrival-rate sweep (`perf.scalability_harness.run_arrival_rate_sweep`)

**Question:** at what aggregate event arrival rate does this single
process stop keeping up in real time?

**Method:** for each target arrival rate, pace synthetic event generation
as a Poisson process (`SyntheticEventStream.inter_arrival_delay_sec`) and
enqueue into `perf.async_pipeline.AsyncSubmissionService`, running for a
fixed wall-clock duration. `keeping_up` is `True` when the queue backlog at
the end of the run stays small relative to what was submitted, and `False`
once submissions consistently outpace what the worker pool can commit —
that crossover point **is** the degradation threshold Objective 3 asks
this sweep to identify, measured directly rather than modelled abstractly.

On the reference 2-vCPU sandbox, this crossover was observed between
roughly 700-800 events/sec (comfortably keeping up) and 2,000 events/sec
(backlog growing without bound over a 4-second window) — see
`outputs/phase3_results.md`'s arrival-rate table for the exact run that
produced the numbers cited in the paper. This is a strong, direct argument
for **why Objective 2's Merkle batching matters**: the same 2,000-10,000
events/sec peak load that overwhelms unbatched per-event submission is
exactly the load Objective 2's batching amendment (batch factor 100 →
~12 anchoring tx/sec) is designed to absorb.

## What this does not replace

A production capacity plan for a real 10,000-instance deployment needs a
distributed load generator (Locust/k6) driving multiple submission-service
processes against a real Fabric network, with Prometheus/Grafana
collecting per-host CPU/memory/network metrics — the technologies listed
in Objective 3's own "Technologies and Approaches" table. This
methodology's single-host sweeps are a necessary first characterisation of
the software layer's own behaviour, not a substitute for that distributed
validation.
