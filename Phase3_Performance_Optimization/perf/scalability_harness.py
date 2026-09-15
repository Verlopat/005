"""Scalability testing and load profiling.

Objective 3: "Systematic load testing evaluates performance across
simulated instance counts from 100 to 10,000, arrival rates from 100 to
10,000 events per second... Scaling behaviour is modelled to identify
degradation thresholds and infrastructure requirements."

Two complementary sweeps, both driven by `perf.load_generator`:

1. `run_instance_count_sweep` — fixed-size batches processed through the
   Objective 2 pipeline while varying only the *cardinality* of simulated
   resource_ids (100 -> 10,000), to verify the software layer has no
   hidden per-resource bottleneck (e.g. an accidental O(n) lookup keyed by
   distinct resource count).
2. `run_arrival_rate_sweep` — real-time-paced event arrival via
   `perf.async_pipeline.AsyncSubmissionService`, increasing the aggregate
   arrival rate until queue backlog stops draining, which is precisely the
   "degradation threshold" the docx asks scaling to identify.

This sandbox is a single 2-vCPU host, not a distributed 10,000-node
deployment; both sweeps report exactly that scope in their output rather
than presenting single-host numbers as if they were a cluster-scale
result. See docs/scalability_methodology.md.
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from ._phase2_bridge import ensure_phase2_importable
from .async_pipeline import AsyncSubmissionService, InMemoryQueueBackend, RetryPolicy
from .load_generator import LoadProfile, SyntheticEventStream
from .resource_profiler import ResourceMonitor

ensure_phase2_importable()

from src.anchoring_policy import AnchoringPolicy  # noqa: E402
from src.evidence_store import LocalContentAddressedStore  # noqa: E402
from src.ledger.mock_ledger import MockLedger  # noqa: E402
from src.pipeline import Phase2Pipeline  # noqa: E402
from src.signing import generate_agent_identity  # noqa: E402


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    values = sorted(values)
    k = (len(values) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(values) - 1)
    if f == c:
        return values[f]
    return values[f] + (values[c] - values[f]) * (k - f)


@dataclass
class InstanceCountResult:
    num_instances: int
    events_processed: int
    elapsed_sec: float
    throughput_eps: float
    latency_ms_p50: float
    latency_ms_p95: float
    cpu_utilisation_fraction: float
    rss_mb_peak: float


def run_instance_count_sweep(
    instance_counts: list[int], events_per_run: int = 300, store_root=None
) -> list[InstanceCountResult]:
    results = []
    for count in instance_counts:
        store = LocalContentAddressedStore(store_root / f"instances_{count}" if store_root else _tmp_store_dir(count))
        identity = generate_agent_identity(f"load-agent-{count}")
        ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})
        policy = AnchoringPolicy.from_dict(
            {"anchor_attack_only": False, "confidence_threshold": 0.0, "immediate_confidence_threshold": 0.0}
        )
        pipeline = Phase2Pipeline(store, ledger, identity, policy, batch_size=1)
        stream = SyntheticEventStream(LoadProfile(num_instances=count, arrival_rate_eps=0.0))

        latencies_ms = []
        with ResourceMonitor() as monitor:
            t0 = time.perf_counter()
            for event in stream.iter_events(events_per_run):
                t_start = time.perf_counter()
                pipeline.submit(event)
                latencies_ms.append((time.perf_counter() - t_start) * 1000.0)
            elapsed = time.perf_counter() - t0
        profile = monitor.result()

        results.append(
            InstanceCountResult(
                num_instances=count,
                events_processed=len(latencies_ms),
                elapsed_sec=elapsed,
                throughput_eps=len(latencies_ms) / elapsed if elapsed > 0 else float("inf"),
                latency_ms_p50=_percentile(latencies_ms, 50),
                latency_ms_p95=_percentile(latencies_ms, 95),
                cpu_utilisation_fraction=profile.cpu_utilisation_fraction,
                rss_mb_peak=profile.rss_mb_peak,
            )
        )
    return results


def _tmp_store_dir(suffix):
    import tempfile
    from pathlib import Path

    return Path(tempfile.mkdtemp(prefix=f"phase3_scale_{suffix}_"))


@dataclass
class ArrivalRateResult:
    target_arrival_rate_eps: float
    duration_sec: float
    submitted: int
    committed: int
    dead_lettered: int
    achieved_arrival_rate_eps: float
    achieved_commit_rate_eps: float
    max_queue_depth_observed: int
    backlog_at_end: int
    keeping_up: bool  # True if commit rate tracks arrival rate within tolerance (no unbounded backlog growth)


def run_arrival_rate_sweep(
    arrival_rates_eps: list[float], duration_sec: float = 3.0, num_workers: int = 2, store_root=None
) -> list[ArrivalRateResult]:
    results = []
    for rate in arrival_rates_eps:
        store = LocalContentAddressedStore(store_root / f"rate_{int(rate)}" if store_root else _tmp_store_dir(f"rate_{int(rate)}"))
        identity = generate_agent_identity(f"load-agent-rate-{int(rate)}")
        ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})

        def commit_fn(event: dict, _store=store, _ledger=ledger, _identity=identity) -> None:
            from src.evidence_store import put_json
            from src.ledger.base import EventRecord
            from src.signing import sign_digest

            stored = put_json(_store, event)
            signature = sign_digest(_identity, event["payload_digest"])
            record = EventRecord(
                event_id=event["event_id"],
                payload_digest=event["payload_digest"],
                content_address=stored.content_address,
                resource_id=event["resource_id"],
                threat_category=event["threat_category"],
                severity=event["severity"],
                calibrated_confidence=event["calibrated_confidence"],
                model_digest=event["model"]["model_digest"],
                agent_id=_identity.agent_id,
                signature=signature,
                timestamp=event["timestamp"],
                transaction_id="",
                block_number=None,
            )
            _ledger.log_security_event(record)

        backend = InMemoryQueueBackend()
        service = AsyncSubmissionService(backend, commit_fn, retry_policy=RetryPolicy(max_attempts=2), num_workers=num_workers)
        service.start()

        stream = SyntheticEventStream(LoadProfile(num_instances=1000, arrival_rate_eps=rate))
        max_depth = 0
        t0 = time.perf_counter()
        submitted = 0
        while time.perf_counter() - t0 < duration_sec:
            event = stream.next_event()
            service.enqueue(event)
            submitted += 1
            max_depth = max(max_depth, backend.qsize())
            delay = stream.inter_arrival_delay_sec()
            time.sleep(min(delay, 0.05))  # cap sleep so low rates don't starve the loop past duration_sec
        elapsed = time.perf_counter() - t0

        backlog_before_drain = backend.qsize()
        service.stop(drain=True, drain_timeout_sec=10.0)
        snapshot = service.stats.snapshot()

        results.append(
            ArrivalRateResult(
                target_arrival_rate_eps=rate,
                duration_sec=elapsed,
                submitted=snapshot["submitted"],
                committed=snapshot["committed"],
                dead_lettered=snapshot["dead_lettered"],
                achieved_arrival_rate_eps=submitted / elapsed if elapsed > 0 else 0.0,
                achieved_commit_rate_eps=snapshot["committed"] / elapsed if elapsed > 0 else 0.0,
                max_queue_depth_observed=max_depth,
                backlog_at_end=backlog_before_drain,
                keeping_up=backlog_before_drain < 0.5 * submitted if submitted else True,
            )
        )
    return results
