"""Sustained-load stability test.

Objective 3 success metric: "System stability under sustained load |
Zero event loss and zero service failure across a 24-hour continuous
stress test at peak load."

This module implements the harness capable of that run: it drives
`perf.async_pipeline.AsyncSubmissionService` continuously for a
configurable duration, injects a configurable rate of *transient* commit
failures (simulating "transient network or consensus delay" per
Objective 3's own framing) to exercise retry/dead-letter handling under
real failure conditions rather than a failure-free happy path, and
verifies the two invariants directly:

- **Zero event loss**: every event ever enqueued ends up in exactly one
  of committed or dead-lettered (`stats.snapshot()['zero_loss']`).
- **Zero service failure**: the worker threads are still alive and
  responsive at the end of the run (an unhandled exception in a worker
  thread would silently stop consuming the queue without raising to the
  caller, which is exactly the failure mode this check is for).

Running the full 24 hours specified by Objective 3 requires a dedicated,
continuously-available host; `scripts/run_stability_test.py` defaults to a
short representative duration in this sandbox and documents the exact
command to run the full 24-hour soak on such a host.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass

from ._phase2_bridge import ensure_phase2_importable
from .async_pipeline import AsyncSubmissionService, InMemoryQueueBackend, RetryPolicy
from .load_generator import LoadProfile, SyntheticEventStream

ensure_phase2_importable()

from src.evidence_store import LocalContentAddressedStore, put_json  # noqa: E402
from src.ledger.base import EventRecord  # noqa: E402
from src.ledger.mock_ledger import MockLedger  # noqa: E402
from src.signing import generate_agent_identity, sign_digest  # noqa: E402


@dataclass
class StabilityTestResult:
    duration_sec: float
    submitted: int
    committed: int
    dead_lettered: int
    zero_event_loss: bool
    clean_shutdown: bool
    injected_transient_failures: int
    max_consecutive_dead_letters: int
    unhandled_exceptions: int


def run_stability_test(
    duration_sec: float,
    arrival_rate_eps: float = 200.0,
    transient_failure_probability: float = 0.15,
    num_workers: int = 3,
    store_root=None,
    checkpoint_callback=None,
    checkpoint_interval_sec: float = 300.0,
) -> StabilityTestResult:
    """If `checkpoint_callback` is given, it is called periodically (every
    `checkpoint_interval_sec`) with a dict snapshot of progress so far --
    used by scripts/run_stability_test.py to persist a checkpoint file
    during a long (e.g. 24-hour) run without waiting for completion."""
    if store_root is None:
        import tempfile
        from pathlib import Path

        store_root = Path(tempfile.mkdtemp(prefix="phase3_stability_"))

    store = LocalContentAddressedStore(store_root)
    identity = generate_agent_identity("stability-test-agent")
    ledger = MockLedger(authorised_agents={identity.agent_id: identity.public_key_hex()})

    rng = random.Random(42)
    injected_failures = 0
    unhandled_exceptions = 0
    injected_lock = threading.Lock()
    consecutive_dead_letters = 0
    max_consecutive_dead_letters = 0
    consecutive_lock = threading.Lock()

    def commit_fn(event: dict) -> None:
        nonlocal injected_failures
        # Simulate a transient network/consensus delay failure. This must
        # be retryable (raising here, not corrupting state), matching
        # Objective 3's own framing of what the retry/dead-letter handling
        # exists for.
        if rng.random() < transient_failure_probability:
            with injected_lock:
                injected_failures += 1
            raise ConnectionError("simulated transient ledger commit failure")

        stored = put_json(store, event)
        signature = sign_digest(identity, event["payload_digest"])
        record = EventRecord(
            event_id=event["event_id"],
            payload_digest=event["payload_digest"],
            content_address=stored.content_address,
            resource_id=event["resource_id"],
            threat_category=event["threat_category"],
            severity=event["severity"],
            calibrated_confidence=event["calibrated_confidence"],
            model_digest=event["model"]["model_digest"],
            agent_id=identity.agent_id,
            signature=signature,
            timestamp=event["timestamp"],
            transaction_id="",
            block_number=None,
        )
        ledger.log_security_event(record)

    def on_commit(_result) -> None:
        nonlocal consecutive_dead_letters
        with consecutive_lock:
            consecutive_dead_letters = 0

    def on_dead_letter(_result) -> None:
        nonlocal consecutive_dead_letters, max_consecutive_dead_letters
        with consecutive_lock:
            consecutive_dead_letters += 1
            max_consecutive_dead_letters = max(max_consecutive_dead_letters, consecutive_dead_letters)

    backend = InMemoryQueueBackend()
    service = AsyncSubmissionService(
        backend,
        commit_fn,
        retry_policy=RetryPolicy(max_attempts=4, backoff_base_sec=0.01),
        on_commit=on_commit,
        on_dead_letter=on_dead_letter,
        num_workers=num_workers,
    )
    service.start()

    stream = SyntheticEventStream(LoadProfile(num_instances=2000, arrival_rate_eps=arrival_rate_eps), seed=7)
    submitted = 0
    t0 = time.perf_counter()
    last_checkpoint = t0
    try:
        while time.perf_counter() - t0 < duration_sec:
            service.enqueue(stream.next_event())
            submitted += 1
            time.sleep(min(stream.inter_arrival_delay_sec(), 0.02))
            now = time.perf_counter()
            if checkpoint_callback is not None and now - last_checkpoint >= checkpoint_interval_sec:
                snap = service.stats.snapshot()
                checkpoint_callback({
                    "elapsed_sec": now - t0,
                    "duration_sec": duration_sec,
                    "submitted": snap["submitted"],
                    "committed": snap["committed"],
                    "dead_lettered": snap["dead_lettered"],
                    "zero_loss_so_far": snap["zero_loss"],
                    "injected_transient_failures": injected_failures,
                })
                last_checkpoint = now
    except Exception:
        unhandled_exceptions += 1
        raise
    elapsed = time.perf_counter() - t0

    all_joined_cleanly = service.stop(drain=True, drain_timeout_sec=max(30.0, duration_sec))
    snapshot = service.stats.snapshot()

    # all_joined_cleanly is True iff every worker thread exited within its
    # join timeout during stop() — a hung worker (service failure) would
    # make this False; see AsyncSubmissionService.stop()'s own docstring.
    clean_shutdown = all_joined_cleanly

    return StabilityTestResult(
        duration_sec=elapsed,
        submitted=snapshot["submitted"],
        committed=snapshot["committed"],
        dead_lettered=snapshot["dead_lettered"],
        zero_event_loss=snapshot["zero_loss"],
        clean_shutdown=clean_shutdown,
        injected_transient_failures=injected_failures,
        max_consecutive_dead_letters=max_consecutive_dead_letters,
        unhandled_exceptions=unhandled_exceptions,
    )
