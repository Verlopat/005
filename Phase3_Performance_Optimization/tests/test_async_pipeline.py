import threading
import time

import pytest

from perf.async_pipeline import AsyncSubmissionService, InMemoryQueueBackend, RetryPolicy, SubmissionOutcome


def test_all_events_commit_when_commit_fn_never_fails():
    committed = []
    backend = InMemoryQueueBackend()
    service = AsyncSubmissionService(backend, commit_fn=lambda e: committed.append(e["event_id"]), num_workers=2)
    service.start()
    for i in range(30):
        service.enqueue({"event_id": f"e{i}"})
    ok = service.stop(drain=True, drain_timeout_sec=5)
    assert ok
    snapshot = service.stats.snapshot()
    assert snapshot["submitted"] == 30
    assert snapshot["committed"] == 30
    assert snapshot["dead_lettered"] == 0
    assert snapshot["zero_loss"]
    assert sorted(committed) == sorted(f"e{i}" for i in range(30))


def test_retries_then_succeeds():
    attempts_by_event = {}
    lock = threading.Lock()

    def commit_fn(event):
        with lock:
            attempts_by_event[event["event_id"]] = attempts_by_event.get(event["event_id"], 0) + 1
            attempt = attempts_by_event[event["event_id"]]
        if attempt < 2:
            raise ConnectionError("transient")

    backend = InMemoryQueueBackend()
    service = AsyncSubmissionService(backend, commit_fn, retry_policy=RetryPolicy(max_attempts=3, backoff_base_sec=0.001))
    service.start()
    service.enqueue({"event_id": "e1"})
    service.stop(drain=True, drain_timeout_sec=5)
    snapshot = service.stats.snapshot()
    assert snapshot["committed"] == 1
    assert snapshot["retries"] == 1
    assert attempts_by_event["e1"] == 2


def test_permanent_failure_is_dead_lettered_not_lost():
    def always_fails(event):
        raise RuntimeError("permanent failure")

    backend = InMemoryQueueBackend()
    dead_letters = []
    service = AsyncSubmissionService(
        backend, always_fails, retry_policy=RetryPolicy(max_attempts=2, backoff_base_sec=0.001),
        on_dead_letter=lambda r: dead_letters.append(r),
    )
    service.start()
    service.enqueue({"event_id": "e1"})
    service.stop(drain=True, drain_timeout_sec=5)
    snapshot = service.stats.snapshot()
    assert snapshot["committed"] == 0
    assert snapshot["dead_lettered"] == 1
    assert snapshot["zero_loss"]
    assert dead_letters[0].outcome == SubmissionOutcome.DEAD_LETTERED
    assert dead_letters[0].event_id == "e1"


def test_zero_loss_invariant_holds_under_mixed_outcomes():
    def flaky(event):
        idx = int(event["event_id"][1:])
        if idx % 5 == 0:
            raise RuntimeError("always fails for this event")
        if idx % 3 == 0:
            # succeed only on 2nd+ attempt: fail once via a module-level counter
            pass

    backend = InMemoryQueueBackend()
    service = AsyncSubmissionService(backend, flaky, retry_policy=RetryPolicy(max_attempts=2, backoff_base_sec=0.001), num_workers=3)
    service.start()
    for i in range(100):
        service.enqueue({"event_id": f"e{i}"})
    service.stop(drain=True, drain_timeout_sec=10)
    snapshot = service.stats.snapshot()
    assert snapshot["zero_loss"]
    assert snapshot["committed"] + snapshot["dead_lettered"] == 100


def test_stop_reports_clean_join():
    backend = InMemoryQueueBackend()
    service = AsyncSubmissionService(backend, commit_fn=lambda e: None, num_workers=2)
    service.start()
    service.enqueue({"event_id": "e1"})
    ok = service.stop(drain=True, drain_timeout_sec=5)
    assert ok is True
