"""Asynchronous logging pipeline: decouples inference from ledger commit.

Objective 3: "An asynchronous buffer decouples inference from ledger
submission. Detected anomalies are written immediately to a high-throughput
in-memory queue, allowing the detection service to continue without
blocking on confirmation. A dedicated submission service consumes the queue
and commits asynchronously, with retry and dead-letter handling ensuring
zero event loss under transient network or consensus delay."

This module implements exactly that shape with two interchangeable queue
backends:

- `InMemoryQueueBackend` (default) — a `queue.Queue`-backed buffer. No
  external broker required; this is what the demo, tests, and the
  scalability/stability harnesses use in this environment (no Kafka broker
  is available here).
- `KafkaBackend` (production, optional) — the same interface backed by a
  real Apache Kafka topic via `kafka-python`, guarded by an import check
  exactly like `Phase2_Blockchain_Logging/src/ledger/fabric_gateway.py`
  guards its Fabric dependency. Selected via
  `config/async_pipeline.example.yaml`'s `backend: kafka`.

Both backends are driven by the same `AsyncSubmissionService`, so
switching backends never changes retry/dead-letter/at-least-once semantics.
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from ._phase2_bridge import ensure_phase2_importable

ensure_phase2_importable()


class SubmissionOutcome(str, Enum):
    COMMITTED = "committed"
    DEAD_LETTERED = "dead_lettered"


@dataclass
class SubmissionResult:
    event_id: str
    outcome: SubmissionOutcome
    attempts: int
    enqueued_at: float
    finished_at: float
    error: str | None = None

    @property
    def queue_latency_sec(self) -> float:
        return self.finished_at - self.enqueued_at


class QueueBackend:
    """Interface every queue backend implements: a bounded FIFO of
    (event, attempt_count) pairs with blocking put/get, matching the
    semantics needed by AsyncSubmissionService regardless of whether the
    underlying transport is an in-process queue.Queue or a Kafka topic."""

    def put(self, item: dict) -> None:
        raise NotImplementedError

    def get(self, timeout: float | None = None) -> dict | None:
        raise NotImplementedError

    def qsize(self) -> int:
        raise NotImplementedError

    def close(self) -> None:
        pass


class InMemoryQueueBackend(QueueBackend):
    def __init__(self, maxsize: int = 100_000):
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)

    def put(self, item: dict) -> None:
        self._q.put(item)

    def get(self, timeout: float | None = None) -> dict | None:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self) -> int:
        return self._q.qsize()


class KafkaBackend(QueueBackend):
    """Production backend. Requires a reachable Kafka broker and
    `kafka-python` (Phase3_Performance_Optimization/requirements-kafka.txt).
    Not exercised in this sandbox (no broker available) — see
    docs/async_pipeline.md for the minimal docker-compose broker to
    validate this class on a host that has Docker.
    """

    def __init__(self, bootstrap_servers: str, topic: str, group_id: str = "phase3-submission-service"):
        try:
            from kafka import KafkaConsumer, KafkaProducer  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "KafkaBackend requires 'pip install -r requirements-kafka.txt' and a reachable "
                "Kafka broker; the default demo/test path uses InMemoryQueueBackend and does not need this."
            ) from exc
        import json as _json

        self._topic = topic
        self._producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: _json.dumps(v).encode("utf-8"),
        )
        self._consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            value_deserializer=lambda v: _json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            consumer_timeout_ms=1000,
        )

    def put(self, item: dict) -> None:
        self._producer.send(self._topic, value=item)
        self._producer.flush()

    def get(self, timeout: float | None = None) -> dict | None:
        for message in self._consumer:
            return message.value
        return None

    def qsize(self) -> int:
        # Kafka has no cheap exact queue-depth primitive comparable to
        # queue.Queue.qsize(); operators use consumer-group lag metrics in
        # production instead. Returning -1 signals "not supported" rather
        # than a misleading 0.
        return -1

    def close(self) -> None:
        self._producer.close()
        self._consumer.close()


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    backoff_base_sec: float = 0.05
    backoff_multiplier: float = 2.0

    def backoff_for(self, attempt: int) -> float:
        return self.backoff_base_sec * (self.backoff_multiplier ** max(0, attempt - 1))


@dataclass
class AsyncPipelineStats:
    submitted: int = 0
    committed: int = 0
    dead_lettered: int = 0
    retries: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record_commit(self, retried: bool) -> None:
        with self.lock:
            self.committed += 1
            if retried:
                self.retries += 1

    def record_dead_letter(self) -> None:
        with self.lock:
            self.dead_lettered += 1

    def record_submitted(self) -> None:
        with self.lock:
            self.submitted += 1

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "submitted": self.submitted,
                "committed": self.committed,
                "dead_lettered": self.dead_lettered,
                "retries": self.retries,
                "accounted_for": self.committed + self.dead_lettered,
                "zero_loss": (self.committed + self.dead_lettered) == self.submitted,
            }


class AsyncSubmissionService:
    """Consumes a QueueBackend and commits events via `commit_fn`, with
    retry and dead-letter handling. `commit_fn(event) -> None` should raise
    on failure (e.g. a transient ledger/network error); anything it raises
    is caught, retried up to `retry_policy.max_attempts` times with
    exponential backoff, and dead-lettered (never silently dropped) if
    every attempt fails.

    "Zero event loss" (Objective 3's stability criterion) means every event
    ever put on the queue ends up in exactly one of `on_commit` or
    `on_dead_letter` — `stats.snapshot()['zero_loss']` checks this
    invariant directly rather than assuming it.
    """

    def __init__(
        self,
        backend: QueueBackend,
        commit_fn: Callable[[dict], None],
        retry_policy: RetryPolicy | None = None,
        on_commit: Callable[[SubmissionResult], None] | None = None,
        on_dead_letter: Callable[[SubmissionResult], None] | None = None,
        num_workers: int = 1,
    ):
        self.backend = backend
        self.commit_fn = commit_fn
        self.retry_policy = retry_policy or RetryPolicy()
        self.on_commit = on_commit
        self.on_dead_letter = on_dead_letter
        self.num_workers = num_workers
        self.stats = AsyncPipelineStats()
        self.dead_letters: list[SubmissionResult] = []
        self._dead_letter_lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()

    def enqueue(self, event: dict) -> None:
        """The producer-side call: write immediately to the queue and
        return without blocking on ledger confirmation."""
        self.stats.record_submitted()
        self.backend.put({"event": event, "attempt": 0, "enqueued_at": time.time()})

    def start(self) -> None:
        self._stop_event.clear()
        for _ in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self, drain: bool = True, drain_timeout_sec: float = 30.0) -> bool:
        """Stop all worker threads. Returns True iff every worker thread
        joined cleanly within its timeout (no hung worker) — a stuck
        worker is exactly the "service failure" Objective 3's stability
        criterion is meant to catch, so callers should check this return
        value rather than assume a clean shutdown."""
        if drain:
            deadline = time.time() + drain_timeout_sec
            while self.stats.snapshot()["accounted_for"] < self.stats.submitted and time.time() < deadline:
                time.sleep(0.01)
        self._stop_event.set()
        all_joined_cleanly = True
        for t in self._threads:
            t.join(timeout=5.0)
            if t.is_alive():
                all_joined_cleanly = False
        self._threads.clear()
        self.backend.close()
        return all_joined_cleanly

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            item = self.backend.get(timeout=0.2)
            if item is None:
                continue
            self._process_item(item)

    def _process_item(self, item: dict) -> None:
        event = item["event"]
        attempt = item.get("attempt", 0)
        enqueued_at = item.get("enqueued_at", time.time())

        attempt += 1
        try:
            self.commit_fn(event)
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any commit failure is retryable
            if attempt < self.retry_policy.max_attempts:
                time.sleep(self.retry_policy.backoff_for(attempt))
                self.backend.put({"event": event, "attempt": attempt, "enqueued_at": enqueued_at})
                return
            result = SubmissionResult(
                event_id=event.get("event_id", "unknown"),
                outcome=SubmissionOutcome.DEAD_LETTERED,
                attempts=attempt,
                enqueued_at=enqueued_at,
                finished_at=time.time(),
                error=str(exc),
            )
            self.stats.record_dead_letter()
            with self._dead_letter_lock:
                self.dead_letters.append(result)
            if self.on_dead_letter:
                self.on_dead_letter(result)
            return

        result = SubmissionResult(
            event_id=event.get("event_id", "unknown"),
            outcome=SubmissionOutcome.COMMITTED,
            attempts=attempt,
            enqueued_at=enqueued_at,
            finished_at=time.time(),
        )
        self.stats.record_commit(retried=attempt > 1)
        if self.on_commit:
            self.on_commit(result)
