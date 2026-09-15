"""Local caching with periodic synchronisation.

Objective 3: "Local caching with periodic synchronisation maintains
consistent local state for real-time querying without direct ledger
access." This lets an analyst-facing dashboard or the audit CLI answer
"what's been anchored for resource X" from an in-memory/local structure
instead of issuing a ledger query per request, while staying bounded-stale
by a configurable sync interval.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from ._phase2_bridge import ensure_phase2_importable

ensure_phase2_importable()

from src.ledger.base import EventRecord, LedgerClient  # noqa: E402


@dataclass
class CacheStats:
    sync_count: int = 0
    last_sync_at: float | None = None
    last_sync_duration_sec: float | None = None
    records_cached: int = 0


class LocalStateCache:
    """Periodically pulls `ledger.query_event_history()` into an in-memory
    index, keyed by event_id and by resource_id, so repeated queries for
    the same resource don't each round-trip to the ledger.

    This is explicitly a *read* cache: writes always go through the normal
    pipeline/ledger path (`Phase2Pipeline.submit`), never through the
    cache, so the cache can never become the source of truth for a write
    that hasn't actually been anchored.
    """

    def __init__(self, ledger: LedgerClient, sync_interval_sec: float = 1.0):
        self.ledger = ledger
        self.sync_interval_sec = sync_interval_sec
        self._by_event_id: dict[str, EventRecord] = {}
        self._by_resource_id: dict[str, list[EventRecord]] = {}
        self._lock = threading.RLock()
        self.stats = CacheStats()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def sync_once(self) -> int:
        t0 = time.perf_counter()
        records = self.ledger.query_event_history()
        with self._lock:
            self._by_event_id = {r.event_id: r for r in records}
            by_resource: dict[str, list[EventRecord]] = {}
            for r in records:
                by_resource.setdefault(r.resource_id, []).append(r)
            self._by_resource_id = by_resource
            self.stats.records_cached = len(records)
        self.stats.sync_count += 1
        self.stats.last_sync_at = time.time()
        self.stats.last_sync_duration_sec = time.perf_counter() - t0
        return len(records)

    def start_background_sync(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop_background_sync(self, timeout_sec: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout_sec)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sync_once()
            except Exception:
                pass  # a failed sync leaves the previous cache state intact; retried next interval
            self._stop_event.wait(self.sync_interval_sec)

    def get_by_event_id(self, event_id: str) -> EventRecord | None:
        with self._lock:
            return self._by_event_id.get(event_id)

    def get_by_resource_id(self, resource_id: str) -> list[EventRecord]:
        with self._lock:
            return list(self._by_resource_id.get(resource_id, []))

    def staleness_sec(self) -> float | None:
        if self.stats.last_sync_at is None:
            return None
        return time.time() - self.stats.last_sync_at
