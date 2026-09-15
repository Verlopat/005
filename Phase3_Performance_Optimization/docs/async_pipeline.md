# Asynchronous Logging Pipeline and Local Caching

Objective 3: "An asynchronous buffer decouples inference from ledger
submission. Detected anomalies are written immediately to a
high-throughput in-memory queue, allowing the detection service to
continue without blocking on confirmation. A dedicated submission service
consumes the queue and commits asynchronously, with retry and dead-letter
handling ensuring zero event loss under transient network or consensus
delay. Local caching with periodic synchronisation maintains consistent
local state for real-time querying without direct ledger access."

## Design

`perf/async_pipeline.py` implements this as three composable pieces:

1. **`QueueBackend`** — the transport interface. `InMemoryQueueBackend`
   (default, `queue.Queue`-backed) requires nothing external and is what
   every test, demo, and harness in this repository uses. `KafkaBackend`
   (production) implements the identical interface against a real Kafka
   topic via `kafka-python`, guarded exactly like
   `Phase2_Blockchain_Logging/src/ledger/fabric_gateway.py` guards its
   Fabric dependency — importable and usable only when
   `requirements-kafka.txt` is installed and a broker is reachable.
2. **`AsyncSubmissionService`** — the consumer side. `enqueue()` is the
   non-blocking producer call the detection path uses; one or more worker
   threads drain the queue and call a supplied `commit_fn(event)`. A
   failure raised by `commit_fn` is retried with exponential backoff
   (`RetryPolicy`) up to `max_attempts`; exhausting retries dead-letters
   the event via `on_dead_letter` rather than dropping it silently.
3. **`perf/local_cache.py`'s `LocalStateCache`** — a periodic read-through
   cache over `ledger.query_event_history()`, so a dashboard or the
   Phase 2 audit CLI can serve repeated "what's anchored for resource X"
   queries from local memory instead of a ledger round-trip per request.
   It has no write path at all (`test_local_cache.py` asserts this
   directly) — every write still goes through
   `Phase2_Blockchain_Logging/src/pipeline.py:Phase2Pipeline.submit`, so
   the cache can never itself become a false source of truth for
   something that was never actually anchored.

## The "zero event loss" invariant

`AsyncSubmissionService.stats.snapshot()['zero_loss']` is `True` iff
`committed + dead_lettered == submitted`. This is checked directly by
`tests/test_async_pipeline.py` under normal operation and by
`perf/stability_test.py` under injected transient failures — it is a
structural invariant of the code (every code path through
`_process_item` ends in exactly one of a commit callback or a dead-letter
append), not merely something that happened to be true in one run.

## Running a real Kafka broker to validate `KafkaBackend`

Not exercised in the sandbox this framework was built in (no Docker). On a
host with Docker:

```yaml
# docker-compose.kafka.yml (minimal, for local validation only)
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.6.0
    environment: { ZOOKEEPER_CLIENT_PORT: "2181" }
  kafka:
    image: confluentinc/cp-kafka:7.6.0
    depends_on: [zookeeper]
    environment:
      KAFKA_ZOOKEEPER_CONNECT: "zookeeper:2181"
      KAFKA_ADVERTISED_LISTENERS: "PLAINTEXT://localhost:9092"
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: "1"
    ports: ["9092:9092"]
```

```bash
pip install -r Phase3_Performance_Optimization/requirements-kafka.txt
docker compose -f docker-compose.kafka.yml up -d
python3 -c "
from perf.async_pipeline import KafkaBackend, AsyncSubmissionService
backend = KafkaBackend('localhost:9092', topic='phase3-security-events')
service = AsyncSubmissionService(backend, commit_fn=lambda e: print('committed', e['event_id']))
service.start()
"
```
