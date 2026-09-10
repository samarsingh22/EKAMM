"""Tests for :mod:`ulpf.core.pipeline`."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ulpf.config.settings import IngestSettings, PipelineSettings, Settings, StorageSettings
from ulpf.core.errors import PipelineStoppedError
from ulpf.core.metrics import snapshot
from ulpf.core.models import RawEvent
from ulpf.core.pipeline import NoOpStage, Pipeline, RawStoreStage, Stage
from ulpf.integrity.hashing import make_raw_event
from ulpf.sinks.raw_store import RawStore


def _settings(tmp_path: Path, workers: int = 2) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        pipeline=PipelineSettings(worker_count=workers),
        ingest=IngestSettings(queue_max_size=1000),
    )


def _raw(i: int, marker: bytes = b"") -> RawEvent:
    return make_raw_event(f"event-{i} ".encode() + marker, source_id="test", transport="http")


class _RecordingStage:
    name = "record"

    def __init__(self) -> None:
        self.seen: list[RawEvent] = []

    async def process(self, event: RawEvent) -> RawEvent:
        self.seen.append(event)
        return event


class _FlakyStage:
    """Raises for events whose raw contains b'bad'; passes the rest through."""

    name = "flaky"

    def __init__(self) -> None:
        self.calls = 0

    async def process(self, event: RawEvent) -> RawEvent:
        self.calls += 1
        if b"bad" in event.raw:
            raise ValueError("bad event")
        return event


class _DropStage:
    name = "drop"

    async def process(self, event: RawEvent) -> None:
        return None


class _SlowStage:
    name = "slow"

    async def process(self, event: RawEvent) -> RawEvent:
        await asyncio.sleep(0.03)
        return event


async def test_events_flow_through_stages_in_order(tmp_path: Path) -> None:
    a, b = _RecordingStage(), _RecordingStage()
    b.name = "record2"
    pipeline = Pipeline(_settings(tmp_path), [a, b])

    key = 'ulpf_stage_latency_seconds_count{stage="record"}'
    before = snapshot().get(key, 0.0)

    pipeline.start()
    events = [_raw(i) for i in range(3)]
    for event in events:
        await pipeline.submit(event)
    await pipeline.queue.join()

    assert [e.event_uid for e in a.seen] == [e.event_uid for e in events]
    assert [e.event_uid for e in b.seen] == [e.event_uid for e in events]
    assert snapshot()[key] - before == 3.0


async def test_end_to_end_latency_observed_only_for_events_that_reach_the_sink(
    tmp_path: Path,
) -> None:
    """ulpf_end_to_end_latency_seconds fires per fully-processed event, never for a drop/DLQ."""
    count_key = "ulpf_end_to_end_latency_seconds_count"
    sum_key = "ulpf_end_to_end_latency_seconds_sum"
    before_count = snapshot().get(count_key, 0.0)
    before_sum = snapshot().get(sum_key, 0.0)

    pipeline = Pipeline(_settings(tmp_path), [_DropStage()])
    pipeline.start()
    await pipeline.submit(_raw(0))
    await pipeline.queue.join()
    await pipeline.stop()
    assert snapshot()[count_key] == before_count  # dropped by _DropStage -> not observed

    pipeline = Pipeline(_settings(tmp_path), [_FlakyStage()])
    pipeline.start()
    await pipeline.submit(_raw(1, b"bad"))
    await pipeline.queue.join()
    await pipeline.stop()
    assert snapshot()[count_key] == before_count  # dead-lettered -> not observed

    pipeline = Pipeline(_settings(tmp_path), [NoOpStage()])
    pipeline.start()
    await pipeline.submit(_raw(2))
    await pipeline.queue.join()
    await pipeline.stop()
    after = snapshot()
    assert after[count_key] == before_count + 1  # reached the end of the chain -> observed
    assert after[sum_key] >= before_sum  # a real, non-negative duration was recorded

    await pipeline.stop()


async def test_stage_exception_dead_letters_and_worker_survives(tmp_path: Path) -> None:
    flaky = _FlakyStage()
    downstream = _RecordingStage()
    pipeline = Pipeline(_settings(tmp_path, workers=1), [flaky, downstream])

    pipeline.start()
    markers = [b"", b"bad", b"", b"bad", b""]
    for i, marker in enumerate(markers):
        await pipeline.submit(_raw(i, marker))
    await pipeline.queue.join()

    # 3 good events reached the downstream stage; the worker kept going past
    # each exception (the good events after the bad ones were still processed).
    assert len(downstream.seen) == 3
    assert flaky.calls == 5

    stats = pipeline.dlq.stats()
    assert stats["total"] == 2
    assert stats["by_stage"] == {"flaky": 2}
    assert stats["by_reason"] == {"ValueError": 2}
    dead = list(pipeline.dlq.iter_recent(10))
    assert all(b"bad" in d.raw for d in dead)

    await pipeline.stop()


async def test_none_return_stops_processing_without_dlq(tmp_path: Path) -> None:
    drop = _DropStage()
    downstream = _RecordingStage()
    pipeline = Pipeline(_settings(tmp_path), [drop, downstream])

    pipeline.start()
    for i in range(4):
        await pipeline.submit(_raw(i))
    await pipeline.queue.join()

    assert downstream.seen == []
    assert pipeline.dlq.stats()["total"] == 0

    await pipeline.stop()


async def test_shutdown_flushes_pending_raw_store_writes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    # Large thresholds: nothing auto-flushes, so only stop() can persist.
    store = RawStore(settings, max_buffered_records=10_000, max_buffer_seconds=10_000)
    pipeline = Pipeline(settings, [RawStoreStage(store), NoOpStage()])

    pipeline.start()
    for i in range(5):
        await pipeline.submit(_raw(i))
    await pipeline.queue.join()

    # Written into the buffer, but not yet on disk.
    assert list((tmp_path / "bronze").rglob("events.ndjson.gz")) == []

    await pipeline.stop()

    on_disk = list(store.iter_all())
    assert len(on_disk) == 5


async def test_submit_after_stop_raises(tmp_path: Path) -> None:
    pipeline = Pipeline(_settings(tmp_path), [NoOpStage()])
    pipeline.start()
    await pipeline.stop()
    with pytest.raises(PipelineStoppedError):
        await pipeline.submit(_raw(0))


async def test_double_start_raises(tmp_path: Path) -> None:
    pipeline = Pipeline(_settings(tmp_path), [NoOpStage()])
    pipeline.start()
    try:
        with pytest.raises(RuntimeError):
            pipeline.start()
    finally:
        await pipeline.stop()


async def test_stop_drains_inflight_events(tmp_path: Path) -> None:
    downstream = _RecordingStage()
    pipeline = Pipeline(_settings(tmp_path, workers=3), [_SlowStage(), downstream])

    pipeline.start()
    for i in range(12):
        await pipeline.submit(_raw(i))
    await pipeline.stop()  # must wait for all 12 to finish, not drop them

    assert len(downstream.seen) == 12


# ---------------------------------------------------------------------------
# horizontal scaling: stage_factory (per-worker parser/mapper state)
# ---------------------------------------------------------------------------


def test_pipeline_requires_exactly_one_of_stages_or_stage_factory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        Pipeline(_settings(tmp_path))
    with pytest.raises(ValueError, match="exactly one"):
        Pipeline(_settings(tmp_path), [NoOpStage()], stage_factory=lambda: [NoOpStage()])


def test_worker_buffers_without_a_producer_buffer_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="buffer="):
        Pipeline(_settings(tmp_path), [NoOpStage()], worker_buffers=[])


async def test_stage_factory_builds_one_fresh_stage_instance_per_worker(tmp_path: Path) -> None:
    built: set[int] = set()
    seen: list[tuple[str, int]] = []

    class _TaggingStage:
        name = "tag"

        def __init__(self) -> None:
            self._id = id(self)
            built.add(self._id)

        async def process(self, event: RawEvent) -> RawEvent:
            seen.append((event.event_uid, self._id))
            return event

    pipeline = Pipeline(_settings(tmp_path, workers=4), stage_factory=lambda: [_TaggingStage()])
    pipeline.start()
    events = [_raw(i) for i in range(40)]
    for event in events:
        await pipeline.submit(event)
    await pipeline.queue.join()
    await pipeline.stop()

    assert len(built) == 4  # one worker -> one freshly-constructed stage each
    used = {stage_id for _, stage_id in seen}
    assert used <= built  # every event was handled by one of THIS pipeline's own instances
    assert len(seen) == 40  # nothing lost or duplicated across the 4 independent instances


async def test_flush_runs_once_per_shared_stage_even_when_every_worker_has_it(
    tmp_path: Path,
) -> None:
    """A factory can deliberately still share one singleton (e.g. RawStoreStage) across workers."""

    class _FlushCounter:
        name = "flush_counter"

        def __init__(self) -> None:
            self.flush_calls = 0

        async def process(self, event: RawEvent) -> RawEvent:
            return event

        def flush(self) -> None:
            self.flush_calls += 1

    shared = _FlushCounter()  # captured by the closure -> same object in every worker's list
    pipeline = Pipeline(_settings(tmp_path, workers=4), stage_factory=lambda: [NoOpStage(), shared])
    pipeline.start()
    await pipeline.stop()

    assert shared.flush_calls == 1


# ---------------------------------------------------------------------------
# horizontal scaling: partition-aware mode (one buffer per worker)
# ---------------------------------------------------------------------------


class _FakeConsumeBuffer:
    """A minimal stand-in for a per-worker `_Consumer` (e.g. one Kafka partition set)."""

    def __init__(self, events: list[RawEvent]) -> None:
        self._queue: asyncio.Queue[RawEvent] = asyncio.Queue()
        for event in events:
            self._queue.put_nowait(event)
        self.acked: list[str] = []

    async def get(self) -> RawEvent:
        return await self._queue.get()

    async def ack(self, event: RawEvent) -> None:
        self.acked.append(event.event_uid)


class _FakeProducerBuffer:
    """A minimal stand-in for `submit()`'s producer-side handle (e.g. a Kafka producer)."""

    def __init__(self) -> None:
        self.published: list[RawEvent] = []

    async def put(self, event: RawEvent) -> None:
        self.published.append(event)


async def test_partition_aware_mode_each_worker_only_consumes_its_own_buffer(
    tmp_path: Path,
) -> None:
    per_worker_events = [[_raw(100 * w + i) for i in range(5)] for w in range(3)]
    buffers = [_FakeConsumeBuffer(events) for events in per_worker_events]
    producer = _FakeProducerBuffer()

    built_stages: list[_RecordingStage] = []

    def factory() -> list[Stage]:
        stage = _RecordingStage()
        built_stages.append(stage)
        return [stage]

    pipeline = Pipeline(
        _settings(tmp_path), stage_factory=factory, buffer=producer, worker_buffers=buffers
    )
    pipeline.start()
    await asyncio.sleep(0.1)  # let the 3 workers drain their (tiny, in-memory) buffers

    # submit() in this mode publishes through `buffer`, not any worker's own buffer
    extra = _raw(999)
    await pipeline.submit(extra)
    assert producer.published == [extra]

    await pipeline.stop()  # cancels the 3 workers, now blocked on their empty buffers

    assert len(built_stages) == 3  # one worker per entry in worker_buffers
    for worker_events, stage, buf in zip(per_worker_events, built_stages, buffers, strict=True):
        got = {e.event_uid for e in stage.seen}
        assert got == {e.event_uid for e in worker_events}  # only ITS OWN buffer's events
        assert sorted(buf.acked) == sorted(got)  # every one of them acked exactly once
