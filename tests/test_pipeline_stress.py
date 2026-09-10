"""Stress test for :mod:`ulpf.core.pipeline` horizontal scaling.

Runs the same batch of events through the pipeline once with 1 worker and
once with 4, using a stage with a small simulated I/O latency (``asyncio.sleep``
— the same technique ``test_pipeline.py``'s own ``_SlowStage`` uses) so worker
count actually matters: asyncio concurrency only pays off for work that
yields, and every real ULPF stage does (file I/O, sink writes, ...).

Two things must both hold:

* **Throughput**: 4 concurrent workers each sleeping ``DELAY_S`` per event
  finish a batch in a small fraction of the time 1 worker serializing the same
  sleeps takes. A generous 2x threshold (of an expected ~4x) leaves headroom
  for a loaded CI box while still catching a real regression (e.g. workers
  accidentally serialized behind a shared lock).
* **Correctness**: every event is processed exactly once, in *both* runs —
  the distinct ``event_uid`` count seen downstream equals the input count. No
  event is lost (backpressure/shutdown bug) or duplicated (double delivery).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from ulpf.config.settings import IngestSettings, PipelineSettings, Settings, StorageSettings
from ulpf.core.models import RawEvent
from ulpf.core.pipeline import Pipeline
from ulpf.integrity.hashing import make_raw_event

_N_EVENTS = 200
_DELAY_S = 0.01  # simulated per-event I/O latency
_MIN_SPEEDUP = 2.0  # generous vs. the ~4x a clean 4-worker run should show


def _settings(tmp_path: Path, workers: int) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        pipeline=PipelineSettings(worker_count=workers),
        # generously larger than _N_EVENTS so submission never blocks on
        # backpressure - this test measures processing throughput, not intake.
        ingest=IngestSettings(queue_max_size=_N_EVENTS * 2),
    )


def _raw(i: int) -> RawEvent:
    return make_raw_event(f"stress-event-{i}".encode(), source_id="stress", transport="http")


class _SimulatedIoStage:
    """A stand-in for a real stage's I/O wait (sink write, enrichment lookup, ...)."""

    name = "simulated_io"

    async def process(self, event: RawEvent) -> RawEvent:
        await asyncio.sleep(_DELAY_S)
        return event


class _CollectStage:
    """Records every ``event_uid`` that reaches the end of the chain."""

    name = "collect"

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def process(self, event: RawEvent) -> RawEvent:
        self.seen.append(event.event_uid)
        return event


async def _run(tmp_path: Path, *, workers: int) -> tuple[float, list[str]]:
    """Submit `_N_EVENTS` events through a `workers`-worker pipeline; time until fully processed."""
    collector = _CollectStage()
    pipeline = Pipeline(_settings(tmp_path, workers), [_SimulatedIoStage(), collector])
    pipeline.start()
    try:
        start = time.perf_counter()
        for event in (_raw(i) for i in range(_N_EVENTS)):
            await pipeline.submit(event)
        await pipeline.queue.join()  # blocks until every event has fully run the chain
        elapsed = time.perf_counter() - start
    finally:
        await pipeline.stop()
    return elapsed, collector.seen


async def test_four_workers_are_meaningfully_faster_and_lose_or_duplicate_nothing(
    tmp_path: Path,
) -> None:
    time_1, seen_1 = await _run(tmp_path / "w1", workers=1)
    time_4, seen_4 = await _run(tmp_path / "w4", workers=4)

    # correctness first, for both runs: distinct event_uid count == input count.
    for seen in (seen_1, seen_4):
        assert len(seen) == _N_EVENTS, f"expected {_N_EVENTS} events, got {len(seen)}"
        assert len(set(seen)) == _N_EVENTS, "an event_uid was lost or duplicated"

    # throughput: 4 workers must meaningfully beat 1 on the identical workload.
    speedup = time_1 / time_4
    assert speedup >= _MIN_SPEEDUP, (
        f"4 workers were not meaningfully faster than 1 "
        f"(1w={time_1:.3f}s, 4w={time_4:.3f}s, speedup={speedup:.2f}x, "
        f"wanted >= {_MIN_SPEEDUP:.1f}x)"
    )
