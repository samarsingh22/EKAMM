"""Pipeline orchestrator: wires ingest -> stages -> sinks together.

A :class:`Pipeline` runs a pool of worker tasks. Each worker pulls a
:class:`~ulpf.core.models.RawEvent` off a buffer and passes it through an
ordered list of :class:`Stage`\\ s, timing each stage into
``ulpf_stage_latency_seconds``.

Failure handling per the project rules:

* A stage returning ``None`` deliberately drops the event — processing stops, no
  error.
* Any exception raised by a stage sends the *original* event to the dead-letter
  queue tagged with that stage's name and the exception type, and the worker
  moves on to the next event. One bad event never kills a worker.

HORIZONTAL SCALING
-------------------
:meth:`Pipeline.start` launches ``settings.pipeline.worker_count`` (or
``len(worker_buffers)`` — see below) independent worker tasks. Two things make
that safe to scale:

* **Each worker gets its own parser/mapper state.** Pass ``stage_factory``
  (called once per worker at :meth:`start`) instead of a fixed ``stages``
  list, and every worker builds its *own* :class:`~ulpf.parse.coordinator.ParseCoordinator`
  / :class:`ParseStage` / :class:`~ulpf.normalize.stage.NormalizeStage` /
  :class:`~ulpf.normalize.mapper.Mapper` — nothing about parsing or mapping
  one event can leak into or race with another worker's. A factory closure is
  free to still *share* the handful of stages that must stay single instances
  for correctness — :class:`RawStoreStage` (append-only bronze writer),
  :class:`~ulpf.integrity.stage.IntegrityStage` (one ordered Merkle batch
  across *all* events, not per worker) and
  :class:`~ulpf.sinks.manager.SinkManager` (its own internal batching) — by
  capturing the same instances in every call; see
  :class:`~ulpf.core.runtime.Runtime` for exactly that split. The plain
  ``stages`` list constructor still works unchanged (every worker shares it),
  which is what most tests use.
* **Two buffer topologies**, chosen by what is passed in:

  * *Shared* (the default: neither ``buffer`` nor ``worker_buffers`` given) —
    one internal :class:`~ulpf.ingest.queue.BoundedEventQueue`; every worker
    competes for the next item off the same queue (today's behavior,
    unchanged). Shutdown drains the queue (``join()``) then wakes each worker
    with a sentinel — no item is ever lost or abandoned mid-shutdown.
  * *Partition-aware* (``worker_buffers`` given, one entry per worker) — each
    worker consumes **only its own buffer**. This is the shape
    ``settings.buffer.backend == "kafka"`` uses: :class:`~ulpf.core.runtime.Runtime`
    builds ``worker_count`` separate
    :class:`~ulpf.ingest.buffer.kafka_buffer.KafkaConsumerBuffer`\\ s, all in
    the same consumer group — Kafka's own group-rebalancing protocol then
    assigns each one a disjoint subset of the topic's partitions, so "worker
    N" and "the partitions worker N owns" are the same thing, with no custom
    partition-assignment logic needed here. Shutdown here cancels each worker
    task directly instead of draining: an event a worker was mid-processing
    when cancelled is simply never acknowledged, and a Kafka buffer's
    at-least-once redelivery (see :mod:`ulpf.ingest.buffer.kafka_buffer`)
    picks it up again after a restart — the same trade-off that module's
    docstring already documents, not a new one.

Shutdown, either way, flushes every distinct stage object that exposes a
``flush`` method (e.g. :class:`RawStoreStage`) exactly once, even though a
factory-built shared singleton (like :class:`~ulpf.sinks.manager.SinkManager`)
appears in every worker's own stage list.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import time
from collections import deque
from collections.abc import Callable, Sequence
from typing import Final, Protocol, TypeAlias, runtime_checkable

from ulpf.config.settings import Settings
from ulpf.core.errors import ParseError, PipelineStoppedError
from ulpf.core.metrics import END_TO_END_LATENCY, EVENTS_PARSED, PARSE_SUCCESS_RATE, timed
from ulpf.core.models import NormalizedEvent, ParsedEvent, RawEvent
from ulpf.ingest.queue import BoundedEventQueue
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.raw_store import RawStore

_log = logging.getLogger(__name__)

Event: TypeAlias = RawEvent | ParsedEvent | NormalizedEvent

_SHUTDOWN: Final = object()  # sentinel put on the shared queue to wake a worker to exit


@runtime_checkable
class Stage(Protocol):
    """A pipeline stage: transform an event, or return ``None`` to drop it."""

    name: str

    async def process(self, event: Event) -> Event | None:
        """Process one event; return the (possibly new) event, or ``None`` to stop it."""
        ...


class RawStoreStage:
    """Stage 1: append the raw event to the bronze/evidence store."""

    name = "raw_store"

    def __init__(self, raw_store: RawStore) -> None:
        """Wrap an already-configured :class:`RawStore`."""
        self._store = raw_store

    async def process(self, event: Event) -> Event:
        """Persist ``event`` verbatim and pass it through unchanged."""
        assert isinstance(event, RawEvent)
        self._store.write(event)
        return event

    def flush(self) -> None:
        """Flush buffered bronze writes to disk (called on shutdown)."""
        self._store.flush()


class NoOpStage:
    """A stage that returns the event untouched. Placeholder for real stages."""

    name = "noop"

    async def process(self, event: Event) -> Event:
        """Return ``event`` unchanged."""
        return event


class ParseStage:
    """Stage 2: sniff format, strip the syslog envelope, extract a *best-effort* field hint.

    Wraps :class:`~ulpf.parse.coordinator.ParseCoordinator`. This pass is
    advisory, not authoritative, and by design never attempts a parse that
    needs configuration only a source definition owns: the sniffer has no
    signature for ``grok``/``dissect`` at all, and ``csv``/``tsv`` are
    deliberately never engine-dispatched here either (both engines
    fundamentally require a ``columns``/``column_map``/``#fields`` a matched
    definition supplies — see ``_NO_ENGINE_FORMATS`` in
    :mod:`ulpf.parse.coordinator`). Such a line produces empty fields here,
    never a raised :class:`~ulpf.core.errors.ParseError` — that is expected,
    not a dead event, and it means the field-count metrics below only ever see
    a genuine engine failure (malformed json/kv/cef/leef), not "this source's
    engine needed config the sniff pass doesn't have".
    :class:`~ulpf.normalize.stage.NormalizeStage` does the real, authoritative,
    single parse once it has matched a source definition
    (:func:`~ulpf.parse.coordinator.parse_for_definition`), and is the one
    place that dead-letters a source whose own engine still cannot read it.

    Each attempt updates ``ulpf_parse_success_rate`` (a sniff-based failure
    still counts as a miss, for that KPI); each success bumps
    ``ulpf_events_parsed_total``.
    """

    name = "parse"

    def __init__(
        self, settings: Settings, coordinator: ParseCoordinator, *, window: int = 1000
    ) -> None:
        """Wire the coordinator; ``settings`` kept for signature stability with other stages."""
        self._coordinator = coordinator
        self._outcomes: deque[int] = deque(maxlen=window)

    async def process(self, event: Event) -> Event | None:
        """Return a :class:`ParsedEvent`; never drops the event or dead-letters it."""
        assert isinstance(event, RawEvent)
        try:
            parsed = self._coordinator.parse(event)
        except ParseError as exc:
            self._observe(success=False)
            _log.info(
                "sniff-based parse could not classify this line; the matched "
                "source definition's own engine will re-parse it in normalize",
                extra={"event_uid": event.event_uid, "detail": exc.detail},
            )
            return _unclassified(event)
        self._observe(success=True)
        EVENTS_PARSED.labels(source_type=parsed.source_type or "unknown").inc()
        return parsed

    def _observe(self, *, success: bool) -> None:
        """Record one parse outcome and refresh ``ulpf_parse_success_rate``."""
        self._outcomes.append(1 if success else 0)
        PARSE_SUCCESS_RATE.set(sum(self._outcomes) / len(self._outcomes))


def _unclassified(event: RawEvent) -> ParsedEvent:
    """A :class:`ParsedEvent` stand-in for 'the sniff-based pass could not read this'.

    Same shape as a line that sniffed as ``unknown``: no fields, flagged for
    Drain3 template mining. A matching source definition still gets its own
    authoritative re-parse in :class:`~ulpf.normalize.stage.NormalizeStage`.
    """
    return ParsedEvent(
        **event.model_dump(),
        format="unknown",
        source_type=None,
        fields={},
        envelope={},
        needs_template_mining=True,
    )


@runtime_checkable
class _Producer(Protocol):
    """What :meth:`Pipeline.submit` needs from a partition-aware mode's producer handle.

    Defined locally (rather than importing :class:`~ulpf.ingest.buffer.base.BufferBackend`)
    so this module — squarely in the ``core`` layer — stays decoupled from the
    ``ingest`` layer's buffer implementations; it only needs to know the shape
    it calls. :class:`~ulpf.ingest.buffer.in_process.InProcessBuffer` and
    :class:`~ulpf.ingest.buffer.kafka_buffer.KafkaBuffer` both satisfy this
    structurally, with no import needed on either side.
    """

    async def put(self, event: RawEvent) -> None: ...


@runtime_checkable
class _Consumer(Protocol):
    """What one worker needs from its own buffer in partition-aware mode."""

    async def get(self) -> RawEvent: ...
    async def ack(self, event: RawEvent) -> None: ...


class Pipeline:
    """Runs events from one or more buffers through worker tasks running an ordered stage list.

    See the module docstring's HORIZONTAL SCALING section for what
    ``stage_factory`` / ``worker_buffers`` change and why.
    """

    def __init__(
        self,
        settings: Settings,
        stages: list[Stage] | None = None,
        *,
        stage_factory: Callable[[], list[Stage]] | None = None,
        buffer: _Producer | None = None,
        worker_buffers: Sequence[_Consumer] | None = None,
    ) -> None:
        """Build the DLQ from ``settings``; take a stage source and a buffer topology.

        Args:
            settings: Supplies ``pipeline.worker_count`` (shared-buffer mode
                only — partition-aware mode's worker count is
                ``len(worker_buffers)``) and the DLQ location.
            stages: A fixed stage list every worker shares (today's behavior;
                most callers and tests use this). Mutually exclusive with
                ``stage_factory``.
            stage_factory: Called once per worker at :meth:`start` to build
                that worker's own stage instances. Mutually exclusive with
                ``stages``.
            buffer: The producer-side handle :meth:`submit` publishes through,
                in partition-aware mode. Required when ``worker_buffers`` is
                given; ignored (an internal :class:`BoundedEventQueue` is used
                instead) otherwise.
            worker_buffers: One consumer-side buffer per worker — partition-aware
                mode. Omit for the default shared-queue mode.

        Raises:
            ValueError: Neither/both of ``stages``/``stage_factory`` given, or
                ``worker_buffers`` given without ``buffer``.
        """
        if (stages is None) == (stage_factory is None):
            raise ValueError("Pipeline needs exactly one of stages= or stage_factory=")
        if worker_buffers is not None and buffer is None:
            raise ValueError("worker_buffers= requires buffer= (submit()'s producer-side handle)")

        self._settings = settings
        self._stages = list(stages) if stages is not None else None
        self._stage_factory = stage_factory
        # Always built (cheap): the shared-mode buffer, and what submit() uses
        # whenever worker_buffers is not in play.
        self.queue = BoundedEventQueue(settings)
        self._producer = buffer
        self._worker_buffers: list[_Consumer] | None = (
            list(worker_buffers) if worker_buffers is not None else None
        )
        self.dlq = DeadLetterQueue(settings)
        self._workers: list[asyncio.Task[None]] = []
        self._worker_stages: list[list[Stage]] = []
        self._stopped = False

    def start(self) -> None:
        """Launch a worker per buffer (partition-aware), else ``pipeline.worker_count`` (shared)."""
        if self._workers:
            raise RuntimeError("pipeline already started")
        self._stopped = False
        self._worker_stages = []
        if self._worker_buffers is not None:
            for consumer_buffer in self._worker_buffers:
                stages = self._build_stages()
                self._worker_stages.append(stages)
                self._workers.append(
                    asyncio.create_task(self._worker_owned(consumer_buffer, stages))
                )
        else:
            for _ in range(self._settings.pipeline.worker_count):
                stages = self._build_stages()
                self._worker_stages.append(stages)
                self._workers.append(asyncio.create_task(self._worker_shared(stages)))

    def _build_stages(self) -> list[Stage]:
        """This worker's stage list — the shared list, or a fresh one from the factory."""
        return self._stages if self._stages is not None else self._stage_factory()  # type: ignore[misc]

    async def submit(self, event: Event) -> None:
        """Hand an event to the buffer, applying backpressure when full."""
        if self._stopped:
            raise PipelineStoppedError("pipeline is shutting down")
        if self._worker_buffers is not None:
            assert self._producer is not None  # guaranteed by __init__
            await self._producer.put(event)  # type: ignore[arg-type]
        else:
            await self.queue.put_with_backpressure(event)

    async def stop(self) -> None:
        """Stop every worker (draining first in shared mode), then flush every stage's sink."""
        if self._stopped:
            return
        self._stopped = True
        if self._worker_buffers is not None:
            for task in self._workers:
                task.cancel()
            await asyncio.gather(*self._workers, return_exceptions=True)
        else:
            await self.queue.join()
            for _ in self._workers:
                await self.queue.put_with_backpressure(_SHUTDOWN)
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
        await self._flush_stages()

    # -- internals -------------------------------------------------------

    async def _worker_shared(self, stages: list[Stage]) -> None:
        """Shared-queue mode: consume ``self.queue`` until a shutdown sentinel is received."""
        while True:
            item = await self.queue.get()
            try:
                if item is _SHUTDOWN:
                    return
                await self._run_stages(item, stages)
            finally:
                self.queue.task_done()

    async def _worker_owned(self, buffer: _Consumer, stages: list[Stage]) -> None:
        """Partition-aware mode: consume this worker's own buffer until cancelled.

        No drain-then-sentinel here — :meth:`stop` cancels these tasks
        directly. An event mid-flight when cancelled is simply never
        :meth:`~_Consumer.ack`-ed; see the module docstring for why that is
        the right trade-off for a Kafka-backed buffer.
        """
        with contextlib.suppress(asyncio.CancelledError):
            while True:
                event = await buffer.get()
                try:
                    await self._run_stages(event, stages)
                finally:
                    await buffer.ack(event)

    async def _run_stages(self, event: Event, stages: list[Stage]) -> None:
        """Run one event through ``stages`` in order; DLQ on exception, stop on ``None``."""
        current: Event = event
        for stage in stages:
            try:
                with timed(stage.name):
                    result = await stage.process(current)
            except Exception as exc:  # noqa: BLE001 - isolate stage failures
                self._to_dlq(event, stage.name, exc)
                return
            if result is None:
                return
            current = result
        # Reached the end of the chain (the sink) without being dropped or
        # dead-lettered - this is "ingest to sink" for a genuinely delivered
        # event, exactly what ulpf_end_to_end_latency_seconds documents.
        END_TO_END_LATENCY.observe((time.time_ns() - event.ingest_time_ns) / 1_000_000_000)

    def _to_dlq(self, event: Event, stage_name: str, exc: BaseException) -> None:
        """Route a failed event to the dead-letter queue with context."""
        if not isinstance(event, RawEvent):
            _log.error("cannot dead-letter a non-raw event", extra={"stage": stage_name})
            return
        self.dlq.write(
            event, reason=type(exc).__name__, stage=stage_name, detail={"error": str(exc)}
        )
        _log.warning(
            "stage failed; event dead-lettered",
            extra={"stage": stage_name, "event_uid": event.event_uid, "error": str(exc)},
        )

    async def _flush_stages(self) -> None:
        """Call ``flush()`` once per distinct stage object, across every worker's stage list.

        A factory-built shared singleton (e.g. a :class:`SinkManager` every
        worker's own list happens to include) is flushed exactly once, by
        object identity — not once per worker.
        """
        stage_lists = self._worker_stages or ([self._stages] if self._stages is not None else [])
        seen: set[int] = set()
        for stages in stage_lists:
            for stage in stages:
                if id(stage) in seen:
                    continue
                seen.add(id(stage))
                flush = getattr(stage, "flush", None)
                if not callable(flush):
                    continue
                outcome = flush()
                if inspect.isawaitable(outcome):
                    await outcome
