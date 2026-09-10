"""The default :class:`~ulpf.ingest.buffer.base.BufferBackend`: an in-process bounded queue.

Adapts :class:`~ulpf.ingest.queue.BoundedEventQueue` (see its own module
docstring for the backpressure contract — full, block-or-DLQ, never a silent
drop) to the shared :class:`~ulpf.ingest.buffer.base.BufferBackend` interface,
so code written against that protocol does not need to special-case "no
Kafka". No network call, no external service, no extra dependency — this is
what ``settings.buffer.backend = "in_process"`` (the default) runs.
"""

from __future__ import annotations

from ulpf.config.settings import Settings
from ulpf.core.metrics import BUFFER_CONSUMED, BUFFER_PUBLISHED
from ulpf.core.models import RawEvent
from ulpf.ingest.queue import BoundedEventQueue

BACKEND_NAME = "in_process"


class InProcessBuffer:
    """Wraps a :class:`BoundedEventQueue` behind the :class:`BufferBackend` protocol."""

    def __init__(self, settings: Settings, *, queue: BoundedEventQueue | None = None) -> None:
        """Build (or accept an already-built) queue. ``settings`` sizes it when built here."""
        self._queue = queue if queue is not None else BoundedEventQueue(settings)

    @property
    def queue(self) -> BoundedEventQueue:
        """The wrapped queue — :class:`~ulpf.core.pipeline.Pipeline` still reaches for it."""
        return self._queue

    async def start(self) -> None:
        """No-op: an in-process queue needs no connection setup."""
        return None

    async def stop(self) -> None:
        """No-op: nothing to flush beyond what the pipeline's own shutdown already drains."""
        return None

    async def put(self, event: RawEvent) -> None:
        """Enqueue ``event``, waiting for room rather than dropping it (never silently)."""
        await self._queue.put_with_backpressure(event)
        BUFFER_PUBLISHED.labels(backend=BACKEND_NAME).inc()

    async def get(self) -> RawEvent:
        """Dequeue the next event, waiting if the queue is empty."""
        event = await self._queue.get()
        BUFFER_CONSUMED.labels(backend=BACKEND_NAME).inc()
        return event

    async def ack(self, event: RawEvent) -> None:
        """Mark the queue slot done — there is no offset to commit for an in-process queue."""
        del event  # unused: BoundedEventQueue.task_done() acks whatever was last get()-ed
        self._queue.task_done()

    def depth(self) -> int:
        """Events currently waiting in the queue."""
        return self._queue.depth()
