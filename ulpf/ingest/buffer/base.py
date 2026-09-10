"""``BufferBackend`` — the seam between listeners and the processing pipeline.

Every listener (syslog UDP/TCP/TLS, HTTP, file tail) produces a
:class:`~ulpf.core.models.RawEvent` and hands it off somewhere before a
pipeline worker picks it up and runs it through parse/normalize/enrich/sink.
That hand-off is the *buffer*. ULPF supports two interchangeable
implementations behind this one :class:`Protocol`, selected by
``settings.buffer.backend`` (default ``"in_process"``):

* :class:`~ulpf.ingest.buffer.in_process.InProcessBuffer` — wraps
  :class:`~ulpf.ingest.queue.BoundedEventQueue`, a bounded ``asyncio.Queue``
  living inside this one process. No external service, no configuration,
  zero extra dependencies — the right default for a single air-gapped box.
* :class:`~ulpf.ingest.buffer.kafka_buffer.KafkaBuffer` — durably persists
  every raw event to a Kafka topic before the pipeline consumes it. See that
  module's docstring for the concepts (topics, partitions, offsets, consumer
  groups) and why retention matters.

Both sides of a :class:`BufferBackend` — producer (``put``) and consumer
(``get``/``ack``) — are folded into one interface here because the in-process
queue naturally serves both roles from one object. Kafka does not: publishing
and consuming are genuinely different clients with different lifecycles, so
:mod:`~ulpf.ingest.buffer.kafka_buffer` implements them as two separate
classes (``KafkaProducerBuffer``, ``KafkaConsumerBuffer``) and composes them
behind :class:`~ulpf.ingest.buffer.kafka_buffer.KafkaBuffer` to still satisfy
this one protocol.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ulpf.core.models import RawEvent


@runtime_checkable
class BufferBackend(Protocol):
    """A durable-or-not hand-off between "received" and "being processed"."""

    async def start(self) -> None:
        """Open any underlying connection/resources. Idempotent."""
        ...

    async def stop(self) -> None:
        """Close cleanly, flushing anything buffered. Idempotent."""
        ...

    async def put(self, event: RawEvent) -> None:
        """Hand ``event`` to the buffer, applying backpressure rather than dropping it."""
        ...

    async def get(self) -> RawEvent:
        """Return the next event, waiting if none is available yet."""
        ...

    async def ack(self, event: RawEvent) -> None:
        """Acknowledge that ``event`` (previously returned by :meth:`get`) is fully handled.

        For :class:`~ulpf.ingest.buffer.in_process.InProcessBuffer` this marks
        an ``asyncio.Queue`` slot done; for Kafka it commits that message's
        offset. Always call it exactly once per event :meth:`get` returned.
        """
        ...

    def depth(self) -> int:
        """A best-effort count of events waiting to be consumed."""
        ...
