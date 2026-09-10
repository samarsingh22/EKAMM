"""A durable, replayable :class:`~ulpf.ingest.buffer.base.BufferBackend`, backed by Kafka.

Requires the optional ``ulpf[kafka]`` extra (``aiokafka``). Never imported
unless ``settings.buffer.backend == "kafka"`` — the in-process queue (see
:mod:`ulpf.ingest.buffer.in_process`) is the default, and an air-gapped box
that never opts into Kafka never needs ``aiokafka`` installed at all.

KAFKA IN FOUR TERMS
--------------------
* **Topic** — a named, append-only log of messages. ULPF publishes every raw
  event to one topic, ``settings.buffer.kafka_topic`` (default ``ulpf.raw``).
* **Partition** — a topic is split into ``N`` independent, ordered logs (the
  ``kafka_partitions`` setting) so ``N`` consumers can read it in parallel.
  Kafka only guarantees ordering *within* a partition, never across the whole
  topic — which is why :class:`KafkaProducerBuffer` keys every message by
  ``source_id``: Kafka's default partitioner hashes the key, so every event
  from one device always lands in the same partition and is therefore
  consumed in the order it was produced, while different devices' events can
  land (and be processed) in parallel across partitions.
* **Offset** — a message's position within its partition, a plain increasing
  integer. A consumer's "progress" through a partition *is* an offset; two
  consumers can read the same partition independently at their own offsets.
* **Consumer group** — a named set of consumer processes
  (``kafka_consumer_group``) that *share* a topic's partitions: Kafka assigns
  each partition to exactly one member of the group at a time and tracks, per
  group, the last **committed** offset for each partition. That is how
  several ULPF pipeline processes can point at the same topic and each raw
  event still gets processed exactly once by the group as a whole — and how a
  crashed/restarted consumer resumes from its last commit instead of from the
  beginning (or losing its place).

WHY RETENTION MATTERS
----------------------
A Kafka topic keeps every message for its configured retention window (a
broker-side setting, not one ULPF sets here) instead of deleting a message the
instant it is consumed — consuming only advances a *group's* committed offset,
it does not remove anything from the log. That single property is the whole
reason to run Kafka instead of the in-process queue: **when a parser bug is
found and fixed, every raw event still inside the retention window can be
replayed** — reset the consumer group's offset (or start a fresh group) and
:class:`KafkaConsumerBuffer` reads the same bytes again, through the corrected
parser, exactly like :mod:`ulpf.cli.reprocess` does for bronze evidence, but
without needing the bronze store for that trip. The in-process queue has no
analogue: once a worker calls ``task_done()`` the event is gone.

DELIVERY AND COMMIT SEMANTICS
------------------------------
:class:`KafkaProducerBuffer` awaits the broker's acknowledgement
(``send_and_wait``) before returning, matching :class:`BoundedEventQueue`'s
"never silently drop" contract. :class:`KafkaConsumerBuffer` disables
Kafka's auto-commit and commits an offset only from :meth:`KafkaConsumerBuffer.ack`
— i.e. after whatever called :meth:`~KafkaConsumerBuffer.get` says it is done
with that event, the same *acknowledge, then advance* shape
:class:`~ulpf.ingest.queue.BoundedEventQueue` uses. This is **at-least-once**
delivery, not exactly-once: a crash between processing an event and its
commit re-delivers it on restart. ULPF accepts that trade — the bronze store
and signed integrity ledger are the actual system of record, so a
Kafka-replayed duplicate raw event is a re-run of an idempotent pipeline
stage, not lost or corrupted evidence, and retention means the same
duplicate-safety even covers a deliberate replay.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from ulpf.config.settings import Settings
from ulpf.core.metrics import BUFFER_CONSUMED, BUFFER_PUBLISHED
from ulpf.core.models import RawEvent

try:
    from aiokafka import (
        AIOKafkaConsumer,
        AIOKafkaProducer,
        ConsumerRecord,
        OffsetAndMetadata,
        TopicPartition,
    )
    from aiokafka.admin import AIOKafkaAdminClient, NewTopic
    from aiokafka.errors import KafkaError, TopicAlreadyExistsError
except ImportError as exc:  # pragma: no cover - exercised only without the optional extra
    raise ImportError(
        "ulpf.ingest.buffer.kafka_buffer requires the optional 'kafka' extra: "
        "pip install 'ulpf[kafka]' (adds aiokafka)"
    ) from exc

_log = logging.getLogger(__name__)

BACKEND_NAME = "kafka"


# ======================================================================
# wire format
# ======================================================================


def serialize_raw_event(event: RawEvent) -> bytes:
    """``RawEvent`` -> Kafka message value: JSON, with ``raw`` base64-encoded (lossless)."""
    return event.model_dump_json().encode("utf-8")


def deserialize_raw_event(payload: bytes) -> RawEvent:
    """The inverse of :func:`serialize_raw_event`."""
    return RawEvent.model_validate_json(payload)


def _key_for(event: RawEvent) -> bytes:
    """The message key: ``source_id``, so one device's events share a partition and stay ordered."""
    return event.source_id.encode("utf-8")


# ======================================================================
# producer
# ======================================================================


class KafkaProducerBuffer:
    """Publishes :class:`RawEvent`\\ s to ``settings.buffer.kafka_topic``, keyed by ``source_id``.

    Not itself a full :class:`~ulpf.ingest.buffer.base.BufferBackend` (it only
    produces) — see :class:`KafkaBuffer`, which pairs this with
    :class:`KafkaConsumerBuffer` to satisfy that protocol.
    """

    def __init__(self, settings: Settings, *, client: AIOKafkaProducer | None = None) -> None:
        """Configure from ``settings.buffer``; ``client`` is injectable for tests."""
        cfg = settings.buffer
        self._bootstrap_servers = cfg.kafka_bootstrap_servers
        self._topic = cfg.kafka_topic
        self._partitions = cfg.kafka_partitions
        self._replication_factor = cfg.kafka_replication_factor
        self._batch_size = cfg.kafka_batch_size
        self._linger_ms = cfg.kafka_linger_ms
        self._acks = cfg.kafka_acks
        self._client = client
        self._owns_client = client is None  # only ensure the topic for a real, owned client

    @property
    def topic(self) -> str:
        """The topic this producer publishes to."""
        return self._topic

    async def start(self) -> None:
        """Ensure the topic exists (best-effort), then start the underlying Kafka client."""
        if self._client is None:
            self._client = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                acks=self._acks,
                linger_ms=self._linger_ms,
                max_batch_size=self._batch_size,
            )
        if self._owns_client:
            await self._ensure_topic()
        await self._client.start()

    async def stop(self) -> None:
        """Flush and close the underlying Kafka client."""
        if self._client is not None:
            await self._client.stop()

    async def publish(self, event: RawEvent) -> None:
        """Publish ``event``, keyed by ``source_id``, and wait for the broker's acknowledgement.

        Awaiting the send (rather than fire-and-forget) means a caller only
        ever sees this return after the event is durably on the broker — the
        same "never silently drop" guarantee
        :meth:`~ulpf.ingest.queue.BoundedEventQueue.put_with_backpressure` gives
        the in-process buffer.
        """
        if self._client is None:
            raise RuntimeError("KafkaProducerBuffer.start() has not been called")
        await self._client.send_and_wait(
            self._topic, value=serialize_raw_event(event), key=_key_for(event)
        )
        BUFFER_PUBLISHED.labels(backend=BACKEND_NAME).inc()

    async def put(self, event: RawEvent) -> None:
        """Alias for :meth:`publish`.

        Lets a bare :class:`KafkaProducerBuffer` serve directly as
        :class:`~ulpf.core.pipeline.Pipeline`'s producer-side buffer in
        partition-aware mode, without wrapping it in the full
        :class:`KafkaBuffer` composite (which would also drag in an unused
        consumer half).
        """
        await self.publish(event)

    async def _ensure_topic(self) -> None:
        """Best-effort: create the topic with the configured partition count if it is missing.

        Never fatal — a deployment may already provision the topic (Terraform,
        an ops runbook, broker auto-create) with permissions this producer does
        not have; that is a normal, supported setup, not an error.
        """
        admin = AIOKafkaAdminClient(bootstrap_servers=self._bootstrap_servers)
        await admin.start()
        try:
            await admin.create_topics(
                [
                    NewTopic(
                        name=self._topic,
                        num_partitions=self._partitions,
                        replication_factor=self._replication_factor,
                    )
                ]
            )
            _log.info("kafka: created topic %r with %d partitions", self._topic, self._partitions)
        except TopicAlreadyExistsError:
            pass
        except KafkaError as exc:
            _log.warning(
                "kafka: could not ensure topic %r exists with %d partitions (%s); continuing - "
                "it may already be provisioned",
                self._topic,
                self._partitions,
                exc,
            )
        finally:
            await admin.close()


# ======================================================================
# consumer
# ======================================================================


class KafkaConsumerBuffer:
    """Consumes ``settings.buffer.kafka_topic`` as part of ``settings.buffer.kafka_consumer_group``.

    Not itself a full :class:`~ulpf.ingest.buffer.base.BufferBackend` (it only
    consumes) — see :class:`KafkaBuffer`.
    """

    def __init__(self, settings: Settings, *, client: AIOKafkaConsumer | None = None) -> None:
        """Configure from ``settings.buffer``; ``client`` is injectable for tests."""
        cfg = settings.buffer
        self._bootstrap_servers = cfg.kafka_bootstrap_servers
        self._topic = cfg.kafka_topic
        self._group_id = cfg.kafka_consumer_group
        self._max_poll_records = cfg.kafka_max_poll_records
        self._auto_offset_reset = cfg.kafka_auto_offset_reset
        self._client = client
        # event_uid -> the ConsumerRecord it came from, so ack() knows which
        # (topic, partition, offset) to commit without changing its signature.
        self._pending: dict[str, ConsumerRecord] = {}

    async def start(self) -> None:
        """Join the consumer group and start the underlying Kafka client."""
        if self._client is None:
            self._client = AIOKafkaConsumer(
                self._topic,
                bootstrap_servers=self._bootstrap_servers,
                group_id=self._group_id,
                enable_auto_commit=False,  # commit only from ack(), never on a timer
                auto_offset_reset=self._auto_offset_reset,
                max_poll_records=self._max_poll_records,
            )
        await self._client.start()

    async def stop(self) -> None:
        """Leave the consumer group and close the underlying Kafka client."""
        if self._client is not None:
            await self._client.stop()
        self._pending.clear()

    async def get(self) -> RawEvent:
        """Return the next event, waiting if none is available yet. Call :meth:`ack` once done."""
        if self._client is None:
            raise RuntimeError("KafkaConsumerBuffer.start() has not been called")
        record = await self._client.getone()
        event = deserialize_raw_event(record.value)
        self._pending[event.event_uid] = record
        BUFFER_CONSUMED.labels(backend=BACKEND_NAME).inc()
        return event

    async def ack(self, event: RawEvent) -> None:
        """Commit ``event``'s offset (its partition's progress advances past it).

        A no-op if ``event`` was not one this instance's :meth:`get` returned
        (already acked, or foreign) — acking is idempotent, never an error.
        """
        record = self._pending.pop(event.event_uid, None)
        if record is None or self._client is None:
            return
        tp = TopicPartition(record.topic, record.partition)
        await self._client.commit({tp: OffsetAndMetadata(record.offset + 1, "")})

    def depth(self) -> int:
        """Events returned by :meth:`get` but not yet :meth:`ack`-ed (in-flight, not broker lag)."""
        return len(self._pending)

    async def lag(self) -> int | None:
        """Best-effort total consumer lag across this instance's assigned partitions.

        Unlike :meth:`depth`, this is a real broker round-trip (hence async and
        its own method, rather than folded into the synchronous
        :meth:`~ulpf.ingest.buffer.base.BufferBackend.depth`). Returns
        ``None`` if it cannot be computed (not started, no assignment yet,
        broker error).
        """
        if self._client is None:
            return None
        assignment = self._client.assignment()
        if not assignment:
            return None
        try:
            end_offsets = await self._client.end_offsets(list(assignment))
            total = 0
            for tp in assignment:
                position = await self._client.position(tp)
                total += max(0, end_offsets[tp] - position)
            return total
        except KafkaError:
            return None

    async def consume_into(self, handler: Callable[[RawEvent], Awaitable[None]]) -> None:
        """Feed the pipeline: ``get()`` -> ``handler(event)`` -> ``ack()``, until cancelled.

        The offset commits once ``handler`` *returns*, not once the event has
        finished every downstream pipeline stage — with
        :meth:`~ulpf.core.pipeline.Pipeline.submit` as ``handler`` that is
        "handed to the in-process queue", a fast, cheap point, not "fully
        processed". That is a deliberate, narrow at-least-once window: on a
        crash between hand-off and full processing, replaying that one poll's
        worth of events from Kafka is strictly less risky than either losing
        them or blocking every producer on full end-to-end completion, and it
        is exactly what topic retention exists to make cheap.
        """
        while True:
            event = await self.get()
            await handler(event)
            await self.ack(event)


# ======================================================================
# BufferBackend
# ======================================================================


class KafkaBuffer:
    """A :class:`~ulpf.ingest.buffer.base.BufferBackend` composed from producer + consumer."""

    def __init__(
        self,
        settings: Settings,
        *,
        producer: KafkaProducerBuffer | None = None,
        consumer: KafkaConsumerBuffer | None = None,
    ) -> None:
        """Build (or accept already-built) producer/consumer halves."""
        self._producer = producer if producer is not None else KafkaProducerBuffer(settings)
        self._consumer = consumer if consumer is not None else KafkaConsumerBuffer(settings)

    async def start(self) -> None:
        """Start both the producer and the consumer."""
        await self._producer.start()
        await self._consumer.start()

    async def stop(self) -> None:
        """Stop the consumer, then the producer."""
        await self._consumer.stop()
        await self._producer.stop()

    async def put(self, event: RawEvent) -> None:
        """Publish ``event`` (see :meth:`KafkaProducerBuffer.publish`)."""
        await self._producer.publish(event)

    async def get(self) -> RawEvent:
        """Consume the next event (see :meth:`KafkaConsumerBuffer.get`)."""
        return await self._consumer.get()

    async def ack(self, event: RawEvent) -> None:
        """Commit ``event``'s offset (see :meth:`KafkaConsumerBuffer.ack`)."""
        await self._consumer.ack(event)

    def depth(self) -> int:
        """In-flight (returned, not yet acked) event count on the consumer side."""
        return self._consumer.depth()
