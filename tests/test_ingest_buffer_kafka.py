"""Tests for :mod:`ulpf.ingest.buffer.kafka_buffer`.

Two tiers:

* **Unit tests** against fake producer/consumer clients — no network, no
  broker. They run whenever the optional ``aiokafka`` package is importable
  (it is a ``dev`` extra; see ``pyproject.toml``); the whole module is
  skipped cleanly if it is not (``pytest.importorskip`` below).
* **Integration tests** against a real broker, skipped cleanly — same
  pattern as ``test_clickhouse_sink.py``'s ClickHouse tests — unless
  ``KAFKA_BOOTSTRAP_SERVERS`` is set and a broker actually answers there.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from ulpf.config.settings import BufferSettings, Settings
from ulpf.core.metrics import snapshot
from ulpf.core.models import RawEvent
from ulpf.ingest.buffer.base import BufferBackend
from ulpf.integrity.hashing import make_raw_event

# Importing our own module (not `aiokafka` directly) means this single check
# also exercises the "optional extra missing" guard's happy path, and gives
# every test below the already-guarded aiokafka names via `kafka_buffer.*`
# without a second top-level `import aiokafka` (which ruff would flag as
# E402, coming after this statement).
kafka_buffer = pytest.importorskip("ulpf.ingest.buffer.kafka_buffer")


def _settings(**overrides: Any) -> Settings:
    return Settings(buffer=BufferSettings(backend="kafka", **overrides))


def _event(source_id: str = "fw-1") -> RawEvent:
    return make_raw_event(b"<134>\xff\x00binary raw bytes", source_id=source_id, transport="udp")


# ---------------------------------------------------------------------------
# wire format
# ---------------------------------------------------------------------------


def test_serialize_deserialize_round_trips_including_binary_raw() -> None:
    event = _event()
    payload = kafka_buffer.serialize_raw_event(event)
    assert isinstance(payload, bytes)
    assert kafka_buffer.deserialize_raw_event(payload) == event


# ---------------------------------------------------------------------------
# fakes (no network)
# ---------------------------------------------------------------------------


@dataclass
class _FakeProducerClient:
    started: bool = False
    stopped: bool = False
    sent: list[dict[str, Any]] = field(default_factory=list)

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def send_and_wait(self, topic: str, *, value: bytes, key: bytes) -> None:
        self.sent.append({"topic": topic, "value": value, "key": key})


@dataclass
class _FakeRecord:
    topic: str
    partition: int
    offset: int
    value: bytes


@dataclass
class _FakeConsumerClient:
    records: list[_FakeRecord]
    started: bool = False
    stopped: bool = False
    committed: list[dict[Any, Any]] = field(default_factory=list)
    _next: int = 0

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def getone(self) -> _FakeRecord:
        record = self.records[self._next]
        self._next += 1
        return record

    async def commit(self, offsets: dict[Any, Any]) -> None:
        self.committed.append(offsets)


# ---------------------------------------------------------------------------
# KafkaProducerBuffer
# ---------------------------------------------------------------------------


async def test_producer_publish_sends_serialized_event_keyed_by_source_id() -> None:
    fake = _FakeProducerClient()
    producer = kafka_buffer.KafkaProducerBuffer(_settings(kafka_topic="ulpf.raw.test"), client=fake)

    await producer.start()
    assert fake.started is True  # an injected client skips admin/topic-creation entirely

    event = _event(source_id="fw-42")
    await producer.publish(event)

    assert len(fake.sent) == 1
    sent = fake.sent[0]
    assert sent["topic"] == "ulpf.raw.test"
    assert sent["key"] == b"fw-42"
    assert kafka_buffer.deserialize_raw_event(sent["value"]) == event

    await producer.stop()
    assert fake.stopped is True


async def test_producer_keys_two_events_from_the_same_source_identically() -> None:
    fake = _FakeProducerClient()
    producer = kafka_buffer.KafkaProducerBuffer(_settings(), client=fake)
    await producer.start()
    await producer.publish(_event(source_id="fw-7"))
    await producer.publish(_event(source_id="fw-7"))
    assert fake.sent[0]["key"] == fake.sent[1]["key"] == b"fw-7"


async def test_producer_publish_before_start_raises() -> None:
    producer = kafka_buffer.KafkaProducerBuffer(_settings())
    with pytest.raises(RuntimeError, match="start"):
        await producer.publish(_event())


async def test_producer_publish_increments_the_published_metric() -> None:
    fake = _FakeProducerClient()
    producer = kafka_buffer.KafkaProducerBuffer(_settings(), client=fake)
    await producer.start()
    key = 'ulpf_buffer_published_total{backend="kafka"}'
    before = snapshot().get(key, 0.0)
    await producer.publish(_event())
    assert snapshot()[key] == before + 1


# ---------------------------------------------------------------------------
# KafkaConsumerBuffer
# ---------------------------------------------------------------------------


async def test_consumer_get_deserializes_and_tracks_pending_until_acked() -> None:
    event = _event(source_id="fw-9")
    record = _FakeRecord(
        topic="ulpf.raw", partition=2, offset=17, value=kafka_buffer.serialize_raw_event(event)
    )
    fake = _FakeConsumerClient(records=[record])
    consumer = kafka_buffer.KafkaConsumerBuffer(_settings(), client=fake)

    await consumer.start()
    received = await consumer.get()
    assert received == event
    assert consumer.depth() == 1  # returned by get(), not yet acked

    await consumer.ack(received)
    assert consumer.depth() == 0
    assert fake.committed == [
        {kafka_buffer.TopicPartition("ulpf.raw", 2): kafka_buffer.OffsetAndMetadata(18, "")}
    ]

    await consumer.stop()
    assert fake.stopped is True


async def test_consumer_ack_of_an_unreturned_event_is_a_noop() -> None:
    fake = _FakeConsumerClient(records=[])
    consumer = kafka_buffer.KafkaConsumerBuffer(_settings(), client=fake)
    await consumer.start()
    await consumer.ack(_event())  # never returned by get() - must not raise or commit
    assert fake.committed == []


async def test_consumer_double_ack_commits_only_once() -> None:
    event = _event()
    record = _FakeRecord(
        topic="ulpf.raw", partition=0, offset=5, value=kafka_buffer.serialize_raw_event(event)
    )
    fake = _FakeConsumerClient(records=[record])
    consumer = kafka_buffer.KafkaConsumerBuffer(_settings(), client=fake)
    await consumer.start()
    received = await consumer.get()
    await consumer.ack(received)
    await consumer.ack(received)  # second ack of the same event: a noop, not a second commit
    assert len(fake.committed) == 1


async def test_consumer_get_before_start_raises() -> None:
    consumer = kafka_buffer.KafkaConsumerBuffer(_settings())
    with pytest.raises(RuntimeError, match="start"):
        await consumer.get()


async def test_consumer_get_increments_the_consumed_metric() -> None:
    event = _event()
    record = _FakeRecord(
        topic="t", partition=0, offset=0, value=kafka_buffer.serialize_raw_event(event)
    )
    fake = _FakeConsumerClient(records=[record])
    consumer = kafka_buffer.KafkaConsumerBuffer(_settings(), client=fake)
    await consumer.start()
    key = 'ulpf_buffer_consumed_total{backend="kafka"}'
    before = snapshot().get(key, 0.0)
    await consumer.get()
    assert snapshot()[key] == before + 1


# ---------------------------------------------------------------------------
# KafkaBuffer (BufferBackend composed from the pair)
# ---------------------------------------------------------------------------


async def test_kafka_buffer_conforms_to_buffer_backend_protocol() -> None:
    buf = kafka_buffer.KafkaBuffer(_settings(), producer=AsyncMock(), consumer=AsyncMock())
    assert isinstance(buf, BufferBackend)


async def test_kafka_buffer_delegates_every_method_to_its_producer_and_consumer() -> None:
    producer = AsyncMock()
    consumer = AsyncMock()
    consumer.depth = Mock(return_value=3)
    buf = kafka_buffer.KafkaBuffer(_settings(), producer=producer, consumer=consumer)

    await buf.start()
    producer.start.assert_awaited_once()
    consumer.start.assert_awaited_once()

    event = _event()
    await buf.put(event)
    producer.publish.assert_awaited_once_with(event)

    consumer.get.return_value = event
    assert await buf.get() is event

    await buf.ack(event)
    consumer.ack.assert_awaited_once_with(event)

    assert buf.depth() == 3

    await buf.stop()
    consumer.stop.assert_awaited_once()
    producer.stop.assert_awaited_once()


# ---------------------------------------------------------------------------
# optional-extra import guard
# ---------------------------------------------------------------------------


def test_import_guard_names_the_optional_extra_when_aiokafka_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "aiokafka", None)
    monkeypatch.delitem(sys.modules, "ulpf.ingest.buffer.kafka_buffer", raising=False)
    with pytest.raises(ImportError, match=r"ulpf\[kafka\]"):
        import ulpf.ingest.buffer.kafka_buffer  # noqa: F401


# ---------------------------------------------------------------------------
# optional integration tests - need a real, reachable broker
# ---------------------------------------------------------------------------

_KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")


def _kafka_reachable() -> bool:
    if not _KAFKA_BOOTSTRAP:
        return False

    async def _probe() -> bool:
        producer = kafka_buffer.AIOKafkaProducer(
            bootstrap_servers=_KAFKA_BOOTSTRAP, request_timeout_ms=1500
        )
        try:
            await asyncio.wait_for(producer.start(), timeout=2.0)
        except Exception:  # noqa: BLE001 - any failure here just means "not reachable"
            return False
        else:
            return True
        finally:
            with contextlib.suppress(Exception):
                await producer.stop()

    try:
        return asyncio.run(_probe())
    except Exception:  # noqa: BLE001 - collection-time probe must never raise
        return False


_needs_broker = pytest.mark.skipif(
    not _kafka_reachable(), reason="no Kafka broker (set KAFKA_BOOTSTRAP_SERVERS)"
)


@_needs_broker
async def test_integration_publish_then_consume_preserves_per_key_order() -> None:
    settings = _settings(
        kafka_bootstrap_servers=_KAFKA_BOOTSTRAP,
        kafka_topic=f"ulpf.raw.it.{uuid.uuid4().hex[:12]}",
        kafka_partitions=3,
        kafka_consumer_group=f"ulpf-it-{uuid.uuid4().hex[:12]}",
    )
    producer = kafka_buffer.KafkaProducerBuffer(settings)
    consumer = kafka_buffer.KafkaConsumerBuffer(settings)
    await producer.start()
    await consumer.start()
    try:
        events_a = [_event(source_id="device-a") for _ in range(8)]
        events_b = [_event(source_id="device-b") for _ in range(8)]
        for a, b in zip(events_a, events_b, strict=True):
            await producer.publish(a)
            await producer.publish(b)

        received: list[RawEvent] = []
        for _ in range(16):
            event = await consumer.get()
            received.append(event)
            await consumer.ack(event)

        assert {e.event_uid for e in received} == {e.event_uid for e in [*events_a, *events_b]}
        # ordering is only guaranteed within one partition, i.e. per key
        assert [e for e in received if e.source_id == "device-a"] == events_a
        assert [e for e in received if e.source_id == "device-b"] == events_b
    finally:
        await consumer.stop()
        await producer.stop()


@_needs_broker
async def test_integration_offset_commits_only_on_ack_and_a_restart_resumes_after_it() -> None:
    settings = _settings(
        kafka_bootstrap_servers=_KAFKA_BOOTSTRAP,
        kafka_topic=f"ulpf.raw.it.{uuid.uuid4().hex[:12]}",
        kafka_partitions=1,
        kafka_consumer_group=f"ulpf-it-{uuid.uuid4().hex[:12]}",
    )

    producer = kafka_buffer.KafkaProducerBuffer(settings)
    await producer.start()
    events = [_event(source_id="only-device") for _ in range(3)]
    try:
        for event in events:
            await producer.publish(event)
    finally:
        await producer.stop()

    consumer = kafka_buffer.KafkaConsumerBuffer(settings)
    await consumer.start()
    try:
        first = await consumer.get()
        assert first == events[0]
        await consumer.ack(first)
        second = await consumer.get()
        assert second == events[1]
        # deliberately never acked -> a fresh consumer in the same group must redeliver it
    finally:
        await consumer.stop()

    restarted = kafka_buffer.KafkaConsumerBuffer(settings)
    await restarted.start()
    try:
        redelivered = await restarted.get()
        assert redelivered == events[1]
    finally:
        await restarted.stop()
