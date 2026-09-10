"""Tests for :mod:`ulpf.ingest.buffer.base` / :mod:`ulpf.ingest.buffer.in_process`.

The in-process backend is the default and needs no external service, so its
tests always run (unlike the Kafka backend's, which need the optional
``aiokafka`` extra and, for the integration tests, a real broker).
"""

from __future__ import annotations

from ulpf.config.settings import BufferSettings, IngestSettings, Settings
from ulpf.core.metrics import snapshot
from ulpf.core.models import RawEvent
from ulpf.ingest.buffer import BufferBackend, InProcessBuffer, build_buffer_backend
from ulpf.ingest.queue import BoundedEventQueue
from ulpf.integrity.hashing import make_raw_event


def _settings(max_size: int = 8) -> Settings:
    return Settings(ingest=IngestSettings(queue_max_size=max_size))


def _event(source_id: str = "fw-1") -> RawEvent:
    return make_raw_event(b"<134>hello", source_id=source_id, transport="udp")


async def test_in_process_buffer_conforms_to_buffer_backend_protocol() -> None:
    buf = InProcessBuffer(_settings())
    assert isinstance(buf, BufferBackend)


async def test_in_process_buffer_put_get_ack_roundtrip() -> None:
    buf = InProcessBuffer(_settings())
    event = _event()

    await buf.put(event)
    assert buf.depth() == 1

    received = await buf.get()
    assert received == event
    # depth drops on get() (matches BoundedEventQueue.get()), ack() just marks task_done
    assert buf.depth() == 0

    await buf.ack(received)  # must not raise, and is a pure no-op beyond task_done()


async def test_in_process_buffer_fifo_order() -> None:
    buf = InProcessBuffer(_settings())
    events = [_event(f"fw-{i}") for i in range(5)]
    for event in events:
        await buf.put(event)
    received = [await buf.get() for _ in events]
    assert received == events


async def test_in_process_buffer_start_stop_are_noops() -> None:
    buf = InProcessBuffer(_settings())
    await buf.start()
    await buf.put(_event())
    await buf.stop()
    assert buf.depth() == 1  # stop() does not drain anything


async def test_in_process_buffer_wraps_an_injected_queue() -> None:
    queue = BoundedEventQueue(_settings(max_size=2))
    buf = InProcessBuffer(_settings(), queue=queue)
    assert buf.queue is queue
    await buf.put(_event())
    assert queue.depth() == 1


async def test_in_process_buffer_updates_published_and_consumed_metrics() -> None:
    buf = InProcessBuffer(_settings())
    before = snapshot()
    await buf.put(_event())
    await buf.get()
    after = snapshot()

    published_key = 'ulpf_buffer_published_total{backend="in_process"}'
    consumed_key = 'ulpf_buffer_consumed_total{backend="in_process"}'
    assert after[published_key] == before.get(published_key, 0.0) + 1
    assert after[consumed_key] == before.get(consumed_key, 0.0) + 1


# ---------------------------------------------------------------------------
# build_buffer_backend()
# ---------------------------------------------------------------------------


async def test_build_buffer_backend_defaults_to_in_process() -> None:
    backend = build_buffer_backend(Settings())
    assert isinstance(backend, InProcessBuffer)


async def test_build_buffer_backend_in_process_is_fully_functional() -> None:
    backend = build_buffer_backend(Settings())
    event = _event()
    await backend.start()
    await backend.put(event)
    assert await backend.get() == event
    await backend.ack(event)
    await backend.stop()


def test_build_buffer_backend_selects_kafka_when_configured() -> None:
    settings = Settings(buffer=BufferSettings(backend="kafka"))
    backend = build_buffer_backend(settings)
    assert isinstance(backend, BufferBackend)
    assert type(backend).__name__ == "KafkaBuffer"
