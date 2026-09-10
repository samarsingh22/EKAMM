"""Tests for :mod:`ulpf.core.runtime` — the wired-together process."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ulpf.config.settings import (
    BufferSettings,
    IngestSettings,
    ParseSettings,
    PipelineSettings,
    Settings,
    StorageSettings,
)
from ulpf.core.runtime import Runtime
from ulpf.integrity.hashing import make_raw_event
from ulpf.sinks.raw_store import RawStore


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        ingest=IngestSettings(syslog_udp_port=0, syslog_tcp_port=0, http_port=0),
        parse=ParseSettings(sources_dir=tmp_path / "sources"),
        pipeline=PipelineSettings(worker_count=1),
    )


async def test_udp_datagram_ends_up_in_the_bronze_store(tmp_path: Path) -> None:
    """`ulpf run` wiring: a syslog UDP datagram becomes one bronze record."""
    settings = _settings(tmp_path)
    runtime = Runtime(settings)
    await runtime.start()
    try:
        assert runtime.udp_port > 0
        assert runtime.tcp_port > 0
        assert runtime.tls_port is None  # no cert configured

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", runtime.udp_port)
        )
        transport.sendto(b"test\n")
        transport.close()
        await asyncio.sleep(0.15)  # let datagram_received -> pipeline.submit run
    finally:
        await runtime.stop()  # stops UDP (drains dispatch), then flushes bronze

    events = list(RawStore(settings).iter_all())
    assert len(events) == 1
    assert events[0].raw == b"test\n"
    assert events[0].transport == "udp"
    assert events[0].source_id == "syslog-udp"

    partitions = list((tmp_path / "bronze").rglob("events.ndjson.gz"))
    assert len(partitions) == 1


async def test_start_then_stop_is_clean_with_no_traffic(tmp_path: Path) -> None:
    runtime = Runtime(_settings(tmp_path))
    await runtime.start()
    await runtime.stop()
    # a second stop is a no-op, not an error
    await runtime.pipeline.stop()


async def test_multiple_workers_process_traffic_correctly_end_to_end(tmp_path: Path) -> None:
    """Each worker builds its own parser/mapper (stage_factory); submitted traffic still works.

    Submits straight to ``runtime.pipeline`` (like ``POST /ingest/sample``
    does) rather than over a real UDP socket: per CLAUDE.md, UDP is lossy
    under an unpaced burst, and this test's job is to prove the multi-worker
    *pipeline* wiring, not socket reliability (already covered elsewhere).
    """
    settings = _settings(tmp_path).model_copy(update={"pipeline": PipelineSettings(worker_count=4)})
    runtime = Runtime(settings)
    await runtime.start()
    try:
        for i in range(40):
            event = make_raw_event(f"msg-{i}".encode(), source_id="test", transport="http")
            await runtime.pipeline.submit(event)
        await runtime.pipeline.queue.join()
    finally:
        await runtime.stop()

    events = list(RawStore(settings).iter_all())
    assert len(events) == 40
    assert len({e.event_uid for e in events}) == 40  # nothing lost or duplicated


def test_kafka_backend_wires_one_consumer_buffer_per_worker(tmp_path: Path) -> None:
    """`settings.buffer.backend == "kafka"` builds N per-worker consumers (construction only)."""
    pytest.importorskip("aiokafka")
    settings = _settings(tmp_path).model_copy(
        update={
            "pipeline": PipelineSettings(worker_count=3),
            "buffer": BufferSettings(backend="kafka", kafka_bootstrap_servers="127.0.0.1:1"),
        }
    )
    runtime = Runtime(settings)
    assert runtime._kafka_producer is not None
    assert len(runtime._kafka_consumers) == 3
    assert runtime.pipeline._worker_buffers is not None
    assert len(runtime.pipeline._worker_buffers) == 3


def test_in_process_backend_builds_no_kafka_objects(tmp_path: Path) -> None:
    runtime = Runtime(_settings(tmp_path))
    assert runtime._kafka_producer is None
    assert runtime._kafka_consumers == []
    assert runtime.pipeline._worker_buffers is None
