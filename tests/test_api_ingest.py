"""Tests for :mod:`ulpf.api.routes.ingest` — every ``/api/v1/ingest`` endpoint."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ulpf.api.routes.ingest import build_ingest_router
from ulpf.config.settings import IngestSettings, ParseSettings, Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.core.runtime import Runtime

_REPO = Path(__file__).resolve().parent.parent

_FORTI_LINE = (
    '<189>date=2026-09-01 time=10:00:00 devname="FGT" logid="0000000013" '
    'type="traffic" subtype="forward" level="warning" srcip=192.0.2.5 srcport=51000 '
    'dstip=198.51.100.5 dstport=443 proto=6 action="accept" policyid=9 '
    "sentbyte=10 rcvdbyte=20"
)


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
        parse=ParseSettings(sources_dir=_REPO / "configs" / "sources"),
    )


def _app(settings: Settings, samples_dir: Path) -> FastAPI:
    app = FastAPI()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        runtime = Runtime(settings)
        app.state.runtime = runtime
        await runtime.start()
        try:
            yield
        finally:
            await runtime.stop()

    app.router.lifespan_context = lifespan
    app.include_router(build_ingest_router(settings, samples_dir=samples_dir), prefix="/api/v1")
    return app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = _settings(tmp_path)
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    with TestClient(_app(settings, samples_dir)) as test_client:
        test_client.ulpf_settings = settings  # type: ignore[attr-defined]
        test_client.ulpf_samples_dir = samples_dir  # type: ignore[attr-defined]
        yield test_client


def _wait_for(client: TestClient, task_id: str, *, not_status: str = "running") -> dict:
    """Poll GET /replay/{task_id} until its status leaves ``not_status`` (bounded)."""
    body = {}
    for _ in range(100):
        body = client.get(f"/api/v1/ingest/replay/{task_id}").json()
        if body["status"] != not_status:
            return body
        time.sleep(0.02)
    return body


# ======================================================================
# POST /sample
# ======================================================================


def test_sample_injects_lines_and_the_pipeline_normalizes_them(client: TestClient) -> None:
    # ParquetSink only flushes at 10,000 buffered rows or on a long timer (see
    # ulpf.sinks.parquet_sink), so a single injected line will not have reached
    # durable silver Parquet by the time this test asserts - the *synchronous*,
    # per-event ulpf_events_normalized_total counter is the honest thing to
    # check here for proof the real pipeline (not just the HTTP layer) ran it.
    before = snapshot().get(
        'ulpf_events_normalized_total{class_uid="4001",source_type="fortigate_traffic"}', 0.0
    )
    response = client.post("/api/v1/ingest/sample", json={"lines": [_FORTI_LINE]})
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 1
    assert len(body["event_uids"]) == 1

    after = 0.0
    for _ in range(50):
        after = snapshot().get(
            'ulpf_events_normalized_total{class_uid="4001",source_type="fortigate_traffic"}', 0.0
        )
        if after > before:
            break
        time.sleep(0.05)
    assert after == before + 1


def test_sample_skips_blank_lines(client: TestClient) -> None:
    response = client.post("/api/v1/ingest/sample", json={"lines": [_FORTI_LINE, "", "   "]})
    body = response.json()
    assert body["accepted"] == 1


def test_sample_honors_custom_source_id(client: TestClient) -> None:
    before = snapshot().get('ulpf_events_received_total{transport="http"}', 0.0)
    response = client.post(
        "/api/v1/ingest/sample", json={"lines": ["not a fortigate line"], "source_id": "demo-box"}
    )
    assert response.status_code == 200
    after = snapshot().get('ulpf_events_received_total{transport="http"}', 0.0)
    assert after == before + 1


def test_sample_empty_list_accepts_nothing(client: TestClient) -> None:
    response = client.post("/api/v1/ingest/sample", json={"lines": []})
    assert response.status_code == 200
    assert response.json() == {"accepted": 0, "event_uids": []}


# ======================================================================
# POST /replay, GET /replay/{id}, DELETE /replay/{id}
# ======================================================================


def test_replay_streams_a_sample_file_to_completion(client: TestClient) -> None:
    samples_dir: Path = client.ulpf_samples_dir  # type: ignore[attr-defined]
    (samples_dir / "demo.log").write_text(f"{_FORTI_LINE}\n{_FORTI_LINE}\n", encoding="utf-8")

    response = client.post("/api/v1/ingest/replay", json={"file": "demo.log", "rate_eps": 0})
    assert response.status_code == 200
    task_id = response.json()["task_id"]

    body = _wait_for(client, task_id)
    assert body["status"] == "completed"
    assert body["lines_total"] == 2
    assert body["lines_sent"] == 2
    assert body["finished_ns"] is not None
    assert body["error"] is None


def test_replay_progress_404_for_unknown_task(client: TestClient) -> None:
    response = client.get("/api/v1/ingest/replay/does-not-exist")
    assert response.status_code == 404


def test_replay_404_for_a_missing_sample_file(client: TestClient) -> None:
    response = client.post("/api/v1/ingest/replay", json={"file": "nope.log", "rate_eps": 0})
    assert response.status_code == 404


def test_replay_can_be_stopped_mid_flight(client: TestClient) -> None:
    samples_dir: Path = client.ulpf_samples_dir  # type: ignore[attr-defined]
    lines = "\n".join([_FORTI_LINE] * 50)
    (samples_dir / "slow.log").write_text(lines + "\n", encoding="utf-8")

    response = client.post("/api/v1/ingest/replay", json={"file": "slow.log", "rate_eps": 20})
    task_id = response.json()["task_id"]
    time.sleep(0.1)  # let a few lines through

    stop_body = client.delete(f"/api/v1/ingest/replay/{task_id}").json()
    assert stop_body["status"] == "stopped"
    assert 0 < stop_body["lines_sent"] < 50

    # stopping again (or checking status) reflects the same final state
    final = client.get(f"/api/v1/ingest/replay/{task_id}").json()
    assert final["status"] == "stopped"


def test_replay_stop_404_for_unknown_task(client: TestClient) -> None:
    response = client.delete("/api/v1/ingest/replay/does-not-exist")
    assert response.status_code == 404


# ======================================================================
# path traversal protection
# ======================================================================


@pytest.mark.parametrize(
    "malicious_path",
    [
        "../outside.log",
        "../../etc/passwd",
        "subdir/../../outside.log",
    ],
)
def test_replay_rejects_relative_path_traversal(client: TestClient, malicious_path: str) -> None:
    samples_dir: Path = client.ulpf_samples_dir  # type: ignore[attr-defined]
    outside = samples_dir.parent / "outside.log"
    outside.write_text("secret content\n", encoding="utf-8")

    response = client.post("/api/v1/ingest/replay", json={"file": malicious_path, "rate_eps": 0})
    assert response.status_code == 400
    assert "must resolve under" in response.json()["detail"]


def test_replay_rejects_an_absolute_path(client: TestClient, tmp_path: Path) -> None:
    outside = tmp_path / "outside.log"
    outside.write_text("secret content\n", encoding="utf-8")

    response = client.post("/api/v1/ingest/replay", json={"file": str(outside), "rate_eps": 0})
    assert response.status_code == 400


def test_replay_rejects_empty_file_path(client: TestClient) -> None:
    response = client.post("/api/v1/ingest/replay", json={"file": "", "rate_eps": 0})
    assert response.status_code == 400


# ======================================================================
# GET /listeners
# ======================================================================


def test_listeners_returns_every_bound_listener(client: TestClient) -> None:
    response = client.get("/api/v1/ingest/listeners")
    assert response.status_code == 200
    rows = response.json()
    names = {row["name"] for row in rows}
    assert {"syslog-udp", "syslog-tcp", "http-intake"} <= names
    for row in rows:
        assert row["port"] >= 0
        assert row["events_received"] >= 0
        assert row["bytes_received"] >= 0


def test_listeners_http_counter_increases_after_a_sample_post(client: TestClient) -> None:
    before = next(
        row for row in client.get("/api/v1/ingest/listeners").json() if row["protocol"] == "http"
    )
    client.post("/api/v1/ingest/sample", json={"lines": [_FORTI_LINE]})
    after = next(
        row for row in client.get("/api/v1/ingest/listeners").json() if row["protocol"] == "http"
    )
    assert after["events_received"] > before["events_received"]
    assert after["bytes_received"] > before["bytes_received"]
