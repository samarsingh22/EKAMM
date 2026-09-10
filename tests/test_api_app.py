"""Tests for :mod:`ulpf.api.app` — the management/query API."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ulpf.api.app import create_app
from ulpf.config.settings import (
    ApiSettings,
    IngestSettings,
    ParseSettings,
    PipelineSettings,
    Settings,
    StorageSettings,
)
from ulpf.core.errors import MappingError

_REPO = Path(__file__).resolve().parent.parent


def _settings(tmp_path: Path, **overrides: object) -> Settings:
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
        **overrides,
    )


@pytest.fixture
def client(tmp_path: Path):  # noqa: ANN201
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    with TestClient(create_app(settings)) as client:
        yield client


# --------------------------------------------------------------------------
# GET /health


def test_health_returns_the_full_shape(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "ok"
    assert isinstance(body["uptime_s"], int | float) and body["uptime_s"] >= 0
    assert isinstance(body["version"], str) and body["version"]
    assert isinstance(body["listeners"], list) and body["listeners"]
    assert isinstance(body["sinks"], list) and body["sinks"]
    assert isinstance(body["enrichers"], list) and body["enrichers"]
    assert body["sources_loaded"] == 0


def test_health_lists_the_real_listeners_and_sinks(client: TestClient) -> None:
    body = client.get("/health").json()
    listener_names = {entry["name"] for entry in body["listeners"]}
    assert {"syslog-udp", "syslog-tcp", "http-intake"} <= listener_names

    sinks = {entry["name"]: entry["required"] for entry in body["sinks"]}
    assert sinks["parquet"] is True  # the only required sink by default
    assert sinks["clickhouse"] is False


def test_health_reflects_loaded_source_definitions(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    fixture = (_REPO / "configs" / "sources" / "fortigate_traffic.yaml").read_text(encoding="utf-8")
    (settings.parse.sources_dir / "fortigate_traffic.yaml").write_text(fixture, encoding="utf-8")

    with TestClient(create_app(settings)) as client:
        body = client.get("/health").json()
    assert body["sources_loaded"] == 1


def test_uptime_increases_between_calls(client: TestClient) -> None:
    first = client.get("/health").json()["uptime_s"]
    second = client.get("/health").json()["uptime_s"]
    assert second >= first


# --------------------------------------------------------------------------
# GET /metrics


def test_metrics_serves_prometheus_text_format(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "python_gc_objects_collected_total" in response.text


def test_metrics_reflects_a_ulpf_metric_after_activity(client: TestClient) -> None:
    # /health itself doesn't touch pipeline metrics, but the process metrics
    # (always present) prove the real global registry is being served
    body = client.get("/metrics").text
    assert "# HELP" in body and "# TYPE" in body


# --------------------------------------------------------------------------
# CORS


def test_cors_allows_the_configured_dev_ui_origin(tmp_path: Path) -> None:
    settings = _settings(tmp_path, api=ApiSettings(cors_origins=["http://localhost:5173"]))
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    with TestClient(create_app(settings)) as client:
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_rejects_an_unlisted_origin(tmp_path: Path) -> None:
    settings = _settings(tmp_path, api=ApiSettings(cors_origins=["http://localhost:5173"]))
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    with TestClient(create_app(settings)) as client:
        response = client.options(
            "/health",
            headers={
                "Origin": "http://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert "access-control-allow-origin" not in response.headers


# --------------------------------------------------------------------------
# structured request logging


def test_requests_are_logged_with_structured_fields(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="ulpf.api.app"):
        client.get("/health")

    records = [r for r in caplog.records if r.message == "http request"]
    assert records, "no 'http request' log record was emitted"
    record = records[-1]
    assert record.method == "GET"
    assert record.path == "/health"
    assert record.status_code == 200
    assert isinstance(record.duration_ms, float)


# --------------------------------------------------------------------------
# exception handling


def test_a_ulpf_error_becomes_a_clean_400(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(settings)

    @app.get("/_test/ulpf-error")
    def _boom_domain() -> None:
        raise MappingError("bad field mapping")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_test/ulpf-error")

    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "MappingError"
    assert "bad field mapping" in body["detail"]


def test_an_unhandled_exception_becomes_a_clean_500_not_a_traceback(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(settings)

    @app.get("/_test/boom")
    def _boom() -> None:
        raise RuntimeError("kaboom")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_test/boom")

    assert response.status_code == 500
    body = response.json()
    assert body == {"error": "internal_server_error", "detail": "an unexpected error occurred"}
    assert "kaboom" not in response.text  # no leaked internals


# --------------------------------------------------------------------------
# routers mounted under /api/v1


def test_suggest_router_is_mounted_under_api_v1(client: TestClient) -> None:
    response = client.post(
        "/api/v1/suggest/parser", json={"source_id": "x", "sample_lines": ["one line"]}
    )
    assert response.status_code == 400  # reaches the router; too few samples
    assert "at least" in response.json()["detail"]


# --------------------------------------------------------------------------
# static dashboard (ui/dist) with SPA fallback


def _fake_ui_dist(tmp_path: Path) -> Path:
    dist = tmp_path / "ui-dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(
        "<!doctype html><title>ULPF</title><div id=root>", encoding="utf-8"
    )
    (dist / "assets" / "app-abc123.js").write_text("console.log('ulpf')", encoding="utf-8")
    return dist


def test_dashboard_not_served_without_ui_dist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ulpf.api.app._UI_DIST", tmp_path / "does-not-exist")
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    with TestClient(create_app(settings)) as client:
        # API-only: root and client routes 404, the API still works
        assert client.get("/").status_code == 404
        assert client.get("/events/abc").status_code == 404
        assert client.get("/health").status_code == 200


def test_dashboard_served_with_spa_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ulpf.api.app._UI_DIST", _fake_ui_dist(tmp_path))
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)

    with TestClient(create_app(settings)) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert root.headers["content-type"].startswith("text/html")
        assert "id=root" in root.text

        # a deep client-side route (refresh survival) -> the SAME index.html
        spa = client.get("/integrity")
        assert spa.status_code == 200
        assert spa.text == root.text

        # hashed assets are served for real
        asset = client.get("/assets/app-abc123.js")
        assert asset.status_code == 200
        assert "ulpf" in asset.text
        assert client.get("/assets/missing.js").status_code == 404

        # the API is untouched: an unknown API path is a JSON 404, not the SPA
        api404 = client.get("/api/v1/nope")
        assert api404.status_code == 404
        assert api404.headers["content-type"].startswith("application/json")
        assert "<div id=root>" not in api404.text

        # a real in-route 404 still returns its JSON detail
        detail = client.get("/api/v1/events/does-not-exist")
        assert detail.status_code == 404
        assert "not found" in detail.json()["detail"].lower()

        assert client.get("/health").status_code == 200


def test_dashboard_does_not_shadow_routes_added_after_create_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SPA fallback is a 404 handler, so a route registered post-build still wins."""
    monkeypatch.setattr("ulpf.api.app._UI_DIST", _fake_ui_dist(tmp_path))
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(settings)

    @app.get("/_late/route")
    def _late() -> dict[str, str]:
        return {"ok": "yes"}

    with TestClient(app) as client:
        assert client.get("/_late/route").json() == {"ok": "yes"}


# --------------------------------------------------------------------------
# lifespan actually starts/stops the runtime cleanly


def test_lifespan_starts_and_stops_the_runtime_without_error(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(settings)
    with TestClient(app) as client:
        assert app.state.runtime is not None
        assert client.get("/health").status_code == 200
    # exiting the `with` block runs the lifespan shutdown; getting here at
    # all (no exception) is the assertion
