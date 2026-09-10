"""Tests for :mod:`ulpf.sinks.clickhouse_query` (mocked ClickHouse HTTP endpoint)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from ulpf.config.settings import ClickHouseSettings, Settings, StorageSettings
from ulpf.sinks.clickhouse_query import ClickHouseQuery, ClickHouseQueryError


class FakeClickHouse:
    """Records requests; returns scriptable JSONEachRow responses."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.rows: list[dict] = [{"event_uid": "a"}, {"event_uid": "b"}]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status >= 300:
            return httpx.Response(self.status, text="boom")
        body = "\n".join(f'{{"event_uid": "{r["event_uid"]}"}}' for r in self.rows)
        return httpx.Response(200, text=body)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))


def _settings(tmp_path: Path, **clickhouse: object) -> Settings:
    clickhouse.setdefault("enabled", True)
    return Settings(
        storage=StorageSettings(state_path=tmp_path / "state"),
        clickhouse=ClickHouseSettings(**clickhouse),
    )


async def test_query_sends_format_jsoneachrow_and_parses_rows(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    query = ClickHouseQuery(_settings(tmp_path), client=fake.client())

    rows = await query.query("SELECT * FROM events")

    assert rows == [{"event_uid": "a"}, {"event_uid": "b"}]
    (request,) = fake.requests
    assert request.content.decode().endswith("FORMAT JSONEachRow")


async def test_query_binds_params_via_param_prefixed_query_string(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    query = ClickHouseQuery(_settings(tmp_path), client=fake.client())

    await query.query(
        "SELECT * FROM events WHERE source_type = {source_type:String} "
        "AND class_uid = {class_uid:Int64}",
        {"source_type": "fortigate_traffic", "class_uid": 4001},
    )

    (request,) = fake.requests
    params = dict(request.url.params)
    assert params["param_source_type"] == "fortigate_traffic"
    assert params["param_class_uid"] == "4001"
    assert params["database"] == "ulpf"


def test_query_binds_bool_params_as_0_or_1() -> None:
    from ulpf.sinks.clickhouse_query import _stringify

    assert _stringify(True) == "1"
    assert _stringify(False) == "0"
    assert _stringify(42) == "42"


async def test_non_2xx_response_raises_clickhouse_query_error(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    fake.status = 500
    query = ClickHouseQuery(_settings(tmp_path), client=fake.client())

    with pytest.raises(ClickHouseQueryError, match="HTTP 500"):
        await query.query("SELECT * FROM events")


async def test_transport_error_raises_clickhouse_query_error(tmp_path: Path) -> None:
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(_boom))
    query = ClickHouseQuery(_settings(tmp_path), client=client)

    with pytest.raises(ClickHouseQueryError, match="transport error"):
        await query.query("SELECT * FROM events")


async def test_headers_include_user_and_key_when_configured(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    query = ClickHouseQuery(
        _settings(tmp_path, user="admin", password="s3cret"), client=fake.client()
    )

    await query.query("SELECT * FROM events")

    (request,) = fake.requests
    assert request.headers["X-ClickHouse-User"] == "admin"
    assert request.headers["X-ClickHouse-Key"] == "s3cret"


async def test_no_client_given_opens_and_closes_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeClickHouse()
    real_async_client = httpx.AsyncClient  # capture before patching, to avoid self-recursion
    import ulpf.sinks.clickhouse_query as mod

    monkeypatch.setattr(
        mod.httpx,
        "AsyncClient",
        lambda **kwargs: real_async_client(transport=httpx.MockTransport(fake._handle)),
    )
    query = ClickHouseQuery(_settings(tmp_path))  # no injected client

    rows = await query.query("SELECT * FROM events")
    assert rows == [{"event_uid": "a"}, {"event_uid": "b"}]
