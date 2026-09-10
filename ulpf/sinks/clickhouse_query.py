"""Read-only ClickHouse queries — the ``/api/v1/events`` backend when
``settings.clickhouse.enabled``.

Queries the same table :class:`~ulpf.sinks.clickhouse_sink.ClickHouseSink`
writes, over ClickHouse's plain HTTP interface (no extra driver). Filter
values are never string-interpolated into SQL: every query uses ClickHouse's
HTTP parameter binding (``{name:Type}`` placeholders in the SQL text, bound
via ``param_<name>=<value>`` query-string parameters), the same mechanism
ClickHouse itself recommends for the HTTP interface.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

import httpx

from ulpf.config.settings import Settings
from ulpf.core.errors import UlpfError

_log = logging.getLogger(__name__)


class ClickHouseQueryError(UlpfError):
    """A ClickHouse query failed (transport error or a non-2xx response)."""


class ClickHouseQuery:
    """Runs parameterized ``SELECT`` queries against ClickHouse, over HTTP."""

    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        """Configure from ``settings.clickhouse``; ``client`` is injectable for tests."""
        self._cfg = settings.clickhouse
        self._base_url = self._cfg.url
        self._client = client

    async def query(
        self, sql: str, params: Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Run one ``SELECT``/``WITH`` query; return rows as dicts.

        ``sql`` may reference ``{name:Type}`` placeholders for anything in
        ``params`` (e.g. ``WHERE source_type = {source_type:String}``).
        """
        query_params = {"database": self._cfg.database}
        for key, value in (params or {}).items():
            query_params[f"param_{key}"] = _stringify(value)
        body = f"{sql}\nFORMAT JSONEachRow"

        if self._client is not None:
            return await self._post(self._client, body, query_params)
        async with httpx.AsyncClient(timeout=self._cfg.request_timeout_seconds) as client:
            return await self._post(client, body, query_params)

    async def _post(
        self, client: httpx.AsyncClient, body: str, query_params: dict[str, str]
    ) -> list[dict[str, Any]]:
        try:
            response = await client.post(
                self._base_url, content=body, params=query_params, headers=self._headers()
            )
        except httpx.HTTPError as exc:
            raise ClickHouseQueryError(f"transport error: {exc}") from exc
        if response.status_code >= 300:
            raise ClickHouseQueryError(
                f"HTTP {response.status_code}: {response.text[:300].strip()}"
            )
        return [json.loads(line) for line in response.text.splitlines() if line.strip()]

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        if self._cfg.user:
            headers["X-ClickHouse-User"] = self._cfg.user
        if self._cfg.password:
            headers["X-ClickHouse-Key"] = self._cfg.password
        return headers


def _stringify(value: Any) -> str:
    """Render a Python value the way ClickHouse HTTP parameter binding expects."""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)
