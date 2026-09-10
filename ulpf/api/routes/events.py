"""``/api/v1/events`` — browse, inspect, and trace normalized events.

Backed by :class:`~ulpf.sinks.duckdb_query.LakeQuery` (DuckDB over the Parquet
lake) by default, or :class:`~ulpf.sinks.clickhouse_query.ClickHouseQuery`
when ``settings.clickhouse.enabled`` — the same choice
:mod:`ulpf.sinks.duckdb_query` documents: ULPF runs with zero external
services until an operator turns ClickHouse on. Which backend answered a
request is never visible in the response shape — both return the same
flattened silver-schema columns.

Endpoints
---------
* ``GET /``                    — paginated, filtered event list.
* ``GET /{event_uid}``         — the full normalized OCSF record, unflattened.
* ``GET /{event_uid}/raw``     — the original raw bytes, its hash, and a
  ``verified`` flag (requirement a: lossless raw preservation) — the
  raw-vs-normalized split view.
* ``GET /{event_uid}/lineage`` — the full raw -> ledger -> normalized
  traceability chain in one call (requirement d).
* ``GET /stats/summary``       — counts by source_type/class_uid/action, the
  live parse success rate, and the DLQ rate.
* ``GET /stats/timeseries``    — events per interval, split by source_type
  (``?interval=1m&window=1h``).

``q`` (list filter) is a free-text search: the lake stores every unconsumed
source field (``unmapped``) and every enrichment as JSON strings, so a
substring match across those columns (plus ``src_ip``/``dst_ip``) is the
closest thing to "search the raw" the *silver* tier can answer without an
O(n) join back to bronze for every row of every page; the bronze bytes
themselves are always one ``GET /{event_uid}/raw`` away.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from ulpf.config.settings import Settings
from ulpf.core.metrics import snapshot
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import LEDGER_FILENAME, IntegrityLedger
from ulpf.integrity.proofs import EventProof, ProofBuilder
from ulpf.integrity.signing import Signer, Verifier
from ulpf.sinks.clickhouse_query import ClickHouseQuery, ClickHouseQueryError
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.duckdb_query import LakeQuery
from ulpf.sinks.raw_store import RawStore

_log = logging.getLogger(__name__)

_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 500
_INDEX_FILENAME = "event_index.sqlite"
_JSON_SUFFIX_COLUMNS = ("unmapped_json", "enrichments_json")


@dataclass
class _Filters:
    """One request's ``GET /`` query filters — dialect-agnostic."""

    source_type: str | None = None
    class_uid: int | None = None
    action_id: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    port: int | None = None
    severity_id: int | None = None
    time_from: int | None = None
    time_to: int | None = None
    q: str | None = None


def build_events_router(settings: Settings) -> APIRouter:
    """The ``/events`` router, bound to ``settings`` for its query backend."""
    router = APIRouter(prefix="/events", tags=["events"])
    use_clickhouse = settings.clickhouse.enabled

    async def _list(
        filters: _Filters, page: int, page_size: int
    ) -> tuple[list[dict[str, Any]], int]:
        if use_clickhouse:
            return await _list_clickhouse(settings, filters, page, page_size)
        return await _list_lake(settings, filters, page, page_size)

    async def _get_one(event_uid: str) -> dict[str, Any] | None:
        if use_clickhouse:
            return await _get_clickhouse(settings, event_uid)
        return await _get_lake(settings, event_uid)

    # ------------------------------------------------------------------
    # GET /stats/... - registered before /{event_uid} so "stats" can never
    # be mistaken for an event_uid lookup
    # ------------------------------------------------------------------

    @router.get("/stats/summary")
    async def stats_summary() -> dict[str, Any]:
        """Counts by source_type/class_uid/action, parse success rate, DLQ rate."""
        if use_clickhouse:
            by_source, by_class, by_action, total = await _summary_clickhouse(settings)
        else:
            by_source, by_class, by_action, total = await _summary_lake(settings)

        dlq_total = DeadLetterQueue(settings).stats()["total"]
        denominator = total + dlq_total
        return {
            "total_events": total,
            "by_source_type": by_source,
            "by_class_uid": by_class,
            "by_action": by_action,
            "parse_success_rate": snapshot().get("ulpf_parse_success_rate"),
            "dlq_total": dlq_total,
            "dlq_rate": round(dlq_total / denominator, 4) if denominator else 0.0,
        }

    @router.get("/stats/timeseries")
    async def stats_timeseries(
        interval: str = Query("1m", description="Bucket width, e.g. 1m/5m/1h."),
        window: str = Query("1h", description="How far back, e.g. 1h/24h/7d."),
    ) -> dict[str, Any]:
        """Events per ``interval`` bucket over the last ``window``, split by source_type."""
        _parse_compact_interval(interval)  # validate up front - a 400, never a bare 500
        _parse_compact_interval(window)
        if use_clickhouse:
            points = await _timeseries_clickhouse(settings, interval, window)
        else:
            points = await _timeseries_lake(settings, interval, window)
        return {"interval": interval, "window": window, "points": points}

    # ------------------------------------------------------------------
    # GET / - paginated, filtered list
    # ------------------------------------------------------------------

    @router.get("/")
    async def list_events(
        page: int = Query(1, ge=1),
        page_size: int = Query(_DEFAULT_PAGE_SIZE, ge=1, le=_MAX_PAGE_SIZE),
        source_type: str | None = None,
        class_uid: int | None = None,
        action_id: int | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        port: int | None = None,
        severity_id: int | None = None,
        time_from: int | None = None,
        time_to: int | None = None,
        q: str | None = None,
    ) -> dict[str, Any]:
        filters = _Filters(
            source_type,
            class_uid,
            action_id,
            src_ip,
            dst_ip,
            port,
            severity_id,
            time_from,
            time_to,
            q,
        )
        items, total = await _list(filters, page, page_size)
        return {"items": items, "total": total, "page": page, "page_size": page_size}

    # ------------------------------------------------------------------
    # GET /{event_uid}[...]
    # ------------------------------------------------------------------

    @router.get("/{event_uid}")
    async def get_event(event_uid: str) -> dict[str, Any]:
        """The full normalized OCSF record (plus enrichments), unflattened."""
        row = await _get_one(event_uid)
        if row is None:
            raise HTTPException(status_code=404, detail=f"event {event_uid!r} not found")
        return _unflatten(row)

    @router.get("/{event_uid}/raw")
    async def get_raw(event_uid: str) -> dict[str, Any]:
        """The ORIGINAL raw event, its hash, and a verified flag (requirement a)."""
        raw_store = RawStore(settings)
        event = await asyncio.to_thread(raw_store.read_by_uid, event_uid)
        if event is None:
            raise HTTPException(status_code=404, detail=f"event {event_uid!r} not found in bronze")
        proof = await asyncio.to_thread(_verify_one, settings, event_uid)
        return {
            "event_uid": event.event_uid,
            "raw_b64": base64.b64encode(event.raw).decode("ascii"),
            "raw_text": event.raw.decode("utf-8", errors="replace"),
            "raw_hash": event.raw_hash,
            "raw_len": event.raw_len,
            "ingest_time_ns": event.ingest_time_ns,
            "source_id": event.source_id,
            "transport": event.transport,
            "verified": proof.hash_ok,
        }

    @router.get("/{event_uid}/lineage")
    async def get_lineage(event_uid: str) -> dict[str, Any]:
        """The full raw -> ledger -> normalized traceability chain (requirement d)."""
        proof = await asyncio.to_thread(_verify_one, settings, event_uid)
        if proof.recorded_hash is None:
            raise HTTPException(status_code=404, detail=f"event {event_uid!r} not found")
        row = await _get_one(event_uid)
        return {
            "event_uid": event_uid,
            "raw_hash": proof.recorded_hash.hex(),
            "raw_verified": proof.hash_ok,
            "mapping_version": (row or {}).get("metadata.log_version"),
            "source_type": (row or {}).get("source_type"),
            "ledger_seq": proof.ledger_seq,
            "merkle_proof": [
                {"sibling": sibling.hex(), "side": side} for sibling, side in proof.proof
            ],
            "ledger_verified": proof.found and proof.proof_ok and proof.signature_ok,
        }

    return router


# ======================================================================
# unflattening a silver row back into a nested OCSF record
# ======================================================================


def _unflatten(row: dict[str, Any]) -> dict[str, Any]:
    """Reverse :func:`ulpf.sinks.parquet_sink._flatten` — dotted columns -> nested dict."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        if value is None or key == "date":  # Hive partition column, not part of the record
            continue
        if key in _JSON_SUFFIX_COLUMNS:
            target = key.removesuffix("_json")
            out[target] = json.loads(value) if isinstance(value, str) and value else {}
            continue
        node = out
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


# ======================================================================
# integrity: one event's proof (requirement d)
# ======================================================================


def _load_proof_builder(settings: Settings) -> tuple[ProofBuilder, IntegrityIndex | None]:
    """Build a :class:`ProofBuilder` from whatever integrity artefacts exist on disk.

    Returns the index alongside the builder so the caller can close it — the
    builder itself has no public lifecycle hook, and this index is opened
    fresh for this one request.
    """
    verifier: Verifier | None = None
    integrity = settings.integrity
    if integrity.public_key_path and Path(integrity.public_key_path).is_file():
        verifier = Verifier.load(integrity.public_key_path)
    elif integrity.signing_key_path and Path(integrity.signing_key_path).is_file():
        verifier = Signer.load(integrity.signing_key_path).verifier()

    ledger_path = Path(settings.storage.ledger_path) / LEDGER_FILENAME
    ledger = IntegrityLedger(settings, verifier=verifier) if ledger_path.is_file() else None

    index_path = Path(settings.storage.ledger_path) / _INDEX_FILENAME
    index = IntegrityIndex(index_path) if index_path.is_file() else None

    return ProofBuilder(RawStore(settings), index, ledger), index


def _verify_one(settings: Settings, event_uid: str) -> EventProof:
    """Verify one event's raw-bytes/ledger inclusion/signature (runs off-thread)."""
    builder, index = _load_proof_builder(settings)
    try:
        return builder.for_event(event_uid)
    finally:
        if index is not None:
            index.close()


# ======================================================================
# LakeQuery (DuckDB) backend
# ======================================================================


def _lake_where(filters: _Filters) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if filters.source_type is not None:
        clauses.append("source_type = ?")
        params.append(filters.source_type)
    if filters.class_uid is not None:
        clauses.append("class_uid = ?")
        params.append(filters.class_uid)
    if filters.action_id is not None:
        clauses.append("action_id = ?")
        params.append(filters.action_id)
    if filters.src_ip is not None:
        clauses.append("src_ip = ?")
        params.append(filters.src_ip)
    if filters.dst_ip is not None:
        clauses.append("dst_ip = ?")
        params.append(filters.dst_ip)
    if filters.port is not None:
        clauses.append("(src_port = ? OR dst_port = ?)")
        params.extend([filters.port, filters.port])
    if filters.severity_id is not None:
        clauses.append("severity_id = ?")
        params.append(filters.severity_id)
    if filters.time_from is not None:
        clauses.append('"time" >= ?')
        params.append(filters.time_from)
    if filters.time_to is not None:
        clauses.append('"time" <= ?')
        params.append(filters.time_to)
    if filters.q:
        like = f"%{filters.q}%"
        clauses.append(
            "(unmapped_json ILIKE ? OR enrichments_json ILIKE ? "
            "OR src_ip ILIKE ? OR dst_ip ILIKE ?)"
        )
        params.extend([like, like, like, like])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


async def _list_lake(
    settings: Settings, filters: _Filters, page: int, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    def _run() -> tuple[list[dict[str, Any]], int]:
        with LakeQuery(settings) as lake:
            where, params = _lake_where(filters)
            total = lake.query(f"SELECT COUNT(*) AS n FROM events {where}", params)[0]["n"]
            offset = (page - 1) * page_size
            rows = lake.query(
                f'SELECT * FROM events {where} ORDER BY "time" DESC NULLS LAST LIMIT ? OFFSET ?',
                [*params, page_size, offset],
            )
            return rows, int(total)

    return await asyncio.to_thread(_run)


async def _get_lake(settings: Settings, event_uid: str) -> dict[str, Any] | None:
    def _run() -> dict[str, Any] | None:
        with LakeQuery(settings) as lake:
            rows = lake.query("SELECT * FROM events WHERE event_uid = ? LIMIT 1", [event_uid])
            return rows[0] if rows else None

    return await asyncio.to_thread(_run)


async def _summary_lake(
    settings: Settings,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
    def _run() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
        with LakeQuery(settings) as lake:
            by_source = lake.stats_by_source()
            by_class = lake.query(
                "SELECT class_uid, COUNT(*) AS events FROM events "
                "GROUP BY class_uid ORDER BY events DESC"
            )
            by_action = lake.query(
                "SELECT action_id, COUNT(*) AS events FROM events "
                "GROUP BY action_id ORDER BY events DESC"
            )
            total = sum(row["events"] for row in by_source)
            return by_source, by_class, by_action, total

    return await asyncio.to_thread(_run)


async def _timeseries_lake(settings: Settings, interval: str, window: str) -> list[dict[str, Any]]:
    def _run() -> list[dict[str, Any]]:
        with LakeQuery(settings) as lake:
            return lake.timeseries(_to_lake_interval(interval), _to_lake_interval(window))

    return await asyncio.to_thread(_run)


# ======================================================================
# ClickHouseQuery backend
# ======================================================================

_CH_STRING_FILTERS = ("source_type", "src_ip", "dst_ip")
_CH_INT_FILTERS = ("class_uid", "action_id", "severity_id")


def _ch_where(filters: _Filters) -> tuple[str, dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    for name in _CH_STRING_FILTERS:
        value = getattr(filters, name)
        if value is not None:
            clauses.append(f"{name} = {{{name}:String}}")
            params[name] = value
    for name in _CH_INT_FILTERS:
        value = getattr(filters, name)
        if value is not None:
            clauses.append(f"{name} = {{{name}:Int64}}")
            params[name] = value
    if filters.port is not None:
        clauses.append("(src_port = {port:Int64} OR dst_port = {port:Int64})")
        params["port"] = filters.port
    if filters.time_from is not None:
        clauses.append("time >= {time_from:Int64}")
        params["time_from"] = filters.time_from
    if filters.time_to is not None:
        clauses.append("time <= {time_to:Int64}")
        params["time_to"] = filters.time_to
    if filters.q:
        clauses.append(
            "(positionCaseInsensitive(unmapped, {q:String}) > 0 "
            "OR positionCaseInsensitive(enrichments, {q:String}) > 0 "
            "OR positionCaseInsensitive(src_ip, {q:String}) > 0 "
            "OR positionCaseInsensitive(dst_ip, {q:String}) > 0)"
        )
        params["q"] = filters.q
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _ch_table(settings: Settings) -> str:
    cfg = settings.clickhouse
    return f"`{cfg.database}`.`{cfg.table}`"


async def _run_ch(
    settings: Settings, sql: str, params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    try:
        return await ClickHouseQuery(settings).query(sql, params)
    except ClickHouseQueryError as exc:
        raise HTTPException(status_code=503, detail=f"ClickHouse query failed: {exc}") from exc


async def _list_clickhouse(
    settings: Settings, filters: _Filters, page: int, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    table = _ch_table(settings)
    where, params = _ch_where(filters)
    total_rows = await _run_ch(settings, f"SELECT COUNT(*) AS n FROM {table} {where}", params)
    offset = (page - 1) * page_size
    rows = await _run_ch(
        settings,
        f"SELECT * FROM {table} {where} ORDER BY time DESC LIMIT {page_size} OFFSET {offset}",
        params,
    )
    return rows, int(total_rows[0]["n"]) if total_rows else 0


async def _get_clickhouse(settings: Settings, event_uid: str) -> dict[str, Any] | None:
    table = _ch_table(settings)
    rows = await _run_ch(
        settings,
        f"SELECT * FROM {table} WHERE event_uid = {{event_uid:String}} LIMIT 1",
        {"event_uid": event_uid},
    )
    return rows[0] if rows else None


async def _summary_clickhouse(
    settings: Settings,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
    table = _ch_table(settings)
    by_source = await _run_ch(
        settings,
        f"SELECT source_type, COUNT(*) AS events FROM {table} "
        "GROUP BY source_type ORDER BY events DESC",
    )
    by_class = await _run_ch(
        settings,
        f"SELECT class_uid, COUNT(*) AS events FROM {table} "
        "GROUP BY class_uid ORDER BY events DESC",
    )
    by_action = await _run_ch(
        settings,
        f"SELECT action_id, COUNT(*) AS events FROM {table} "
        "GROUP BY action_id ORDER BY events DESC",
    )
    total = sum(row["events"] for row in by_source)
    return by_source, by_class, by_action, total


async def _timeseries_clickhouse(
    settings: Settings, interval: str, window: str
) -> list[dict[str, Any]]:
    table = _ch_table(settings)
    interval_n, interval_unit = _parse_compact_interval(interval)
    window_n, window_unit = _parse_compact_interval(window)
    sql = (
        f"SELECT toStartOfInterval(toDateTime(intDiv(time, 1000000000)), "
        f"INTERVAL {interval_n} {interval_unit}) AS bucket, source_type, COUNT(*) AS events "
        f"FROM {table} "
        f"WHERE time >= (toUnixTimestamp(now()) - {_seconds(window_n, window_unit)}) * 1000000000 "
        "GROUP BY bucket, source_type ORDER BY bucket, source_type"
    )
    return await _run_ch(settings, sql)


# ======================================================================
# compact interval parsing ("1m"/"5m"/"1h"/"24h"/"7d" -> the two shapes
# LakeQuery.timeseries and the ClickHouse query above need)
# ======================================================================

_UNIT_NAMES = {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY", "w": "WEEK"}
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_COMPACT_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)


def _parse_compact_interval(value: str) -> tuple[int, str]:
    """``"5m"`` -> ``(5, "MINUTE")``. Raises :class:`~fastapi.HTTPException` on a bad value."""
    match = _COMPACT_RE.match(value)
    if not match:
        raise HTTPException(
            status_code=400, detail=f"invalid interval {value!r} (expected e.g. 5m, 1h)"
        )
    n, unit = match.groups()
    return int(n), _UNIT_NAMES[unit.lower()]


def _seconds(n: int, unit_name: str) -> int:
    unit = next(k for k, v in _UNIT_NAMES.items() if v == unit_name)
    return n * _UNIT_SECONDS[unit]


def _to_lake_interval(value: str) -> str:
    """``"5m"`` -> ``"5 minutes"`` (what :meth:`LakeQuery.timeseries` expects)."""
    match = _COMPACT_RE.match(value)
    if not match:
        return value  # already "<n> <unit>" form; let LakeQuery raise a clear error
    n, unit = match.groups()
    name = _UNIT_NAMES[unit.lower()].lower()
    return f"{n} {name}{'s' if n != '1' else ''}"
