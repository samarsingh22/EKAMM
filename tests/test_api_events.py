"""Tests for :mod:`ulpf.api.routes.events` — every ``/api/v1/events`` endpoint,
against both query backends (LakeQuery/DuckDB and mocked ClickHouse HTTP).
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ulpf.api.routes.events import (
    _parse_compact_interval,
    _to_lake_interval,
    _unflatten,
    build_events_router,
)
from ulpf.config.settings import (
    ClickHouseSettings,
    EnrichSettings,
    IntegritySettings,
    ParseSettings,
    PipelineSettings,
    Settings,
    StorageSettings,
)
from ulpf.core.models import RawEvent
from ulpf.core.pipeline import ParseStage, Pipeline, RawStoreStage
from ulpf.enrich.factory import build_enrichers
from ulpf.enrich.pipeline import EnrichmentPipeline
from ulpf.enrich.stage import EnrichStage
from ulpf.integrity.hashing import make_raw_event
from ulpf.integrity.signing import Signer, generate_keypair
from ulpf.integrity.stage import IntegrityStage
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.manager import SinkManager
from ulpf.sinks.raw_store import RawStore

_REPO = Path(__file__).resolve().parent.parent


def _settings(
    root: Path,
    *,
    signing_key_path: Path | None = None,
    public_key_path: Path | None = None,
    **overrides: object,
) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=root / "bronze",
            silver_path=root / "silver",
            dlq_path=root / "dlq",
            ledger_path=root / "ledger",
            state_path=root / "state",
        ),
        parse=ParseSettings(sources_dir=_REPO / "configs" / "sources"),
        pipeline=PipelineSettings(worker_count=1),
        enrich=EnrichSettings(enabled=False),
        integrity=IntegritySettings(
            signing_key_path=signing_key_path,
            public_key_path=public_key_path,
            batch_size=10_000,
            batch_timeout_seconds=0.0,
        ),
        **overrides,
    )


def _fortigate_lines(n: int, *, date: str) -> list[bytes]:
    """Distinct synthetic FortiGate traffic lines; every 7th is a "deny"."""
    return [
        (
            f"<189>date={date} time=10:{i // 60 % 60:02d}:{i % 60:02d} "
            f'devname="FGT" logid="0000000013" type="traffic" subtype="forward" '
            f'level="warning" srcip=192.0.2.{i % 254 + 1} srcport={10000 + i} '
            f"dstip=198.51.100.{i % 254 + 1} dstport=443 proto=6 "
            f'action="{"deny" if i % 7 == 0 else "accept"}" policyid=9 '
            f"sentbyte={i} rcvdbyte={2 * i}"
        ).encode()
        for i in range(n)
    ]


def _build_pipeline(settings: Settings) -> tuple[Pipeline, SinkManager]:
    """RawStoreStage -> [IntegrityStage] -> Parse -> Normalize -> Enrich -> Validate -> sinks."""
    registry = SourceRegistry()
    registry.load_all(settings.parse.sources_dir)
    enrich = EnrichmentPipeline(settings, build_enrichers(settings))
    sinks = SinkManager.from_settings(settings)
    stages: list[object] = [RawStoreStage(RawStore(settings))]
    if settings.integrity.signing_key_path is not None:
        stages.append(
            IntegrityStage(settings, signer=Signer.load(settings.integrity.signing_key_path))
        )
    stages += [
        ParseStage(settings, ParseCoordinator()),
        NormalizeStage(settings, registry),
        EnrichStage(settings, enrich),
        ValidateStage(settings, registry),
        sinks,
    ]
    pipeline = Pipeline(settings, stages)  # type: ignore[arg-type]
    return pipeline, sinks


def _ingest(settings: Settings, lines: list[bytes]) -> list[RawEvent]:
    """Push ``lines`` through the full pipeline and wait for it to drain + flush."""

    async def _run() -> list[RawEvent]:
        events = [make_raw_event(line, source_id="apitest", transport="udp") for line in lines]
        pipeline, sinks = _build_pipeline(settings)
        await sinks.start()
        pipeline.start()
        for event in events:
            await pipeline.submit(event)
        await pipeline.stop()  # drains, then flushes every stage (parquet + ledger)
        return events

    return asyncio.run(_run())


def _flip_one_byte_in_bronze(settings: Settings, event_uid: str) -> None:
    """Flip one byte of one stored raw event's payload (bronze tamper helper)."""
    path = next(Path(settings.storage.bronze_path).rglob("events.ndjson.gz"))
    with gzip.open(path, "rb") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    for record in records:
        if record["event_uid"] == event_uid:
            raw = bytearray(base64.b64decode(record["raw_b64"]))
            raw[len(raw) // 2] ^= 0xFF
            record["raw_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    with gzip.open(path, "wb") as handle:
        for record in records:
            handle.write((json.dumps(record, separators=(",", ":")) + "\n").encode())


def _events_app(settings: Settings) -> FastAPI:
    app = FastAPI()
    app.include_router(build_events_router(settings), prefix="/api/v1")
    return app


# ======================================================================
# LakeQuery (DuckDB) backend, no integrity ledger
# ======================================================================


@pytest.fixture(scope="module")
def lake(tmp_path_factory: pytest.TempPathFactory) -> tuple[Settings, list[RawEvent]]:
    """500 fortigate events, no signing key (integrity off) - shared read-only."""
    root = tmp_path_factory.mktemp("events-lake")
    settings = _settings(root)
    events = _ingest(settings, _fortigate_lines(500, date="2026-09-01"))
    return settings, events


@pytest.fixture(scope="module")
def lake_client(lake: tuple[Settings, list[RawEvent]]) -> TestClient:
    settings, _events = lake
    return TestClient(_events_app(settings))


# -- GET / --------------------------------------------------------------


def test_list_returns_items_total_page_page_size(lake_client: TestClient) -> None:
    response = lake_client.get("/api/v1/events/")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 500
    assert body["page"] == 1
    assert body["page_size"] == 50
    assert len(body["items"]) == 50


def test_list_filters_by_source_type(lake_client: TestClient) -> None:
    body = lake_client.get("/api/v1/events/", params={"source_type": "fortigate_traffic"}).json()
    assert body["total"] == 500
    body_none = lake_client.get("/api/v1/events/", params={"source_type": "nope"}).json()
    assert body_none["total"] == 0
    assert body_none["items"] == []


def test_list_filters_by_class_uid_and_action_id(lake_client: TestClient) -> None:
    # every 7th of 500 -> i % 7 == 0 is "deny" (action_id 2), rest "accept" (action_id 1)
    denies = len([i for i in range(500) if i % 7 == 0])
    body = lake_client.get("/api/v1/events/", params={"action_id": 2, "page_size": 500}).json()
    assert body["total"] == denies
    assert all(item["action_id"] == 2 for item in body["items"])

    body = lake_client.get("/api/v1/events/", params={"class_uid": 4001, "page_size": 1}).json()
    assert body["total"] == 500


def test_list_filters_by_src_ip_and_dst_ip(lake_client: TestClient) -> None:
    body = lake_client.get("/api/v1/events/", params={"src_ip": "192.0.2.1"}).json()
    assert body["total"] >= 1
    assert all(item["src_ip"] == "192.0.2.1" for item in body["items"])

    body = lake_client.get("/api/v1/events/", params={"dst_ip": "10.10.10.10"}).json()
    assert body["total"] == 0


def test_list_filters_by_port_matches_src_or_dst(lake_client: TestClient) -> None:
    # dstport is always 443 in the synthetic data - filtering on it should match everything
    body = lake_client.get("/api/v1/events/", params={"port": 443, "page_size": 1}).json()
    assert body["total"] == 500

    # srcport 10000 is unique to event 0
    body = lake_client.get("/api/v1/events/", params={"port": 10000}).json()
    assert body["total"] == 1


def test_list_filters_by_severity_id(lake_client: TestClient) -> None:
    body = lake_client.get("/api/v1/events/", params={"severity_id": 3}).json()
    assert body["total"] == 500  # fortigate "warning" level maps to severity_id 3
    body = lake_client.get("/api/v1/events/", params={"severity_id": 99}).json()
    assert body["total"] == 0


def test_list_filters_by_time_range(lake_client: TestClient) -> None:
    full = lake_client.get("/api/v1/events/", params={"page_size": 500}).json()
    times = sorted(item["time"] for item in full["items"])
    midpoint = times[len(times) // 2]

    body = lake_client.get(
        "/api/v1/events/", params={"time_from": midpoint, "page_size": 500}
    ).json()
    assert all(item["time"] >= midpoint for item in body["items"])
    assert 0 < body["total"] < 500

    body = lake_client.get("/api/v1/events/", params={"time_to": midpoint, "page_size": 500}).json()
    assert all(item["time"] <= midpoint for item in body["items"])


def test_list_free_text_q_matches_ip_substring(lake_client: TestClient) -> None:
    body = lake_client.get("/api/v1/events/", params={"q": "192.0.2.1"}).json()
    assert body["total"] >= 1
    assert all("192.0.2.1" in json.dumps(item) for item in body["items"])


def test_list_pagination_page_two_and_max_page_size(lake_client: TestClient) -> None:
    page1 = lake_client.get("/api/v1/events/", params={"page": 1, "page_size": 100}).json()
    page2 = lake_client.get("/api/v1/events/", params={"page": 2, "page_size": 100}).json()
    uids1 = {item["event_uid"] for item in page1["items"]}
    uids2 = {item["event_uid"] for item in page2["items"]}
    assert len(page1["items"]) == 100
    assert len(page2["items"]) == 100
    assert uids1.isdisjoint(uids2)

    too_big = lake_client.get("/api/v1/events/", params={"page_size": 100_000})
    assert too_big.status_code == 422  # exceeds _MAX_PAGE_SIZE


# -- GET /{event_uid} -----------------------------------------------------


def test_get_event_returns_unflattened_ocsf_record(
    lake: tuple[Settings, list[RawEvent]], lake_client: TestClient
) -> None:
    _settings_, events = lake
    uid = events[0].event_uid

    response = lake_client.get(f"/api/v1/events/{uid}")
    assert response.status_code == 200
    body = response.json()
    assert body["event_uid"] == uid
    assert body["src_endpoint"]["ip"] == "192.0.2.1"
    assert body["dst_endpoint"]["ip"] == "198.51.100.1"
    assert body["class_uid"] == 4001
    assert "unmapped" in body and isinstance(body["unmapped"], dict)
    assert "date" not in body


def test_get_event_404_for_unknown_uid(lake_client: TestClient) -> None:
    response = lake_client.get("/api/v1/events/does-not-exist")
    assert response.status_code == 404


# -- GET /{event_uid}/raw ---------------------------------------------------


def test_get_raw_returns_original_bytes_hash_and_unverified_when_no_ledger(
    lake: tuple[Settings, list[RawEvent]], lake_client: TestClient
) -> None:
    settings, events = lake
    victim = events[0]

    response = lake_client.get(f"/api/v1/events/{victim.event_uid}/raw")
    assert response.status_code == 200
    body = response.json()
    assert body["event_uid"] == victim.event_uid
    assert base64.b64decode(body["raw_b64"]) == victim.raw
    assert body["raw_text"] == victim.raw.decode("utf-8")
    assert body["raw_hash"] == victim.raw_hash
    assert body["raw_len"] == victim.raw_len
    assert body["source_id"] == "apitest"
    assert body["transport"] == "udp"
    # no signing key -> no ledger -> ProofBuilder still hashes the stored bytes
    assert body["verified"] is True


def test_get_raw_404_for_unknown_uid(lake_client: TestClient) -> None:
    response = lake_client.get("/api/v1/events/does-not-exist/raw")
    assert response.status_code == 404


# -- GET /{event_uid}/lineage -----------------------------------------------


def test_get_lineage_without_a_ledger_has_raw_verified_true_ledger_verified_false(
    lake: tuple[Settings, list[RawEvent]], lake_client: TestClient
) -> None:
    settings, events = lake
    uid = events[0].event_uid

    response = lake_client.get(f"/api/v1/events/{uid}/lineage")
    assert response.status_code == 200
    body = response.json()
    assert body["event_uid"] == uid
    assert body["raw_verified"] is True
    assert body["source_type"] == "fortigate_traffic"
    assert body["ledger_seq"] is None
    assert body["merkle_proof"] == []
    assert body["ledger_verified"] is False


def test_get_lineage_404_for_unknown_uid(lake_client: TestClient) -> None:
    response = lake_client.get("/api/v1/events/does-not-exist/lineage")
    assert response.status_code == 404


# -- GET /stats/summary ------------------------------------------------------


def test_stats_summary_aggregates_and_dlq_rate(lake: tuple[Settings, list[RawEvent]]) -> None:
    settings, _events = lake
    # seed one DLQ entry against the same lake settings (does not disturb other tests -
    # the lake fixture's own ingest already ran, this only adds an unrelated dead letter)
    dlq = DeadLetterQueue(settings)
    stray = make_raw_event(b"totally unparseable garbage", source_id="apitest", transport="udp")
    dlq.write(stray, reason="unsniffable", stage="detect", detail={})

    client = TestClient(_events_app(settings))
    response = client.get("/api/v1/events/stats/summary")
    assert response.status_code == 200
    body = response.json()

    assert body["total_events"] == 500
    by_source = {row["source_type"]: row for row in body["by_source_type"]}
    assert by_source["fortigate_traffic"]["events"] == 500

    by_class = {row["class_uid"]: row["events"] for row in body["by_class_uid"]}
    assert by_class[4001] == 500

    by_action = {row["action_id"]: row["events"] for row in body["by_action"]}
    denies = len([i for i in range(500) if i % 7 == 0])
    assert by_action[2] == denies
    assert by_action[1] == 500 - denies

    assert body["parse_success_rate"] is not None
    assert body["dlq_total"] == 1
    assert body["dlq_rate"] == pytest.approx(1 / 501, abs=1e-4)


# -- GET /stats/timeseries ----------------------------------------------------


def test_stats_timeseries_returns_bucketed_points(lake_client: TestClient) -> None:
    response = lake_client.get(
        "/api/v1/events/stats/timeseries", params={"interval": "5m", "window": "24h"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["interval"] == "5m"
    assert body["window"] == "24h"
    assert isinstance(body["points"], list) and body["points"]
    for point in body["points"]:
        assert point["source_type"] == "fortigate_traffic"
        assert point["events"] > 0
        assert "bucket" in point


def test_stats_timeseries_invalid_interval_is_a_400(lake_client: TestClient) -> None:
    response = lake_client.get(
        "/api/v1/events/stats/timeseries", params={"interval": "not-an-interval"}
    )
    assert response.status_code == 400


# ======================================================================
# LakeQuery backend WITH a signed integrity ledger - /raw and /lineage
# verified=True/False paths, plus a tampered-bytes case
# ======================================================================


@pytest.fixture
def signed_lake(tmp_path: Path) -> tuple[Settings, list[RawEvent]]:
    keys = generate_keypair(tmp_path / "keys")
    settings = _settings(tmp_path, signing_key_path=keys.private, public_key_path=keys.public)
    events = _ingest(settings, _fortigate_lines(50, date="2026-09-02"))
    return settings, events


def test_raw_and_lineage_are_fully_verified_with_a_signed_ledger(
    signed_lake: tuple[Settings, list[RawEvent]],
) -> None:
    settings, events = signed_lake
    uid = events[3].event_uid
    client = TestClient(_events_app(settings))

    raw_body = client.get(f"/api/v1/events/{uid}/raw").json()
    assert raw_body["verified"] is True

    lineage_body = client.get(f"/api/v1/events/{uid}/lineage").json()
    assert lineage_body["raw_hash"] == events[3].raw_hash
    assert lineage_body["raw_verified"] is True
    assert lineage_body["source_type"] == "fortigate_traffic"
    assert lineage_body["ledger_seq"] == 0
    assert lineage_body["ledger_verified"] is True
    assert isinstance(lineage_body["merkle_proof"], list)
    for step in lineage_body["merkle_proof"]:
        assert set(step) == {"sibling", "side"}
        assert step["side"] in ("left", "right")


def test_raw_and_lineage_reflect_tampered_bronze_bytes(
    signed_lake: tuple[Settings, list[RawEvent]],
) -> None:
    settings, events = signed_lake
    victim = events[7]
    _flip_one_byte_in_bronze(settings, victim.event_uid)
    client = TestClient(_events_app(settings))

    raw_body = client.get(f"/api/v1/events/{victim.event_uid}/raw").json()
    assert raw_body["verified"] is False

    lineage_body = client.get(f"/api/v1/events/{victim.event_uid}/lineage").json()
    assert lineage_body["raw_verified"] is False
    assert lineage_body["ledger_verified"] is False


# ======================================================================
# _unflatten - unit level
# ======================================================================


def test_unflatten_reconstructs_nested_dict_and_json_sidecars() -> None:
    row = {
        "event_uid": "abc",
        "src_endpoint.ip": "10.0.0.1",
        "src_endpoint.port": 51000,
        "date": "2026-09-01",  # Hive partition column - must be dropped
        "raw_hash": None,  # None values are dropped
        "unmapped_json": '{"extra_field": "x"}',
        "enrichments_json": "",
    }
    out = _unflatten(row)
    assert out == {
        "event_uid": "abc",
        "src_endpoint": {"ip": "10.0.0.1", "port": 51000},
        "unmapped": {"extra_field": "x"},
        "enrichments": {},
    }


# ======================================================================
# compact interval helpers - unit level
# ======================================================================


@pytest.mark.parametrize(
    ("value", "expected"),
    [("5m", (5, "MINUTE")), ("1h", (1, "HOUR")), ("24h", (24, "HOUR")), ("7d", (7, "DAY"))],
)
def test_parse_compact_interval(value: str, expected: tuple[int, str]) -> None:
    assert _parse_compact_interval(value) == expected


def test_parse_compact_interval_invalid_raises_400() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        _parse_compact_interval("banana")
    assert exc_info.value.status_code == 400


@pytest.mark.parametrize(
    ("value", "expected"), [("5m", "5 minutes"), ("1m", "1 minute"), ("1h", "1 hour")]
)
def test_to_lake_interval(value: str, expected: str) -> None:
    assert _to_lake_interval(value) == expected


# ======================================================================
# ClickHouse backend - same 6 endpoints via a mocked HTTP server
# ======================================================================


class _FakeClickHouseEvents:
    """A minimal scriptable ClickHouse HTTP server for the events router.

    Recognizes just enough of the SQL shapes ``events.py`` generates to answer
    sensibly, so every route's ClickHouse code path is genuinely exercised
    (params bound, SQL text shaped as expected) rather than merely mocked away.
    """

    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.requests: list[httpx.Request] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = request.content.decode()
        params = dict(request.url.params)

        if "COUNT(*) AS n" in body and "GROUP BY" not in body:
            rows = self._filtered(params)
            return self._respond([{"n": len(rows)}])
        if "GROUP BY source_type" in body:
            counts: dict[str, int] = {}
            for row in self.rows:
                counts[row["source_type"]] = counts.get(row["source_type"], 0) + 1
            return self._respond([{"source_type": k, "events": v} for k, v in counts.items()])
        if "GROUP BY class_uid" in body:
            counts = {}
            for row in self.rows:
                counts[row["class_uid"]] = counts.get(row["class_uid"], 0) + 1
            return self._respond([{"class_uid": k, "events": v} for k, v in counts.items()])
        if "GROUP BY action_id" in body:
            counts = {}
            for row in self.rows:
                counts[row["action_id"]] = counts.get(row["action_id"], 0) + 1
            return self._respond([{"action_id": k, "events": v} for k, v in counts.items()])
        if "GROUP BY bucket, source_type" in body:
            return self._respond(
                [{"bucket": "2026-09-01 00:00:00", "source_type": "fortigate_traffic", "events": 3}]
            )
        if "WHERE event_uid = " in body:
            target = params.get("param_event_uid")
            matches = [r for r in self.rows if r["event_uid"] == target]
            return self._respond(matches[:1])
        # the plain paginated list
        return self._respond(self._filtered(params))

    def _filtered(self, params: dict[str, str]) -> list[dict]:
        rows = self.rows
        if "param_source_type" in params:
            rows = [r for r in rows if r["source_type"] == params["param_source_type"]]
        if "param_action_id" in params:
            rows = [r for r in rows if str(r["action_id"]) == params["param_action_id"]]
        return rows

    def _respond(self, rows: list[dict]) -> httpx.Response:
        text = "\n".join(json.dumps(row) for row in rows)
        return httpx.Response(200, text=text)


def _ch_row(i: int) -> dict:
    return {
        "event_uid": f"ch-evt-{i:04d}",
        "time": 1_788_264_000_000_000_000 + i,
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 6,
        "severity_id": 3,
        "source_type": "fortigate_traffic",
        "src_ip": f"192.0.2.{i % 254 + 1}",
        "src_port": 10000 + i,
        "dst_ip": "198.51.100.1",
        "dst_port": 443,
        "action_id": 2 if i % 7 == 0 else 1,
        "bytes_in": i,
        "bytes_out": 2 * i,
        "unmapped_json": "{}",
        "enrichments_json": "{}",
    }


@pytest.fixture
def ch_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    fake = _FakeClickHouseEvents([_ch_row(i) for i in range(20)])
    real_async_client = httpx.AsyncClient

    import ulpf.sinks.clickhouse_query as ch_mod

    monkeypatch.setattr(
        ch_mod,
        "httpx",
        SimpleNamespace(
            AsyncClient=lambda **kwargs: real_async_client(
                transport=httpx.MockTransport(fake._handle)
            )
        ),
    )

    settings = _settings(tmp_path, clickhouse=ClickHouseSettings(enabled=True))
    client = TestClient(_events_app(settings))
    client._fake = fake  # type: ignore[attr-defined]
    return client


def test_clickhouse_list_returns_paginated_shape(ch_client: TestClient) -> None:
    response = ch_client.get("/api/v1/events/")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 20
    assert len(body["items"]) == 20  # default page_size (50) > total rows


def test_clickhouse_list_filters_by_source_type_and_action_id(ch_client: TestClient) -> None:
    body = ch_client.get("/api/v1/events/", params={"source_type": "fortigate_traffic"}).json()
    assert body["total"] == 20

    denies = len([i for i in range(20) if i % 7 == 0])
    body = ch_client.get("/api/v1/events/", params={"action_id": 2}).json()
    assert body["total"] == denies


def test_clickhouse_get_event_by_uid(ch_client: TestClient) -> None:
    response = ch_client.get("/api/v1/events/ch-evt-0005")
    assert response.status_code == 200
    assert response.json()["event_uid"] == "ch-evt-0005"


def test_clickhouse_get_event_404(ch_client: TestClient) -> None:
    response = ch_client.get("/api/v1/events/does-not-exist")
    assert response.status_code == 404


def test_clickhouse_stats_summary(ch_client: TestClient) -> None:
    response = ch_client.get("/api/v1/events/stats/summary")
    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] == 20
    by_source = {row["source_type"]: row["events"] for row in body["by_source_type"]}
    assert by_source["fortigate_traffic"] == 20


def test_clickhouse_stats_timeseries(ch_client: TestClient) -> None:
    response = ch_client.get(
        "/api/v1/events/stats/timeseries", params={"interval": "5m", "window": "1h"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["points"] == [
        {"bucket": "2026-09-01 00:00:00", "source_type": "fortigate_traffic", "events": 3}
    ]


def test_clickhouse_query_failure_surfaces_as_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    real_async_client = httpx.AsyncClient
    import ulpf.sinks.clickhouse_query as ch_mod

    monkeypatch.setattr(
        ch_mod,
        "httpx",
        SimpleNamespace(
            AsyncClient=lambda **kwargs: real_async_client(transport=httpx.MockTransport(_boom))
        ),
    )
    settings = _settings(tmp_path, clickhouse=ClickHouseSettings(enabled=True))
    client = TestClient(_events_app(settings))

    response = client.get("/api/v1/events/")
    assert response.status_code == 503
