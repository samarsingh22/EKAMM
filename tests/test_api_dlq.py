"""Tests for :mod:`ulpf.api.routes.dlq` — every ``/api/v1/dlq`` endpoint."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ulpf.api.routes.dlq import build_dlq_router
from ulpf.config.settings import ParseSettings, Settings, StorageSettings
from ulpf.core.models import DeadLetter, RawEvent
from ulpf.integrity.hashing import make_raw_event
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.raw_store import RawStore

_REPO = Path(__file__).resolve().parent.parent
_TODAY = dt.datetime.now(dt.UTC).date().isoformat()

# Detected and normalized cleanly by configs/sources/fortigate_traffic.yaml -
# stands in for "a dead letter that now replays successfully".
_GOOD_LINE = (
    f'<189>date={_TODAY} time=22:14:05 devname="FGT" logid="0000000013" '
    'type="traffic" subtype="forward" srcip=10.0.0.9 srcport=51000 '
    'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=100 rcvdbyte=200'
).encode()

# date/time cannot be parsed -> mapping fails again on replay, every time.
_BAD_LINE = (
    b'<189>date=not-a-date time=not-a-time devname="FGT" logid="0000000013" '
    b'type="traffic" subtype="forward" srcip=10.0.0.10 srcport=51000 '
    b'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=0 rcvdbyte=0'
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            state_path=tmp_path / "state",
        ),
        parse=ParseSettings(sources_dir=_REPO / "configs" / "sources"),
    )


def _seed_dlq_entry(
    settings: Settings, raw: bytes, *, reason: str, stage: str
) -> tuple[RawEvent, DeadLetter]:
    store = RawStore(settings)
    event = make_raw_event(raw, source_id="t", transport="udp")
    store.write(event)
    store.flush()
    entry = DeadLetterQueue(settings).write(
        event, reason=reason, stage=stage, detail={"note": "seeded for test"}
    )
    return event, entry


def _app(settings: Settings) -> FastAPI:
    app = FastAPI()
    app.include_router(build_dlq_router(settings), prefix="/api/v1")
    return app


def _silver_rows(settings: Settings) -> list[dict]:
    silver = Path(settings.storage.silver_path)
    return [
        row
        for path in silver.rglob("part-*.parquet")
        for row in pq.ParquetFile(path).read().to_pylist()
    ]


@pytest.fixture
def wired(tmp_path: Path) -> tuple[Settings, TestClient]:
    settings = _settings(tmp_path)
    return settings, TestClient(_app(settings))


# ======================================================================
# GET /
# ======================================================================


def test_list_returns_newest_first_with_previews(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    first, entry1 = _seed_dlq_entry(settings, _GOOD_LINE, reason="mapping_error", stage="normalize")
    second, entry2 = _seed_dlq_entry(settings, _BAD_LINE, reason="unsniffable", stage="detect")

    response = client.get("/api/v1/dlq/")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["page"] == 1 and body["page_size"] == 50
    assert [item["event_uid"] for item in body["items"]] == [entry2.event_uid, entry1.event_uid]

    newest = body["items"][0]
    assert newest["reason"] == "unsniffable"
    assert newest["stage"] == "detect"
    assert newest["raw_preview"] == _BAD_LINE.decode()
    assert newest["raw_truncated"] is False
    assert newest["resolved"] is False
    assert newest["detail"] == {"note": "seeded for test"}


def test_list_truncates_a_long_raw_preview(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    long_raw = b"x" * 500
    _seed_dlq_entry(settings, long_raw, reason="huge", stage="parse")

    (item,) = client.get("/api/v1/dlq/").json()["items"]
    assert len(item["raw_preview"]) == 300
    assert item["raw_truncated"] is True


def test_list_filters_by_reason(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    _seed_dlq_entry(settings, _GOOD_LINE, reason="reason_a", stage="normalize")
    _seed_dlq_entry(settings, _BAD_LINE, reason="reason_b", stage="parse")

    body = client.get("/api/v1/dlq/", params={"reason": "reason_a"}).json()
    assert body["total"] == 1
    assert body["items"][0]["reason"] == "reason_a"


def test_list_filters_by_stage(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    _seed_dlq_entry(settings, _GOOD_LINE, reason="r", stage="normalize")
    _seed_dlq_entry(settings, _BAD_LINE, reason="r", stage="validate")

    body = client.get("/api/v1/dlq/", params={"stage": "validate"}).json()
    assert body["total"] == 1
    assert body["items"][0]["stage"] == "validate"


def test_list_filters_unresolved_only(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    _event, entry = _seed_dlq_entry(settings, _GOOD_LINE, reason="r", stage="normalize")
    DeadLetterQueue(settings).mark_resolved(entry.event_uid)
    _seed_dlq_entry(settings, _BAD_LINE, reason="r", stage="normalize")

    body = client.get("/api/v1/dlq/", params={"unresolved_only": True}).json()
    assert body["total"] == 1

    all_body = client.get("/api/v1/dlq/").json()
    assert all_body["total"] == 2
    resolved_item = next(i for i in all_body["items"] if i["event_uid"] == entry.event_uid)
    assert resolved_item["resolved"] is True


def test_list_pagination(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    for i in range(5):
        _seed_dlq_entry(settings, f"line {i}".encode(), reason="r", stage="normalize")

    page1 = client.get("/api/v1/dlq/", params={"page": 1, "page_size": 2}).json()
    page2 = client.get("/api/v1/dlq/", params={"page": 2, "page_size": 2}).json()
    assert len(page1["items"]) == 2
    assert len(page2["items"]) == 2
    assert page1["total"] == 5
    uids1 = {i["event_uid"] for i in page1["items"]}
    uids2 = {i["event_uid"] for i in page2["items"]}
    assert uids1.isdisjoint(uids2)


def test_list_empty_queue(wired: tuple[Settings, TestClient]) -> None:
    _settings_, client = wired
    body = client.get("/api/v1/dlq/").json()
    assert body == {"items": [], "total": 0, "page": 1, "page_size": 50}


# ======================================================================
# GET /stats
# ======================================================================


def test_stats_counts_by_reason_and_stage(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    _seed_dlq_entry(settings, _GOOD_LINE, reason="mapping_error", stage="normalize")
    _seed_dlq_entry(settings, _GOOD_LINE, reason="mapping_error", stage="normalize")
    _seed_dlq_entry(settings, _BAD_LINE, reason="unsniffable", stage="detect")

    body = client.get("/api/v1/dlq/stats").json()
    assert body["total"] == 3
    assert body["resolved"] == 0
    assert body["unresolved"] == 3
    assert body["by_reason"] == {"mapping_error": 2, "unsniffable": 1}
    assert body["by_stage"] == {"normalize": 2, "detect": 1}


def test_stats_on_an_empty_queue_is_a_clean_zero(wired: tuple[Settings, TestClient]) -> None:
    _settings_, client = wired
    body = client.get("/api/v1/dlq/stats").json()
    assert body["total"] == 0 and body["by_reason"] == {} and body["by_stage"] == {}


# ======================================================================
# POST /replay
# ======================================================================


def test_replay_success_marks_resolved_and_writes_to_sinks(
    wired: tuple[Settings, TestClient],
) -> None:
    settings, client = wired
    event, entry = _seed_dlq_entry(settings, _GOOD_LINE, reason="old_parser_bug", stage="normalize")

    response = client.post("/api/v1/dlq/replay", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["candidates"] == 1
    assert body["succeeded"] == 1
    assert body["written"] == 1
    assert body["dry_run"] is False

    dlq = DeadLetterQueue(settings)
    assert dlq.resolved_event_uids() == {entry.event_uid}
    rows = _silver_rows(settings)
    assert len(rows) == 1
    assert rows[0]["event_uid"] == event.event_uid


def test_replay_dry_run_previews_without_writing_or_resolving(
    wired: tuple[Settings, TestClient],
) -> None:
    settings, client = wired
    _event, entry = _seed_dlq_entry(
        settings, _GOOD_LINE, reason="old_parser_bug", stage="normalize"
    )

    body = client.post("/api/v1/dlq/replay", json={"dry_run": True}).json()
    assert body["dry_run"] is True
    assert body["candidates"] == 1
    assert body["succeeded"] == 1
    assert body["written"] == 0

    assert DeadLetterQueue(settings).resolved_event_uids() == set()
    assert _silver_rows(settings) == []
    assert entry.event_uid  # still a candidate: not resolved


def test_replay_still_failing_stays_unresolved(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    _event, entry = _seed_dlq_entry(settings, _BAD_LINE, reason="seeded_broken", stage="parse")

    body = client.post("/api/v1/dlq/replay", json={}).json()
    assert body["candidates"] == 1
    assert body["succeeded"] == 0
    assert body["still_failing"] == 1

    dlq = DeadLetterQueue(settings)
    assert entry.event_uid not in dlq.resolved_event_uids()
    assert dlq.stats()["total"] == 2  # dead-lettered again -> a second entry


def test_replay_reason_filter_only_touches_matching_entries(
    wired: tuple[Settings, TestClient],
) -> None:
    settings, client = wired
    _event, fixable = _seed_dlq_entry(
        settings, _GOOD_LINE, reason="fixed_reason", stage="normalize"
    )
    _event2, other = _seed_dlq_entry(settings, _GOOD_LINE, reason="other_reason", stage="normalize")

    body = client.post("/api/v1/dlq/replay", json={"reason": "fixed_reason"}).json()
    assert body["candidates"] == 1 and body["succeeded"] == 1

    resolved = DeadLetterQueue(settings).resolved_event_uids()
    assert resolved == {fixable.event_uid}
    assert other.event_uid not in resolved


def test_replay_since_filter_excludes_older_entries(wired: tuple[Settings, TestClient]) -> None:
    settings, client = wired
    _seed_dlq_entry(settings, _GOOD_LINE, reason="old_parser_bug", stage="normalize")

    future = (dt.datetime.now(dt.UTC) + dt.timedelta(days=1)).date().isoformat()
    excluded = client.post("/api/v1/dlq/replay", json={"since": future})
    assert excluded.json()["candidates"] == 0

    past = (dt.datetime.now(dt.UTC) - dt.timedelta(days=1)).date().isoformat()
    included = client.post("/api/v1/dlq/replay", json={"since": past})
    assert included.json()["candidates"] == 1


def test_replay_on_an_empty_queue_is_a_clean_no_op(wired: tuple[Settings, TestClient]) -> None:
    _settings_, client = wired
    body = client.post("/api/v1/dlq/replay", json={}).json()
    assert body == {
        "reason": None,
        "since": None,
        "dry_run": False,
        "candidates": 0,
        "succeeded": 0,
        "still_failing": 0,
        "written": 0,
    }
