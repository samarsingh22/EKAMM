"""Tests for :mod:`ulpf.parse.templates.store`."""

from __future__ import annotations

from pathlib import Path

import pytest

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.parse.templates.store import TemplateStore

_BASE_NS = 1_788_600_000_000_000_000


class _Clock:
    """A settable epoch-nanoseconds clock."""

    def __init__(self, start: int = _BASE_NS) -> None:
        self.t = start

    def __call__(self) -> int:
        return self.t

    def advance(self, ns: int = 1_000_000_000) -> None:
        self.t += ns


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(state_path=tmp_path / "state"))


def _store(tmp_path: Path, clock: _Clock | None = None) -> TemplateStore:
    return TemplateStore(_settings(tmp_path), clock=clock or _Clock())


# --------------------------------------------------------------------------
# record()


def test_record_creates_a_row_with_the_full_schema(tmp_path: Path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock)
    rec = store.record(1, "connect from <IP>:<PORT>", "fw1", "connect from 10.0.0.1:22")

    assert rec.template_id == "1"
    assert rec.template == "connect from <IP>:<PORT>"
    assert rec.source_id == "fw1"
    assert rec.first_seen_ns == _BASE_NS
    assert rec.last_seen_ns == _BASE_NS
    assert rec.count == 1
    assert rec.sample_lines == ["connect from 10.0.0.1:22"]
    assert rec.suggested_fields == ["IP", "PORT"]
    assert rec.recent_ns == [_BASE_NS]

    (row,) = store.list_templates()
    assert set(row) == {
        "template_id",
        "template",
        "source_id",
        "first_seen_ns",
        "last_seen_ns",
        "count",
        "sample_lines",
        "suggested_fields",
        "recent_ns",
    }


def test_record_accumulates_count_and_last_seen_but_keeps_first_seen(tmp_path: Path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock)
    store.record(1, "t <NUM>", "fw1", "t 1")
    clock.advance()
    clock.advance()
    rec = store.record(1, "t <NUM>", "fw1", "t 2")

    assert rec.count == 2
    assert rec.first_seen_ns == _BASE_NS
    assert rec.last_seen_ns == _BASE_NS + 2_000_000_000


def test_sample_lines_are_capped_at_five(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for i in range(9):
        store.record(1, "t <NUM>", "fw1", f"t {i}")

    (row,) = store.list_templates()
    assert row["count"] == 9
    assert row["sample_lines"] == ["t 0", "t 1", "t 2", "t 3", "t 4"]


def test_recent_ns_accumulates_one_timestamp_per_occurrence(tmp_path: Path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock)
    for _ in range(5):
        store.record(1, "t <NUM>", "fw1", "t x")
        clock.advance()

    (row,) = store.list_templates()
    assert row["recent_ns"] == [_BASE_NS + i * 1_000_000_000 for i in range(5)]


def test_recent_ns_is_capped_and_keeps_only_the_most_recent(tmp_path: Path) -> None:
    from ulpf.parse.templates.store import _MAX_RECENT_TIMESTAMPS

    clock = _Clock()
    store = _store(tmp_path, clock)
    total = _MAX_RECENT_TIMESTAMPS + 50
    for _ in range(total):
        store.record(1, "t <NUM>", "fw1", "t x")
        clock.advance()

    (row,) = store.list_templates()
    assert row["count"] == total
    assert len(row["recent_ns"]) == _MAX_RECENT_TIMESTAMPS
    # the earliest 50 occurrences fell off; the tail is the most recent ones
    assert row["recent_ns"][0] == _BASE_NS + 50 * 1_000_000_000
    assert row["recent_ns"][-1] == _BASE_NS + (total - 1) * 1_000_000_000


def test_same_template_id_from_two_sources_are_distinct_rows(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(1, "fw shape <IP>", "fw1", "fw shape 10.0.0.1")
    store.record(1, "ids shape <NUM>", "ids1", "ids shape 42")

    rows = store.list_templates(order_by="template_id")
    assert [(r["source_id"], r["template_id"], r["template"]) for r in rows] == [
        ("fw1", "1", "fw shape <IP>"),
        ("ids1", "1", "ids shape <NUM>"),
    ]


def test_suggested_fields_are_distinct_mask_names_in_first_seen_order(tmp_path: Path) -> None:
    store = _store(tmp_path)
    rec = store.record(1, "<TIMESTAMP> <IP> sent <BYTES> to <IP>:<PORT> id=<UUID>", "fw1", "raw")
    assert rec.suggested_fields == ["TIMESTAMP", "IP", "BYTES", "PORT", "UUID"]


# --------------------------------------------------------------------------
# list_templates()


def test_list_templates_orders_by_count_desc_by_default(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for _ in range(3):
        store.record(1, "a <NUM>", "fw1", "a")
    store.record(2, "b <NUM>", "fw1", "b")
    for _ in range(2):
        store.record(3, "c <NUM>", "fw1", "c")

    counts = [r["count"] for r in store.list_templates()]
    assert counts == [3, 2, 1]


def test_list_templates_can_order_by_last_seen(tmp_path: Path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock)
    store.record(1, "a <NUM>", "fw1", "a")
    clock.advance()
    store.record(2, "b <NUM>", "fw1", "b")
    clock.advance()
    store.record(1, "a <NUM>", "fw1", "a again")  # 1 is now the most recent

    ids = [r["template_id"] for r in store.list_templates(order_by="last_seen_ns")]
    assert ids == ["1", "2"]


def test_list_templates_filters_by_source_id(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(1, "a <NUM>", "fw1", "a")
    store.record(1, "b <NUM>", "ids1", "b")
    store.record(2, "c <NUM>", "fw1", "c")

    fw_rows = store.list_templates(source_id="fw1")
    assert {r["template"] for r in fw_rows} == {"a <NUM>", "c <NUM>"}
    assert len(store.list_templates(source_id="ids1")) == 1
    assert len(store.list_templates()) == 3


def test_list_templates_rejects_an_unknown_order_by(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="order_by"):
        store.list_templates(order_by="frequency")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# get_samples()


def test_get_samples_returns_the_recorded_lines(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(7, "t <NUM>", "fw1", "t 1")
    store.record(7, "t <NUM>", "fw1", "t 2")
    assert store.get_samples(7) == ["t 1", "t 2"]
    assert store.get_samples("7") == ["t 1", "t 2"]  # accepts str or int


def test_get_samples_disambiguates_by_source_id(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(1, "fw <IP>", "fw1", "fw line")
    store.record(1, "ids <NUM>", "ids1", "ids line")

    assert store.get_samples(1, source_id="ids1") == ["ids line"]
    assert store.get_samples(1, source_id="fw1") == ["fw line"]


def test_get_samples_is_empty_for_an_unknown_template(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(1, "t <NUM>", "fw1", "t 1")
    assert store.get_samples(999) == []
    assert store.get_samples(1, source_id="nope") == []


# --------------------------------------------------------------------------
# persistence


def test_catalog_persists_to_templates_json_and_reloads(tmp_path: Path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock)
    store.record(1, "a <IP>", "fw1", "a 10.0.0.1")
    clock.advance()
    store.record(1, "a <IP>", "fw1", "a 10.0.0.2")
    store.record(2, "b <NUM>", "ids1", "b 5")

    assert store.path == tmp_path / "state" / "templates.json"
    assert store.path.is_file()
    assert not list(store.path.parent.glob("*.tmp"))  # atomic write left no temp file

    reloaded = TemplateStore(_settings(tmp_path))
    rows = reloaded.list_templates(order_by="template_id")
    assert len(rows) == 2
    a = next(r for r in rows if r["template_id"] == "1")
    assert a["count"] == 2
    assert a["first_seen_ns"] == _BASE_NS
    assert a["last_seen_ns"] == _BASE_NS + 1_000_000_000
    assert a["sample_lines"] == ["a 10.0.0.1", "a 10.0.0.2"]
    assert reloaded.get_samples(2, source_id="ids1") == ["b 5"]


def test_corrupt_catalog_file_is_ignored_not_fatal(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "templates.json").write_text("{ this is not json", encoding="utf-8")

    store = TemplateStore(_settings(tmp_path))  # must not raise
    assert store.list_templates() == []
    store.record(1, "t <NUM>", "fw1", "t 1")  # and still usable
    assert len(store.list_templates()) == 1


# --------------------------------------------------------------------------
# metrics


def test_templates_total_gauge_tracks_distinct_templates_per_source(tmp_path: Path) -> None:
    store = _store(tmp_path)
    src = "store-metrics-gauge-src"
    store.record(1, "a <NUM>", src, "a")
    store.record(2, "b <NUM>", src, "b")
    store.record(1, "a <NUM>", src, "a again")  # not a new template

    key = f'ulpf_templates_total{{source_id="{src}"}}'
    assert snapshot()[key] == 2.0


def test_template_events_counter_increments_on_every_record(tmp_path: Path) -> None:
    store = _store(tmp_path)
    tid = "store-metrics-counter-tid"
    key = f'ulpf_template_events_total{{template_id="{tid}"}}'
    before = snapshot().get(key, 0.0)

    store.record(tid, "t <NUM>", "fw1", "t 1")
    store.record(tid, "t <NUM>", "fw1", "t 2")
    store.record(tid, "t <NUM>", "fw1", "t 3")

    assert snapshot()[key] - before == 3.0


def test_gauges_are_restored_on_reload(tmp_path: Path) -> None:
    src = "store-metrics-reload-src"
    first = _store(tmp_path)
    first.record(1, "a <NUM>", src, "a")
    first.record(2, "b <NUM>", src, "b")
    first.record(3, "c <NUM>", src, "c")

    key = f'ulpf_templates_total{{source_id="{src}"}}'

    # a fresh process loading the same catalog must re-publish the gauge
    TemplateStore(_settings(tmp_path))
    assert snapshot()[key] == 3.0
