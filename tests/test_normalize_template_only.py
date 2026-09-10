"""Tests for :meth:`ulpf.normalize.stage.NormalizeStage._template_only` —

a line that matches no source YAML is never dropped: it is mined for its shape
and emitted as a minimal OCSF 4001 skeleton, recorded to the template store as
a candidate for an auto-generated parser.
"""

from __future__ import annotations

from pathlib import Path

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.core.models import NormalizedEvent, ParsedEvent
from ulpf.core.timeutil import parse_timestamp
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.templates import TemplateMinerRegistry, TemplateStore
from ulpf.sinks.dlq import DeadLetterQueue

_REPO = Path(__file__).resolve().parent.parent
_DRAIN_INI = _REPO / "configs" / "drain3.ini"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            dlq_path=tmp_path / "dlq",
            bronze_path=tmp_path / "b",
            state_path=tmp_path / "state",
        )
    )


def _empty_registry(tmp_path: Path) -> SourceRegistry:
    directory = tmp_path / "sources"
    directory.mkdir(parents=True, exist_ok=True)
    registry = SourceRegistry()
    registry.load_all(directory)  # nothing loaded -> nothing ever matches
    return registry


def _stage(tmp_path: Path) -> tuple[NormalizeStage, TemplateStore]:
    settings = _settings(tmp_path)
    store = TemplateStore(settings)
    miners = TemplateMinerRegistry(settings, config_path=_DRAIN_INI)
    stage = NormalizeStage(settings, _empty_registry(tmp_path), miners=miners, template_store=store)
    return stage, store


def _parsed(
    raw_bytes: bytes,
    *,
    fields: dict[str, str] | None = None,
    envelope: dict[str, object] | None = None,
    source_id: str = "syslog-udp",
) -> ParsedEvent:
    raw = make_raw_event(raw_bytes, source_id=source_id, transport="udp")
    return ParsedEvent(
        **raw.model_dump(),
        format="unknown",
        fields=fields or {},
        envelope=envelope or {},
        needs_template_mining=True,
    )


_LINE_A = b"<13>Oct 11 22:14:15 host weirddaemon: connection from 10.0.0.5 port 4444 failed code 7"
_ENV_A: dict[str, object] = {
    "format": "rfc3164",
    "timestamp": "Oct 11 22:14:15",
    "hostname": "host",
    "header_raw": "<13>Oct 11 22:14:15 host weirddaemon: ",
}


# --------------------------------------------------------------------------
# the skeleton record


async def test_unmatched_line_becomes_a_template_only_ocsf_4001_skeleton(tmp_path: Path) -> None:
    stage, _store = _stage(tmp_path)
    event = _parsed(_LINE_A, fields={"a": "1", "b": "2"}, envelope=dict(_ENV_A))

    result = await stage.process(event)

    assert isinstance(result, NormalizedEvent)
    assert result.source_type.startswith("unknown:")
    assert result.mapping_version == "none"

    ocsf = result.ocsf
    assert ocsf["class_uid"] == 4001
    assert ocsf["category_uid"] == 4
    assert ocsf["class_name"] == "Network Activity"  # finalize ran
    assert ocsf["metadata"]["uid"] == event.event_uid  # requirement (d)
    assert ocsf["metadata"]["log_hash"] == event.raw_hash
    assert ocsf["unmapped"] == {"a": "1", "b": "2"}  # every extracted field, verbatim
    assert ocsf["enrichments"]["parse_status"] == "template_only"
    assert result.enrichment["parse_status"] == "template_only"
    assert result.enrichment["needs_template_mining"] is True

    # traceability carried through
    assert result.event_uid == event.event_uid
    assert result.raw_hash == event.raw_hash


async def test_template_only_event_is_never_dead_lettered(tmp_path: Path) -> None:
    stage, _store = _stage(tmp_path)
    await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))
    assert DeadLetterQueue(_settings(tmp_path)).stats()["total"] == 0


async def test_source_type_encodes_the_template_id(tmp_path: Path) -> None:
    stage, store = _stage(tmp_path)
    result = await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))

    template_id = result.source_type.split(":", 1)[1]
    assert result.ocsf["enrichments"]["template_id"] == template_id
    # and that id exists in the store
    assert store.get_samples(template_id, source_id="syslog-udp")


# --------------------------------------------------------------------------
# time inference


async def test_time_comes_from_the_syslog_envelope_when_present(tmp_path: Path) -> None:
    stage, _store = _stage(tmp_path)
    result = await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))
    assert result.ocsf["time"] == parse_timestamp("Oct 11 22:14:15")


async def test_time_falls_back_to_ingest_time_without_an_envelope(tmp_path: Path) -> None:
    stage, _store = _stage(tmp_path)
    event = _parsed(b"just an ordinary sentence with no envelope", envelope={})
    result = await stage.process(event)
    assert result.ocsf["time"] == event.ingest_time_ns


async def test_time_falls_back_to_ingest_time_on_an_unparseable_envelope_timestamp(
    tmp_path: Path,
) -> None:
    stage, _store = _stage(tmp_path)
    event = _parsed(_LINE_A, envelope={"format": "rfc3164", "timestamp": "not-a-timestamp"})
    result = await stage.process(event)
    assert result.ocsf["time"] == event.ingest_time_ns


# --------------------------------------------------------------------------
# template store integration


async def test_the_shape_is_recorded_to_the_template_store(tmp_path: Path) -> None:
    stage, store = _stage(tmp_path)
    event = _parsed(_LINE_A, envelope=dict(_ENV_A))

    result = await stage.process(event)
    template_id = result.source_type.split(":", 1)[1]

    (row,) = store.list_templates()
    assert row["template_id"] == template_id
    assert row["source_id"] == "syslog-udp"
    assert row["count"] == 1
    # header stripped: the template is about the message, not the envelope
    assert row["template"] == "connection from <IP> port <NUM> failed code <NUM>"
    assert row["suggested_fields"] == ["IP", "NUM"]
    assert row["sample_lines"] == ["connection from 10.0.0.5 port 4444 failed code 7"]


async def test_same_shape_twice_is_one_template_counted_twice(tmp_path: Path) -> None:
    stage, store = _stage(tmp_path)
    line2 = (
        b"<13>Oct 11 23:00:00 host weirddaemon: connection from 192.0.2.9 port 51000 failed code 3"
    )
    env2 = {
        **_ENV_A,
        "timestamp": "Oct 11 23:00:00",
        "header_raw": "<13>Oct 11 23:00:00 host weirddaemon: ",
    }

    first = await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))
    second = await stage.process(_parsed(line2, envelope=env2))

    assert first.source_type == second.source_type  # same template
    (row,) = store.list_templates()
    assert row["count"] == 2


async def test_different_shapes_get_different_template_ids(tmp_path: Path) -> None:
    stage, store = _stage(tmp_path)
    other = b"<13>Oct 11 22:20:00 host otherdaemon: shutdown complete"
    env_other = {
        **_ENV_A,
        "timestamp": "Oct 11 22:20:00",
        "header_raw": "<13>Oct 11 22:20:00 host otherdaemon: ",
    }

    a = await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))
    b = await stage.process(_parsed(other, envelope=env_other))

    assert a.source_type != b.source_type
    assert len(store.list_templates()) == 2


# --------------------------------------------------------------------------
# metrics


async def test_unknown_events_metric_increments_per_template(tmp_path: Path) -> None:
    stage, _store = _stage(tmp_path)
    result = await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))
    template_id = result.source_type.split(":", 1)[1]

    key = f'ulpf_unknown_events_total{{template_id="{template_id}"}}'
    before = snapshot().get(key, 0.0)
    await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))
    await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))
    assert snapshot()[key] - before == 2.0


# --------------------------------------------------------------------------
# validate stage lets it through


async def test_validate_stage_passes_template_only_records_through_untouched(
    tmp_path: Path,
) -> None:
    stage, _store = _stage(tmp_path)
    settings = _settings(tmp_path)
    registry = _empty_registry(tmp_path / "v")
    normalized = await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))

    result = await ValidateStage(settings, registry).process(normalized)

    assert result is normalized  # not validated, not dead-lettered
    assert DeadLetterQueue(settings).stats()["total"] == 0


# --------------------------------------------------------------------------
# default construction (no injected miner/store) still works


async def test_normalize_stage_builds_its_own_miner_and_store_by_default(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    stage = NormalizeStage(settings, _empty_registry(tmp_path))  # no miners/template_store kwargs

    result = await stage.process(_parsed(_LINE_A, envelope=dict(_ENV_A)))

    assert result.source_type.startswith("unknown:")
    assert (settings.storage.state_path / "templates.json").is_file()
