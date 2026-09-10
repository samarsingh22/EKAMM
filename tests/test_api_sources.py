"""Tests for :mod:`ulpf.api.routes.sources` — every ``/api/v1/sources`` endpoint."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ulpf.api.routes.sources import build_sources_router
from ulpf.config.settings import (
    EnrichSettings,
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
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.manager import SinkManager
from ulpf.sinks.raw_store import RawStore

_REPO = Path(__file__).resolve().parent.parent

_ACME_YAML = """\
name: acme_fw
version: "1.0.0"
vendor: Acme
product: Acme Firewall
product_version: "1.0"
priority: 50

detect:
  contains: '"vendor": "ACMEFW"'

parse:
  envelope: none
  engine: json
  options: {}

normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  constants:
    metadata.product.vendor_name: Acme
    metadata.product.name: Acme Firewall
    severity_id: 1
  fields:
    src_endpoint.ip: {from: src_ip, type: ip, required: true}
    src_endpoint.port: {from: src_port, type: int}
    dst_endpoint.ip: {from: dst_ip, type: ip, required: true}
    dst_endpoint.port: {from: dst_port, type: int}
    connection_info.protocol_name: {from: proto, type: str}
    action_id: {from: action, map: {deny: 2, allow: 1}, default: 0}
    action: {from: action, map: {deny: Denied, allow: Allowed}, default: null}
    time: {from: ts, type: timestamp, required: true}
  unmapped: keep_all

validate:
  required: [src_endpoint.ip, dst_endpoint.ip, time, class_uid, category_uid]
  on_failure: dead_letter
"""


def _acme_line(i: int, *, action: str = "allow") -> str:
    return json.dumps(
        {
            "vendor": "ACMEFW",
            "ts": f"2026-09-05T10:{i % 60:02d}:00Z",
            "src_ip": f"203.0.113.{i % 254 + 1}",
            "src_port": 51000 + i,
            "dst_ip": "198.51.100.9",
            "dst_port": 443,
            "proto": "tcp",
            "action": action,
        }
    )


def _settings(root: Path, sources_dir: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=root / "bronze",
            silver_path=root / "silver",
            dlq_path=root / "dlq",
            ledger_path=root / "ledger",
            state_path=root / "state",
        ),
        parse=ParseSettings(sources_dir=sources_dir),
        pipeline=PipelineSettings(worker_count=1),
        enrich=EnrichSettings(enabled=False),
    )


def _sources_app(settings: Settings, registry: SourceRegistry) -> FastAPI:
    app = FastAPI()
    app.state.runtime = SimpleNamespace(sources=registry)
    app.include_router(build_sources_router(settings), prefix="/api/v1")
    return app


def _fortigate_lines(n: int, *, date: str) -> list[bytes]:
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


def _ingest(settings: Settings, registry: SourceRegistry, lines: list[bytes]) -> list[RawEvent]:
    """Push ``lines`` through the full pipeline (a fresh registry copy, same dir)."""

    async def _run() -> list[RawEvent]:
        events = [make_raw_event(line, source_id="apitest", transport="udp") for line in lines]
        enrich = EnrichmentPipeline(settings, build_enrichers(settings))
        sinks = SinkManager.from_settings(settings)
        pipeline = Pipeline(
            settings,
            [
                RawStoreStage(RawStore(settings)),
                ParseStage(settings, ParseCoordinator()),
                NormalizeStage(settings, registry),
                EnrichStage(settings, enrich),
                ValidateStage(settings, registry),
                sinks,
            ],
        )
        await sinks.start()
        pipeline.start()
        for event in events:
            await pipeline.submit(event)
        await pipeline.stop()
        return events

    return asyncio.run(_run())


# ======================================================================
# GET /
# ======================================================================


@pytest.fixture
def fortigate_only(tmp_path: Path) -> tuple[Settings, SourceRegistry, TestClient]:
    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    fixture = (_REPO / "configs" / "sources" / "fortigate_traffic.yaml").read_text("utf-8")
    (sources_dir / "fortigate_traffic.yaml").write_text(fixture, encoding="utf-8")
    settings = _settings(tmp_path, sources_dir)
    registry = SourceRegistry()
    registry.load_all(sources_dir)
    client = TestClient(_sources_app(settings, registry))
    return settings, registry, client


def test_list_with_no_events_seen_yet(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.get("/api/v1/sources/")
    assert response.status_code == 200
    (row,) = response.json()
    assert row["name"] == "fortigate_traffic"
    assert row["vendor"] == "Fortinet"
    assert row["product"] == "FortiGate"
    assert row["enabled"] is True
    assert row["events_seen"] == 0
    assert row["parse_rate"] is None
    assert row["avg_completeness"] is None
    assert row["last_event_ns"] is None


def test_list_reflects_real_ingested_traffic(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    settings, registry, client = fortigate_only
    ingest_registry = SourceRegistry()
    ingest_registry.load_all(settings.parse.sources_dir)
    _ingest(settings, ingest_registry, _fortigate_lines(200, date="2026-09-01"))

    (row,) = client.get("/api/v1/sources/").json()
    assert row["events_seen"] == 200
    assert row["parse_rate"] == 1.0  # nothing dead-lettered
    assert row["avg_completeness"] is not None
    assert 0.0 < row["avg_completeness"] <= 1.0
    assert row["last_event_ns"] is not None


# ======================================================================
# GET /{name}
# ======================================================================


def test_get_source_returns_definition_and_yaml_text(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.get("/api/v1/sources/fortigate_traffic")
    assert response.status_code == 200
    body = response.json()
    assert body["definition"]["name"] == "fortigate_traffic"
    assert body["definition"]["vendor"] == "Fortinet"
    assert "validate" in body["definition"]  # alias, not "validation"
    assert "class_uid: 4001" in body["yaml"]
    assert body["path"].endswith("fortigate_traffic.yaml")


def test_get_source_404_for_unknown_name(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.get("/api/v1/sources/does-not-exist")
    assert response.status_code == 404


# ======================================================================
# POST /validate
# ======================================================================


def test_validate_accepts_a_good_definition(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.post("/api/v1/sources/validate", content=_ACME_YAML)
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["errors"] == []
    assert body["name"] == "acme_fw"
    assert body["vendor"] == "Acme"
    assert body["class_uid"] == 4001


def test_validate_rejects_broken_yaml_syntax(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.post("/api/v1/sources/validate", content="name: [unclosed")
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["errors"]


def test_validate_rejects_schema_invalid_definition(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    broken = _ACME_YAML.replace("vendor: Acme\n", "")  # drop a required field
    response = client.post("/api/v1/sources/validate", content=broken)
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert any("vendor" in e for e in body["errors"])


# ======================================================================
# POST /test
# ======================================================================


def test_test_endpoint_applies_definition_to_samples(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    lines = [_acme_line(i) for i in range(10)]
    response = client.post("/api/v1/sources/test", json={"yaml": _ACME_YAML, "sample_lines": lines})
    assert response.status_code == 200
    body = response.json()
    assert body["score"]["parse_rate"] == 1.0
    assert len(body["results"]) == 10
    assert body["results_truncated"] is False
    first = body["results"][0]
    assert first["matched_detect"] is True
    assert first["valid"] is True
    assert first["ocsf"]["src_endpoint"]["ip"] == "203.0.113.1"
    assert first["error"] is None


def test_test_endpoint_reports_lines_that_do_not_match_detect(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    lines = [_acme_line(0), "totally unrelated line"]
    response = client.post("/api/v1/sources/test", json={"yaml": _ACME_YAML, "sample_lines": lines})
    assert response.status_code == 200
    body = response.json()
    assert body["score"]["parse_rate"] == 0.5
    assert body["results"][1]["matched_detect"] is False
    assert body["results"][1]["ocsf"] is None


def test_test_endpoint_400_for_invalid_yaml(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.post(
        "/api/v1/sources/test", json={"yaml": "not: [valid", "sample_lines": ["x"]}
    )
    assert response.status_code == 400


def test_test_endpoint_400_for_empty_sample_lines(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.post("/api/v1/sources/test", json={"yaml": _ACME_YAML, "sample_lines": []})
    assert response.status_code == 400


# ======================================================================
# PUT /{name}
# ======================================================================


def test_put_writes_a_new_source_and_hot_reloads_it(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    settings, registry, client = fortigate_only
    response = client.put("/api/v1/sources/acme_fw", content=_ACME_YAML)
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "name": "acme_fw",
        "written": True,
        "path": body["path"],
        "backed_up": False,
    }
    assert Path(body["path"]).is_file()
    assert registry.get("acme_fw") is not None  # live registry updated synchronously

    # a source written through the API is immediately usable by the pipeline
    events = _ingest(settings, registry, [_acme_line(0).encode()])
    assert len(events) == 1


def test_put_backs_up_the_previous_version_to_history(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    settings, registry, client = fortigate_only
    original = (_REPO / "configs" / "sources" / "fortigate_traffic.yaml").read_text("utf-8")
    modified = original.replace("priority: 100", "priority: 42", 1)
    if "priority:" not in modified:
        modified = original + "\npriority: 42\n"

    response = client.put("/api/v1/sources/fortigate_traffic", content=modified)
    assert response.status_code == 200
    body = response.json()
    assert body["backed_up"] is True

    history_dir = settings.parse.sources_dir / ".history"
    backups = list(history_dir.glob("fortigate_traffic-*.yaml"))
    assert len(backups) == 1
    assert backups[0].read_text("utf-8") == original


def test_put_rejects_a_name_mismatch(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.put("/api/v1/sources/some-other-name", content=_ACME_YAML)
    assert response.status_code == 400
    assert "does not match" in response.json()["detail"]


def test_put_rejects_invalid_yaml(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.put("/api/v1/sources/acme_fw", content="not: [valid")
    assert response.status_code == 400


# ======================================================================
# DELETE /{name}
# ======================================================================


def test_delete_disables_rather_than_deletes(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    settings, registry, client = fortigate_only
    original_path = registry.path_for("fortigate_traffic")
    assert original_path is not None and original_path.is_file()

    response = client.delete("/api/v1/sources/fortigate_traffic")
    assert response.status_code == 200
    body = response.json()
    assert body["disabled"] is True
    assert not original_path.exists()  # moved, not copied

    disabled_path = settings.parse.sources_dir / ".disabled" / "fortigate_traffic.yaml"
    assert disabled_path.is_file()
    assert body["path"] == str(disabled_path)

    # the live registry no longer serves it
    assert registry.get("fortigate_traffic") is None
    assert client.get("/api/v1/sources/fortigate_traffic").status_code == 404


def test_delete_404_for_unknown_name(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.delete("/api/v1/sources/does-not-exist")
    assert response.status_code == 404


# ======================================================================
# GET /reload-status
# ======================================================================


def test_reload_status_reflects_the_initial_load(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    _settings_, _registry, client = fortigate_only
    response = client.get("/api/v1/sources/reload-status")
    assert response.status_code == 200
    body = response.json()
    assert body["reload_count"] >= 1
    assert body["last_reload_ns"] is not None and body["last_reload_ns"] > 0
    assert body["load_errors"] == []


def test_reload_status_surfaces_a_broken_file_on_disk(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    settings, registry, client = fortigate_only
    broken_path = settings.parse.sources_dir / "broken.yaml"
    broken_path.write_text("name: [not, a, mapping]", encoding="utf-8")
    error = registry.reload_path(broken_path)
    assert error is not None

    body = client.get("/api/v1/sources/reload-status").json()
    assert len(body["load_errors"]) == 1
    assert body["load_errors"][0]["path"] == str(broken_path)
    assert body["load_errors"][0]["error"]


def test_put_success_clears_a_previous_load_error_for_the_same_path(
    fortigate_only: tuple[Settings, SourceRegistry, TestClient],
) -> None:
    settings, registry, client = fortigate_only
    path = settings.parse.sources_dir / "acme_fw.yaml"
    path.write_text("name: [broken", encoding="utf-8")
    assert registry.reload_path(path) is not None
    assert len(registry.load_errors()) == 1

    response = client.put("/api/v1/sources/acme_fw", content=_ACME_YAML)
    assert response.status_code == 200
    assert registry.load_errors() == []
