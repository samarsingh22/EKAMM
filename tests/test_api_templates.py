"""Tests for :mod:`ulpf.api.routes.templates` — every ``/api/v1/templates`` endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ulpf.api.routes.templates import build_templates_router
from ulpf.config.settings import Settings, StorageSettings
from ulpf.parse.templates.store import TemplateStore

_BASE_NS = 1_788_600_000_000_000_000  # arbitrary fixed instant
_S = 1_000_000_000  # one second, in ns


class _Clock:
    """A settable epoch-nanoseconds clock, shared between the store and the router."""

    def __init__(self, t: int = _BASE_NS) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(state_path=tmp_path / "state"))


def _app(settings: Settings, clock: _Clock) -> FastAPI:
    app = FastAPI()
    app.include_router(build_templates_router(settings, clock=clock), prefix="/api/v1")
    return app


_ACTIONS = ["allow", "allow", "allow", "allow", "deny"]


def _acmewall_lines(n: int) -> list[str]:
    """A synthetic, space-delimited firewall format (same shape as test_template_suggest.py)."""
    return [
        (
            f"<190>Sep 12 08:{i % 60:02d}:00 acmefw ACMEWALL: conn "
            f"10.20.{i % 50}.{i % 254 + 1}:{30000 + i} to 198.51.100.{i % 10 + 1}:443 "
            f"tcp {_ACTIONS[i % len(_ACTIONS)]} "
            f"bytes {100 + i * 37} {50 + i * 19} intf eth0"
        )
        for i in range(n)
    ]


# ======================================================================
# GET /
# ======================================================================


@pytest.fixture
def seeded(tmp_path: Path) -> tuple[Settings, _Clock, TestClient]:
    clock = _Clock()
    settings = _settings(tmp_path)
    store = TemplateStore(settings, clock=clock)
    for line in _acmewall_lines(10):
        store.record(
            "7",
            "conn <IP>:<PORT> to <IP>:<PORT> tcp <*> bytes <NUM> <NUM> intf eth0",
            "acmewall-1",
            line,
        )
    for _ in range(3):
        store.record("2", "connect from <IP>:<PORT>", "other-fw", "connect from 10.0.0.1:22")
    client = TestClient(_app(settings, clock))
    return settings, clock, client


def test_list_sorted_by_count_desc(seeded: tuple[Settings, _Clock, TestClient]) -> None:
    _settings_, _clock, client = seeded
    response = client.get("/api/v1/templates/")
    assert response.status_code == 200
    rows = response.json()
    assert [r["template_id"] for r in rows] == ["7", "2"]  # 10 events then 3
    assert rows[0]["count"] == 10
    assert rows[0]["source_id"] == "acmewall-1"
    assert rows[0]["suggested_fields"] == ["IP", "PORT", "NUM"]
    assert "recent_ns" not in rows[0]  # internal-only, never exposed


def test_list_filters_by_source_id(seeded: tuple[Settings, _Clock, TestClient]) -> None:
    _settings_, _clock, client = seeded
    response = client.get("/api/v1/templates/", params={"source_id": "other-fw"})
    (row,) = response.json()
    assert row["template_id"] == "2"
    assert row["count"] == 3


def test_list_empty_store(tmp_path: Path) -> None:
    clock = _Clock()
    client = TestClient(_app(_settings(tmp_path), clock))
    response = client.get("/api/v1/templates/")
    assert response.status_code == 200
    assert response.json() == []


# ======================================================================
# GET /unknown
# ======================================================================


def test_unknown_returns_the_same_catalog_unfiltered(
    seeded: tuple[Settings, _Clock, TestClient],
) -> None:
    _settings_, _clock, client = seeded
    all_rows = client.get("/api/v1/templates/").json()
    unknown_rows = client.get("/api/v1/templates/unknown").json()
    assert unknown_rows == all_rows


# ======================================================================
# GET /{template_id}
# ======================================================================


def test_get_template_returns_samples_and_inferred_fields(tmp_path: Path) -> None:
    clock = _Clock()
    settings = _settings(tmp_path)
    store = TemplateStore(settings, clock=clock)
    lines = [
        "connect from 10.0.0.1:22",
        "connect from 10.0.0.2:8080",
        "connect from 10.0.0.3:443",
    ]
    for line in lines:
        store.record("2", "connect from <IP>:<PORT>", "fw1", line)
    client = TestClient(_app(settings, clock))

    response = client.get("/api/v1/templates/2", params={"source_id": "fw1"})
    assert response.status_code == 200
    body = response.json()
    assert body["template_id"] == "2"
    assert body["sample_lines"] == lines
    fields = {f["inferred_semantic"]: f for f in body["inferred_fields"]}
    assert fields["source_ip"]["mask_type"] == "IP"
    assert fields["source_ip"]["confidence"] == 1.0
    assert fields["port"]["example_values"] == ["22", "8080", "443"]


def test_get_template_disambiguates_by_source_id(
    seeded: tuple[Settings, _Clock, TestClient],
) -> None:
    _settings_, _clock, client = seeded
    response = client.get("/api/v1/templates/2", params={"source_id": "other-fw"})
    assert response.status_code == 200
    assert response.json()["source_id"] == "other-fw"


def test_get_template_404_for_unknown_id(seeded: tuple[Settings, _Clock, TestClient]) -> None:
    _settings_, _clock, client = seeded
    response = client.get("/api/v1/templates/does-not-exist")
    assert response.status_code == 404


# ======================================================================
# POST /{template_id}/suggest
# ======================================================================


def test_suggest_returns_yaml_score_and_warnings(
    seeded: tuple[Settings, _Clock, TestClient],
) -> None:
    _settings_, _clock, client = seeded
    response = client.post("/api/v1/templates/7/suggest", params={"source_id": "acmewall-1"})
    assert response.status_code == 200
    body = response.json()
    assert "name:" in body["yaml"]
    # TemplateStore caps sample_lines at 5; among the first 5 acmewall lines the
    # 5th is a "deny" whose action word the tiny detect rule fitted on the
    # other 4 doesn't share - a real (if narrow) score, not a bug in the router.
    assert body["score"]["parse_rate"] >= 0.8
    assert isinstance(body["warnings"], list)


def test_suggest_404_for_unknown_template(seeded: tuple[Settings, _Clock, TestClient]) -> None:
    _settings_, _clock, client = seeded
    response = client.post("/api/v1/templates/nope/suggest")
    assert response.status_code == 404


def test_suggest_400_when_too_few_samples(tmp_path: Path) -> None:
    clock = _Clock()
    settings = _settings(tmp_path)
    store = TemplateStore(settings, clock=clock)
    store.record("1", "t <NUM>", "fw1", "t 1")  # only 1 occurrence, below min_samples=3
    client = TestClient(_app(settings, clock))

    response = client.post("/api/v1/templates/1/suggest", params={"source_id": "fw1"})
    assert response.status_code == 400


# ======================================================================
# GET /drift
# ======================================================================


@pytest.fixture
def drift_seeded(tmp_path: Path) -> tuple[Settings, _Clock, TestClient]:
    """Two templates: one spiking in the current window, one gone quiet."""
    settings = _settings(tmp_path)
    clock = _Clock(_BASE_NS)
    store = TemplateStore(settings, clock=clock)

    # "spike": a low steady baseline rate (10 events, 600s apart, ending well
    # before the window starts), then a burst of 20 events well inside the
    # current 1h window.
    now = _BASE_NS + 20_000 * _S
    for i in range(10):
        clock.t = now - 14400 * _S + i * 600 * _S  # last one at now-9000s, still well outside 1h
        store.record("spike", "hot <NUM>", "fw1", f"hot {i}")
    for i in range(20):
        clock.t = now - 1200 * _S + i * 60 * _S
        store.record("spike", "hot <NUM>", "fw1", f"hot burst {i}")

    # "quiet": 10 events long ago, nothing since (well outside the window)
    for i in range(10):
        clock.t = now - 12600 * _S + i * 600 * _S
        store.record("quiet", "cold <NUM>", "fw1", f"cold {i}")

    clock.t = now  # "now" for the query
    client = TestClient(_app(settings, clock))
    return settings, clock, client


def test_drift_shape_and_window(drift_seeded: tuple[Settings, _Clock, TestClient]) -> None:
    _settings_, _clock, client = drift_seeded
    response = client.get("/api/v1/templates/drift", params={"window": "1h"})
    assert response.status_code == 200
    body = response.json()
    assert {e["template_id"] for e in body} == {"spike", "quiet"}
    for entry in body:
        assert entry["window_seconds"] == 3600
        assert entry["source_id"] == "fw1"


def test_drift_detects_a_spike_in_the_current_window(
    drift_seeded: tuple[Settings, _Clock, TestClient],
) -> None:
    _settings_, _clock, client = drift_seeded
    body = client.get("/api/v1/templates/drift", params={"window": "1h"}).json()
    spike = next(e for e in body if e["template_id"] == "spike")
    assert spike["observed_in_window"] == 20
    assert spike["current_rate_per_s"] > spike["baseline_rate_per_s"]
    assert spike["z_score"] is not None and spike["z_score"] > 0


def test_drift_detects_a_template_gone_quiet(
    drift_seeded: tuple[Settings, _Clock, TestClient],
) -> None:
    _settings_, _clock, client = drift_seeded
    body = client.get("/api/v1/templates/drift", params={"window": "1h"}).json()
    quiet = next(e for e in body if e["template_id"] == "quiet")
    assert quiet["observed_in_window"] == 0
    assert quiet["current_rate_per_s"] == 0.0
    assert quiet["z_score"] is not None and quiet["z_score"] < 0


def test_drift_sorted_by_absolute_z_score_desc(
    drift_seeded: tuple[Settings, _Clock, TestClient],
) -> None:
    _settings_, _clock, client = drift_seeded
    body = client.get("/api/v1/templates/drift", params={"window": "1h"}).json()
    z_scores = [abs(e["z_score"]) for e in body]
    assert z_scores == sorted(z_scores, reverse=True)


def test_drift_filters_by_source_id(drift_seeded: tuple[Settings, _Clock, TestClient]) -> None:
    _settings_, _clock, client = drift_seeded
    body = client.get(
        "/api/v1/templates/drift", params={"window": "1h", "source_id": "nope"}
    ).json()
    assert body == []


def test_drift_invalid_window_is_a_400(drift_seeded: tuple[Settings, _Clock, TestClient]) -> None:
    _settings_, _clock, client = drift_seeded
    response = client.get("/api/v1/templates/drift", params={"window": "banana"})
    assert response.status_code == 400
