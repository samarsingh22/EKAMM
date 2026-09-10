"""Tests for :mod:`ulpf.api.suggest` — ``POST /suggest/parser``."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from ulpf.api.suggest import create_suggest_app
from ulpf.config.settings import Settings, StorageSettings
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.templates.store import TemplateStore

_ACTIONS = ["allow", "allow", "allow", "allow", "deny"]


def _acme_lines(n: int) -> list[str]:
    return [
        (
            f"<190>Sep 12 08:{i % 60:02d}:00 acmefw ACMEWALL: conn "
            f"10.20.{i % 50}.{i % 254 + 1}:{30000 + i} to 198.51.100.{i % 10 + 1}:443 "
            f"tcp {_ACTIONS[i % len(_ACTIONS)]} "
            f"bytes {100 + i * 37} {50 + i * 19} intf eth0"
        )
        for i in range(n)
    ]


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(state_path=tmp_path / "state"))


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_suggest_app(_settings(tmp_path)))


def test_suggest_parser_from_sample_lines_returns_valid_yaml_and_a_high_score(
    client: TestClient,
) -> None:
    lines = _acme_lines(200)
    response = client.post(
        "/suggest/parser",
        json={
            "source_id": "acmewall-1",
            "sample_lines": lines,
            "vendor": "AcmeCorp",
            "product": "AcmeWall",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    definition = load_source_definition(yaml.safe_load(body["yaml"]))
    assert definition.vendor == "AcmeCorp"

    score = body["score"]
    assert score["parse_rate"] == 1.0
    assert score["required_fields_covered"] == 1.0
    assert score["warnings"] == []


def test_suggest_parser_from_template_id(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = TemplateStore(settings)
    for line in _acme_lines(10):
        store.record(
            "3",
            "conn <IP>:<PORT> to <IP>:<PORT> tcp <*> bytes <NUM> <NUM> intf eth0",
            "acmewall-1",
            line,
        )
    client = TestClient(create_suggest_app(settings))

    response = client.post("/suggest/parser", json={"source_id": "acmewall-1", "template_id": "3"})

    assert response.status_code == 200, response.text
    load_source_definition(yaml.safe_load(response.json()["yaml"]))


def test_suggest_parser_too_few_samples_is_a_400(client: TestClient) -> None:
    response = client.post(
        "/suggest/parser", json={"source_id": "acmewall-1", "sample_lines": ["one line"]}
    )
    assert response.status_code == 400
    assert "at least" in response.json()["detail"]


def test_suggest_parser_unknown_template_id_is_a_400(client: TestClient) -> None:
    response = client.post(
        "/suggest/parser", json={"source_id": "acmewall-1", "template_id": "999"}
    )
    assert response.status_code == 400
    assert "no template" in response.json()["detail"]


def test_suggest_parser_requires_exactly_one_of_sample_lines_or_template_id(
    client: TestClient,
) -> None:
    neither = client.post("/suggest/parser", json={"source_id": "acmewall-1"})
    assert neither.status_code == 400

    both = client.post(
        "/suggest/parser",
        json={"source_id": "acmewall-1", "sample_lines": ["a", "b", "c"], "template_id": "1"},
    )
    assert both.status_code == 400


def test_suggest_parser_low_quality_samples_still_returns_a_score_not_an_error(
    client: TestClient,
) -> None:
    """Scoring poorly is not a request error - the caller decides what to do with it."""
    lines = [
        f"<134>Sep 12 08:00:00 host NOISYFW: conn 10.0.0.{i % 254 + 1} done" for i in range(20)
    ]
    lines += [f"totally unrelated {i}" for i in range(10)]

    response = client.post("/suggest/parser", json={"source_id": "noisyfw", "sample_lines": lines})

    assert response.status_code == 200, response.text
    score = response.json()["score"]
    assert score["parse_rate"] < 1.0
    assert score["warnings"]
