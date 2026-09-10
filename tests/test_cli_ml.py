"""Tests for :mod:`ulpf.cli.ml` — ``ulpf ml train`` and ``ulpf ml score``."""

from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from ulpf.cli import ml as ml_mod
from ulpf.cli.main import app
from ulpf.config.settings import MlSettings, Settings, StorageSettings

runner = CliRunner()

_DATE = "2026-09-05"
_S = 1_000_000_000
_BASE_NS = 1_788_609_600 * _S


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        ml=MlSettings(
            model_path=tmp_path / "models" / "anomaly.joblib",
            anomalies_path=tmp_path / "anomalies",
            drift_state_path=tmp_path / "state" / "drift.json",
            contamination=0.2,
        ),
    )


def _seed_silver(settings: Settings, count: int = 60) -> None:
    rows = [
        {
            "event_uid": f"e{i:04d}",
            "time": _BASE_NS + i * _S,
            "src_ip": f"10.0.0.{i % 6}",
            "dst_ip": "8.8.8.8",
            "dst_port": (80, 443, 53)[i % 3],
            "protocol": "tcp",
            "action_id": 1 if i % 7 else 2,
            "severity_id": 1,
            "bytes_in": 100 + i,
            "bytes_out": 50 + i,
        }
        for i in range(count)
    ]
    part_dir = Path(settings.storage.silver_path) / f"date={_DATE}" / "source_type=acme_fw"
    part_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), part_dir / "part-000.parquet")


@pytest.fixture
def seeded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    settings = _settings(tmp_path)
    _seed_silver(settings)
    monkeypatch.setattr(ml_mod, "_load_settings", lambda: settings)
    return settings


def test_train_then_score(seeded: Settings) -> None:
    trained = runner.invoke(
        app, ["ml", "train", "--date-from", _DATE, "--date-to", _DATE, "--json"]
    )
    assert trained.exit_code == 0, trained.output
    body = json.loads(trained.output)
    assert body["n_samples"] == 60
    assert Path(body["model_path"]).is_file()

    scored = runner.invoke(app, ["ml", "score", "--date", _DATE, "--json"])
    assert scored.exit_code == 0, scored.output
    result = json.loads(scored.output)
    assert result["scored"] == 60
    assert result["anomalies"] >= 1
    assert result["output_paths"]


def test_train_plain_output_lists_fields(seeded: Settings) -> None:
    result = runner.invoke(app, ["ml", "train", "--date-from", _DATE, "--date-to", _DATE])
    assert result.exit_code == 0, result.output
    assert "model_path:" in result.output
    assert "n_samples:" in result.output


def test_score_without_a_trained_model_exits_1(seeded: Settings) -> None:
    result = runner.invoke(app, ["ml", "score", "--date", _DATE])
    assert result.exit_code == 1
    assert "no anomaly model" in result.output


def test_train_with_reversed_date_range_exits_1(seeded: Settings) -> None:
    result = runner.invoke(
        app, ["ml", "train", "--date-from", "2026-09-09", "--date-to", "2026-09-01"]
    )
    assert result.exit_code == 1
    assert "before" in result.output


def test_train_with_no_silver_data_exits_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)  # nothing seeded
    monkeypatch.setattr(ml_mod, "_load_settings", lambda: settings)
    result = runner.invoke(app, ["ml", "train", "--date-from", _DATE, "--date-to", _DATE])
    assert result.exit_code == 1
    assert "no features" in result.output
