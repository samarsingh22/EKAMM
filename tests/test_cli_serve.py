"""Tests for the ``ulpf serve`` CLI command."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from ulpf.cli import main as main_mod
from ulpf.cli.main import app
from ulpf.config.settings import ApiSettings, ParseSettings, Settings, StorageSettings

runner = CliRunner()


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        parse=ParseSettings(sources_dir=tmp_path / "sources"),
        api=ApiSettings(host="127.0.0.1", port=9999),
    )


@pytest.fixture
def fake_uvicorn(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Replace ``uvicorn.run`` with a stub that just records how it was called."""
    calls: dict = {}

    def fake_run(app: object, *, host: str, port: int, log_level: str) -> None:
        calls["app"] = app
        calls["host"] = host
        calls["port"] = port
        calls["log_level"] = log_level

    monkeypatch.setattr(main_mod, "uvicorn", SimpleNamespace(run=fake_run))
    # the real configure_logging() replaces the ROOT logger's handlers/level
    # process-wide, with no teardown - leaking that into every test that runs
    # afterward in this session. `serve` calling it for real is not this
    # fixture's concern, so make it a no-op here.
    monkeypatch.setattr(main_mod, "configure_logging", lambda level: None)
    return calls


def test_serve_binds_to_the_configured_host_and_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_uvicorn: dict
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)

    result = runner.invoke(app, ["serve"])

    assert result.exit_code == 0, result.output
    assert fake_uvicorn["host"] == "127.0.0.1"
    assert fake_uvicorn["port"] == 9999
    assert "127.0.0.1:9999" in result.stdout


def test_serve_host_and_port_flags_override_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_uvicorn: dict
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)

    result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "1234"])

    assert result.exit_code == 0, result.output
    assert fake_uvicorn["host"] == "0.0.0.0"
    assert fake_uvicorn["port"] == 1234


def test_serve_workers_flag_overrides_pipeline_worker_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_uvicorn: dict
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)

    captured: dict = {}
    monkeypatch.setattr(
        main_mod, "create_app", lambda s: (captured.__setitem__("settings", s), object())[1]
    )

    result = runner.invoke(app, ["serve", "--workers", "8"])

    assert result.exit_code == 0, result.output
    assert captured["settings"].pipeline.worker_count == 8


def test_serve_passes_a_real_fastapi_app_to_uvicorn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_uvicorn: dict
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)

    runner.invoke(app, ["serve"])

    from fastapi import FastAPI

    assert isinstance(fake_uvicorn["app"], FastAPI)
