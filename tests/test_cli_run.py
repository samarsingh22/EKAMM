"""Tests for the ``ulpf run`` CLI command — in particular ``--workers``."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ulpf.cli import main as main_mod
from ulpf.cli.main import app
from ulpf.config.settings import ParseSettings, Settings, StorageSettings

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
    )


class _FakeRuntime:
    """Records the `Settings` it was built with; never binds a real listener."""

    captured_settings: Settings | None = None

    def __init__(self, settings: Settings) -> None:
        _FakeRuntime.captured_settings = settings

    async def serve(self, on_started: object = None) -> None:
        del on_started
        return None


@pytest.fixture
def fake_runtime(monkeypatch: pytest.MonkeyPatch) -> type[_FakeRuntime]:
    _FakeRuntime.captured_settings = None
    monkeypatch.setattr(main_mod, "Runtime", _FakeRuntime)
    # the real configure_logging() mutates the ROOT logger process-wide with
    # no teardown - a no-op here keeps that out of every other test's way.
    monkeypatch.setattr(main_mod, "configure_logging", lambda level: None)
    return _FakeRuntime


def test_run_without_the_flag_leaves_worker_count_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_runtime: type[_FakeRuntime]
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)

    result = runner.invoke(app, ["run"])

    assert result.exit_code == 0, result.output
    assert fake_runtime.captured_settings is not None
    assert fake_runtime.captured_settings.pipeline.worker_count == settings.pipeline.worker_count


def test_run_workers_flag_overrides_pipeline_worker_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_runtime: type[_FakeRuntime]
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)

    result = runner.invoke(app, ["run", "--workers", "6"])

    assert result.exit_code == 0, result.output
    assert fake_runtime.captured_settings is not None
    assert fake_runtime.captured_settings.pipeline.worker_count == 6


def test_run_workers_flag_rejects_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_runtime: type[_FakeRuntime]
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)

    result = runner.invoke(app, ["run", "--workers", "0"])

    assert result.exit_code != 0
