"""Tests for :mod:`ulpf.cli.suggest_parser` — ``ulpf suggest-parser``."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from ulpf.cli import suggest_parser as suggest_parser_mod
from ulpf.cli.main import app
from ulpf.config.settings import Settings, StorageSettings
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.templates.store import TemplateStore

runner = CliRunner()

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


# --------------------------------------------------------------------------
# --file


def test_file_dry_run_prints_valid_yaml_to_stdout(tmp_path: Path) -> None:
    log = tmp_path / "acme.log"
    log.write_text("\n".join(_acme_lines(200)), encoding="utf-8")

    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--dry-run"])

    assert result.exit_code == 0, result.output
    load_source_definition(yaml.safe_load(result.stdout))


def test_file_without_out_or_dry_run_still_prints_and_warns(tmp_path: Path) -> None:
    log = tmp_path / "acme.log"
    log.write_text("\n".join(_acme_lines(200)), encoding="utf-8")

    result = runner.invoke(app, ["suggest-parser", "--file", str(log)])

    assert result.exit_code == 0, result.output
    assert "No --out given" in result.stdout


def test_file_with_out_writes_a_loadable_definition(tmp_path: Path) -> None:
    log = tmp_path / "acme.log"
    log.write_text("\n".join(_acme_lines(200)), encoding="utf-8")
    out = tmp_path / "configs" / "sources" / "acmewall.yaml"

    result = runner.invoke(
        app,
        [
            "suggest-parser",
            "--file",
            str(log),
            "--out",
            str(out),
            "--vendor",
            "AcmeCorp",
            "--product",
            "AcmeWall",
        ],
    )

    assert result.exit_code == 0, result.output
    assert out.is_file()
    definition = load_source_definition(yaml.safe_load(out.read_text(encoding="utf-8")))
    assert definition.vendor == "AcmeCorp"
    assert definition.product == "AcmeWall"


def test_source_id_defaults_to_the_file_stem(tmp_path: Path) -> None:
    log = tmp_path / "my-weird-firewall.log"
    log.write_text("\n".join(_acme_lines(200)), encoding="utf-8")

    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "source_id: my-weird-firewall" in result.stdout


def test_file_with_too_few_lines_fails_loudly(tmp_path: Path) -> None:
    log = tmp_path / "tiny.log"
    log.write_text("only one line here", encoding="utf-8")

    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--dry-run"])

    assert result.exit_code == 1
    assert "at least" in result.stdout


# --------------------------------------------------------------------------
# input-selection guards


def test_no_input_selector_is_a_usage_error() -> None:
    result = runner.invoke(app, ["suggest-parser"])
    assert result.exit_code == 2


def test_file_combined_with_source_id_is_a_usage_error(tmp_path: Path) -> None:
    log = tmp_path / "acme.log"
    log.write_text("\n".join(_acme_lines(10)), encoding="utf-8")
    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--source-id", "acmewall-1"])
    assert result.exit_code == 2


def test_template_id_without_source_id_is_a_usage_error(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    settings = _settings(tmp_path)
    monkeypatch.setattr(suggest_parser_mod, "_load_settings", lambda: settings)
    result = runner.invoke(app, ["suggest-parser", "--template-id", "1"])
    assert result.exit_code == 2


# --------------------------------------------------------------------------
# --source-id / --template-id (TemplateStore-backed)


def test_source_id_alone_picks_the_busiest_template(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
) -> None:
    settings = _settings(tmp_path)
    store = TemplateStore(settings)
    for _line in _acme_lines(5):
        store.record("1", "quiet template <NUM>", "acmewall-1", "quiet 1")
    for line in _acme_lines(10):
        store.record(
            "2",
            "conn <IP>:<PORT> to <IP>:<PORT> tcp <*> bytes <NUM> <NUM> intf eth0",
            "acmewall-1",
            line,
        )
    monkeypatch.setattr(suggest_parser_mod, "_load_settings", lambda: settings)

    result = runner.invoke(app, ["suggest-parser", "--source-id", "acmewall-1", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "template_id: 2" in result.stdout  # the busier (10-sample) template won
    load_source_definition(yaml.safe_load(result.stdout))


def test_source_id_with_no_recorded_templates_fails_loudly(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(suggest_parser_mod, "_load_settings", lambda: settings)
    result = runner.invoke(app, ["suggest-parser", "--source-id", "nobody-seen-this", "--dry-run"])
    assert result.exit_code == 1
    assert "no templates recorded" in result.stdout


def test_explicit_template_id_is_used_verbatim(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    settings = _settings(tmp_path)
    store = TemplateStore(settings)
    for line in _acme_lines(5):
        store.record(
            "9",
            "conn <IP>:<PORT> to <IP>:<PORT> tcp <*> bytes <NUM> <NUM> intf eth0",
            "acmewall-1",
            line,
        )
    monkeypatch.setattr(suggest_parser_mod, "_load_settings", lambda: settings)

    result = runner.invoke(
        app, ["suggest-parser", "--source-id", "acmewall-1", "--template-id", "9", "--dry-run"]
    )

    assert result.exit_code == 0, result.output
    assert "template_id: 9" in result.stdout


# --------------------------------------------------------------------------
# scoring


def test_dry_run_output_includes_the_score_as_trailing_comments(tmp_path: Path) -> None:
    log = tmp_path / "acme.log"
    log.write_text("\n".join(_acme_lines(200)), encoding="utf-8")

    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "# parse_rate:" in result.stdout
    assert "100.00%" in result.stdout
    load_source_definition(yaml.safe_load(result.stdout))  # trailing comments don't break reparsing


def test_written_file_also_carries_the_score(tmp_path: Path) -> None:
    log = tmp_path / "acme.log"
    log.write_text("\n".join(_acme_lines(200)), encoding="utf-8")
    out = tmp_path / "acmewall.yaml"

    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--out", str(out)])

    assert result.exit_code == 0, result.output
    written = out.read_text(encoding="utf-8")
    assert "# parse_rate:" in written
    load_source_definition(yaml.safe_load(written))


# --------------------------------------------------------------------------
# --min-parse-rate / --force


def _noisy_log(tmp_path: Path) -> Path:
    """A log whose generated definition scores well below the default threshold."""
    lines = [
        f"<134>Sep 12 08:00:00 host NOISYFW: conn 10.0.0.{i % 254 + 1}:{40000 + i} done"
        for i in range(20)
    ]
    lines += [f"totally unrelated line {i}" for i in range(15)]
    log = tmp_path / "noisy.log"
    log.write_text("\n".join(lines), encoding="utf-8")
    return log


def test_low_score_refuses_to_write_out_without_force(tmp_path: Path) -> None:
    log = _noisy_log(tmp_path)
    out = tmp_path / "noisyfw.yaml"

    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--out", str(out)])

    assert result.exit_code == 1
    assert not out.exists()
    assert "refusing to write" in result.stdout
    assert "--force" in result.stdout


def test_low_score_writes_anyway_with_force(tmp_path: Path) -> None:
    log = _noisy_log(tmp_path)
    out = tmp_path / "noisyfw.yaml"

    result = runner.invoke(
        app, ["suggest-parser", "--file", str(log), "--out", str(out), "--force"]
    )

    assert result.exit_code == 0, result.output
    assert out.is_file()
    load_source_definition(yaml.safe_load(out.read_text(encoding="utf-8")))


def test_min_parse_rate_can_be_relaxed_instead_of_forcing(tmp_path: Path) -> None:
    log = _noisy_log(tmp_path)
    out = tmp_path / "noisyfw.yaml"

    result = runner.invoke(
        app, ["suggest-parser", "--file", str(log), "--out", str(out), "--min-parse-rate", "0.5"]
    )

    assert result.exit_code == 0, result.output
    assert out.is_file()


def test_high_score_writes_without_needing_force(tmp_path: Path) -> None:
    log = tmp_path / "acme.log"
    log.write_text("\n".join(_acme_lines(200)), encoding="utf-8")
    out = tmp_path / "acmewall.yaml"

    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--out", str(out)])

    assert result.exit_code == 0, result.output
    assert out.is_file()


def test_dry_run_is_unaffected_by_a_low_score(tmp_path: Path) -> None:
    """--dry-run never writes anything, so the threshold guard doesn't apply to it."""
    log = _noisy_log(tmp_path)
    result = runner.invoke(app, ["suggest-parser", "--file", str(log), "--dry-run"])
    assert result.exit_code == 0, result.output
    load_source_definition(yaml.safe_load(result.stdout))
