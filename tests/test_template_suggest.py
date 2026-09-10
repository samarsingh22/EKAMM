"""Tests for :mod:`ulpf.parse.templates.suggest` — requirement (i): reduced
parser development effort.

The headline test in this file is the actual proof of requirement (i): a
synthetic firewall format ULPF has never seen, fed only as raw lines, comes
back as a YAML source definition that a fresh :class:`SourceRegistry` can
load, match, parse, and normalize into a *valid* OCSF record for every one of
200 sample lines — with zero hand-written parsing code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ulpf.config.settings import Settings, StorageSettings
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import ParseCoordinator, parse_for_definition
from ulpf.parse.dsl.loader import SourceRegistry, evaluate_detect
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.templates.store import TemplateStore
from ulpf.parse.templates.suggest import (
    _MASK_RE,
    SuggestError,
    _dissect_pattern,
    _dissect_safe,
    _grok_pattern,
    _PField,
    suggest_source_definition,
)

_STUB_GUESS = {
    "position": 0,
    "mask_type": "*",
    "inferred_semantic": "unknown",
    "confidence": 1.0,
    "example_values": [],
}


def _stub_field(name: str) -> _PField:
    return _PField(name=name, guess=dict(_STUB_GUESS))


_ACTIONS = ["allow", "allow", "allow", "allow", "deny"]  # 20% deny, deterministic


def _acme_lines(n: int) -> list[str]:
    """A synthetic, space-delimited firewall format ULPF ships no YAML for."""
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


# ==========================================================================
# HEADLINE TEST — proof of requirement (i)
# ==========================================================================


def test_requirement_i_auto_generated_parser_handles_200_never_before_seen_lines(
    tmp_path: Path,
) -> None:
    """200 lines of a format with no hand-written YAML: generate one, then prove it works.

    This is the whole point of :mod:`ulpf.parse.templates.suggest`: a source
    nobody has onboarded yet still becomes fully queryable OCSF, and reduced
    parser development effort (requirement i) is not a slogan — every one of
    these 200 lines is matched, parsed, normalized, and validated using
    *only* the auto-generated definition, with zero hand-written code for
    this vendor.
    """
    lines = _acme_lines(200)
    # this vendor genuinely has no hand-written YAML anywhere in the repo
    real_sources = Path("configs/sources")
    if real_sources.is_dir():
        assert not any("acmewall" in p.stem for p in real_sources.glob("*.yaml"))

    yaml_text = suggest_source_definition(
        "acmewall-1", sample_lines=lines, vendor="AcmeCorp", product="AcmeWall"
    )

    # 1. it is valid YAML, and a valid SourceDefinition
    parsed = yaml.safe_load(yaml_text)
    definition = load_source_definition(parsed)
    assert definition.name
    assert definition.parse.engine == "dissect"  # the preferred, safe engine

    # 2. load it into a real registry and run the full match -> parse -> normalize
    #    -> validate chain for every single sample line
    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    (sources_dir / "acmewall.yaml").write_text(yaml_text, encoding="utf-8")
    registry = SourceRegistry()
    registry.load_all(sources_dir)

    coordinator = ParseCoordinator()
    mapper = Mapper()
    validator = OcsfValidator()

    matched = normalized = validated = 0
    for i, line in enumerate(lines):
        raw = make_raw_event(line.encode(), source_id="acmewall-1", transport="udp")
        parsed_event = coordinator.parse(raw)

        matched_def = registry.match(parsed_event)
        assert matched_def is not None, f"line {i} did not match the generated definition"
        assert matched_def.name == definition.name
        matched += 1

        fields = parse_for_definition(raw.raw, matched_def)
        ocsf = finalize(
            mapper.apply(matched_def, fields, event_uid=raw.event_uid, raw_hash=raw.raw_hash)
        )
        normalized += 1

        result = validator.validate(ocsf)
        assert result.valid, f"line {i} failed OCSF validation: {result.errors}"
        validated += 1

        # the auto-generated mapping actually extracted the right values
        assert ocsf["src_endpoint"]["ip"] == f"10.20.{i % 50}.{i % 254 + 1}"
        assert ocsf["src_endpoint"]["port"] == 30000 + i
        assert ocsf["dst_endpoint"]["ip"] == f"198.51.100.{i % 10 + 1}"
        assert ocsf["dst_endpoint"]["port"] == 443
        expected_action_id = 2 if _ACTIONS[i % len(_ACTIONS)] == "deny" else 1
        assert ocsf["action_id"] == expected_action_id
        assert ocsf["class_uid"] == 4001

    assert (matched, normalized, validated) == (200, 200, 200)


def test_headline_scenario_detect_rule_does_not_match_an_unrelated_line() -> None:
    """The generated detect rule is specific, not a rubber stamp for anything."""
    yaml_text = suggest_source_definition("acmewall-1", sample_lines=_acme_lines(50))
    definition = load_source_definition(yaml.safe_load(yaml_text))

    assert evaluate_detect(definition.detect, _acme_lines(1)[0], {})
    unrelated = "<134>Oct 11 22:14:15 host sshd[123]: Accepted password for root from 1.2.3.4"
    assert not evaluate_detect(definition.detect, unrelated, {})


# ==========================================================================
# structured formats
# ==========================================================================


def _json_lines(n: int) -> list[str]:
    return [
        json.dumps(
            {
                "ts": f"2026-09-{i % 28 + 1:02d}T10:00:00Z",
                "src_ip": f"10.0.{i % 50}.5",
                "dst_ip": "198.51.100.9",
                "action": "deny" if i % 4 == 0 else "allow",
                "proto": 6,
            }
        )
        for i in range(n)
    ]


def test_json_source_generates_and_round_trips(tmp_path: Path) -> None:
    lines = _json_lines(30)
    yaml_text = suggest_source_definition("jsonfw", sample_lines=lines)
    definition = load_source_definition(yaml.safe_load(yaml_text))
    assert definition.parse.engine == "json"
    assert definition.normalize.fields["src_endpoint.ip"].from_ == "src_ip"

    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    (sources_dir / "jsonfw.yaml").write_text(yaml_text, encoding="utf-8")
    registry = SourceRegistry()
    registry.load_all(sources_dir)
    coordinator = ParseCoordinator()
    mapper = Mapper()

    for line in lines:
        raw = make_raw_event(line.encode(), source_id="jsonfw", transport="udp")
        parsed_event = coordinator.parse(raw)
        matched = registry.match(parsed_event)
        assert matched is not None
        fields = parse_for_definition(raw.raw, matched)
        ocsf = finalize(
            mapper.apply(matched, fields, event_uid=raw.event_uid, raw_hash=raw.raw_hash)
        )
        assert OcsfValidator().validate(ocsf).valid
        assert ocsf["src_endpoint"]["ip"].startswith("10.0.")


def _kv_lines(n: int) -> list[str]:
    return [
        (
            f'<134>Sep 12 08:00:00 fw1 KVWALL: type="traffic" src={i % 254 + 1}.0.0.1 '
            f"sport={20000 + i} dst=203.0.113.9 dport=443 proto=6 "
            f'action="{"deny" if i % 3 == 0 else "accept"}"'
        )
        for i in range(n)
    ]


def test_kv_source_generates_and_round_trips(tmp_path: Path) -> None:
    lines = _kv_lines(30)
    yaml_text = suggest_source_definition("kvwall", sample_lines=lines)
    definition = load_source_definition(yaml.safe_load(yaml_text))
    assert definition.parse.engine == "kv"
    # no explicit timestamp key in the kv body -> falls back to the syslog envelope
    assert definition.normalize.fields["time"].from_ == "envelope.timestamp"

    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    (sources_dir / "kvwall.yaml").write_text(yaml_text, encoding="utf-8")
    registry = SourceRegistry()
    registry.load_all(sources_dir)
    coordinator = ParseCoordinator()
    mapper = Mapper()

    ok = 0
    for line in lines:
        raw = make_raw_event(line.encode(), source_id="kvwall", transport="udp")
        parsed_event = coordinator.parse(raw)
        matched = registry.match(parsed_event)
        assert matched is not None
        fields = parse_for_definition(raw.raw, matched)
        ocsf = finalize(
            mapper.apply(matched, fields, event_uid=raw.event_uid, raw_hash=raw.raw_hash)
        )
        assert OcsfValidator().validate(ocsf).valid
        ok += 1
    assert ok == 30


def _csv_lines(n: int) -> list[str]:
    return [
        (
            f"2026-09-01T10:00:{i % 60:02d}Z,10.0.{i % 50}.5,198.51.100.9,"
            f"{30000 + i},443,6,{'deny' if i % 4 == 0 else 'allow'},f1,f2,f3"
        )
        for i in range(n)
    ]


def test_csv_source_generates_and_round_trips(tmp_path: Path) -> None:
    lines = _csv_lines(30)
    yaml_text = suggest_source_definition("csvfw", sample_lines=lines)
    definition = load_source_definition(yaml.safe_load(yaml_text))
    assert definition.parse.engine == "csv"

    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    (sources_dir / "csvfw.yaml").write_text(yaml_text, encoding="utf-8")
    registry = SourceRegistry()
    registry.load_all(sources_dir)
    coordinator = ParseCoordinator()
    mapper = Mapper()

    ok = 0
    for line in lines:
        raw = make_raw_event(line.encode(), source_id="csvfw", transport="udp")
        parsed_event = coordinator.parse(raw)
        matched = registry.match(parsed_event)
        assert matched is not None
        fields = parse_for_definition(raw.raw, matched)
        ocsf = finalize(
            mapper.apply(matched, fields, event_uid=raw.event_uid, raw_hash=raw.raw_hash)
        )
        assert OcsfValidator().validate(ocsf).valid
        ok += 1
    assert ok == 30


# ==========================================================================
# review comments / confidence
# ==========================================================================


def test_low_confidence_fields_get_a_review_comment_and_still_validate() -> None:
    """A field that's *mostly*, but not overwhelmingly, interface-shaped must
    still get mapped (that's the useful draft), flagged for review, and must
    never break the generated YAML."""
    lines = []
    for i in range(30):
        # 80% look like interface names, 20% are numeric noise -> classified
        # interface_name, but at a confidence below the review threshold
        value = f"eth{i % 2}" if i % 5 != 0 else str(9000 + i)
        lines.append(
            f'<134>Sep 12 08:00:00 host NOISYFW: type="traffic" srcintf={value} action="allow"'
        )

    yaml_text = suggest_source_definition("noisyfw", sample_lines=lines)
    definition = load_source_definition(yaml.safe_load(yaml_text))  # still validates
    assert definition.normalize.fields["src_endpoint.interface_name"].from_ == "srcintf"
    assert "REVIEW REQUIRED" in yaml_text


def test_a_clean_synthetic_source_needs_no_review() -> None:
    yaml_text = suggest_source_definition("acmewall-1", sample_lines=_acme_lines(50))
    assert "REVIEW REQUIRED" not in yaml_text


# ==========================================================================
# template_id / TemplateStore lookup path
# ==========================================================================


def test_suggest_from_a_stored_template_id(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = TemplateStore(settings)
    lines = _acme_lines(10)
    for line in lines:
        store.record(
            "7",
            "conn <IP>:<PORT> to <IP>:<PORT> tcp <*> bytes <NUM> <NUM> intf eth0",
            "acmewall-1",
            line,
        )

    yaml_text = suggest_source_definition(
        "acmewall-1", template_id="7", settings=settings, template_store=store
    )
    load_source_definition(yaml.safe_load(yaml_text))


def test_unknown_template_id_raises_suggest_error(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = TemplateStore(settings)
    with pytest.raises(SuggestError, match="no template"):
        suggest_source_definition(
            "acmewall-1", template_id="999", settings=settings, template_store=store
        )


# ==========================================================================
# input validation / guards
# ==========================================================================


def test_neither_template_id_nor_sample_lines_raises_value_error() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        suggest_source_definition("acmewall-1")


def test_both_template_id_and_sample_lines_raises_value_error() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        suggest_source_definition("acmewall-1", template_id="1", sample_lines=["a"])


def test_too_few_samples_raises_suggest_error() -> None:
    with pytest.raises(SuggestError, match="at least"):
        suggest_source_definition("acmewall-1", sample_lines=["one line only"])


# ==========================================================================
# dissect-vs-grok fallback (unit level: a zero-gap template is hard to
# produce naturally through Drain, so this exercises the boundary directly)
# ==========================================================================


def test_dissect_is_preferred_when_every_gap_is_non_empty() -> None:
    template = "conn <IP>:<PORT> to <IP>:<PORT>"
    marks = list(_MASK_RE.finditer(template))
    assert _dissect_safe(template, marks)


def test_grok_fallback_triggers_on_a_zero_width_gap_between_placeholders() -> None:
    template = "id<HEX><NUM> done"  # no separator between the two masks
    marks = list(_MASK_RE.finditer(template))
    assert not _dissect_safe(template, marks)


def test_grok_pattern_escapes_regex_metacharacters_in_literal_text() -> None:
    template = "cost=$<NUM> (approx.)"
    marks = list(_MASK_RE.finditer(template))

    pattern = _grok_pattern(template, marks, [_stub_field("cost")])
    assert pattern.startswith(r"cost=\$")  # "=" is not a regex metachar; "$" is
    assert "%{NUMBER:cost}" in pattern
    assert r"\(approx\.\)" in pattern


def test_dissect_pattern_places_named_captures_between_literal_delimiters() -> None:
    template = "conn <IP>:<PORT> done"
    marks = list(_MASK_RE.finditer(template))

    pattern = _dissect_pattern(template, marks, [_stub_field("ip"), _stub_field("port")])
    assert pattern == "conn %{ip}:%{port} done"
