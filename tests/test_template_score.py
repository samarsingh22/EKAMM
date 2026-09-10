"""Tests for :mod:`ulpf.parse.templates.score`."""

from __future__ import annotations

import pytest

from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.templates.score import (
    DEFAULT_PARSE_RATE_THRESHOLD,
    SuggestionScore,
    score_suggestion,
)
from ulpf.parse.templates.suggest import suggest_source_definition

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


_GOOD_YAML = """
name: perfectfw
version: "1.0.0"
vendor: Acme
product: Perfect
product_version: "1.0"
priority: 50
detect:
  contains: 'PERFECTFW:'
parse:
  envelope: syslog
  engine: dissect
  options:
    # the RFC 3164 envelope already consumes "PERFECTFW:" as the syslog TAG
    # (see CLAUDE.md's Windows-testing note on FortiGate/tag-eating) - the
    # message handed to the engine starts right after it
    pattern: 'src=%{src} dst=%{dst} action=%{action}'
normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  constants:
    severity_id: 1
  fields:
    src_endpoint.ip: {from: src, type: ip, required: true}
    dst_endpoint.ip: {from: dst, type: ip, required: true}
    action_id: {from: action, map: {allow: 1, deny: 2}, default: 0}
    time: {from: envelope.timestamp, type: timestamp, required: true}
  unmapped: keep_all
validate:
  required: [src_endpoint.ip, dst_endpoint.ip, time]
  on_failure: dead_letter
"""


def _good_lines(n: int) -> list[str]:
    return [
        f"<134>Sep 12 08:00:{i % 60:02d} host PERFECTFW: src=10.0.0.{i % 254 + 1} "
        f"dst=198.51.100.9 action={'deny' if i % 3 == 0 else 'allow'}"
        for i in range(n)
    ]


# --------------------------------------------------------------------------
# a definition that works perfectly on its own samples


def test_a_good_definition_scores_perfectly_on_its_own_samples() -> None:
    lines = _good_lines(30)
    score = score_suggestion(_GOOD_YAML, lines)

    assert score.parse_rate == 1.0
    assert score.required_fields_covered == 1.0
    assert score.completeness > 0.0
    assert score.confidence > 0.0
    assert score.warnings == []
    assert score.meets_threshold()


def test_score_suggestion_accepts_an_already_loaded_definition() -> None:
    definition = load_source_definition(__import__("yaml").safe_load(_GOOD_YAML))
    score = score_suggestion(definition, _good_lines(10))
    assert score.parse_rate == 1.0


def test_headline_generated_definition_scores_well_on_its_own_samples() -> None:
    """The auto-generated definition should score itself highly - it was
    built from exactly these samples."""
    lines = _acme_lines(200)
    yaml_text = suggest_source_definition("acmewall-1", sample_lines=lines)
    score = score_suggestion(yaml_text, lines)

    assert score.parse_rate == 1.0
    assert score.required_fields_covered == 1.0
    assert score.meets_threshold()
    assert score.warnings == []


# --------------------------------------------------------------------------
# detect-rule mismatches


def test_lines_that_miss_the_detect_rule_lower_parse_rate_and_warn() -> None:
    good = _good_lines(40)
    noise = [f"totally unrelated line {i}" for i in range(10)]
    score = score_suggestion(_GOOD_YAML, good + noise)

    assert score.parse_rate == pytest.approx(40 / 50)
    assert any("detect rule" in w for w in score.warnings)


# --------------------------------------------------------------------------
# fields that fail to actually parse / map


_BAD_ENGINE_YAML = """
name: brokenfw
version: "1.0.0"
vendor: Acme
product: Broken
product_version: "1.0"
priority: 50
detect:
  contains: 'BROKENFW:'
parse:
  envelope: none
  engine: dissect
  options:
    pattern: 'BROKENFW: %{a} strict %{b} shape %{c}'
normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  fields:
    src_endpoint.ip: {from: a, type: ip, required: true}
    dst_endpoint.ip: {from: b, type: ip, required: true}
    time: {from: c, type: timestamp, required: true}
  unmapped: keep_all
validate:
  required: [src_endpoint.ip, dst_endpoint.ip, time]
  on_failure: dead_letter
"""


def test_lines_that_do_not_fit_the_dissect_pattern_fail_to_parse() -> None:
    lines = [
        "BROKENFW: not the right shape at all",  # detect matches, dissect pattern doesn't
        "BROKENFW: not the right shape either",
        "BROKENFW: still no third field",
    ]
    score = score_suggestion(_BAD_ENGINE_YAML, lines)

    assert score.parse_rate == 0.0
    assert score.completeness == 0.0
    assert score.confidence == 0.0
    assert any("failed to parse" in w for w in score.warnings)


_MAPPING_FAIL_YAML = """
name: badmapfw
version: "1.0.0"
vendor: Acme
product: BadMap
product_version: "1.0"
priority: 50
detect:
  contains: 'BADMAP:'
parse:
  envelope: none
  engine: dissect
  options:
    pattern: 'BADMAP: ip=%{ip} ts=%{ts}'
normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  fields:
    src_endpoint.ip: {from: ip, type: ip, required: true}
    time: {from: ts, type: timestamp, required: true}
  unmapped: keep_all
validate:
  required: [src_endpoint.ip, time]
  on_failure: dead_letter
"""


def test_lines_that_parse_but_fail_mapping_are_counted_separately() -> None:
    lines = ["BADMAP: ip=not-an-ip ts=2026-09-01T10:00:00Z" for _ in range(5)]
    score = score_suggestion(_MAPPING_FAIL_YAML, lines)

    assert score.parse_rate == 0.0
    assert any("OCSF mapping" in w for w in score.warnings)


# --------------------------------------------------------------------------
# required_fields_covered / per-field warnings


_PARTIAL_REQUIRED_YAML = """
name: partialfw
version: "1.0.0"
vendor: Acme
product: Partial
product_version: "1.0"
priority: 50
detect:
  contains: PARTIALFW
parse:
  envelope: none
  engine: kv
  options: {}
normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  fields:
    src_endpoint.ip: {from: src, type: ip, required: true}
    dst_endpoint.ip: {from: extra, type: ip}
  unmapped: keep_all
validate:
  required: [src_endpoint.ip, dst_endpoint.ip]
  on_failure: dead_letter
"""


def test_required_fields_covered_reflects_a_field_that_is_only_sometimes_present() -> None:
    # "extra" (a plain, non-required kv key) is only present on half the
    # lines - a mapping failure would abort the whole line, so this has to be
    # a key that is sometimes wholly ABSENT, not sometimes malformed
    lines = []
    for i in range(20):
        line = f"PARTIALFW src=10.0.0.{i % 254 + 1}"
        if i % 2 == 0:
            line += f" extra=198.51.100.{i % 254 + 1}"
        lines.append(line)

    score = score_suggestion(_PARTIAL_REQUIRED_YAML, lines)

    assert score.parse_rate == 1.0
    assert 0.0 < score.required_fields_covered < 1.0
    assert any("dst_endpoint.ip" in w and "populated in only" in w for w in score.warnings)


def test_an_empty_required_list_is_trivially_fully_covered() -> None:
    yaml_text = """
name: norequiredfw
version: "1.0.0"
vendor: Acme
product: NoRequired
product_version: "1.0"
priority: 50
detect:
  contains: 'NOREQ:'
parse:
  envelope: none
  engine: dissect
  options:
    pattern: 'NOREQ: %{a}'
normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  fields:
    src_endpoint.ip: {from: a, type: ip}
  unmapped: keep_all
validate:
  required: []
  on_failure: dead_letter
"""
    score = score_suggestion(yaml_text, ["NOREQ: 10.0.0.1"] * 5)
    assert score.required_fields_covered == 1.0


# --------------------------------------------------------------------------
# confidence formula and edge cases


def test_confidence_is_zero_when_nothing_parses() -> None:
    score = score_suggestion(_GOOD_YAML, ["nothing here matches at all"] * 5)
    assert score.parse_rate == 0.0
    assert score.confidence == 0.0


def test_no_sample_lines_is_a_clean_zero_score_with_a_warning() -> None:
    score = score_suggestion(_GOOD_YAML, [])
    assert score == SuggestionScore(0.0, 0.0, 0.0, 0.0, ["no sample lines provided"])


def test_to_dict_round_trips_the_score() -> None:
    score = score_suggestion(_GOOD_YAML, _good_lines(10))
    data = score.to_dict()
    assert set(data) == {
        "parse_rate",
        "completeness",
        "required_fields_covered",
        "confidence",
        "warnings",
    }
    assert data["parse_rate"] == score.parse_rate


def test_meets_threshold_uses_the_default_and_accepts_an_override() -> None:
    assert DEFAULT_PARSE_RATE_THRESHOLD == 0.9
    score = SuggestionScore(0.85, 1.0, 1.0, 0.85, [])

    assert not score.meets_threshold()  # 0.85 < the default 0.9
    assert not score.meets_threshold(parse_rate=0.9)
    assert score.meets_threshold(parse_rate=0.8)
