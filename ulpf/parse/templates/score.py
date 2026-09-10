"""``score_suggestion`` — measure how well a generated definition actually works.

:mod:`ulpf.parse.templates.suggest` builds a definition from *inference* —
masks, cluster shapes, value heuristics. Every one of those is a guess, and
guesses can be wrong in ways that only show up when the definition is run
against real lines: a dissect delimiter that was too greedy, a field the
inference module classified with high confidence but that turns out absent
half the time, a detect rule so loose (or so tight) it misses the very
samples it was built from. :func:`score_suggestion` closes that loop — it
runs the generated definition through the **exact same** detect -> parse ->
map -> validate chain :class:`~ulpf.normalize.stage.NormalizeStage` uses in
production, over the sample lines, and reports how well it actually did.
Trust the measurement, not the generation.

METRICS
-------
* ``parse_rate`` — fraction of sample lines that matched the definition's own
  ``detect`` rule *and* were parsed and mapped to OCSF without error. This is
  the headline number: a definition that cannot even parse its own training
  samples is useless regardless of how confident the inference step was.
* ``completeness`` — mean :attr:`~ulpf.normalize.validator.ValidationResult.completeness`
  (the same OCSF required+recommended attribute fraction the live pipeline
  tracks) over every sample that *did* parse.
* ``required_fields_covered`` — mean, across the definition's own
  ``validate.required`` paths, of the fraction of parsed samples where that
  exact path ended up populated. This is the sharpest, most literal check:
  did the fields this definition itself declares mandatory actually show up.
* ``confidence`` — ``parse_rate * (completeness + required_fields_covered) / 2``:
  zero the moment parsing itself fails, and only as high as the resulting
  records' actual quality otherwise.
* ``warnings`` — human-readable specifics (which stage failed, on how many
  samples, and — for ``required_fields_covered`` — exactly which path is
  under-populated) an operator can act on directly.

``ulpf suggest-parser`` refuses to auto-write into ``configs/sources/`` when
``parse_rate`` falls below :data:`DEFAULT_PARSE_RATE_THRESHOLD` unless
``--force`` is given — see :mod:`ulpf.cli.suggest_parser`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from ulpf.core.errors import MappingError, ParseError
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import parse_for_definition
from ulpf.parse.dsl.loader import evaluate_detect
from ulpf.parse.dsl.schema import SourceDefinition, load_source_definition

DEFAULT_PARSE_RATE_THRESHOLD = 0.9


@dataclass
class SuggestionScore:
    """How well a generated (or hand-written) definition performs on real samples."""

    parse_rate: float
    completeness: float
    required_fields_covered: float
    confidence: float
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parse_rate": self.parse_rate,
            "completeness": self.completeness,
            "required_fields_covered": self.required_fields_covered,
            "confidence": self.confidence,
            "warnings": list(self.warnings),
        }

    def meets_threshold(self, *, parse_rate: float = DEFAULT_PARSE_RATE_THRESHOLD) -> bool:
        """Whether :attr:`parse_rate` clears ``parse_rate`` (default from this module)."""
        return self.parse_rate >= parse_rate


@dataclass
class _Tally:
    """Running counts while scoring one sample set."""

    total: int = 0
    detect_misses: int = 0
    parse_failures: list[str] = field(default_factory=list)
    mapping_failures: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)
    completeness_scores: list[float] = field(default_factory=list)
    required_hits: dict[str, int] = field(default_factory=dict)

    @property
    def parsed_ok(self) -> int:
        return len(self.completeness_scores)


def score_suggestion(
    definition_yaml: str | SourceDefinition,
    sample_lines: list[str],
    *,
    mapper: Mapper | None = None,
    validator: OcsfValidator | None = None,
) -> SuggestionScore:
    """Run ``definition_yaml`` over ``sample_lines`` and score how well it worked.

    Args:
        definition_yaml: A YAML document (as produced by
            :func:`~ulpf.parse.templates.suggest.suggest_source_definition`)
            or an already-loaded :class:`SourceDefinition`.
        sample_lines: Raw lines to score against — ideally the same ones the
            definition was generated from, though any real sample works.
        mapper: Override for tests (default: a fresh :class:`Mapper`).
        validator: Override for tests (default: a metrics-silent
            :class:`OcsfValidator`, so scoring a draft never pollutes
            ``ulpf_normalization_completeness``).
    """
    definition = (
        definition_yaml
        if isinstance(definition_yaml, SourceDefinition)
        else load_source_definition(yaml.safe_load(definition_yaml))
    )
    mapper = mapper or Mapper()
    validator = validator or OcsfValidator(record_metrics=False)
    required_paths = list(definition.validation.required)

    tally = _Tally(total=len(sample_lines), required_hits=dict.fromkeys(required_paths, 0))
    for line in sample_lines:
        _score_one(line, definition, mapper, validator, required_paths, tally)

    return _finish(tally, required_paths)


def _score_one(
    line: str,
    definition: SourceDefinition,
    mapper: Mapper,
    validator: OcsfValidator,
    required_paths: list[str],
    tally: _Tally,
) -> None:
    """Run the detect -> parse -> map -> validate chain for one sample line."""
    if not evaluate_detect(definition.detect, line, {}):
        tally.detect_misses += 1
        return

    raw_event = make_raw_event(line.encode("utf-8", "replace"), source_id="score", transport="file")
    try:
        fields = parse_for_definition(raw_event.raw, definition)
    except ParseError as exc:
        tally.parse_failures.append(str(exc))
        return

    try:
        ocsf = finalize(
            mapper.apply(
                definition, fields, event_uid=raw_event.event_uid, raw_hash=raw_event.raw_hash
            )
        )
    except MappingError as exc:
        tally.mapping_failures.append(str(exc))
        return

    result = validator.validate(ocsf)
    tally.completeness_scores.append(result.completeness)
    if not result.valid:
        tally.invalid.append("; ".join(result.errors) or "invalid record")
    for path in required_paths:
        if _is_populated(_get_nested(ocsf, path)):
            tally.required_hits[path] += 1


def _finish(tally: _Tally, required_paths: list[str]) -> SuggestionScore:
    """Reduce the tally into a :class:`SuggestionScore`."""
    total = tally.total
    parse_rate = round(tally.parsed_ok / total, 4) if total else 0.0
    completeness = (
        round(sum(tally.completeness_scores) / len(tally.completeness_scores), 4)
        if tally.completeness_scores
        else 0.0
    )

    if required_paths:
        denom = tally.parsed_ok or 1
        path_fracs = {path: tally.required_hits[path] / denom for path in required_paths}
        required_fields_covered = round(sum(path_fracs.values()) / len(path_fracs), 4)
    else:
        path_fracs = {}
        required_fields_covered = 1.0

    confidence = round(parse_rate * (completeness + required_fields_covered) / 2, 4)
    warnings = _build_warnings(tally, path_fracs)
    return SuggestionScore(parse_rate, completeness, required_fields_covered, confidence, warnings)


def _build_warnings(tally: _Tally, path_fracs: dict[str, float]) -> list[str]:
    warnings: list[str] = []
    total = tally.total
    if total == 0:
        warnings.append("no sample lines provided")
        return warnings
    if tally.detect_misses:
        warnings.append(
            f"{tally.detect_misses}/{total} sample line(s) did not match the definition's own "
            "detect rule (they would never reach this parser in production)"
        )
    if tally.parse_failures:
        warnings.append(
            f"{len(tally.parse_failures)}/{total} sample line(s) failed to parse: "
            f"{tally.parse_failures[0]}"
        )
    if tally.mapping_failures:
        warnings.append(
            f"{len(tally.mapping_failures)}/{total} sample line(s) failed OCSF mapping: "
            f"{tally.mapping_failures[0]}"
        )
    if tally.invalid:
        warnings.append(
            f"{len(tally.invalid)}/{tally.parsed_ok} normalized record(s) failed full OCSF "
            f"validation: {tally.invalid[0]}"
        )
    for path, frac in sorted(path_fracs.items()):
        if frac < 1.0:
            warnings.append(f"required field {path!r} populated in only {frac:.0%} of samples")
    return warnings


def _get_nested(record: dict[str, Any], path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _is_populated(value: Any) -> bool:
    return bool(value is not None and value != "" and value != {} and value != [])
