"""``/api/v1/sources`` — browse, validate, try, and hot-reload source definitions.

Backed by the **live** :class:`~ulpf.parse.dsl.loader.SourceRegistry` the
running :class:`~ulpf.core.runtime.Runtime` uses (``request.app.state.runtime
.sources``) — not a fresh one built per request — so ``GET /`` and
``GET /reload-status`` reflect the actual hot-reload state of the process
serving the request, and ``PUT``/``DELETE`` take effect immediately rather
than waiting on the filesystem watcher to notice.

Endpoints
---------
* ``GET /``              — every loaded definition plus live stats (events
  seen, parse rate, average normalization completeness, last event time).
* ``GET /{name}``         — the full definition, plus its raw YAML text.
* ``POST /validate``      — body is YAML text; validate against the schema
  without saving (the in-browser editor's live-validation feed).
* ``POST /test``          — body is ``{yaml, sample_lines}``; runs the
  definition's own detect -> parse -> map -> validate chain over the samples
  and returns the per-line normalized output plus an aggregate
  :func:`~ulpf.parse.templates.score.score_suggestion` score — all without
  saving ("try before you commit").
* ``PUT /{name}``         — validates, backs up whatever was previously at
  ``configs/sources/{name}.yaml`` into ``configs/sources/.history/``, writes
  the new YAML, then reloads it into the live registry synchronously.
* ``DELETE /{name}``      — never deletes: moves the file to
  ``configs/sources/.disabled/`` and drops it from the live registry. The
  original stays on disk, restorable by moving it back.
* ``GET /reload-status``  — ``{last_reload_ns, reload_count, load_errors}``.

``events_seen`` / ``avg_completeness`` are read from the Parquet silver lake
(:class:`~ulpf.sinks.duckdb_query.LakeQuery`); ``avg_completeness`` is sampled
over each source's most recent rows and re-derived the same way
``ulpf reprocess --compare`` does (an attribute is "populated" if its own
column, or any of its dotted sub-columns, has a value) — the silver schema has
no stored completeness column. ``parse_rate`` here means something different
from :func:`score_suggestion`'s: it is ``events_seen / (events_seen +
dead_letters_for_this_source)``, over everything this *running* source has
ever actually seen, not over one sample batch — dead letters are attributable
to a source only when one was already matched (``NormalizeStage`` stamps
``detail.source_type`` on a parse/mapping/validation failure); a line no
source matched at all is not counted against any of them.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from ulpf.config.settings import Settings
from ulpf.core.errors import MappingError, ParseError
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf import CLASS_REGISTRY
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import parse_for_definition
from ulpf.parse.dsl.loader import SourceRegistry, evaluate_detect
from ulpf.parse.dsl.schema import SourceDefinition, load_source_definition
from ulpf.parse.templates.score import score_suggestion
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.duckdb_query import LakeQuery

_log = logging.getLogger(__name__)

_HISTORY_DIRNAME = ".history"
_DISABLED_DIRNAME = ".disabled"
_MAX_TEST_RESULTS = 50
_COMPLETENESS_SAMPLE_LIMIT = 200


# ======================================================================
# wire models
# ======================================================================


class TestRequest(BaseModel):
    """Body for ``POST /test``."""

    yaml: str
    sample_lines: list[str]


class ScoreOut(BaseModel):
    """Wire shape of :class:`~ulpf.parse.templates.score.SuggestionScore`."""

    parse_rate: float
    completeness: float
    required_fields_covered: float
    confidence: float
    warnings: list[str] = Field(default_factory=list)


class TestResult(BaseModel):
    """One sample line's outcome from ``POST /test``."""

    line: str
    matched_detect: bool
    ocsf: dict[str, Any] | None = None
    valid: bool | None = None
    completeness: float | None = None
    error: str | None = None


class TestResponse(BaseModel):
    """Response body for ``POST /test``."""

    results: list[TestResult]
    results_truncated: bool
    score: ScoreOut


class ValidateResponse(BaseModel):
    """Response body for ``POST /validate``."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    name: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    class_uid: int | None = None


class WriteResponse(BaseModel):
    """Response body for ``PUT /{name}``."""

    name: str
    written: bool
    path: str
    backed_up: bool


class DisableResponse(BaseModel):
    """Response body for ``DELETE /{name}``."""

    name: str
    disabled: bool
    path: str


class ReloadStatus(BaseModel):
    """Response body for ``GET /reload-status``."""

    last_reload_ns: int | None
    reload_count: int
    load_errors: list[dict[str, str]]


# ======================================================================
# router
# ======================================================================


def build_sources_router(settings: Settings) -> APIRouter:
    """The ``/sources`` router, bound to ``settings`` for the on-disk directory."""
    router = APIRouter(prefix="/sources", tags=["sources"])

    # ------------------------------------------------------------------
    # GET /reload-status, POST /validate, POST /test — registered before
    # GET/PUT/DELETE /{name} so none of these literal segments can ever be
    # mistaken for a source name.
    # ------------------------------------------------------------------

    @router.get("/reload-status", response_model=ReloadStatus)
    async def reload_status(request: Request) -> ReloadStatus:
        registry = _registry(request)
        last = registry.last_reload_time
        return ReloadStatus(
            last_reload_ns=int(last * 1_000_000_000) if last is not None else None,
            reload_count=registry.reload_count,
            load_errors=registry.load_errors(),
        )

    @router.post("/validate", response_model=ValidateResponse)
    async def validate_source(request: Request) -> ValidateResponse:
        text = (await request.body()).decode("utf-8", errors="replace")
        definition, errors = await asyncio.to_thread(_validate_yaml_text, text)
        if definition is None:
            return ValidateResponse(valid=False, errors=errors)
        return ValidateResponse(
            valid=True,
            name=definition.name,
            vendor=definition.vendor,
            product=definition.product,
            version=definition.version,
            class_uid=definition.normalize.class_uid,
        )

    @router.post("/test", response_model=TestResponse)
    async def test_source(payload: TestRequest) -> TestResponse:
        definition, errors = await asyncio.to_thread(_validate_yaml_text, payload.yaml)
        if definition is None:
            raise HTTPException(status_code=400, detail="; ".join(errors) or "invalid definition")
        if not payload.sample_lines:
            raise HTTPException(status_code=400, detail="sample_lines must not be empty")

        results = await asyncio.to_thread(_run_samples, definition, payload.sample_lines)
        score = await asyncio.to_thread(score_suggestion, definition, payload.sample_lines)
        return TestResponse(
            results=[TestResult(**r) for r in results],
            results_truncated=len(payload.sample_lines) > _MAX_TEST_RESULTS,
            score=ScoreOut(**score.to_dict()),
        )

    # ------------------------------------------------------------------
    # GET / — every loaded definition plus live stats
    # ------------------------------------------------------------------

    @router.get("/")
    async def list_sources(request: Request) -> list[dict[str, Any]]:
        registry = _registry(request)
        return await asyncio.to_thread(_list_with_stats, settings, registry)

    # ------------------------------------------------------------------
    # GET/PUT/DELETE /{name}
    # ------------------------------------------------------------------

    @router.get("/{name}")
    async def get_source(name: str, request: Request) -> dict[str, Any]:
        registry = _registry(request)
        definition = registry.get(name)
        if definition is None:
            raise HTTPException(status_code=404, detail=f"source {name!r} not found")
        path = registry.path_for(name)
        yaml_text = await asyncio.to_thread(path.read_text, encoding="utf-8") if path else ""
        return {
            "definition": definition.model_dump(by_alias=True),
            "yaml": yaml_text,
            "path": str(path) if path else None,
        }

    @router.put("/{name}", response_model=WriteResponse)
    async def put_source(name: str, request: Request) -> WriteResponse:
        text = (await request.body()).decode("utf-8", errors="replace")
        definition, errors = await asyncio.to_thread(_validate_yaml_text, text)
        if definition is None:
            raise HTTPException(status_code=400, detail="; ".join(errors) or "invalid definition")
        if definition.name != name:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"URL name {name!r} does not match the definition's own "
                    f"name {definition.name!r}"
                ),
            )
        registry = _registry(request)
        path, backed_up = await asyncio.to_thread(
            _write_source_file, settings, registry, name, text
        )
        reload_error = registry.reload_path(path)
        if reload_error:  # defensive: we already validated the same text above
            raise HTTPException(
                status_code=500, detail=f"written but failed to hot-reload: {reload_error}"
            )
        return WriteResponse(name=name, written=True, path=str(path), backed_up=backed_up)

    @router.delete("/{name}", response_model=DisableResponse)
    async def delete_source(name: str, request: Request) -> DisableResponse:
        registry = _registry(request)
        path = registry.path_for(name)
        if path is None or not path.is_file():
            raise HTTPException(status_code=404, detail=f"source {name!r} not found")
        new_path = await asyncio.to_thread(_disable_source_file, settings, path)
        registry.forget_path(path)
        return DisableResponse(name=name, disabled=True, path=str(new_path))

    return router


def _registry(request: Request) -> SourceRegistry:
    """The live registry the running :class:`~ulpf.core.runtime.Runtime` owns."""
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(status_code=503, detail="runtime not started")
    return runtime.sources


# ======================================================================
# validation (POST /validate, POST /test, PUT /{name})
# ======================================================================


def _validate_yaml_text(text: str) -> tuple[SourceDefinition | None, list[str]]:
    """Parse + schema-validate raw YAML text; never raises."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return None, [f"YAML syntax error: {exc}"]
    if not isinstance(data, dict):
        return None, ["top-level YAML is not a mapping"]
    try:
        return load_source_definition(data), []
    except ValidationError as exc:
        return None, [_format_pydantic_error(e) for e in exc.errors()]
    except ValueError as exc:
        return None, [str(exc)]


def _format_pydantic_error(error: dict[str, Any]) -> str:
    loc = ".".join(str(part) for part in error["loc"]) or "<root>"
    return f"{loc}: {error['msg']}"


# ======================================================================
# POST /test — apply a definition to sample lines, without saving
# ======================================================================


def _run_samples(definition: SourceDefinition, sample_lines: list[str]) -> list[dict[str, Any]]:
    mapper = Mapper()
    validator = OcsfValidator(record_metrics=False)
    return [
        _run_one_sample(line, definition, mapper, validator)
        for line in sample_lines[:_MAX_TEST_RESULTS]
    ]


def _run_one_sample(
    line: str, definition: SourceDefinition, mapper: Mapper, validator: OcsfValidator
) -> dict[str, Any]:
    """Run the detect -> parse -> map -> validate chain for one sample line."""
    out: dict[str, Any] = {
        "line": line,
        "matched_detect": False,
        "ocsf": None,
        "valid": None,
        "completeness": None,
        "error": None,
    }
    if not evaluate_detect(definition.detect, line, {}):
        return out
    out["matched_detect"] = True

    raw_event = make_raw_event(line.encode("utf-8", "replace"), source_id="test", transport="file")
    try:
        fields = parse_for_definition(raw_event.raw, definition)
    except ParseError as exc:
        out["error"] = f"parse error: {exc}"
        return out

    try:
        ocsf = finalize(
            mapper.apply(
                definition, fields, event_uid=raw_event.event_uid, raw_hash=raw_event.raw_hash
            )
        )
    except MappingError as exc:
        out["error"] = f"mapping error: {exc}"
        return out

    result = validator.validate(ocsf)
    out["ocsf"] = ocsf
    out["valid"] = result.valid
    out["completeness"] = result.completeness
    if not result.valid:
        out["error"] = "; ".join(result.errors)
    return out


# ======================================================================
# GET / — live per-source stats from the silver lake + DLQ
# ======================================================================


def _list_with_stats(settings: Settings, registry: SourceRegistry) -> list[dict[str, Any]]:
    definitions = registry.definitions()
    dlq_by_source: Counter[str] = Counter()
    for record in DeadLetterQueue(settings).iter_entries():
        source = record.detail.get("source_type") if isinstance(record.detail, dict) else None
        if source:
            dlq_by_source[source] += 1

    out: list[dict[str, Any]] = []
    with LakeQuery(settings) as lake:
        events_by_source = {row["source_type"]: row for row in lake.stats_by_source()}
        for definition in definitions:
            stats = events_by_source.get(definition.name, {})
            events_seen = int(stats.get("events") or 0)
            dlq_n = dlq_by_source.get(definition.name, 0)
            denom = events_seen + dlq_n
            avg_completeness = _avg_completeness(lake, definition) if events_seen else None
            out.append(
                {
                    "name": definition.name,
                    "vendor": definition.vendor,
                    "product": definition.product,
                    "version": definition.version,
                    "enabled": definition.enabled,
                    "events_seen": events_seen,
                    "parse_rate": round(events_seen / denom, 4) if denom else None,
                    "avg_completeness": avg_completeness,
                    "last_event_ns": stats.get("last_time_ns"),
                }
            )
    return out


def _avg_completeness(lake: LakeQuery, definition: SourceDefinition) -> float | None:
    """Mean OCSF completeness over this source's most recent rows in the lake.

    Re-derives :attr:`~ulpf.normalize.validator.ValidationResult.completeness`
    from the flat silver columns the same way ``ulpf reprocess --compare``
    does (there is no stored completeness column) — see the module docstring.
    """
    module = CLASS_REGISTRY.get(definition.normalize.class_uid)
    if module is None:
        return None
    shape = module.CLASS_SHAPE
    attrs = list(dict.fromkeys([*shape["required"], *shape["recommended"]]))
    if not attrs:
        return None
    rows = lake.by_source(definition.name, limit=_COMPLETENESS_SAMPLE_LIMIT)
    if not rows:
        return None
    scores = [sum(1 for attr in attrs if _attr_populated(row, attr)) / len(attrs) for row in rows]
    return round(sum(scores) / len(scores), 4)


def _attr_populated(row: dict[str, Any], attr: str) -> bool:
    """Whether ``attr`` has data in a flat silver row (scalar column or any ``attr.*`` column)."""
    if attr in ("unmapped", "enrichments"):
        value = row.get(f"{attr}_json")
        return value not in (None, "", "{}")
    direct = row.get(attr)
    if direct not in (None, ""):
        return True
    prefix = f"{attr}."
    return any(value not in (None, "") for key, value in row.items() if key.startswith(prefix))


# ======================================================================
# PUT /{name} — validate, back up, write, hot-reload
# ======================================================================


def _write_source_file(
    settings: Settings, registry: SourceRegistry, name: str, text: str
) -> tuple[Path, bool]:
    """Back up whatever previously lived at ``name``'s path, then write ``text`` there."""
    sources_dir = Path(settings.parse.sources_dir)
    sources_dir.mkdir(parents=True, exist_ok=True)
    path = registry.path_for(name) or (sources_dir / f"{name}.yaml")

    backed_up = False
    if path.is_file():
        history_dir = sources_dir / _HISTORY_DIRNAME
        history_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, history_dir / f"{name}-{time.time_ns()}.yaml")
        backed_up = True

    path.write_text(text, encoding="utf-8")
    return path, backed_up


# ======================================================================
# DELETE /{name} — disable, never delete
# ======================================================================


def _disable_source_file(settings: Settings, path: Path) -> Path:
    """Move ``path`` into ``configs/sources/.disabled/`` (never deletes it)."""
    sources_dir = Path(settings.parse.sources_dir)
    disabled_dir = sources_dir / _DISABLED_DIRNAME
    disabled_dir.mkdir(parents=True, exist_ok=True)
    target = disabled_dir / path.name
    if target.exists():
        target = disabled_dir / f"{path.stem}-{time.time_ns()}{path.suffix}"
    shutil.move(str(path), str(target))
    return target
