"""``/api/v1/templates`` — the "unmapped traffic" onboarding worklist.

Backed by :class:`~ulpf.parse.templates.store.TemplateStore`, built fresh
from ``settings`` per request (the store's own docstring: reading/writing its
one JSON file is cheap enough to just always do — no shared mutable state to
wire up, matching every other read-only router in this package).

**Every template this store holds is, today, from an unmatched source.**
:class:`~ulpf.normalize.stage.NormalizeStage` only ever calls
:meth:`TemplateStore.record` from its ``_template_only`` branch — a line a
*matched* source definition already parsed never reaches the miner at all
(there is nothing to mine: the source's own YAML already describes its
shape). So ``GET /`` and ``GET /unknown`` read the exact same catalog today;
they are kept as two endpoints because they serve two different questions —
``GET /`` is the general, filterable listing, ``GET /unknown`` is
specifically framed as *"what should I write a parser for next"*, unfiltered
and always sorted by event count. If a future source ever needs deliberate
per-source template mining even after a match, this is the seam where the two
would actually diverge.

Endpoints
---------
* ``GET /``                    — every template, sorted by ``count`` desc,
  optionally filtered to one ``source_id``.
* ``GET /unknown``              — the same catalog, unfiltered — the
  operator's onboarding worklist.
* ``GET /{template_id}``        — one template's detail: its stored sample
  lines plus :func:`~ulpf.parse.templates.inference.infer_field_types`'
  per-wildcard guesses (recomputed from those exact samples against the
  stored template text — the store itself keeps no field-type state).
* ``POST /{template_id}/suggest`` — runs
  :func:`~ulpf.parse.templates.suggest.suggest_source_definition` +
  :func:`~ulpf.parse.templates.score.score_suggestion` over this template's
  stored samples and returns ``{yaml, score, warnings}``. Nothing is written
  to ``configs/sources/`` — see ``PUT /api/v1/sources/{name}`` for that step.
* ``GET /drift``                — for each template, a current-window
  occurrence rate vs. its own observed-lifetime baseline rate, with a
  Poisson-rate z-score. Real per-occurrence timestamps back this (a bounded
  ring buffer, ``TemplateRecord.recent_ns``, added alongside this router) —
  not a fabricated number: ``baseline_rate = count / (last_seen - first_seen)``
  over the template's whole observed history, ``expected_in_window =
  baseline_rate * window``, and ``z = (observed_in_window - expected) /
  sqrt(expected)`` (undefined, reported as ``null``, when ``expected`` is 0 —
  a template with no established baseline rate yet).

``template_id`` alone is unique only *within* one source's Drain3 tree (see
:mod:`ulpf.parse.templates.store`'s module docstring) — pass ``source_id`` to
disambiguate when two sources happen to report the same numeric id; without
it, the first match found is used (same convention as
:meth:`TemplateStore.get_samples`).
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from typing import Any

from drain3 import TemplateMiner as _Drain3Engine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ulpf.config.settings import Settings
from ulpf.parse.templates.inference import infer_field_types
from ulpf.parse.templates.miner import load_drain3_config
from ulpf.parse.templates.score import score_suggestion
from ulpf.parse.templates.store import TemplateStore
from ulpf.parse.templates.suggest import SuggestError, suggest_source_definition

_DEFAULT_WINDOW = "1h"
_WINDOW_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_WINDOW_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_MIN_BASELINE_SECONDS = (
    1.0  # floor for count / lifetime so a single-occurrence template never divides by 0
)


# ======================================================================
# wire models
# ======================================================================


class TemplateOut(BaseModel):
    """One mined template's public shape (``GET /`` / ``GET /unknown``)."""

    template_id: str
    source_id: str
    template: str
    count: int
    first_seen_ns: int
    last_seen_ns: int
    suggested_fields: list[str] = Field(default_factory=list)


class FieldGuessOut(BaseModel):
    """Wire shape of :class:`~ulpf.parse.templates.inference.FieldGuess`."""

    position: int
    mask_type: str
    inferred_semantic: str
    confidence: float
    example_values: list[str] = Field(default_factory=list)


class TemplateDetail(TemplateOut):
    """``GET /{template_id}``: the listing shape plus samples and field guesses."""

    sample_lines: list[str] = Field(default_factory=list)
    inferred_fields: list[FieldGuessOut] = Field(default_factory=list)


class TemplateSuggestScore(BaseModel):
    """Wire shape of :class:`~ulpf.parse.templates.score.SuggestionScore`, minus warnings."""

    parse_rate: float
    completeness: float
    required_fields_covered: float
    confidence: float


class TemplateSuggestResponse(BaseModel):
    """Response body for ``POST /{template_id}/suggest``."""

    yaml: str
    score: TemplateSuggestScore
    warnings: list[str] = Field(default_factory=list)


class DriftEntry(BaseModel):
    """One template's frequency drift for ``GET /drift``."""

    template_id: str
    source_id: str
    template: str
    window_seconds: int
    baseline_rate_per_s: float
    current_rate_per_s: float
    observed_in_window: int
    expected_in_window: float
    z_score: float | None


# ======================================================================
# router
# ======================================================================


def build_templates_router(
    settings: Settings, *, clock: Callable[[], int] = time.time_ns
) -> APIRouter:
    """The ``/templates`` router. ``clock`` (UTC epoch-ns) is injectable for tests."""
    router = APIRouter(prefix="/templates", tags=["templates"])

    # ------------------------------------------------------------------
    # GET /unknown, GET /drift — registered before GET /{template_id} so
    # neither literal segment can ever be mistaken for a template id.
    # ------------------------------------------------------------------

    @router.get("/unknown", response_model=list[TemplateOut])
    async def list_unknown() -> list[TemplateOut]:
        """Every template, unfiltered, sorted by count desc — the onboarding worklist."""
        rows = await asyncio.to_thread(_list_rows, settings, None)
        return [TemplateOut(**row) for row in rows]

    @router.get("/drift", response_model=list[DriftEntry])
    async def drift(
        window: str = Query(_DEFAULT_WINDOW, description="Current-window width, e.g. 5m/1h/24h."),
        source_id: str | None = Query(None),
    ) -> list[DriftEntry]:
        window_seconds = _parse_window_seconds(window)
        rows = await asyncio.to_thread(_list_rows, settings, source_id, with_recent=True)
        now_ns = clock()
        entries = [_drift_entry(row, window_seconds, now_ns) for row in rows]
        entries.sort(key=lambda e: (e.z_score is None, -abs(e.z_score or 0.0)))
        return entries

    # ------------------------------------------------------------------
    # GET /
    # ------------------------------------------------------------------

    @router.get("/", response_model=list[TemplateOut])
    async def list_templates(source_id: str | None = Query(None)) -> list[TemplateOut]:
        rows = await asyncio.to_thread(_list_rows, settings, source_id)
        return [TemplateOut(**row) for row in rows]

    # ------------------------------------------------------------------
    # GET/POST /{template_id}[...]
    # ------------------------------------------------------------------

    @router.get("/{template_id}", response_model=TemplateDetail)
    async def get_template(template_id: str, source_id: str | None = Query(None)) -> TemplateDetail:
        row = await asyncio.to_thread(_find_row, settings, template_id, source_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"template {template_id!r} not found")
        inferred = await asyncio.to_thread(_infer_fields, row["template"], row["sample_lines"])
        return TemplateDetail(
            **_public_fields(row),
            sample_lines=row["sample_lines"],
            inferred_fields=[FieldGuessOut(**g) for g in inferred],
        )

    @router.post("/{template_id}/suggest", response_model=TemplateSuggestResponse)
    async def suggest(
        template_id: str, source_id: str | None = Query(None)
    ) -> TemplateSuggestResponse:
        row = await asyncio.to_thread(_find_row, settings, template_id, source_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"template {template_id!r} not found")
        try:
            yaml_text, score = await asyncio.to_thread(_suggest_and_score, settings, row)
        except SuggestError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return TemplateSuggestResponse(
            yaml=yaml_text,
            score=TemplateSuggestScore(
                parse_rate=score.parse_rate,
                completeness=score.completeness,
                required_fields_covered=score.required_fields_covered,
                confidence=score.confidence,
            ),
            warnings=list(score.warnings),
        )

    return router


# ======================================================================
# TemplateStore access
# ======================================================================


def _public_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Project a store row down to :class:`TemplateOut`'s fields (drops ``recent_ns``)."""
    return {
        "template_id": row["template_id"],
        "source_id": row["source_id"],
        "template": row["template"],
        "count": row["count"],
        "first_seen_ns": row["first_seen_ns"],
        "last_seen_ns": row["last_seen_ns"],
        "suggested_fields": row["suggested_fields"],
    }


def _list_rows(
    settings: Settings, source_id: str | None, *, with_recent: bool = False
) -> list[dict[str, Any]]:
    rows = TemplateStore(settings).list_templates(source_id=source_id, order_by="count")
    return rows if with_recent else [_public_fields(row) for row in rows]


def _find_row(settings: Settings, template_id: str, source_id: str | None) -> dict[str, Any] | None:
    for row in TemplateStore(settings).list_templates(source_id=source_id, order_by="count"):
        if row["template_id"] == template_id:
            return row
    return None


# ======================================================================
# GET /{template_id} — inferred field types
# ======================================================================


def _infer_fields(template: str, sample_lines: list[str]) -> list[dict[str, Any]]:
    """Re-derive each wildcard's parameter values, then guess what each one means.

    A throwaway, unpersisted Drain3 engine's ``get_parameter_list`` is a pure
    function of ``(template, line)`` — it needs no clustering history, just
    the same masking config every live per-source tree uses.
    """
    engine = _Drain3Engine(persistence_handler=None, config=load_drain3_config())
    sample_values = [engine.get_parameter_list(template, line) for line in sample_lines]
    return list(infer_field_types(template, sample_values))


# ======================================================================
# POST /{template_id}/suggest
# ======================================================================


def _suggest_and_score(settings: Settings, row: dict[str, Any]) -> tuple[str, Any]:
    store = TemplateStore(settings)
    yaml_text = suggest_source_definition(
        row["source_id"],
        template_id=row["template_id"],
        settings=settings,
        template_store=store,
    )
    score = score_suggestion(yaml_text, row["sample_lines"])
    return yaml_text, score


# ======================================================================
# GET /drift
# ======================================================================


def _parse_window_seconds(value: str) -> int:
    match = _WINDOW_RE.match(value)
    if not match:
        raise HTTPException(
            status_code=400, detail=f"invalid window {value!r} (expected e.g. 5m, 1h, 24h)"
        )
    n, unit = match.groups()
    return int(n) * _WINDOW_UNIT_SECONDS[unit.lower()]


def _drift_entry(row: dict[str, Any], window_seconds: int, now_ns: int) -> DriftEntry:
    """One template's current-window rate vs. its own observed-lifetime baseline."""
    recent_ns: list[int] = row.get("recent_ns", [])
    lifetime_s = max(
        _MIN_BASELINE_SECONDS, (row["last_seen_ns"] - row["first_seen_ns"]) / 1_000_000_000
    )
    baseline_rate = row["count"] / lifetime_s

    window_start_ns = now_ns - window_seconds * 1_000_000_000
    observed = sum(1 for ts in recent_ns if ts >= window_start_ns)
    expected = baseline_rate * window_seconds
    z_score = (observed - expected) / (expected**0.5) if expected > 0 else None

    return DriftEntry(
        template_id=row["template_id"],
        source_id=row["source_id"],
        template=row["template"],
        window_seconds=window_seconds,
        baseline_rate_per_s=round(baseline_rate, 6),
        current_rate_per_s=round(observed / window_seconds, 6),
        observed_in_window=observed,
        expected_in_window=round(expected, 4),
        z_score=round(z_score, 4) if z_score is not None else None,
    )
