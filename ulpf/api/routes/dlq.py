"""``/api/v1/dlq`` — inspect and recover from the dead-letter queue.

Backed by :class:`~ulpf.sinks.dlq.DeadLetterQueue` (list/stats) and
:func:`~ulpf.cli.dlq.run_replay` (replay) — the exact same recovery path
``ulpf dlq replay`` drives, so a dead letter resolved through the dashboard
and one resolved from the CLI go through identical parse -> normalize ->
enrich -> validate -> sink logic and leave an identical, append-only
resolution trail (see that module's docstring).

Endpoints
---------
* ``GET /``        — paginated dead letters (newest first), each with its
  reason, stage, a truncated raw preview, and whether it has since been
  resolved. Filterable by ``reason``, ``stage``, and ``unresolved_only``.
* ``GET /stats``   — counts by reason and by stage (plus total/resolved/
  unresolved) — :meth:`~ulpf.sinks.dlq.DeadLetterQueue.stats` verbatim.
* ``POST /replay`` — re-run dead letters matching a filter through today's
  pipeline; a successful replay is marked resolved, never deleted or
  rewritten (requirement d: the original failure stays in the audit trail).
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from ulpf.cli.dlq import ReplayReport, run_replay
from ulpf.config.settings import Settings
from ulpf.core.models import DeadLetter
from ulpf.sinks.dlq import DeadLetterQueue

_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 500
_RAW_PREVIEW_CHARS = 300


# ======================================================================
# wire models
# ======================================================================


class DeadLetterOut(BaseModel):
    """One dead-letter entry's public shape (``GET /``)."""

    event_uid: str
    raw_hash: str
    reason: str
    stage: str
    ts_ns: int
    detail: dict[str, Any] = Field(default_factory=dict)
    raw_preview: str
    raw_truncated: bool
    resolved: bool


class DlqListResponse(BaseModel):
    """Response body for ``GET /``."""

    items: list[DeadLetterOut]
    total: int
    page: int
    page_size: int


class ReplayRequest(BaseModel):
    """Body for ``POST /replay``."""

    reason: str | None = None
    since: str | None = None
    dry_run: bool = False


# ======================================================================
# router
# ======================================================================


def build_dlq_router(settings: Settings) -> APIRouter:
    """The ``/dlq`` router, bound to ``settings``."""
    router = APIRouter(prefix="/dlq", tags=["dlq"])

    @router.get("/stats")
    async def stats() -> dict[str, Any]:
        return await asyncio.to_thread(DeadLetterQueue(settings).stats)

    @router.get("/", response_model=DlqListResponse)
    async def list_dead_letters(
        page: int = Query(1, ge=1),
        page_size: int = Query(_DEFAULT_PAGE_SIZE, ge=1, le=_MAX_PAGE_SIZE),
        reason: str | None = Query(None),
        stage: str | None = Query(None),
        unresolved_only: bool = Query(False),
    ) -> DlqListResponse:
        items, total = await asyncio.to_thread(
            _list_page, settings, page, page_size, reason, stage, unresolved_only
        )
        return DlqListResponse(items=items, total=total, page=page, page_size=page_size)

    @router.post("/replay")
    async def replay(payload: ReplayRequest) -> dict[str, Any]:
        report: ReplayReport = await run_replay(
            settings, reason=payload.reason, since=payload.since, dry_run=payload.dry_run
        )
        return report.to_dict()

    return router


# ======================================================================
# GET / — pagination over DeadLetterQueue.iter_entries
# ======================================================================


def _list_page(
    settings: Settings,
    page: int,
    page_size: int,
    reason: str | None,
    stage: str | None,
    unresolved_only: bool,
) -> tuple[list[DeadLetterOut], int]:
    dlq = DeadLetterQueue(settings)
    resolved = dlq.resolved_event_uids()
    entries = list(dlq.iter_entries(reason=reason, unresolved_only=unresolved_only))
    if stage is not None:
        entries = [e for e in entries if e.stage == stage]
    entries.reverse()  # iter_entries is oldest-first; the list view is newest-first

    total = len(entries)
    offset = (page - 1) * page_size
    page_entries = entries[offset : offset + page_size]
    return [_to_out(entry, resolved) for entry in page_entries], total


def _to_out(entry: DeadLetter, resolved: set[str]) -> DeadLetterOut:
    text = entry.raw.decode("utf-8", errors="replace")
    truncated = len(text) > _RAW_PREVIEW_CHARS
    return DeadLetterOut(
        event_uid=entry.event_uid,
        raw_hash=entry.raw_hash,
        reason=entry.reason,
        stage=entry.stage,
        ts_ns=entry.ts_ns,
        detail=entry.detail,
        raw_preview=text[:_RAW_PREVIEW_CHARS],
        raw_truncated=truncated,
        resolved=entry.event_uid in resolved,
    )
