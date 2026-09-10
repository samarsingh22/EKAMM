"""Persisted catalog of mined templates — the dashboard's onboarding worklist.

:class:`~ulpf.parse.templates.miner.TemplateMiner` decides *which* cluster a
line belongs to; :class:`TemplateStore` is where that decision becomes
something a human can act on. Every call to :meth:`TemplateStore.record`
updates one row: when this shape was first/last seen, how many times, a
handful of real example lines, and a best-effort guess at what fields it
carries — so "unmapped traffic dashboard" can show *"this device is sending
1,200 lines/day that look like `<TIMESTAMP> <IP> connect <PORT>` and nobody
has written a source YAML for it yet"* instead of a wall of raw text.

STORAGE
-------
One JSON file, ``<state_path>/templates.json`` — a small, slowly-growing
catalog (bounded by the number of distinct *shapes* a fleet emits, not by
event volume), so a single atomic rewrite per :meth:`record` call (temp file +
:func:`os.replace`, matching every other state file in this project) is cheap
enough to just always do rather than add a batching layer. Each row is keyed
by ``(source_id, template_id)`` — a Drain3 cluster id is only unique *within*
one source's parse tree (each source's :class:`TemplateMiner` counts its own
clusters from 1), so two different sources can and will report the same
numeric ``template_id`` for two unrelated templates.

SUGGESTED FIELDS
----------------
A template like ``"connect from <IP>:<PORT> at <TIMESTAMP>"`` already names
the shape of a source YAML's ``fields:`` block without any extra inference:
``suggested_fields`` is simply the distinct mask names (``IP``, ``PORT``,
``TIMESTAMP``, ...) that appear in the template text, in first-seen order —
exactly the set of ``configs/drain3.ini`` masks that fired on this shape.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from ulpf.config.settings import Settings
from ulpf.core.metrics import TEMPLATE_EVENTS, TEMPLATES_TOTAL

_STATE_FILENAME = "templates.json"
_MAX_SAMPLE_LINES = 5
_MAX_RECENT_TIMESTAMPS = 500  # bounded ring buffer for GET /drift's rate computation
_MASK_TOKEN_RE = re.compile(r"<([A-Z_]+)>")

OrderBy = Literal["count", "first_seen_ns", "last_seen_ns", "template_id"]
_VALID_ORDER_BY = ("count", "first_seen_ns", "last_seen_ns", "template_id")


@dataclass
class TemplateRecord:
    """One mined template's accumulated state."""

    template_id: str
    template: str
    source_id: str
    first_seen_ns: int
    last_seen_ns: int
    count: int = 0
    sample_lines: list[str] = field(default_factory=list)
    suggested_fields: list[str] = field(default_factory=list)
    # bounded, most-recent-first-seen-order occurrence timestamps - not part of
    # the "public" template shape (list_templates()/get_samples() callers never
    # needed it before), but real per-occurrence timing is exactly what
    # GET /api/v1/templates/drift needs to tell a current-window rate from a
    # baseline one; capped so a hot template cannot grow this file unbounded.
    recent_ns: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TemplateRecord:
        return cls(
            template_id=str(data["template_id"]),
            template=data["template"],
            source_id=data["source_id"],
            first_seen_ns=int(data["first_seen_ns"]),
            last_seen_ns=int(data["last_seen_ns"]),
            count=int(data.get("count", 0)),
            sample_lines=list(data.get("sample_lines", [])),
            suggested_fields=list(data.get("suggested_fields", [])),
            recent_ns=list(data.get("recent_ns", [])),
        )


def _suggested_fields(template: str) -> list[str]:
    """Distinct ``<MASK>`` names in ``template``, in first-seen order."""
    seen: dict[str, None] = {}
    for name in _MASK_TOKEN_RE.findall(template):
        seen.setdefault(name, None)
    return list(seen)


class TemplateStore:
    """Persisted, queryable catalog of every template every source has produced.

    Thread-safe: :meth:`record` and the read methods all take an internal
    lock, since template mining runs off whichever pipeline worker happens to
    process a given unstructured line.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        clock: Any = time.time_ns,
    ) -> None:
        """Load any existing catalog from ``storage.state_path/templates.json``.

        Args:
            settings: Supplies ``storage.state_path``.
            clock: UTC epoch-nanoseconds source (injectable for tests).
        """
        self._path = Path(settings.storage.state_path) / _STATE_FILENAME
        self._clock = clock
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], TemplateRecord] = {}
        self._load()
        self._refresh_gauges()

    @property
    def path(self) -> Path:
        """Where the catalog is persisted."""
        return self._path

    # -- writing -----------------------------------------------------------

    def record(
        self, template_id: int | str, template: str, source_id: str, raw_line: str
    ) -> TemplateRecord:
        """Record one occurrence of ``template_id`` (from ``source_id``) and persist it.

        Creates the row on first occurrence; every call bumps ``count``,
        updates ``last_seen_ns``, and keeps up to :data:`_MAX_SAMPLE_LINES`
        example raw lines. Always increments ``ulpf_template_events_total``
        and, on a genuinely new template, ``ulpf_templates_total``.
        """
        key = (source_id, str(template_id))
        now = self._clock()
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                record = TemplateRecord(
                    template_id=str(template_id),
                    template=template,
                    source_id=source_id,
                    first_seen_ns=now,
                    last_seen_ns=now,
                    count=1,
                    sample_lines=[raw_line],
                    suggested_fields=_suggested_fields(template),
                    recent_ns=[now],
                )
                self._records[key] = record
                is_new = True
            else:
                existing.template = template
                existing.last_seen_ns = now
                existing.count += 1
                if len(existing.sample_lines) < _MAX_SAMPLE_LINES:
                    existing.sample_lines.append(raw_line)
                existing.suggested_fields = _suggested_fields(template)
                existing.recent_ns.append(now)
                if len(existing.recent_ns) > _MAX_RECENT_TIMESTAMPS:
                    del existing.recent_ns[:-_MAX_RECENT_TIMESTAMPS]
                record = existing
                is_new = False
            self._save()
            if is_new:
                self._refresh_gauge_for(source_id)
        TEMPLATE_EVENTS.labels(template_id=str(template_id)).inc()
        return record

    # -- reading -------------------------------------------------------

    def list_templates(
        self, source_id: str | None = None, order_by: OrderBy = "count"
    ) -> list[dict[str, Any]]:
        """Every known template, optionally scoped to one source.

        Args:
            source_id: Only templates from this source; ``None`` for all.
            order_by: ``"count"`` (busiest first, the default), ``"last_seen_ns"``
                or ``"first_seen_ns"`` (most recent first), or ``"template_id"``
                (ascending, for stable browsing).

        Raises:
            ValueError: If ``order_by`` is not one of the above.
        """
        if order_by not in _VALID_ORDER_BY:
            raise ValueError(f"order_by must be one of {_VALID_ORDER_BY}; got {order_by!r}")
        with self._lock:
            records = list(self._records.values())
        if source_id is not None:
            records = [r for r in records if r.source_id == source_id]
        if order_by == "template_id":
            records.sort(key=lambda r: (r.source_id, r.template_id))
        else:
            records.sort(key=lambda r: getattr(r, order_by), reverse=True)
        return [r.to_dict() for r in records]

    def get_samples(self, template_id: int | str, source_id: str | None = None) -> list[str]:
        """Sample raw lines recorded for ``template_id``.

        ``template_id`` alone is unique only within one source's tree; pass
        ``source_id`` to disambiguate when two sources happen to share a
        numeric id. Without it, the first match found is returned. Returns an
        empty list if nothing matches.
        """
        target = str(template_id)
        with self._lock:
            for (rec_source, rec_template), record in self._records.items():
                if rec_template != target:
                    continue
                if source_id is not None and rec_source != source_id:
                    continue
                return list(record.sample_lines)
        return []

    # -- persistence -----------------------------------------------------

    def _load(self) -> None:
        """Populate ``self._records`` from disk, if a catalog already exists."""
        if not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for entry in raw:
            record = TemplateRecord.from_dict(entry)
            self._records[(record.source_id, record.template_id)] = record

    def _save(self) -> None:
        """Atomically rewrite the catalog (temp file + :func:`os.replace`)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = [record.to_dict() for record in self._records.values()]
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=f".{_STATE_FILENAME}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except BaseException:
            os.unlink(tmp_name)
            raise
        os.replace(tmp_name, self._path)

    def _refresh_gauges(self) -> None:
        """Set ``ulpf_templates_total`` for every source currently in the catalog."""
        sources = {source_id for source_id, _ in self._records}
        for source_id in sources:
            self._refresh_gauge_for(source_id)

    def _refresh_gauge_for(self, source_id: str) -> None:
        """Recompute ``ulpf_templates_total{source_id}`` from the in-memory catalog."""
        count = sum(1 for (rec_source, _) in self._records if rec_source == source_id)
        TEMPLATES_TOTAL.labels(source_id=source_id).set(count)
