"""Normalization stages: :class:`NormalizeStage` then :class:`ValidateStage`.

They are split so :class:`~ulpf.enrich.stage.EnrichStage` can run *between* them
— an enricher may promote a value into a proper OCSF slot that should then be
validated.

:class:`NormalizeStage` (after :class:`~ulpf.core.pipeline.ParseStage`):

1. :meth:`~ulpf.parse.dsl.loader.SourceRegistry.match` finds the source
   definition. **No match -> the event is still normalized**, into a
   *template-only* OCSF skeleton (:meth:`NormalizeStage._template_only`), not
   dead-lettered and not dropped:

   * the raw line is run through :class:`~ulpf.parse.templates.TemplateMiner`
     to get a stable ``template_id`` for its shape;
   * a minimal OCSF ``class_uid=4001`` record is built from only what is safe
     to infer — ``time`` (from the syslog envelope if present, else the
     ingest time), ``metadata``, and **every** extracted field verbatim under
     ``unmapped``;
   * ``source_type`` becomes ``"unknown:<template_id>"`` and
     ``enrichments.parse_status = "template_only"`` marks it;
   * the shape is recorded to :class:`~ulpf.parse.templates.TemplateStore` and
     ``ulpf_unknown_events_total{template_id}`` is incremented.

   So a source nobody has written a YAML for still produces queryable
   structure and a traceable record — it becomes a *candidate for
   auto-generated parsing*, not a lost event.
2. Once matched, :func:`~ulpf.parse.coordinator.parse_for_definition`
   re-parses the RAW bytes with that definition's own declared engine and
   options — the authoritative parse; ``ParseStage``'s sniff-based fields are
   only ever a hint used for matching, since the sniffer cannot recognise
   ``grok``/``dissect`` and cannot supply a source's own ``csv`` columns etc.
   If the source's own engine still cannot read the line, that is a
   :class:`~ulpf.core.errors.ParseError` and the event is dead-lettered here
   (``reason`` from the engine, e.g. ``"grok_no_match"``).
3. :meth:`~ulpf.normalize.mapper.Mapper.apply` maps those fields to a nested
   OCSF record; a :class:`~ulpf.core.errors.MappingError` dead-letters the event
   with the parsed fields and partial record in ``detail``.
4. :func:`~ulpf.normalize.ocsf.base.finalize` fills derived name fields.
5. A :class:`~ulpf.core.models.NormalizedEvent` is emitted and
   ``ulpf_events_normalized_total{source_type,class_uid}`` incremented.

:class:`ValidateStage` (after :class:`~ulpf.enrich.stage.EnrichStage`):

* runs :class:`~ulpf.normalize.validator.OcsfValidator`; a valid record passes
  through untouched;
* an invalid record whose source definition says ``on_failure: dead_letter`` is
  dead-lettered (``stage="validate"``) and dropped — the original bytes remain
  in bronze under ``raw_hash``; ``on_failure: warn`` logs and emits it anyway;
* template-only (``source_type`` starting ``"unknown:"``) records are not
  validated — there is no source policy to validate them against.
"""

from __future__ import annotations

import logging
from typing import Any

from ulpf.config.settings import Settings
from ulpf.core.errors import MappingError, ParseError
from ulpf.core.metrics import EVENTS_NORMALIZED, UNKNOWN_EVENTS
from ulpf.core.models import NormalizedEvent, ParsedEvent, RawEvent
from ulpf.core.pipeline import Event
from ulpf.core.timeutil import parse_timestamp
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import OCSF_VERSION, finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import parse_for_definition
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import SourceDefinition
from ulpf.parse.templates import TemplateMinerRegistry, TemplateStore
from ulpf.sinks.dlq import DeadLetterQueue

_log = logging.getLogger(__name__)

_UNKNOWN = "unknown"
_TEMPLATE_ONLY_PREFIX = "unknown:"


class NormalizeStage:
    """Match a source definition, map to OCSF, and finalize."""

    name = "normalize"

    def __init__(
        self,
        settings: Settings,
        registry: SourceRegistry,
        *,
        mapper: Mapper | None = None,
        miners: TemplateMinerRegistry | None = None,
        template_store: TemplateStore | None = None,
    ) -> None:
        """Wire the source registry, mapper, DLQ, and the template miner/store.

        ``miners``/``template_store`` are injectable for tests; by default they
        are built from ``settings`` (both are cheap to construct and do no I/O
        until an unmatched line actually needs them).
        """
        self._registry = registry
        self._mapper = mapper or Mapper()
        self._dlq = DeadLetterQueue(settings)
        self._miners = miners or TemplateMinerRegistry(settings)
        self._template_store = template_store or TemplateStore(settings)

    async def process(self, event: Event) -> NormalizedEvent | None:
        """Normalize one event; ``None`` if a parse or mapping failure dead-lettered it."""
        assert isinstance(event, ParsedEvent)
        definition = self._registry.match(event)
        if definition is None:
            return self._template_only(event)

        try:
            fields = parse_for_definition(event.raw, definition)
        except ParseError as exc:
            self._dead_letter_parse_failure(event, definition, exc)
            return None

        try:
            ocsf = finalize(
                self._mapper.apply(
                    definition, fields, event_uid=event.event_uid, raw_hash=event.raw_hash
                )
            )
        except MappingError as exc:
            self._dead_letter_mapping_failure(event, definition, fields, exc)
            return None

        class_uid = ocsf.get("class_uid")
        EVENTS_NORMALIZED.labels(
            source_type=definition.name,
            class_uid=str(class_uid) if class_uid is not None else _UNKNOWN,
        ).inc()
        return NormalizedEvent(
            event_uid=event.event_uid,
            raw_hash=event.raw_hash,
            ingest_time_ns=event.ingest_time_ns,
            ocsf=ocsf,
            source_type=definition.name,
            mapping_version=definition.version,
            enrichment={},
        )

    def _dead_letter_parse_failure(
        self, event: ParsedEvent, definition: SourceDefinition, exc: ParseError
    ) -> None:
        """Dead-letter a source whose OWN declared engine still could not read the line.

        Distinct from a mapping failure: the source's ``detect`` rule matched
        the line, but ``parse_for_definition`` — using that source's own
        engine and options, the authoritative parse — could not extract fields
        from it at all.
        """
        self._dlq.write(
            event,
            reason=str(exc.detail.get("reason") or "source_parse_failed"),
            stage=self.name,
            detail={"source_type": definition.name, "error": str(exc), **exc.detail},
        )
        _log.warning(
            "matched source's own engine failed to parse the event; dead-lettered",
            extra={
                "source_type": definition.name,
                "event_uid": event.event_uid,
                "detail": exc.detail,
            },
        )

    def _dead_letter_mapping_failure(
        self,
        event: ParsedEvent,
        definition: SourceDefinition,
        fields: dict[str, Any],
        exc: MappingError,
    ) -> None:
        """Dead-letter a mapping failure, keeping the parsed fields and partial record.

        The raw event is already in bronze; this makes the DLQ entry show *what
        was parsed* (via the source's own engine, not ``ParseStage``'s sniff-
        based hint) and *how far mapping got*, so an operator can fix the
        source definition without replaying the log.
        """
        detail = dict(exc.detail)
        detail.setdefault("parsed_fields", dict(fields))
        detail.setdefault("partial_ocsf", {})
        self._dlq.write(
            event,
            reason=str(detail.get("reason") or "mapping_failed"),
            stage=self.name,
            detail={"source_type": definition.name, "error": str(exc), **detail},
        )
        _log.warning(
            "mapping failed; event dead-lettered with parsed fields",
            extra={
                "source_type": definition.name,
                "event_uid": event.event_uid,
                "target": detail.get("target"),
                "field_count": len(fields),
            },
        )

    def _template_only(self, event: ParsedEvent) -> NormalizedEvent:
        """No source matched: mine the shape, emit a template-only OCSF skeleton.

        The event is never dropped or dead-lettered. It becomes a candidate for
        an auto-generated source definition: its shape is mined to a stable
        ``template_id``, a minimal ``class_uid=4001`` record is built from only
        what is safe to infer (time + metadata + every extracted field under
        ``unmapped``), and the shape is recorded to the template store.
        """
        line = _line_for_mining(event)
        mined = self._miners.get(event.source_id).mine(line)
        template_id = str(mined["template_id"])
        self._template_store.record(template_id, mined["template"], event.source_id, line)
        UNKNOWN_EVENTS.labels(template_id=template_id).inc()

        source_type = f"{_TEMPLATE_ONLY_PREFIX}{template_id}"
        enrichments = {"parse_status": "template_only", "template_id": template_id}
        ocsf = finalize(
            {
                "class_uid": 4001,
                "category_uid": 4,
                "time": _infer_time_ns(event),
                "metadata": {
                    "uid": event.event_uid,
                    "log_hash": event.raw_hash,  # requirement (d)
                    "version": OCSF_VERSION,
                },
                "unmapped": dict(event.fields),
                "enrichments": enrichments,
            }
        )
        return NormalizedEvent(
            event_uid=event.event_uid,
            raw_hash=event.raw_hash,
            ingest_time_ns=event.ingest_time_ns,
            ocsf=ocsf,
            source_type=source_type,
            mapping_version="none",
            enrichment={
                **enrichments,
                "needs_template_mining": event.needs_template_mining,
            },
        )


class ValidateStage:
    """Validate the (possibly enriched) OCSF record; dead-letter per source policy."""

    name = "validate"

    def __init__(
        self,
        settings: Settings,
        registry: SourceRegistry,
        *,
        validator: OcsfValidator | None = None,
    ) -> None:
        """Wire the validator, the registry (for the per-source policy) and the DLQ."""
        self._registry = registry
        self._validator = validator or OcsfValidator()
        self._dlq = DeadLetterQueue(settings)

    async def process(self, event: Event) -> NormalizedEvent | None:
        """Return the event if valid (or ``on_failure: warn``), else ``None``."""
        assert isinstance(event, NormalizedEvent)
        if _is_unmapped(event.source_type) or "class_uid" not in event.ocsf:
            return event  # pass-through / template-only / non-OCSF records are not validated

        result = self._validator.validate(event.ocsf)
        if result.valid:
            return event

        definition = self._registry.get(event.source_type)
        on_failure = definition.validation.on_failure if definition is not None else "dead_letter"
        if on_failure == "dead_letter":
            self._dlq.write(
                _raw_stub(event),
                reason="ocsf_validation_failed",
                stage=self.name,
                detail={
                    "source_type": event.source_type,
                    "errors": result.errors,
                    "note": "raw bytes are in the bronze store under raw_hash",
                },
            )
            _log.warning(
                "normalized record failed validation; dead-lettered",
                extra={"source_type": event.source_type, "event_uid": event.event_uid},
            )
            return None

        _log.warning(
            "normalized record failed validation (on_failure=warn); emitting anyway",
            extra={
                "source_type": event.source_type,
                "event_uid": event.event_uid,
                "errors": result.errors,
            },
        )
        return event


def _is_unmapped(source_type: str) -> bool:
    """Whether ``source_type`` is the legacy ``"unknown"`` or a ``"unknown:<id>"`` skeleton."""
    return source_type == _UNKNOWN or source_type.startswith(_TEMPLATE_ONLY_PREFIX)


def _line_for_mining(event: ParsedEvent) -> str:
    """Text whose shape to mine: the message body, with any syslog header removed.

    Mining the bare message (not the ``<PRI>timestamp host tag`` envelope) keeps
    the learned template about what the *device* said, not how it was framed —
    the envelope is already structured on ``event.envelope`` and would only add
    per-line noise (host, timestamp) to every template.
    """
    text = event.raw.decode("utf-8", errors="replace")
    header_raw = event.envelope.get("header_raw")
    if isinstance(header_raw, str) and header_raw and text.startswith(header_raw):
        return text[len(header_raw) :]
    return text


def _infer_time_ns(event: ParsedEvent) -> int:
    """OCSF ``time`` for a template-only record: the syslog envelope's, else ingest time."""
    raw_ts = event.envelope.get("timestamp")
    if isinstance(raw_ts, str) and raw_ts:
        try:
            return parse_timestamp(raw_ts)
        except (ParseError, ValueError, TypeError):
            _log.debug(
                "template-only: unparseable envelope timestamp %r; using ingest time", raw_ts
            )
    return event.ingest_time_ns


def _raw_stub(event: NormalizedEvent) -> RawEvent:
    """A minimal :class:`RawEvent` carrying the traceability keys for the DLQ.

    The original bytes are already in the bronze store keyed by ``raw_hash``; a
    post-normalization failure does not need to re-persist them.
    """
    return RawEvent(
        event_uid=event.event_uid,
        raw=b"",
        raw_hash=event.raw_hash,
        raw_len=0,
        ingest_time_ns=event.ingest_time_ns,
        source_id=event.source_type,
        transport="file",
    )
