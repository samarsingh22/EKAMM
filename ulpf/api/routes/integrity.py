"""``/api/v1/integrity`` — the signed Merkle ledger's status, verification, and proofs.

Wraps the same artefacts and logic :mod:`ulpf.cli.verify` drives (``ulpf
verify chain``/``events``/``event``), so a chain-broken-at-seq-N or a
tampered-event result is identical whether it came from the CLI on set day or
this API from the dashboard. ``_load_verifier``/``_load_ledger``/``_load_index``
below duplicate the small, private artefact-loading glue in
:mod:`ulpf.cli.verify` rather than importing it — the same tradeoff
``ulpf.api.routes.events`` already documents for its own copy.

Endpoints
---------
* ``GET /status``          — ``{ledger_entries, total_events_sealed,
  last_seal_ns, chain_verified, last_verification_ns}``. ``chain_verified``
  runs a real, live :meth:`~ulpf.integrity.ledger.IntegrityLedger.verify_chain`
  on every call (not a cached flag) — ``last_verification_ns`` is simply *when
  this call ran it*, since nothing persists a verification timestamp anywhere
  else in the system.
* ``POST /verify/chain``   — :func:`~ulpf.cli.verify.run_verify_chain`.
* ``POST /verify/events``  — :func:`~ulpf.cli.verify.run_verify_events`,
  optionally scoped to one ingest ``?date=YYYY-MM-DD``.
* ``GET /ledger``          — every sealed batch entry (``seq``, ``sealed_at_ns``,
  ``leaf_count``, roots, signature) plus a per-entry ``signature_ok`` — for
  the dashboard's ledger table.
* ``GET /proof/{event_uid}`` — one event's :class:`~ulpf.integrity.proofs.EventProof`
  (hash/proof/signature checks, the Merkle authentication path) plus the full
  ledger entry that seals its batch, when one exists.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ulpf.cli.verify import ChainReport, EventsReport, run_verify_chain, run_verify_events
from ulpf.config.settings import Settings
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import (
    LEDGER_FILENAME,
    IntegrityLedger,
    LedgerEntry,
    chain_roots,
)
from ulpf.integrity.proofs import EventProof, ProofBuilder
from ulpf.integrity.signing import Signer, Verifier
from ulpf.sinks.raw_store import RawStore

_INDEX_FILENAME = "event_index.sqlite"


# ======================================================================
# wire models
# ======================================================================


class IntegrityStatus(BaseModel):
    """Response body for ``GET /status``."""

    ledger_entries: int
    total_events_sealed: int
    last_seal_ns: int | None
    chain_verified: bool
    last_verification_ns: int


class LedgerEntryOut(BaseModel):
    """One sealed batch's ledger record (hex-encoded byte fields)."""

    seq: int
    batch_root: str
    prev_chained_root: str
    chained_root: str
    leaf_count: int
    first_event_uid: str | None
    last_event_uid: str | None
    sealed_at_ns: int
    signature: str


class LedgerEntryRow(LedgerEntryOut):
    """One ledger entry plus its per-entry integrity checks.

    ``signature_ok`` is the pure Ed25519 check over ``chained_root``;
    ``verified`` also requires the chain-link recompute
    (``chained_root == SHA-256(prev_chained_root || batch_root)``), so a
    ``batch_root`` tamper — which leaves the signature over the untouched
    ``chained_root`` intact — still shows as unverified.
    """

    signature_ok: bool
    verified: bool


class MerkleProofStep(BaseModel):
    """One step of a Merkle authentication path."""

    sibling: str
    side: str


class EventProofOut(BaseModel):
    """Response body for ``GET /proof/{event_uid}``."""

    event_uid: str
    found: bool
    ok: bool
    hash_ok: bool
    proof_ok: bool
    signature_ok: bool
    leaf_index: int | None
    recorded_hash: str | None
    recomputed_hash: str | None
    merkle_proof: list[MerkleProofStep] = Field(default_factory=list)
    ledger_entry: LedgerEntryOut | None
    reason: str | None


# ======================================================================
# router
# ======================================================================


def build_integrity_router(
    settings: Settings, *, clock: Callable[[], int] = time.time_ns
) -> APIRouter:
    """The ``/integrity`` router. ``clock`` (UTC epoch-ns) is injectable for tests."""
    router = APIRouter(prefix="/integrity", tags=["integrity"])

    @router.get("/status", response_model=IntegrityStatus)
    async def status() -> IntegrityStatus:
        return await asyncio.to_thread(_status, settings, clock)

    @router.post("/verify/chain")
    async def verify_chain() -> dict[str, Any]:
        report: ChainReport = await asyncio.to_thread(
            run_verify_chain, settings, show_progress=False
        )
        return report.to_dict()

    @router.post("/verify/events")
    async def verify_events(
        date: str | None = Query(None, description="Restrict to one ingest date (YYYY-MM-DD)."),
    ) -> dict[str, Any]:
        report: EventsReport = await asyncio.to_thread(run_verify_events, settings, date)
        return report.to_dict()

    @router.get("/ledger", response_model=list[LedgerEntryRow])
    async def ledger_rows() -> list[LedgerEntryRow]:
        return await asyncio.to_thread(_ledger_rows, settings)

    @router.get("/proof/{event_uid}", response_model=EventProofOut)
    async def proof(event_uid: str) -> EventProofOut:
        result = await asyncio.to_thread(_event_proof, settings, event_uid)
        if result is None:
            raise HTTPException(status_code=404, detail=f"event {event_uid!r} not found")
        return result

    return router


# ======================================================================
# artefact loading — mirrors ulpf.cli.verify's private helpers
# ======================================================================


def _load_verifier(settings: Settings) -> Verifier | None:
    integrity = settings.integrity
    if integrity.public_key_path and Path(integrity.public_key_path).is_file():
        return Verifier.load(integrity.public_key_path)
    if integrity.signing_key_path and Path(integrity.signing_key_path).is_file():
        return Signer.load(integrity.signing_key_path).verifier()
    return None


def _load_ledger(settings: Settings) -> IntegrityLedger | None:
    if not (Path(settings.storage.ledger_path) / LEDGER_FILENAME).is_file():
        return None
    return IntegrityLedger(settings, verifier=_load_verifier(settings))


def _load_index(settings: Settings) -> IntegrityIndex | None:
    path = Path(settings.storage.ledger_path) / _INDEX_FILENAME
    return IntegrityIndex(path) if path.is_file() else None


# ======================================================================
# GET /status
# ======================================================================


def _status(settings: Settings, clock: Callable[[], int]) -> IntegrityStatus:
    ledger = _load_ledger(settings)
    if ledger is None:
        # no ledger at all == nothing to contradict; verify_chain's own
        # convention for an absent/empty ledger is also "ok" (see run_verify_chain).
        return IntegrityStatus(
            ledger_entries=0,
            total_events_sealed=0,
            last_seal_ns=None,
            chain_verified=True,
            last_verification_ns=clock(),
        )
    entries = ledger.entries()
    chain_ok, _broken_at = ledger.verify_chain()
    return IntegrityStatus(
        ledger_entries=len(entries),
        total_events_sealed=sum(entry.leaf_count for entry in entries),
        last_seal_ns=entries[-1].sealed_at_ns if entries else None,
        chain_verified=chain_ok,
        last_verification_ns=clock(),
    )


# ======================================================================
# GET /proof/{event_uid}
# ======================================================================


def _ledger_entry_out(entry: LedgerEntry) -> LedgerEntryOut:
    return LedgerEntryOut(
        seq=entry.seq,
        batch_root=entry.batch_root.hex(),
        prev_chained_root=entry.prev_chained_root.hex(),
        chained_root=entry.chained_root.hex(),
        leaf_count=entry.leaf_count,
        first_event_uid=entry.first_event_uid,
        last_event_uid=entry.last_event_uid,
        sealed_at_ns=entry.sealed_at_ns,
        signature=entry.signature.hex(),
    )


def _ledger_rows(settings: Settings) -> list[LedgerEntryRow]:
    """Every ledger entry plus its per-entry signature + chain-link checks."""
    ledger = _load_ledger(settings)
    if ledger is None:
        return []
    verifier = ledger.verifier
    rows: list[LedgerEntryRow] = []
    for entry in ledger.entries():
        signature_ok = verifier is not None and verifier.verify(entry.chained_root, entry.signature)
        link_ok = chain_roots(entry.prev_chained_root, entry.batch_root) == entry.chained_root
        rows.append(
            LedgerEntryRow(
                **_ledger_entry_out(entry).model_dump(),
                signature_ok=signature_ok,
                verified=signature_ok and link_ok,
            )
        )
    return rows


def _event_proof(settings: Settings, event_uid: str) -> EventProofOut | None:
    ledger = _load_ledger(settings)
    index = _load_index(settings)
    try:
        proof: EventProof = ProofBuilder(RawStore(settings), index, ledger).for_event(event_uid)
    finally:
        if index is not None:
            index.close()

    if proof.recorded_hash is None:
        return None  # not in the bronze store at all

    ledger_entry_out = None
    if ledger is not None and proof.ledger_seq is not None:
        entry = next((e for e in ledger.entries() if e.seq == proof.ledger_seq), None)
        ledger_entry_out = _ledger_entry_out(entry) if entry is not None else None

    return EventProofOut(
        event_uid=proof.event_uid,
        found=proof.found,
        ok=proof.ok,
        hash_ok=proof.hash_ok,
        proof_ok=proof.proof_ok,
        signature_ok=proof.signature_ok,
        leaf_index=proof.leaf_index,
        recorded_hash=proof.recorded_hash.hex() if proof.recorded_hash else None,
        recomputed_hash=proof.recomputed_hash.hex() if proof.recomputed_hash else None,
        merkle_proof=[
            MerkleProofStep(sibling=sibling.hex(), side=side) for sibling, side in proof.proof
        ],
        ledger_entry=ledger_entry_out,
        reason=proof.reason,
    )
