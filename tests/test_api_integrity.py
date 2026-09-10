"""Tests for :mod:`ulpf.api.routes.integrity` — every ``/api/v1/integrity`` endpoint."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ulpf.api.routes.integrity import build_integrity_router
from ulpf.config.settings import IntegritySettings, ParseSettings, Settings, StorageSettings
from ulpf.integrity.hashing import make_raw_event
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import LEDGER_FILENAME, IntegrityLedger
from ulpf.integrity.signing import Signer, generate_keypair
from ulpf.sinks.raw_store import RawStore

_REPO = Path(__file__).resolve().parent.parent

_FORTI_LINES = [
    b'<189>date=2026-08-15 time=22:14:%02d level="warning" devname="FGT" '
    b'logid="0000000013" type="traffic" subtype="forward" srcip=10.0.0.%d srcport=51000 '
    b'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=0 rcvdbyte=0' % (i, i)
    for i in range(5)
]


def _settings(tmp_path: Path, *, signed: bool = True) -> Settings:
    integrity = (
        IntegritySettings(
            signing_key_path=generate_keypair(tmp_path / "keys").private,
            public_key_path=tmp_path / "keys" / "ulpf_ed25519_public.pem",
        )
        if signed
        else IntegritySettings(signing_key_path=None)
    )
    return Settings(
        storage=StorageSettings(bronze_path=tmp_path / "bronze", ledger_path=tmp_path / "ledger"),
        parse=ParseSettings(sources_dir=_REPO / "configs" / "sources"),
        integrity=integrity,
    )


def _seal_one_batch(settings: Settings, lines: list[bytes]) -> list:
    store = RawStore(settings)
    events = [make_raw_event(line, source_id="t", transport="udp") for line in lines]
    for event in events:
        store.write(event)
    store.flush()
    signer = Signer.load(settings.integrity.signing_key_path)
    ledger = IntegrityLedger(settings, signer)
    index = IntegrityIndex(Path(settings.storage.ledger_path) / "event_index.sqlite")
    uids = [e.event_uid for e in events]
    entry = ledger.append_batch([bytes.fromhex(e.raw_hash) for e in events], event_uids=uids)
    index.add_batch(entry.seq, uids)
    index.close()
    return events


def _tamper_bronze(settings: Settings, event_uid: str) -> None:
    path = next(Path(settings.storage.bronze_path).rglob("events.ndjson.gz"))
    with gzip.open(path, "rb") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    for record in records:
        if record["event_uid"] == event_uid:
            record["raw_b64"] = base64.b64encode(b"attacker rewrote this").decode("ascii")
    with gzip.open(path, "wb") as handle:
        for record in records:
            handle.write((json.dumps(record, separators=(",", ":")) + "\n").encode())


def _corrupt_ledger_line(settings: Settings, index: int) -> None:
    path = Path(settings.storage.ledger_path) / LEDGER_FILENAME
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[index])
    row["batch_root"] = "ff" * 32
    lines[index] = json.dumps(row, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _app(settings: Settings, *, now_ns: int = 123) -> FastAPI:
    app = FastAPI()
    app.include_router(build_integrity_router(settings, clock=lambda: now_ns), prefix="/api/v1")
    return app


@pytest.fixture
def sealed(tmp_path: Path) -> tuple[Settings, list, TestClient]:
    settings = _settings(tmp_path)
    events = _seal_one_batch(settings, _FORTI_LINES)
    client = TestClient(_app(settings, now_ns=999_000_000_000))
    return settings, events, client


# ======================================================================
# GET /status
# ======================================================================


def test_status_reflects_a_sealed_ledger(sealed: tuple[Settings, list, TestClient]) -> None:
    _settings_, events, client = sealed
    response = client.get("/api/v1/integrity/status")
    assert response.status_code == 200
    body = response.json()
    assert body["ledger_entries"] == 1
    assert body["total_events_sealed"] == len(events)
    assert body["last_seal_ns"] is not None
    assert body["chain_verified"] is True
    assert body["last_verification_ns"] == 999_000_000_000


def test_status_with_no_ledger_is_trivially_verified(tmp_path: Path) -> None:
    settings = _settings(tmp_path, signed=False)  # bronze/ledger never written
    client = TestClient(_app(settings, now_ns=42))
    body = client.get("/api/v1/integrity/status").json()
    assert body == {
        "ledger_entries": 0,
        "total_events_sealed": 0,
        "last_seal_ns": None,
        "chain_verified": True,
        "last_verification_ns": 42,
    }


def test_status_detects_a_broken_chain(sealed: tuple[Settings, list, TestClient]) -> None:
    settings, _events, client = sealed
    _corrupt_ledger_line(settings, 0)
    body = client.get("/api/v1/integrity/status").json()
    assert body["chain_verified"] is False
    assert body["ledger_entries"] == 1  # still reports what's on disk


# ======================================================================
# POST /verify/chain
# ======================================================================


def test_verify_chain_intact(sealed: tuple[Settings, list, TestClient]) -> None:
    _settings_, _events, client = sealed
    response = client.post("/api/v1/integrity/verify/chain")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True and body["broken_at"] is None
    assert body["entries_total"] == 1 and body["checked"] == 1


def test_verify_chain_names_the_broken_sequence(sealed: tuple[Settings, list, TestClient]) -> None:
    settings, _events, client = sealed
    _corrupt_ledger_line(settings, 0)
    body = client.post("/api/v1/integrity/verify/chain").json()
    assert body["ok"] is False and body["broken_at"] == 0
    assert body["broken_reason"]


def test_verify_chain_with_no_ledger_is_a_clean_ok(tmp_path: Path) -> None:
    settings = _settings(tmp_path, signed=False)
    client = TestClient(_app(settings))
    body = client.post("/api/v1/integrity/verify/chain").json()
    assert body["ledger_present"] is False
    assert body["ok"] is True


# ======================================================================
# POST /verify/events
# ======================================================================


def test_verify_events_passes_for_an_untouched_store(
    sealed: tuple[Settings, list, TestClient],
) -> None:
    _settings_, events, client = sealed
    body = client.post("/api/v1/integrity/verify/events").json()
    assert body["checked"] == len(events)
    assert body["passed"] == len(events) and body["failed"] == 0
    assert body["failures"] == []


def test_verify_events_flags_a_tampered_event(sealed: tuple[Settings, list, TestClient]) -> None:
    settings, events, client = sealed
    victim = events[2].event_uid
    _tamper_bronze(settings, victim)

    body = client.post("/api/v1/integrity/verify/events").json()
    assert body["failed"] == 1 and body["passed"] == len(events) - 1
    failure = body["failures"][0]
    assert failure["event_uid"] == victim
    assert failure["hash_ok"] is False and failure["proof_ok"] is False
    assert "tamper" in failure["reason"].lower()


def test_verify_events_date_filter(sealed: tuple[Settings, list, TestClient]) -> None:
    _settings_, _events, client = sealed
    body = client.post("/api/v1/integrity/verify/events", params={"date": "1999-01-01"}).json()
    assert body["checked"] == 0


# ======================================================================
# GET /ledger
# ======================================================================


def test_ledger_lists_every_entry_verified(sealed: tuple[Settings, list, TestClient]) -> None:
    _settings_, events, client = sealed
    response = client.get("/api/v1/integrity/ledger")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    (row,) = rows
    assert row["seq"] == 0
    assert row["leaf_count"] == len(events)
    assert row["signature_ok"] is True
    assert row["verified"] is True
    assert row["first_event_uid"] == events[0].event_uid
    assert len(row["batch_root"]) == 64  # hex-encoded 32 bytes


def test_ledger_flags_a_corrupted_entry(sealed: tuple[Settings, list, TestClient]) -> None:
    settings, _events, client = sealed
    # rewrites batch_root: the signature over the untouched chained_root still
    # verifies, but the chain-link recompute no longer does.
    _corrupt_ledger_line(settings, 0)
    (row,) = client.get("/api/v1/integrity/ledger").json()
    assert row["signature_ok"] is True
    assert row["verified"] is False


def test_ledger_is_empty_without_a_ledger(tmp_path: Path) -> None:
    settings = _settings(tmp_path, signed=False)
    client = TestClient(_app(settings))
    response = client.get("/api/v1/integrity/ledger")
    assert response.status_code == 200
    assert response.json() == []


# ======================================================================
# GET /proof/{event_uid}
# ======================================================================


def test_proof_for_a_good_event(sealed: tuple[Settings, list, TestClient]) -> None:
    _settings_, events, client = sealed
    victim = events[1].event_uid
    response = client.get(f"/api/v1/integrity/proof/{victim}")
    assert response.status_code == 200
    body = response.json()
    assert body["event_uid"] == victim
    assert body["ok"] is True
    assert body["recorded_hash"] == body["recomputed_hash"]
    assert len(body["merkle_proof"]) == 3  # ceil(log2(5))
    assert all(step["side"] in {"left", "right"} for step in body["merkle_proof"])
    entry = body["ledger_entry"]
    assert entry is not None
    assert entry["seq"] == 0
    assert entry["leaf_count"] == 5
    assert entry["first_event_uid"] == events[0].event_uid
    assert entry["last_event_uid"] == events[-1].event_uid


def test_proof_for_a_tampered_event(sealed: tuple[Settings, list, TestClient]) -> None:
    settings, events, client = sealed
    victim = events[0].event_uid
    _tamper_bronze(settings, victim)
    body = client.get(f"/api/v1/integrity/proof/{victim}").json()
    assert body["ok"] is False
    assert body["hash_ok"] is False
    assert body["recorded_hash"] != body["recomputed_hash"]


def test_proof_404_for_unknown_event(sealed: tuple[Settings, list, TestClient]) -> None:
    _settings_, _events, client = sealed
    response = client.get("/api/v1/integrity/proof/does-not-exist")
    assert response.status_code == 404


def test_proof_with_no_ledger_still_hashes(tmp_path: Path) -> None:
    settings = _settings(tmp_path, signed=False)
    store = RawStore(settings)
    event = make_raw_event(_FORTI_LINES[0], source_id="t", transport="udp")
    store.write(event)
    store.flush()
    client = TestClient(_app(settings))

    body = client.get(f"/api/v1/integrity/proof/{event.event_uid}").json()
    assert body["hash_ok"] is True
    assert body["found"] is False  # no ledger batch indexes it
    assert body["ledger_entry"] is None
    assert body["ok"] is False  # found is required for .ok
