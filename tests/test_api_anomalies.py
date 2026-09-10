"""Tests for :mod:`ulpf.api.routes.anomalies` — every ``/api/v1/anomalies`` endpoint."""

from __future__ import annotations

from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ulpf.api.routes.anomalies import build_anomalies_router
from ulpf.config.settings import MlSettings, Settings, StorageSettings
from ulpf.ml import jobs
from ulpf.parse.templates.store import TemplateStore

_DATE = "2026-09-05"
_S = 1_000_000_000
_BASE_NS = 1_788_609_600 * _S
_SCORED_AT = _BASE_NS + 400 * _S


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        ml=MlSettings(
            model_path=tmp_path / "models" / "anomaly.joblib",
            anomalies_path=tmp_path / "anomalies",
            drift_state_path=tmp_path / "state" / "drift.json",
            contamination=0.2,
        ),
    )


def _write_silver(settings: Settings) -> None:
    rows: list[dict[str, object]] = []
    for i in range(180):
        rows.append(
            {
                "event_uid": f"n{i:04d}",
                "time": _BASE_NS + i * _S,
                "src_ip": f"10.0.0.{i % 5}",
                "dst_ip": "8.8.8.8",
                "dst_port": (80, 443, 53)[i % 3],
                "protocol": "tcp",
                "action_id": 1,
                "severity_id": 1,
                "bytes_in": 200 + i,
                "bytes_out": 100 + i,
            }
        )
    for j in range(15):
        rows.append(
            {
                "event_uid": f"s{j:04d}",
                "time": _BASE_NS + (180 + j) * _S,
                "src_ip": "10.9.9.9",
                "dst_ip": "8.8.8.8",
                "dst_port": 1000 + j,
                "protocol": "tcp",
                "action_id": 2,
                "severity_id": 3,
                "bytes_in": 0,
                "bytes_out": 40,
            }
        )
    part_dir = Path(settings.storage.silver_path) / f"date={_DATE}" / "source_type=acme_fw"
    part_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), part_dir / "part-000.parquet")


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    settings = _settings(tmp_path)
    _write_silver(settings)
    jobs.train(settings, date_from=_DATE, date_to=_DATE)
    jobs.score_day(settings, date=_DATE, now_ns=_SCORED_AT)

    app = FastAPI()
    app.include_router(build_anomalies_router(settings), prefix="/api/v1")
    test_client = TestClient(app)
    test_client.settings = settings  # type: ignore[attr-defined]
    return test_client


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------


def test_list_returns_scored_anomalies_with_explanations(client: TestClient) -> None:
    resp = client.get("/api/v1/anomalies/")
    assert resp.status_code == 200
    rows = resp.json()
    assert rows
    for row in rows:
        assert row["is_anomaly"] is True
        assert row["event_uid"]
        assert row["anomaly_score"] > 0
        assert row["explanation"] and len(row["explanation"]) <= 3
        top = row["explanation"][0]
        assert {
            "feature",
            "value",
            "percentile",
            "direction",
            "training_median",
            "note",
        } <= top.keys()


def test_list_min_score_filter(client: TestClient) -> None:
    everything = client.get("/api/v1/anomalies/").json()
    ceiling = max(row["anomaly_score"] for row in everything) + 1.0
    resp = client.get("/api/v1/anomalies/", params={"min_score": ceiling})
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_include_normal_returns_every_event(client: TestClient) -> None:
    resp = client.get("/api/v1/anomalies/", params={"include_normal": True, "limit": 1000})
    assert resp.status_code == 200
    assert len(resp.json()) == 195


# ---------------------------------------------------------------------------
# GET /model
# ---------------------------------------------------------------------------


def test_model_info_after_training(client: TestClient) -> None:
    resp = client.get("/api/v1/anomalies/model")
    assert resp.status_code == 200
    body = resp.json()
    assert body["trained"] is True
    assert body["n_samples"] == 195
    assert body["n_features"] == 23
    assert body["contamination"] == 0.2
    assert body["trained_at"]
    assert len(body["feature_names"]) == 23


def test_model_info_before_any_training(tmp_path: Path) -> None:
    app = FastAPI()
    app.include_router(build_anomalies_router(_settings(tmp_path)), prefix="/api/v1")
    resp = TestClient(app).get("/api/v1/anomalies/model")
    assert resp.status_code == 200
    assert resp.json() == {
        "trained": False,
        "trained_at": None,
        "n_samples": None,
        "n_features": None,
        "contamination": None,
        "feature_names": [],
    }


# ---------------------------------------------------------------------------
# GET /timeline
# ---------------------------------------------------------------------------


def test_timeline_buckets_scores(client: TestClient) -> None:
    resp = client.get("/api/v1/anomalies/timeline", params={"window": "24h", "bucket": "1h"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["window_seconds"] == 86_400
    assert body["bucket_seconds"] == 3_600
    assert body["points"]
    assert sum(point["scored"] for point in body["points"]) == 195
    assert sum(point["anomalies"] for point in body["points"]) > 0


def test_timeline_rejects_a_bad_window(client: TestClient) -> None:
    resp = client.get("/api/v1/anomalies/timeline", params={"window": "soon"})
    assert resp.status_code == 400


def test_timeline_on_an_empty_lake_is_empty(tmp_path: Path) -> None:
    app = FastAPI()
    app.include_router(build_anomalies_router(_settings(tmp_path)), prefix="/api/v1")
    resp = TestClient(app).get("/api/v1/anomalies/timeline")
    assert resp.status_code == 200
    assert resp.json()["points"] == []


# ---------------------------------------------------------------------------
# GET /drift
# ---------------------------------------------------------------------------


def test_drift_endpoint_tracks_a_template_going_silent(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    t0 = 1_000_000 * _S
    clk = [t0 + 30 * _S]
    store = TemplateStore(settings, clock=lambda: t0)
    for i in range(16):
        store.record(1, "login from <*>", "sshd", f"login from 10.0.0.{i}")

    app = FastAPI()
    app.include_router(build_anomalies_router(settings, clock=lambda: clk[0]), prefix="/api/v1")
    api = TestClient(app)

    for _ in range(5):  # steady baseline
        resp = api.get("/api/v1/anomalies/drift", params={"window_minutes": 1.0})
        assert resp.status_code == 200
        assert resp.json() == []

    clk[0] = t0 + 3_600 * _S  # an hour of silence for that template
    resp = api.get("/api/v1/anomalies/drift", params={"window_minutes": 1.0})
    assert resp.status_code == 200
    signals = resp.json()
    assert len(signals) == 1
    assert signals[0]["direction"] == "drop"
    assert signals[0]["template"] == "login from <*>"
    assert signals[0]["z_score"] < -3.0


# ---------------------------------------------------------------------------
# POST /train
# ---------------------------------------------------------------------------


def test_train_endpoint_retrains_the_model(client: TestClient) -> None:
    resp = client.post("/api/v1/anomalies/train", json={"date_from": _DATE, "date_to": _DATE})
    assert resp.status_code == 200
    body = resp.json()
    assert body["n_samples"] == 195
    assert body["n_features"] == 23
    assert Path(body["model_path"]).is_file()


def test_train_endpoint_rejects_a_reversed_range(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/anomalies/train", json={"date_from": "2026-09-09", "date_to": _DATE}
    )
    assert resp.status_code == 400
