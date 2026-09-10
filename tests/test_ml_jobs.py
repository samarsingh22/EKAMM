"""Tests for :mod:`ulpf.ml.jobs` — train / score / score-recent / drift / the scoring loop."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from ulpf.config.settings import MlSettings, Settings, StorageSettings
from ulpf.ml import jobs
from ulpf.parse.templates.store import TemplateStore

_DATE = "2026-09-05"
_S = 1_000_000_000
_BASE_NS = 1_788_609_600 * _S  # 2026-09-05T12:00:00Z, give or take — a fixed instant
_SCORED_AT = _BASE_NS + 400 * _S


def _settings(
    tmp_path: Path, *, scoring_enabled: bool = False, scoring_interval: float = 60.0
) -> Settings:
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
            contamination=0.2,  # loose: guarantees some rows flag, keeps assertions simple
            scoring_enabled=scoring_enabled,
            scoring_interval_seconds=scoring_interval,
        ),
    )


def _event_rows(base_ns: int) -> list[dict[str, object]]:
    """200 humdrum connections + 15 rows of one IP sweeping ports and getting denied."""
    rows: list[dict[str, object]] = []
    for i in range(200):
        rows.append(
            {
                "event_uid": f"n{i:04d}",
                "time": base_ns + i * _S,
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
                "time": base_ns + (200 + j) * _S,
                "src_ip": "10.9.9.9",
                "dst_ip": "8.8.8.8",
                "dst_port": 1000 + j,
                "protocol": "tcp",
                "action_id": 2,  # deny
                "severity_id": 3,
                "bytes_in": 0,
                "bytes_out": 40,
            }
        )
    return rows


def _write_silver(
    settings: Settings, date: str, source_type: str, rows: list[dict[str, object]]
) -> None:
    part_dir = Path(settings.storage.silver_path) / f"date={date}" / f"source_type={source_type}"
    part_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), part_dir / "part-000.parquet")


@pytest.fixture
def trained(tmp_path: Path) -> Settings:
    settings = _settings(tmp_path)
    _write_silver(settings, _DATE, "acme_fw", _event_rows(_BASE_NS))
    jobs.train(settings, date_from=_DATE, date_to=_DATE)
    return settings


# ---------------------------------------------------------------------------
# train
# ---------------------------------------------------------------------------


def test_train_writes_model_with_metadata(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _write_silver(settings, _DATE, "acme_fw", _event_rows(_BASE_NS))

    result = jobs.train(settings, date_from=_DATE, date_to=_DATE)

    assert Path(result.model_path).is_file()
    assert result.n_samples == 215
    assert result.n_features == 23  # 16 per-event + 7 windowed
    assert result.trained_at
    assert result.dates == [_DATE]
    assert result.contamination == 0.2

    reloaded = jobs.load_detector(settings)
    assert reloaded.metadata["n_samples"] == 215


def test_train_with_no_silver_data_raises(tmp_path: Path) -> None:
    with pytest.raises(jobs.MlJobError, match="no features"):
        jobs.train(_settings(tmp_path), date_from=_DATE, date_to=_DATE)


def test_date_range_helper() -> None:
    assert jobs.date_range("2026-09-01", "2026-09-03") == [
        "2026-09-01",
        "2026-09-02",
        "2026-09-03",
    ]
    with pytest.raises(jobs.MlJobError, match="before"):
        jobs.date_range("2026-09-03", "2026-09-01")
    with pytest.raises(jobs.MlJobError, match="invalid date"):
        jobs.date_range("not-a-date", "2026-09-01")


def test_load_detector_without_a_model_raises(tmp_path: Path) -> None:
    with pytest.raises(jobs.MlJobError, match="no anomaly model"):
        jobs.load_detector(_settings(tmp_path))


def test_model_info(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    assert jobs.model_info(settings) is None  # nothing trained yet

    _write_silver(settings, _DATE, "acme_fw", _event_rows(_BASE_NS))
    jobs.train(settings, date_from=_DATE, date_to=_DATE)

    info = jobs.model_info(settings)
    assert info is not None
    assert info["n_samples"] == 215
    assert info["n_features"] == 23
    assert info["contamination"] == 0.2
    assert len(info["feature_names"]) == 23


# ---------------------------------------------------------------------------
# score_day
# ---------------------------------------------------------------------------


def test_score_day_writes_parquet_with_the_documented_schema(trained: Settings) -> None:
    result = jobs.score_day(trained, date=_DATE, now_ns=_SCORED_AT)

    assert result.scored == 215
    assert 0 < result.anomalies <= 215
    assert result.output_paths

    path = Path(result.output_paths[0])
    assert path.is_file()
    assert f"date={_DATE}" in path.as_posix()

    frame = pq.read_table(path).to_pandas()
    assert set(frame.columns) == set(jobs.ANOMALY_COLUMNS)
    assert frame["is_anomaly"].sum() == result.anomalies
    assert (frame["scored_at_ns"] == _SCORED_AT).all()

    flagged = frame[frame["is_anomaly"]]
    normal = frame[~frame["is_anomaly"]]
    assert (flagged["explanation_json"].str.len() > 2).all()  # a real JSON list
    assert (normal["explanation_json"] == "").all()  # unflagged rows carry none


def test_score_day_with_no_events_is_a_clean_no_op(trained: Settings) -> None:
    result = jobs.score_day(trained, date="2020-01-01")
    assert result.scored == 0
    assert result.anomalies == 0
    assert result.output_paths == []


# ---------------------------------------------------------------------------
# reading the anomalies lake
# ---------------------------------------------------------------------------


def test_read_recent_anomalies_dedupes_to_the_latest_scoring(trained: Settings) -> None:
    jobs.score_day(trained, date=_DATE, now_ns=1_000)
    jobs.score_day(trained, date=_DATE, now_ns=2_000)  # re-score; newer scored_at_ns

    rows = jobs.read_recent_anomalies(trained, limit=500)

    uids = [row["event_uid"] for row in rows]
    assert len(uids) == len(set(uids))  # one row per event_uid
    assert rows and all(row["scored_at_ns"] == 2_000 for row in rows)
    assert all(row["is_anomaly"] for row in rows)  # only_anomalies by default
    assert all(isinstance(row["explanation"], list) and row["explanation"] for row in rows)

    ceiling = max(row["anomaly_score"] for row in rows) + 1.0
    assert jobs.read_recent_anomalies(trained, min_score=ceiling) == []

    everything = jobs.read_recent_anomalies(trained, limit=1_000, only_anomalies=False)
    assert len(everything) == 215


def test_read_recent_anomalies_empty_lake_returns_empty(tmp_path: Path) -> None:
    assert jobs.read_recent_anomalies(_settings(tmp_path)) == []


def test_anomaly_timeline_buckets_by_event_time(trained: Settings) -> None:
    jobs.score_day(trained, date=_DATE, now_ns=1_000)

    points = jobs.anomaly_timeline(trained, window_seconds=86_400, bucket_seconds=3_600)

    assert points
    assert sum(point["scored"] for point in points) == 215
    assert sum(point["anomalies"] for point in points) > 0
    buckets = [point["bucket_ns"] for point in points]
    assert buckets == sorted(buckets)
    assert all(point["max_score"] is not None for point in points)


# ---------------------------------------------------------------------------
# score_recent
# ---------------------------------------------------------------------------


def test_score_recent_only_scores_events_inside_the_window(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    rows = _event_rows(_BASE_NS)
    rows.append(
        {
            "event_uid": "old-0001",
            "time": _BASE_NS - 1_800 * _S,  # 30 minutes before the window
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "protocol": "tcp",
            "action_id": 1,
            "severity_id": 1,
            "bytes_in": 1,
            "bytes_out": 1,
        }
    )
    _write_silver(settings, _DATE, "acme_fw", rows)
    jobs.train(settings, date_from=_DATE, date_to=_DATE)

    now = _BASE_NS + 300 * _S
    result = jobs.score_recent(settings, window_minutes=10.0, now_ns=now)

    assert result.scored == 215  # the 30-minutes-stale row is excluded
    assert result.date == _DATE
    assert result.output_paths


# ---------------------------------------------------------------------------
# template drift (stateful, persisted between calls)
# ---------------------------------------------------------------------------


def test_run_template_drift_flags_a_template_going_silent(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    t0 = 1_000_000 * _S
    clock = [t0]
    store = TemplateStore(settings, clock=lambda: clock[0])
    for i in range(16):
        store.record(1, "login from <*>", "sshd", f"login from 10.0.0.{i}")

    # A steady baseline: the same 16 events sit in the trailing minute each pass.
    steady = [
        jobs.run_template_drift(settings, window_minutes=1.0, z_threshold=3.0, now_ns=t0 + 30 * _S)
        for _ in range(5)
    ]
    assert all(signals == [] for signals in steady)
    assert Path(settings.ml.drift_state_path).is_file()  # baseline persisted

    # ...then the template goes silent: nothing in the trailing minute an hour later.
    signals = jobs.run_template_drift(
        settings, window_minutes=1.0, z_threshold=3.0, now_ns=t0 + 3_600 * _S
    )

    assert len(signals) == 1
    assert signals[0].direction == "drop"
    assert signals[0].source_id == "sshd"
    assert signals[0].template == "login from <*>"
    assert signals[0].z_score < -3.0


def test_run_template_drift_source_id_filter(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = TemplateStore(settings, clock=lambda: 5_000 * _S)
    for i in range(12):
        store.record(1, "conn <*>", "fw_a", f"conn {i}")
        store.record(1, "auth <*>", "fw_b", f"auth {i}")

    for _ in range(5):
        jobs.run_template_drift(settings, window_minutes=1.0, now_ns=5_000 * _S + 30 * _S)
    signals = jobs.run_template_drift(
        settings, window_minutes=1.0, now_ns=9_000 * _S, source_id="fw_a"
    )
    assert signals
    assert {s.source_id for s in signals} == {"fw_a"}


# ---------------------------------------------------------------------------
# AnomalyScoringLoop
# ---------------------------------------------------------------------------


async def test_scoring_loop_is_a_no_op_when_disabled(tmp_path: Path) -> None:
    loop = jobs.AnomalyScoringLoop(_settings(tmp_path))  # scoring_enabled=False
    assert loop.enabled is False

    loop.start()
    assert loop.running is False
    await loop.stop()  # no-op, must not raise


async def test_scoring_loop_tick_scores_the_recent_window(trained: Settings) -> None:
    fixed_now = _BASE_NS + 100 * _S
    loop = jobs.AnomalyScoringLoop(trained, clock=lambda: fixed_now)

    await loop._tick()

    written = list(Path(trained.ml.anomalies_path).rglob("*.parquet"))
    assert written, "a tick should have scored the recent window and written a file"


async def test_scoring_loop_start_stop_lifecycle(tmp_path: Path) -> None:
    settings = _settings(tmp_path, scoring_enabled=True)
    _write_silver(settings, _DATE, "acme_fw", _event_rows(_BASE_NS))
    jobs.train(settings, date_from=_DATE, date_to=_DATE)
    loop = jobs.AnomalyScoringLoop(settings, clock=lambda: _BASE_NS + 100 * _S)

    loop.start()
    assert loop.running is True
    await asyncio.sleep(0)  # let the task reach its first await
    await loop.stop()
    assert loop.running is False
