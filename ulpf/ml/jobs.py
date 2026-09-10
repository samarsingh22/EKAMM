"""Batch + streaming ML jobs — train the anomaly detector, score events, keep scoring.

* :func:`train`        — ``ulpf ml train --date-from --date-to``: load features
  from the silver lake across a date range, fit
  :class:`~ulpf.ml.anomaly.AnomalyDetector`, save it (with metadata) to
  ``settings.ml.model_path``.
* :func:`score_day`    — ``ulpf ml score --date``: score one event-date's
  events and append the results to the anomalies lake as Parquet.
* :func:`score_recent` — score just the last N minutes; what
  :class:`AnomalyScoringLoop` runs every minute when
  ``settings.ml.scoring_enabled``.
* :func:`run_template_drift` — one pass of the stateful EWMA
  :class:`~ulpf.ml.drift.TemplateDriftDetector` over the live template catalog,
  its baseline persisted between calls at ``settings.ml.drift_state_path``.

THE ANOMALIES LAKE
------------------
``settings.ml.anomalies_path``, Hive-partitioned ``date=YYYY-MM-DD`` by the
event's own time (same convention as silver). One Parquet file per job / tick.
Columns (:data:`ANOMALY_COLUMNS`): ``event_uid`` — the join key back to the
silver row, the raw bronze bytes, and the signed ledger leaf (requirement d) —
``src_ip``, ``event_time_ns``, ``source_type``, ``anomaly_score`` (higher =
more anomalous), ``is_anomaly``, ``scored_at_ns``, ``model_trained_at``, and
``explanation_json`` — the detector's top-3 feature attribution for a flagged
row, so the dashboard can answer *why* without loading the model.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ulpf.config.settings import Settings
from ulpf.core.errors import UlpfError
from ulpf.ml.anomaly import AnomalyDetector
from ulpf.ml.drift import DriftSignal, TemplateDriftDetector
from ulpf.ml.features import DEFAULT_WINDOW, load_features
from ulpf.parse.templates.store import TemplateStore
from ulpf.sinks.parquet_sink import epoch_ns_to_date

_log = logging.getLogger(__name__)

_NS_PER_MINUTE = 60_000_000_000
_MAX_RANGE_DAYS = 366

ANOMALY_COLUMNS: tuple[str, ...] = (
    "event_uid",
    "src_ip",
    "event_time_ns",
    "source_type",
    "anomaly_score",
    "is_anomaly",
    "scored_at_ns",
    "model_trained_at",
    "explanation_json",
)


class MlJobError(UlpfError):
    """A training/scoring job could not run (no data, no model, bad date range)."""


# ======================================================================
# results
# ======================================================================


@dataclass
class TrainResult:
    """Outcome of :func:`train`."""

    model_path: str
    dates: list[str]
    n_samples: int
    n_features: int
    trained_at: str | None
    contamination: float | str

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_path": self.model_path,
            "dates": list(self.dates),
            "n_samples": self.n_samples,
            "n_features": self.n_features,
            "trained_at": self.trained_at,
            "contamination": self.contamination,
        }


@dataclass
class ScoreResult:
    """Outcome of :func:`score_day` / :func:`score_recent`."""

    date: str
    scored: int
    anomalies: int
    output_paths: list[str]
    model_trained_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "date": self.date,
            "scored": self.scored,
            "anomalies": self.anomalies,
            "output_paths": list(self.output_paths),
            "model_trained_at": self.model_trained_at,
        }


# ======================================================================
# date range + feature loading
# ======================================================================


def _parse_date(value: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise MlJobError(f"invalid date {value!r} (expected YYYY-MM-DD)") from exc


def date_range(date_from: str, date_to: str) -> list[str]:
    """Every ``YYYY-MM-DD`` from ``date_from`` to ``date_to``, inclusive."""
    start, end = _parse_date(date_from), _parse_date(date_to)
    if end < start:
        raise MlJobError(f"--date-to {date_to} is before --date-from {date_from}")
    span = (end - start).days
    if span >= _MAX_RANGE_DAYS:
        raise MlJobError(f"date range too wide: {span + 1} days (max {_MAX_RANGE_DAYS})")
    return [(start + dt.timedelta(days=offset)).isoformat() for offset in range(span + 1)]


def _source_types(silver: Path, date: str) -> list[str]:
    """Every ``source_type=`` partition present under ``date=<date>`` in silver."""
    date_dir = silver / f"date={date}"
    if not date_dir.is_dir():
        return []
    prefix = "source_type="
    return sorted(p.name[len(prefix) :] for p in date_dir.glob(f"{prefix}*") if p.is_dir())


def load_range_features(
    settings: Settings, dates: list[str], *, window: str = DEFAULT_WINDOW
) -> pd.DataFrame:
    """Concatenate :func:`~ulpf.ml.features.load_features` over every ``date`` / ``source_type``.

    Each block is tagged with its ``source_type`` (the feature extractor does
    not carry it). Returns an empty frame when the range holds no silver data.
    """
    silver = Path(settings.storage.silver_path)
    frames: list[pd.DataFrame] = []
    for date in dates:
        for source_type in _source_types(silver, date):
            frame = load_features(date, source_type, settings=settings, window=window)
            if frame.empty:
                continue
            frame = frame.copy()
            frame["source_type"] = source_type
            frames.append(frame)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


# ======================================================================
# train
# ======================================================================


def train(
    settings: Settings,
    *,
    date_from: str,
    date_to: str,
    contamination: float | str | None = None,
) -> TrainResult:
    """Fit the anomaly detector on the silver lake between two event dates and save it."""
    dates = date_range(date_from, date_to)
    features = load_range_features(settings, dates)
    if features.empty:
        raise MlJobError(f"no features found in silver for {date_from}..{date_to}")

    contam = settings.ml.contamination if contamination is None else contamination
    detector = AnomalyDetector(contamination=contam)
    detector.fit(features)

    model_path = Path(settings.ml.model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    detector.save(model_path)
    _log.info(
        "ml train: fit on %d samples over %s..%s -> %s",
        detector.n_samples,
        date_from,
        date_to,
        model_path,
    )
    return TrainResult(
        model_path=str(model_path),
        dates=dates,
        n_samples=detector.n_samples,
        n_features=len(detector.feature_names),
        trained_at=detector.trained_at,
        contamination=contam,
    )


def load_detector(settings: Settings, model_path: str | Path | None = None) -> AnomalyDetector:
    """Load the saved detector, or raise :class:`MlJobError` if there is none yet."""
    path = Path(model_path or settings.ml.model_path)
    if not path.is_file():
        raise MlJobError(f"no anomaly model at {path}; run `ulpf ml train` first")
    return AnomalyDetector.load(path)


def model_info(settings: Settings, model_path: str | Path | None = None) -> dict[str, Any] | None:
    """The trained detector's metadata (plus ``n_features``), or ``None`` if untrained."""
    path = Path(model_path or settings.ml.model_path)
    if not path.is_file():
        return None
    detector = AnomalyDetector.load(path)
    meta = detector.metadata
    meta["n_features"] = len(detector.feature_names)
    return meta


# ======================================================================
# score
# ======================================================================


def _explanations(
    detector: AnomalyDetector, features: pd.DataFrame, flags: pd.Series[bool]
) -> list[str]:
    """``explanation_json`` per row — top-3 attribution for a flagged row, ``""`` otherwise."""
    out = [""] * len(features)
    for pos, flagged in enumerate(flags.to_numpy()):
        if flagged:
            out[pos] = json.dumps(detector.explain(features.iloc[pos]))
    return out


def score_frame(
    detector: AnomalyDetector, features: pd.DataFrame, *, scored_at_ns: int
) -> pd.DataFrame:
    """Run the detector over a feature frame and shape it to :data:`ANOMALY_COLUMNS`."""
    scored = detector.score(features).reset_index(drop=True)
    feats = features.reset_index(drop=True)
    return pd.DataFrame(
        {
            "event_uid": scored["event_uid"],
            "src_ip": scored["src_ip"],
            "event_time_ns": pd.to_numeric(scored["time"], errors="coerce").astype("Int64"),
            "source_type": feats.get("source_type", pd.NA),
            "anomaly_score": scored["anomaly_score"].astype(float),
            "is_anomaly": scored["is_anomaly"].astype(bool),
            "scored_at_ns": scored_at_ns,
            "model_trained_at": detector.trained_at,
            "explanation_json": _explanations(detector, feats, scored["is_anomaly"]),
        }
    )


def write_anomalies(settings: Settings, frame: pd.DataFrame) -> list[str]:
    """Write ``frame`` to the anomalies lake, one Parquet file per event-date partition."""
    if frame.empty:
        return []
    frame = frame[frame["event_time_ns"].notna()].astype({"event_time_ns": "int64"})
    root = Path(settings.ml.anomalies_path)
    written: list[str] = []
    for date, group in frame.groupby(frame["event_time_ns"].map(epoch_ns_to_date)):
        part_dir = root / f"date={date}"
        part_dir.mkdir(parents=True, exist_ok=True)
        path = part_dir / f"part-{uuid.uuid4().hex}.parquet"
        table = pa.Table.from_pandas(group[list(ANOMALY_COLUMNS)], preserve_index=False)
        pq.write_table(table, path)
        written.append(str(path))
    return written


def score_day(
    settings: Settings,
    *,
    date: str,
    model_path: str | Path | None = None,
    now_ns: int | None = None,
) -> ScoreResult:
    """Score every event on ``date`` and append the results to the anomalies lake."""
    _parse_date(date)
    detector = load_detector(settings, model_path)
    features = load_range_features(settings, [date])
    scored_at = now_ns if now_ns is not None else time.time_ns()
    if features.empty:
        return ScoreResult(date, 0, 0, [], detector.trained_at)
    frame = score_frame(detector, features, scored_at_ns=scored_at)
    paths = write_anomalies(settings, frame)
    result = ScoreResult(
        date, len(frame), int(frame["is_anomaly"].sum()), paths, detector.trained_at
    )
    _log.info("ml score: date=%s scored=%d anomalies=%d", date, result.scored, result.anomalies)
    return result


def score_recent(
    settings: Settings,
    *,
    window_minutes: float | None = None,
    now_ns: int | None = None,
    model_path: str | Path | None = None,
) -> ScoreResult:
    """Score only events from the last ``window_minutes``.

    ``window_minutes`` defaults to ``settings.ml.scoring_window_minutes``.
    """
    window = settings.ml.scoring_window_minutes if window_minutes is None else window_minutes
    now = now_ns if now_ns is not None else time.time_ns()
    start = now - int(window * _NS_PER_MINUTE)
    dates = sorted({epoch_ns_to_date(start), epoch_ns_to_date(now)})
    label = epoch_ns_to_date(now)

    detector = load_detector(settings, model_path)
    features = load_range_features(settings, dates)
    if not features.empty:
        event_ns = pd.to_numeric(features["time"], errors="coerce")
        features = features[(event_ns >= start) & (event_ns <= now)]
    if features.empty:
        return ScoreResult(label, 0, 0, [], detector.trained_at)
    frame = score_frame(detector, features, scored_at_ns=now)
    paths = write_anomalies(settings, frame)
    return ScoreResult(
        label, len(frame), int(frame["is_anomaly"].sum()), paths, detector.trained_at
    )


# ======================================================================
# reading the anomalies lake (for the API)
# ======================================================================


def _anomaly_glob(settings: Settings) -> str | None:
    root = Path(settings.ml.anomalies_path)
    if not any(root.rglob("*.parquet")):
        return None
    return (root / "**" / "*.parquet").as_posix()


def _sql_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _latest_cte(glob: str) -> str:
    """A ``latest`` CTE: one row per ``event_uid`` — its most recent scoring."""
    return (
        "WITH latest AS ("
        "  SELECT event_uid, src_ip, event_time_ns, source_type, anomaly_score, is_anomaly,"
        "         scored_at_ns, model_trained_at, explanation_json"
        f"  FROM read_parquet({_sql_str(glob)}, union_by_name = true, hive_partitioning = true,"
        "                    hive_types = {'date': 'VARCHAR'})"
        "  QUALIFY row_number() OVER (PARTITION BY event_uid ORDER BY scored_at_ns DESC) = 1"
        ")"
    )


def _rows(cursor: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    columns = [description[0] for description in cursor.description or []]
    return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def _load_json_list(value: Any) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def read_recent_anomalies(
    settings: Settings,
    *,
    limit: int = 100,
    min_score: float | None = None,
    only_anomalies: bool = True,
    since_ns: int | None = None,
) -> list[dict[str, Any]]:
    """Most recent anomalies — one row per ``event_uid`` (its latest scoring)."""
    glob = _anomaly_glob(settings)
    if glob is None:
        return []
    clauses: list[str] = []
    params: list[Any] = []
    if only_anomalies:
        clauses.append("is_anomaly")
    if min_score is not None:
        clauses.append("anomaly_score >= ?")
        params.append(float(min_score))
    if since_ns is not None:
        clauses.append("scored_at_ns >= ?")
        params.append(int(since_ns))
    where = " AND ".join(clauses) if clauses else "TRUE"
    params.append(max(1, int(limit)))
    sql = (
        _latest_cte(glob) + f" SELECT * FROM latest WHERE {where}"
        " ORDER BY scored_at_ns DESC, anomaly_score DESC LIMIT ?"
    )
    con = duckdb.connect(":memory:")
    try:
        rows = _rows(con.execute(sql, params))
    finally:
        con.close()
    for row in rows:
        row["explanation"] = _load_json_list(row.pop("explanation_json", None))
    return rows


def anomaly_timeline(
    settings: Settings, *, window_seconds: int, bucket_seconds: int
) -> list[dict[str, Any]]:
    """Bucketed anomaly-score stats over the most recent ``window_seconds`` of scored events."""
    glob = _anomaly_glob(settings)
    if glob is None:
        return []
    bucket_ns = max(1, int(bucket_seconds)) * 1_000_000_000
    window_ns = max(1, int(window_seconds)) * 1_000_000_000
    sql = (
        _latest_cte(glob) + ", span AS (SELECT max(event_time_ns) AS newest FROM latest) "
        "SELECT CAST(floor(event_time_ns / ?) * ? AS BIGINT) AS bucket_ns,"
        "       count(*) AS scored,"
        "       count(*) FILTER (WHERE is_anomaly) AS anomalies,"
        "       max(anomaly_score) AS max_score,"
        "       avg(anomaly_score) AS mean_score "
        "FROM latest, span "
        "WHERE span.newest IS NOT NULL AND event_time_ns >= span.newest - ? "
        "GROUP BY bucket_ns ORDER BY bucket_ns"
    )
    con = duckdb.connect(":memory:")
    try:
        return _rows(con.execute(sql, [bucket_ns, bucket_ns, window_ns]))
    finally:
        con.close()


# ======================================================================
# template drift (stateful EWMA, persisted between calls)
# ======================================================================


def run_template_drift(
    settings: Settings,
    *,
    window_minutes: float | None = None,
    z_threshold: float | None = None,
    source_id: str | None = None,
    now_ns: int | None = None,
) -> list[DriftSignal]:
    """One EWMA drift pass over the live template catalog; baseline persisted between calls.

    State lives in ``settings.ml.drift_state_path`` — each call advances every
    template's exponentially weighted baseline rate and writes it back, so the
    dashboard's periodic poll of ``GET /api/v1/anomalies/drift`` is what keeps
    the baseline current. The first ever call only seeds baselines (returns
    ``[]``). Single-writer assumption: the scoring loop does not touch this file.
    """
    window = settings.ml.drift_window_minutes if window_minutes is None else window_minutes
    threshold = settings.ml.drift_z_threshold if z_threshold is None else z_threshold
    state_path = Path(settings.ml.drift_state_path)

    if state_path.is_file():
        detector = TemplateDriftDetector.restore(json.loads(state_path.read_text("utf-8")))
        detector.z_threshold = threshold
    else:
        detector = TemplateDriftDetector(z_threshold=threshold)

    signals = detector.detect(window, store=TemplateStore(settings), now_ns=now_ns)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(detector.snapshot()), encoding="utf-8")
    if source_id is not None:
        signals = [signal for signal in signals if signal.source_id == source_id]
    return signals


# ======================================================================
# background scoring loop
# ======================================================================


class AnomalyScoringLoop:
    """Background task: re-score the last N minutes every minute when enabled.

    A no-op unless ``settings.ml.scoring_enabled``. Owned by
    :class:`~ulpf.core.runtime.Runtime` — started in its ``start`` and stopped
    in its ``stop``. A failed tick is logged, never fatal.
    """

    def __init__(self, settings: Settings, *, clock: Callable[[], int] = time.time_ns) -> None:
        """Configure the loop (nothing runs until :meth:`start`)."""
        self._settings = settings
        self._clock = clock
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    @property
    def enabled(self) -> bool:
        """Whether ``settings.ml.scoring_enabled`` turned this loop on."""
        return bool(self._settings.ml.scoring_enabled)

    @property
    def running(self) -> bool:
        """Whether the loop task is currently alive."""
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Launch the loop (no-op when disabled or already running)."""
        if not self.enabled or self.running:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Cancel the loop and wait for it to unwind (no-op when not running)."""
        if self._task is None:
            return
        self._stop.set()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def _run(self) -> None:
        interval = max(1.0, float(self._settings.ml.scoring_interval_seconds))
        while not self._stop.is_set():
            await self._tick()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=interval)

    async def _tick(self) -> None:
        """One scoring pass — swallows and logs any failure so the loop survives."""
        try:
            result = await asyncio.to_thread(score_recent, self._settings, now_ns=self._clock())
        except MlJobError as exc:
            _log.warning("anomaly scoring skipped: %s", exc)
        except Exception:  # noqa: BLE001 - a background task must never die silently
            _log.exception("anomaly scoring tick failed")
        else:
            _log.info(
                "anomaly scoring tick: scored=%d anomalies=%d", result.scored, result.anomalies
            )
