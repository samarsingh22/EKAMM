"""``/api/v1/anomalies`` — anomaly-detection results and template drift.

Reads the anomalies lake (``settings.ml.anomalies_path``, written by
:mod:`ulpf.ml.jobs`) and the live template catalog. Every anomaly row keeps
its ``event_uid`` so the dashboard can jump straight to the normalized event,
its raw bytes, and its ledger proof (requirement d).

Endpoints
---------
* ``GET /``          — most recent anomalies (latest scoring per event), each
  with its score and the detector's top-3 explanation.
* ``GET /model``     — the trained detector's provenance: trained-at, sample
  count, contamination, feature count (``{"trained": false}`` if none yet).
* ``GET /timeline``  — bucketed anomaly-score stats over ``?window=`` for the
  chart (``?bucket=`` sets the bucket width).
* ``GET /drift``     — one EWMA pass of
  :class:`~ulpf.ml.drift.TemplateDriftDetector` over the template catalog; its
  baseline is persisted between calls, so polling this endpoint is what keeps
  the baseline current.
* ``POST /train``    — start a training run over a date range.

``POST /train`` is EXPENSIVE and REWRITES THE PRODUCTION MODEL. ULPF ships no
auth layer yet; in a real deployment this route MUST sit behind admin
authentication/authorization — an API gateway, a role check, mTLS, whatever
the deployment uses. It is left open here only because there is no auth surface
to hang it on. Do not expose this API to untrusted networks.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ulpf.config.settings import Settings
from ulpf.ml import jobs

_WINDOW_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


# ======================================================================
# wire models
# ======================================================================


class AnomalyExplanationOut(BaseModel):
    """One feature's contribution to an anomaly score (percentile vs. training)."""

    feature: str
    value: float
    percentile: float
    direction: str  # "high" | "low"
    training_median: float
    note: str


class AnomalyOut(BaseModel):
    """One scored event from ``GET /``."""

    event_uid: str
    src_ip: str | None = None
    event_time_ns: int | None = None
    source_type: str | None = None
    anomaly_score: float
    is_anomaly: bool
    scored_at_ns: int | None = None
    model_trained_at: str | None = None
    explanation: list[AnomalyExplanationOut] = Field(default_factory=list)


class TimelinePoint(BaseModel):
    """One bucket of ``GET /timeline``."""

    bucket_ns: int
    scored: int
    anomalies: int
    max_score: float | None = None
    mean_score: float | None = None


class AnomalyTimeline(BaseModel):
    """Response body for ``GET /timeline``."""

    window_seconds: int
    bucket_seconds: int
    points: list[TimelinePoint]


class DriftOut(BaseModel):
    """One template-rate drift signal from ``GET /drift``."""

    template_id: str
    source_id: str
    template: str
    baseline_rate: float
    current_rate: float
    z_score: float
    direction: str  # "spike" | "drop"
    observed: int
    expected: float
    window_minutes: float
    sample_lines: list[str] = Field(default_factory=list)


class TrainRequest(BaseModel):
    """Body for ``POST /train``."""

    date_from: str
    date_to: str
    contamination: float | None = None


class TrainOut(BaseModel):
    """Response body for ``POST /train``."""

    model_path: str
    dates: list[str]
    n_samples: int
    n_features: int
    trained_at: str | None = None
    contamination: float | str


class ModelInfoOut(BaseModel):
    """Response body for ``GET /model`` — the trained detector's provenance card."""

    trained: bool
    trained_at: str | None = None
    n_samples: int | None = None
    n_features: int | None = None
    contamination: float | str | None = None
    feature_names: list[str] = Field(default_factory=list)


# ======================================================================
# router
# ======================================================================


def build_anomalies_router(
    settings: Settings, *, clock: Callable[[], int] = time.time_ns
) -> APIRouter:
    """The ``/anomalies`` router. ``clock`` (UTC epoch-ns) is injectable for tests."""
    router = APIRouter(prefix="/anomalies", tags=["anomalies"])

    @router.get("/", response_model=list[AnomalyOut])
    async def list_anomalies(
        limit: int = Query(100, ge=1, le=1000),
        min_score: float | None = Query(None, description="Only rows scoring at least this."),
        include_normal: bool = Query(False, description="Also return rows the model did not flag."),
    ) -> list[AnomalyOut]:
        rows = await asyncio.to_thread(
            jobs.read_recent_anomalies,
            settings,
            limit=limit,
            min_score=min_score,
            only_anomalies=not include_normal,
        )
        return [_anomaly_out(row) for row in rows]

    @router.get("/model", response_model=ModelInfoOut)
    async def model_info() -> ModelInfoOut:
        meta = await asyncio.to_thread(jobs.model_info, settings)
        if meta is None:
            return ModelInfoOut(trained=False)
        return ModelInfoOut(
            trained=True,
            trained_at=meta.get("trained_at"),
            n_samples=meta.get("n_samples"),
            n_features=meta.get("n_features"),
            contamination=meta.get("contamination"),
            feature_names=list(meta.get("feature_names", [])),
        )

    @router.get("/timeline", response_model=AnomalyTimeline)
    async def timeline(
        window: str = Query("1h", description="Look-back, e.g. 15m / 1h / 24h."),
        bucket: str = Query("1m", description="Bucket width, e.g. 1m / 5m."),
    ) -> AnomalyTimeline:
        window_s = _seconds(window)
        bucket_s = _seconds(bucket)
        points = await asyncio.to_thread(
            jobs.anomaly_timeline, settings, window_seconds=window_s, bucket_seconds=bucket_s
        )
        return AnomalyTimeline(
            window_seconds=window_s,
            bucket_seconds=bucket_s,
            points=[TimelinePoint(**point) for point in points],
        )

    @router.get("/drift", response_model=list[DriftOut])
    async def drift(
        window_minutes: float = Query(5.0, gt=0.0),
        z_threshold: float = Query(3.0, gt=0.0),
        source_id: str | None = Query(None),
    ) -> list[DriftOut]:
        signals = await asyncio.to_thread(
            jobs.run_template_drift,
            settings,
            window_minutes=window_minutes,
            z_threshold=z_threshold,
            source_id=source_id,
            now_ns=clock(),
        )
        return [DriftOut(**signal.to_dict()) for signal in signals]

    # POST /train — see the module docstring: admin-only in a real deployment.
    @router.post("/train", response_model=TrainOut)
    async def train(body: TrainRequest) -> TrainOut:
        try:
            result = await asyncio.to_thread(
                jobs.train,
                settings,
                date_from=body.date_from,
                date_to=body.date_to,
                contamination=body.contamination,
            )
        except jobs.MlJobError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return TrainOut(**result.to_dict())

    return router


# ======================================================================
# helpers
# ======================================================================


def _seconds(spec: str) -> int:
    """Parse ``"15m"`` / ``"1h"`` / ``"24h"`` to seconds; 400 on anything else."""
    match = _WINDOW_RE.match(spec)
    if match is None:
        raise HTTPException(status_code=400, detail=f"invalid window {spec!r} (e.g. 15m, 1h, 24h)")
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2).lower()]


def _anomaly_out(row: dict[str, Any]) -> AnomalyOut:
    return AnomalyOut(
        event_uid=row.get("event_uid") or "",
        src_ip=row.get("src_ip"),
        event_time_ns=row.get("event_time_ns"),
        source_type=row.get("source_type"),
        anomaly_score=float(row.get("anomaly_score") or 0.0),
        is_anomaly=bool(row.get("is_anomaly")),
        scored_at_ns=row.get("scored_at_ns"),
        model_trained_at=row.get("model_trained_at"),
        explanation=[_explanation_out(entry) for entry in row.get("explanation", [])],
    )


def _explanation_out(entry: dict[str, Any]) -> AnomalyExplanationOut:
    return AnomalyExplanationOut(
        feature=str(entry.get("feature", "")),
        value=float(entry.get("value", 0.0)),
        percentile=float(entry.get("percentile", 0.0)),
        direction=str(entry.get("direction", "")),
        training_median=float(entry.get("training_median", 0.0)),
        note=str(entry.get("note", "")),
    )
