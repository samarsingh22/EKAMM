"""Unsupervised anomaly detection over the OCSF feature matrix (requirement *h*).

Consumes the frame :mod:`ulpf.ml.features` produces — per-event byte/port/time
features plus the source-IP windowed aggregates — and scores each row for how
far it sits from the bulk of recent traffic. No labels: perimeter incidents
are rare, varied, and mostly unseen, so a model that needs examples of "bad"
is the wrong tool.

WHY ISOLATION FOREST, NOT DeepLog / LogBERT
------------------------------------------
This is a deliberate engineering choice, not a capability ceiling:

* **It trains in seconds on a CPU.** An air-gapped appliance retrains on a
  rolling window of its own traffic every hour — no GPU, no cluster, no
  multi-hour job. A sequence model (DeepLog, LogBERT, LogAnomaly) needs an
  accelerator and minutes-to-hours per fit, which makes "retrain as the
  baseline drifts" impractical in the environments ULPF targets.
* **It is explainable to the analyst on shift.** :meth:`AnomalyDetector.explain`
  attributes every alert to the three features that put it there, each with
  its percentile position against the training distribution ("``win_distinct
  _dst_ports`` = 312 sits at the 99.9th percentile; normally ≈ 4"). Per-alert
  explanation for deep log-sequence models is still an open research problem;
  an unexplained alert is an alert an analyst cannot action.
* **The evidence does not favour the deep models on realistic data.**
  Reproducibility and evaluation-methodology studies of log anomaly detection
  (e.g. Le & Zhang's critical re-evaluations of DeepLog/LogBERT-style models;
  Landauer et al., *Deep Learning for Anomaly Detection in Log Data: A
  Survey*, 2023, and the follow-on work on assessing detection accuracy
  honestly) repeatedly find that once benchmark leakage, near-duplicate test
  rows, and unrealistic label ratios are controlled for, newer deep models do
  **not** reliably beat classical detectors such as Isolation Forest, PCA, or
  one-class SVM — and often lose to them.

The feature matrix is model-agnostic. If a specific deployment's data ever
justifies a heavier model, it drops in behind the same
:class:`AnomalyDetector` surface; nothing upstream changes.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from scipy.stats import percentileofscore
from sklearn.ensemble import IsolationForest

from ulpf.core.errors import UlpfError

# Columns that :mod:`ulpf.ml.features` carries for joining, not for modelling.
_NON_FEATURE_COLUMNS: frozenset[str] = frozenset({"event_uid", "src_ip", "time", "window_start"})

# Cap on stored order-statistics per feature (for :meth:`explain`'s percentile
# lookup). Beyond this, an evenly-spaced quantile grid is kept instead — enough
# for a stable percentile without holding millions of values per feature.
_DIST_GRID = 20_000

_DEFAULT_N_ESTIMATORS = 100
_DEFAULT_RANDOM_STATE = 42


class ModelNotFittedError(UlpfError):
    """:meth:`AnomalyDetector.score` / :meth:`explain` / :meth:`save` before :meth:`fit`."""


class AnomalyDetector:
    """Isolation-Forest anomaly scorer with per-alert percentile explanations."""

    def __init__(
        self,
        *,
        contamination: float | str = "auto",
        n_estimators: int = _DEFAULT_N_ESTIMATORS,
        random_state: int = _DEFAULT_RANDOM_STATE,
    ) -> None:
        """Configure the detector (nothing is trained until :meth:`fit`).

        Args:
            contamination: expected outlier fraction — a float in ``(0, 0.5]``
                or ``"auto"`` (sklearn's default threshold). Drives only the
                boolean ``is_anomaly`` flag, never the continuous score.
            n_estimators: number of trees (pinned at 100 by default).
            random_state: fixed for reproducibility — the same data and seed
                always yield the same scores.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self._model: IsolationForest | None = None
        self.feature_names: list[str] = []
        self._medians: dict[str, float] = {}
        self._dist: dict[str, np.ndarray] = {}
        self.trained_at: str | None = None
        self.n_samples: int = 0

    # -- lifecycle ---------------------------------------------------------

    def fit(self, features_df: pd.DataFrame) -> AnomalyDetector:
        """Train on a feature frame (typically :func:`ulpf.ml.features.extract_features` output).

        Non-numeric and identifier columns are ignored. Every remaining
        column is a model feature; its median and training distribution are
        stored for imputation and for :meth:`explain`.
        """
        self.feature_names = _select_feature_columns(features_df)
        if not self.feature_names:
            raise ValueError("no numeric feature columns to train on")

        frame = _numeric_frame(features_df, self.feature_names)
        self._medians = {
            col: float(np.nanmedian(frame[col].to_numpy())) for col in self.feature_names
        }
        matrix = _impute(frame, self._medians).to_numpy(dtype=np.float64)

        self._dist = {
            col: _order_statistics(matrix[:, i]) for i, col in enumerate(self.feature_names)
        }

        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,  # type: ignore[arg-type]
            random_state=self.random_state,
            bootstrap=False,
        ).fit(matrix)

        self.n_samples = int(matrix.shape[0])
        self.trained_at = dt.datetime.now(dt.UTC).isoformat()
        return self

    def score(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Score each row: ``anomaly_score`` (higher = more anomalous) + ``is_anomaly``.

        ``anomaly_score`` is ``-IsolationForest.score_samples`` — a continuous,
        monotonic measure independent of ``contamination``. ``is_anomaly`` is
        the model's own decision at the configured contamination threshold.
        Identifier columns present on the input (``event_uid``, ``src_ip``,
        ``time``) are carried through. The result keeps the input index.
        """
        model = self._require_fitted()
        matrix = self._matrix_for(features_df)

        out = pd.DataFrame(index=features_df.index)
        for col in ("event_uid", "src_ip", "time"):
            if col in features_df.columns:
                out[col] = features_df[col].to_numpy()
        out["anomaly_score"] = -model.score_samples(matrix)
        out["is_anomaly"] = model.predict(matrix) == -1
        return out

    def explain(self, row: pd.Series | Mapping[str, Any] | pd.DataFrame) -> list[dict[str, Any]]:
        """The 3 features that most explain why ``row`` scored as it did.

        Each feature's value is placed as a percentile within the training
        distribution; "extremeness" is ``max(pct, 100 - pct)`` — how far into
        either tail it sits. The three most extreme are returned, most extreme
        first, each with the value, its percentile, the direction, and the
        training median / p5 / p95 for context.
        """
        self._require_fitted()
        values = _row_to_series(row).reindex(self.feature_names)

        entries: list[dict[str, Any]] = []
        for feature in self.feature_names:
            raw = values.get(feature)
            value = self._medians[feature] if raw is None or pd.isna(raw) else float(raw)
            dist = self._dist[feature]
            pct = float(percentileofscore(dist, value, kind="mean"))
            extremeness = max(pct, 100.0 - pct)
            median = float(np.median(dist))
            p5, p95 = (float(x) for x in np.percentile(dist, [5, 95]))
            direction = "high" if pct >= 50.0 else "low"
            entries.append(
                {
                    "feature": feature,
                    "value": value,
                    "percentile": round(pct, 2),
                    "extremeness": round(extremeness, 2),
                    "direction": direction,
                    "training_median": round(median, 4),
                    "training_p5": round(p5, 4),
                    "training_p95": round(p95, 4),
                    "note": (
                        f"{feature} = {value:g} is at the {pct:.1f}th percentile "
                        f"(typical ≈ {median:g}, p5-p95 {p5:g}-{p95:g}) — unusually {direction}"
                    ),
                }
            )

        entries.sort(key=lambda e: e["extremeness"], reverse=True)
        return entries[:3]

    # -- persistence -----------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Serialize the fitted detector (model + distributions + metadata) with joblib."""
        self._require_fitted()
        joblib.dump(
            {
                "model": self._model,
                "feature_names": self.feature_names,
                "medians": self._medians,
                "dist": self._dist,
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "random_state": self.random_state,
                "trained_at": self.trained_at,
                "n_samples": self.n_samples,
            },
            path,
        )

    @classmethod
    def load(cls, path: str | Path) -> AnomalyDetector:
        """Reload a detector saved by :meth:`save`."""
        state = joblib.load(path)
        detector = cls(
            contamination=state["contamination"],
            n_estimators=state["n_estimators"],
            random_state=state["random_state"],
        )
        detector._model = state["model"]
        detector.feature_names = list(state["feature_names"])
        detector._medians = dict(state["medians"])
        detector._dist = dict(state["dist"])
        detector.trained_at = state["trained_at"]
        detector.n_samples = int(state["n_samples"])
        return detector

    # -- metadata ------------------------------------------------------

    @property
    def metadata(self) -> dict[str, Any]:
        """Provenance for the trained model."""
        return {
            "trained_at": self.trained_at,
            "n_samples": self.n_samples,
            "feature_names": list(self.feature_names),
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
        }

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    # -- internals ---------------------------------------------------

    def _require_fitted(self) -> IsolationForest:
        if self._model is None:
            raise ModelNotFittedError("AnomalyDetector.fit() must be called before this")
        return self._model

    def _matrix_for(self, features_df: pd.DataFrame) -> np.ndarray:
        frame = _numeric_frame(features_df, self.feature_names)
        return _impute(frame, self._medians).to_numpy(dtype=np.float64)


# ======================================================================
# helpers
# ======================================================================


def _select_feature_columns(df: pd.DataFrame) -> list[str]:
    return [
        col
        for col in df.columns
        if col not in _NON_FEATURE_COLUMNS and pd.api.types.is_numeric_dtype(df[col])
    ]


def _numeric_frame(df: pd.DataFrame, feature_names: list[str]) -> pd.DataFrame:
    """A float frame with exactly ``feature_names`` — missing columns become all-NaN."""
    out = pd.DataFrame(index=pd.RangeIndex(len(df)))
    for col in feature_names:
        if col in df.columns:
            series = pd.to_numeric(df[col], errors="coerce").to_numpy(dtype=np.float64)
        else:
            series = np.full(len(df), np.nan)
        out[col] = np.where(np.isfinite(series), series, np.nan)
    return out


def _impute(frame: pd.DataFrame, medians: Mapping[str, float]) -> pd.DataFrame:
    return frame.fillna({col: medians.get(col, 0.0) for col in frame.columns})


def _order_statistics(values: np.ndarray) -> np.ndarray:
    """Sorted values, thinned to an evenly-spaced quantile grid past ``_DIST_GRID``."""
    clean = np.sort(values[np.isfinite(values)])
    if clean.size == 0:
        return np.zeros(1)
    if clean.size <= _DIST_GRID:
        return clean
    idx = np.linspace(0, clean.size - 1, _DIST_GRID).round().astype(np.int64)
    return clean[idx]


def _row_to_series(row: pd.Series | Mapping[str, Any] | pd.DataFrame) -> pd.Series:
    if isinstance(row, pd.DataFrame):
        if len(row) != 1:
            raise ValueError(f"explain() expects a single row, got {len(row)}")
        return row.iloc[0]
    if isinstance(row, pd.Series):
        return row
    return pd.Series(dict(row))
