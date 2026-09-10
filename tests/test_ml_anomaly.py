"""Tests for :mod:`ulpf.ml.anomaly` — Isolation-Forest anomaly detector.

Synthetic data: a dense cluster of "normal" traffic feature rows plus a
handful of rows with one feature driven far into a tail (the injected
outliers). The detector must flag the outliers, score them above the normal
bulk, explain each by naming the driven feature, reproduce its scores under a
fixed seed, and survive a joblib round-trip.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from ulpf.ml.anomaly import AnomalyDetector, ModelNotFittedError

_FEATURES = [
    "bytes_out",
    "dst_port",
    "win_distinct_dst_ports",
    "win_deny_ratio",
    "win_connection_count",
]


def _normal_frame(n: int, seed: int) -> pd.DataFrame:
    """A tight cluster of benign-looking feature rows."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "event_uid": [f"ev-{i:04d}" for i in range(n)],
            "src_ip": rng.choice(["10.0.0.5", "10.0.0.6", "10.0.0.7"], size=n),
            "time": pd.Timestamp("2026-09-01", tz="UTC") + pd.to_timedelta(np.arange(n), unit="s"),
            "bytes_out": rng.normal(4_000, 400, n).clip(0),
            "dst_port": rng.choice([80, 443, 53], size=n).astype(float),
            "win_distinct_dst_ports": rng.integers(1, 6, n).astype(float),
            "win_deny_ratio": rng.uniform(0.0, 0.05, n),
            "win_connection_count": rng.integers(5, 25, n).astype(float),
        }
    )


def _with_outliers(base: pd.DataFrame) -> tuple[pd.DataFrame, list[int], str]:
    """Append rows with ``win_distinct_dst_ports`` blown out — a port scan."""
    scan_feature = "win_distinct_dst_ports"
    outliers = pd.DataFrame(
        {
            "event_uid": ["scan-0", "scan-1", "scan-2"],
            "src_ip": ["192.168.1.66"] * 3,
            "time": [base["time"].iloc[-1]] * 3,
            "bytes_out": [3_900.0, 4_100.0, 4_050.0],
            "dst_port": [4444.0, 4445.0, 4446.0],
            scan_feature: [280.0, 305.0, 320.0],
            "win_deny_ratio": [0.93, 0.95, 0.97],
            "win_connection_count": [340.0, 360.0, 355.0],
        }
    )
    combined = pd.concat([base, outliers], ignore_index=True)
    outlier_idx = list(range(len(base), len(combined)))
    return combined, outlier_idx, scan_feature


def test_fit_score_flags_injected_outliers() -> None:
    train = _normal_frame(400, seed=1)
    detector = AnomalyDetector(contamination=0.02).fit(train)

    test_df, outlier_idx, _ = _with_outliers(_normal_frame(60, seed=2))
    scored = detector.score(test_df)

    assert scored.loc[outlier_idx, "is_anomaly"].all()
    normal_idx = [i for i in scored.index if i not in outlier_idx]
    # The benign bulk is overwhelmingly not flagged.
    assert scored.loc[normal_idx, "is_anomaly"].mean() < 0.1
    # Every outlier scores well clear of the benign bulk.
    assert scored.loc[outlier_idx, "anomaly_score"].min() > scored.loc[
        normal_idx, "anomaly_score"
    ].quantile(0.95)


def test_score_carries_identifier_columns_and_index() -> None:
    train = _normal_frame(200, seed=3)
    detector = AnomalyDetector().fit(train)
    scored = detector.score(train)

    assert list(scored.columns) == ["event_uid", "src_ip", "time", "anomaly_score", "is_anomaly"]
    assert scored["event_uid"].tolist() == train["event_uid"].tolist()
    assert scored.index.equals(train.index)
    assert scored["anomaly_score"].dtype == np.float64
    assert scored["is_anomaly"].dtype == bool


def test_explain_names_the_driven_feature() -> None:
    train = _normal_frame(400, seed=4)
    detector = AnomalyDetector(contamination=0.02).fit(train)

    test_df, outlier_idx, scan_feature = _with_outliers(_normal_frame(20, seed=5))
    row = test_df.iloc[outlier_idx[0]]

    top = detector.explain(row)
    assert len(top) == 3
    names = [e["feature"] for e in top]
    assert scan_feature in names
    driven = next(e for e in top if e["feature"] == scan_feature)
    assert driven["direction"] == "high"
    assert driven["percentile"] > 99.0
    assert driven["value"] == pytest.approx(280.0)
    assert "percentile" in driven["note"]


def test_explain_accepts_series_dict_and_dataframe() -> None:
    train = _normal_frame(150, seed=6)
    detector = AnomalyDetector().fit(train)
    row = train.iloc[10]

    as_series = detector.explain(row)
    as_dict = detector.explain(row.to_dict())
    as_frame = detector.explain(train.iloc[[10]])

    assert [e["feature"] for e in as_series] == [e["feature"] for e in as_dict]
    assert [e["feature"] for e in as_series] == [e["feature"] for e in as_frame]


def test_reproducible_under_fixed_seed() -> None:
    train = _normal_frame(300, seed=7)
    test_df = _normal_frame(50, seed=8)

    a = AnomalyDetector(random_state=42).fit(train).score(test_df)
    b = AnomalyDetector(random_state=42).fit(train).score(test_df)

    pd.testing.assert_frame_equal(a, b)


def test_contamination_controls_flag_rate() -> None:
    train = _normal_frame(500, seed=9)
    high = AnomalyDetector(contamination=0.2).fit(train).score(train)
    low = AnomalyDetector(contamination=0.01).fit(train).score(train)

    assert high["is_anomaly"].mean() > low["is_anomaly"].mean()
    assert 0.1 < high["is_anomaly"].mean() < 0.3


def test_save_load_round_trip_preserves_scores_and_metadata(tmp_path) -> None:
    train = _normal_frame(250, seed=10)
    test_df, _, _ = _with_outliers(_normal_frame(30, seed=11))

    detector = AnomalyDetector(contamination=0.05).fit(train)
    before = detector.score(test_df)
    explain_before = detector.explain(test_df.iloc[-1])

    path = tmp_path / "detector.joblib"
    detector.save(path)
    reloaded = AnomalyDetector.load(path)

    pd.testing.assert_frame_equal(before, reloaded.score(test_df))
    assert reloaded.explain(test_df.iloc[-1]) == explain_before
    assert reloaded.metadata == detector.metadata
    assert reloaded.feature_names == detector.feature_names


def test_metadata_fields() -> None:
    train = _normal_frame(123, seed=12)
    detector = AnomalyDetector(contamination=0.07).fit(train)
    meta = detector.metadata

    assert meta["n_samples"] == 123
    assert meta["contamination"] == 0.07
    assert meta["n_estimators"] == 100
    assert meta["random_state"] == 42
    assert set(meta["feature_names"]) == set(_FEATURES)
    # trained_at is a parseable UTC ISO-8601 timestamp.
    parsed = pd.Timestamp(meta["trained_at"])
    assert parsed.tzinfo is not None


def test_unfitted_detector_raises() -> None:
    detector = AnomalyDetector()
    frame = _normal_frame(10, seed=13)

    assert detector.is_fitted is False
    with pytest.raises(ModelNotFittedError):
        detector.score(frame)
    with pytest.raises(ModelNotFittedError):
        detector.explain(frame.iloc[0])
    with pytest.raises(ModelNotFittedError):
        detector.save(str(frame))


def test_fit_requires_numeric_features() -> None:
    frame = pd.DataFrame({"event_uid": ["a", "b"], "src_ip": ["1.1.1.1", "2.2.2.2"]})
    with pytest.raises(ValueError, match="no numeric feature columns"):
        AnomalyDetector().fit(frame)


def test_missing_feature_column_at_score_time_is_imputed() -> None:
    train = _normal_frame(200, seed=14)
    detector = AnomalyDetector().fit(train)

    partial = train.drop(columns=["win_deny_ratio"]).iloc[:20]
    scored = detector.score(partial)  # must not raise
    assert len(scored) == 20
    assert scored["anomaly_score"].notna().all()


def test_nan_and_inf_values_are_handled() -> None:
    train = _normal_frame(200, seed=15)
    train.loc[0, "bytes_out"] = np.inf
    train.loc[1, "bytes_out"] = np.nan
    train.loc[2, "win_deny_ratio"] = -np.inf

    detector = AnomalyDetector().fit(train)
    scored = detector.score(train)
    assert scored["anomaly_score"].notna().all()


def test_runs_on_extract_features_output() -> None:
    """Integration: feed the real feature extractor's frame straight in."""
    pytest.importorskip("ulpf.ml.features")
    from ulpf.ml.features import extract_features

    base_ns = 1_756_684_800_000_000_000
    rows = []
    for i in range(60):
        rows.append(
            {
                "event_uid": f"u{i}",
                "time": base_ns + i * 1_000_000_000,
                "src_ip": "10.1.1.10",
                "dst_ip": f"10.2.2.{i % 20}",
                "dst_port": 400 + i,
                "protocol": "tcp",
                "bytes_in": 100 + i,
                "bytes_out": 200 + i,
                "action_id": 1,
                "severity_id": 1,
            }
        )
    features = extract_features(pd.DataFrame(rows))
    detector = AnomalyDetector().fit(features)
    scored = detector.score(features)
    assert len(scored) == len(features)
    assert "anomaly_score" in scored.columns
