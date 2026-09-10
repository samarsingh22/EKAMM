"""Tests for :mod:`ulpf.ml.features` — per-event + windowed OCSF feature extraction."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from ulpf.config.settings import Settings, StorageSettings
from ulpf.ml.features import (
    PER_EVENT_FEATURES,
    WINDOW_FEATURES,
    extract_features,
    load_features,
    windowed_source_features,
)

# 2026-09-01T12:00:00Z — a Tuesday (dayofweek == 1), hour 12.
_BASE_NS = 1_788_264_000_000_000_000
_MINUTE_NS = 60_000_000_000


def _events(rows: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def _ev(i: int, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "event_uid": f"e{i}",
        "time": _BASE_NS + i * 1_000_000_000,
        "src_ip": "10.0.0.9",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "protocol": "tcp",
        "action_id": 1,
        "severity_id": 1,
        "bytes_in": 100,
        "bytes_out": 50,
    }
    row.update(overrides)
    return row


# ======================================================================
# per-event features
# ======================================================================


def test_output_shape_and_columns() -> None:
    feat = extract_features(_events([_ev(0), _ev(1)]))
    assert len(feat) == 2
    expected = {
        "event_uid",
        "src_ip",
        "time",
        *PER_EVENT_FEATURES,
        *(f"win_{w}" for w in WINDOW_FEATURES),
    }
    assert set(feat.columns) == expected


def test_byte_features() -> None:
    feat = extract_features(_events([_ev(0, bytes_in=1000, bytes_out=250)]))
    row = feat.iloc[0]
    assert row["bytes_in"] == 1000
    assert row["bytes_out"] == 250
    assert row["bytes_ratio"] == pytest.approx(250 / 1001)  # bytes_out / (bytes_in + 1)


def test_port_kind_features() -> None:
    df = _events(
        [
            _ev(0, dst_port=22),  # well-known
            _ev(1, dst_port=443),  # well-known
            _ev(2, dst_port=8080),  # neither
            _ev(3, dst_port=51000),  # ephemeral
            _ev(4, dst_port=0),  # neither (no port)
        ]
    )
    feat = extract_features(df)
    assert feat["is_well_known_port"].tolist() == [1, 1, 0, 0, 0]
    assert feat["is_ephemeral_port"].tolist() == [0, 0, 0, 1, 0]


def test_protocol_num_from_string_and_explicit() -> None:
    df = _events(
        [
            _ev(0, protocol="tcp"),
            _ev(1, protocol="udp"),
            _ev(2, protocol="icmp"),
            _ev(3, protocol="tcp", **{"connection_info.protocol_num": 132}),  # explicit wins
        ]
    )
    feat = extract_features(df)
    assert feat["protocol_num"].tolist() == [6, 17, 1, 132]


def test_time_features_hour_and_weekday() -> None:
    feat = extract_features(_events([_ev(0)]))  # _BASE_NS is Tue 2026-09-01 12:00:00 UTC
    assert feat.iloc[0]["hour_of_day"] == 12
    assert feat.iloc[0]["day_of_week"] == 1  # 0 = Monday


def test_private_ip_and_direction() -> None:
    df = _events(
        [
            _ev(0, src_ip="10.0.0.5", dst_ip="8.8.8.8"),  # private -> public : Outbound
            _ev(1, src_ip="8.8.8.8", dst_ip="192.168.1.10"),  # public -> private : Inbound
            _ev(2, src_ip="10.0.0.5", dst_ip="172.16.0.9"),  # private -> private : Lateral
            _ev(3, src_ip="1.1.1.1", dst_ip="8.8.4.4"),  # public -> public : Unknown
            _ev(4, src_ip="10.0.0.5", dst_ip="8.8.8.8", **{"connection_info.direction_id": 1}),
        ]
    )
    feat = extract_features(df)
    assert feat["is_private_src"].tolist() == [1, 0, 1, 0, 1]
    assert feat["is_private_dst"].tolist() == [0, 1, 1, 0, 0]
    assert feat["direction_id"].tolist() == [2, 1, 3, 0, 1]  # last: explicit overrides inference


def test_packets_from_total_or_halves() -> None:
    df = _events(
        [
            _ev(0, **{"traffic.packets": 12}),
            _ev(1, **{"traffic.packets_in": 3, "traffic.packets_out": 4}),
            _ev(2),  # no packet columns -> 0
        ]
    )
    feat = extract_features(df)
    assert feat["packets"].tolist() == [12, 7, 0]


def test_duration_passthrough_and_default() -> None:
    feat = extract_features(_events([_ev(0, duration=1.5), _ev(1)]))
    assert feat["duration"].tolist() == [1.5, 0.0]


def test_missing_columns_are_tolerated() -> None:
    minimal = pd.DataFrame([{"event_uid": "x", "time": _BASE_NS, "src_ip": "10.0.0.1"}])
    feat = extract_features(minimal)  # must not raise
    assert len(feat) == 1
    row = feat.iloc[0]
    assert row["bytes_in"] == 0
    assert row["dst_port"] == 0
    assert row["protocol_num"] == 0
    assert row["is_private_src"] == 1


def test_accepts_pyarrow_table() -> None:
    df = _events([_ev(0), _ev(1)])
    from_df = extract_features(df)
    from_table = extract_features(pa.Table.from_pandas(df))
    pd.testing.assert_frame_equal(from_df, from_table)


def test_empty_input_returns_empty_frame_with_columns() -> None:
    feat = extract_features(pd.DataFrame())
    assert len(feat) == 0
    assert "bytes_ratio" in feat.columns
    assert "win_distinct_dst_ports" in feat.columns


# ======================================================================
# windowed per-source-IP features — the port-scan signal
# ======================================================================


def _scan_and_talk() -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    # scanner: one src, 40 distinct dst ports, every one denied
    for i in range(40):
        rows.append(
            _ev(
                i,
                src_ip="10.0.0.66",
                dst_ip="10.0.9.9",
                dst_port=1000 + i,
                action_id=2,
                bytes_out=0,
            )
        )
    # normal talker: one src, one dst:443, allowed, large transfer
    for i in range(6):
        rows.append(
            _ev(
                100 + i,
                src_ip="10.0.0.77",
                dst_ip="10.0.9.20",
                dst_port=443,
                action_id=1,
                bytes_out=900_000,
            )
        )
    return _events(rows)


def test_port_scan_is_visible_in_windowed_features() -> None:
    win = windowed_source_features(_scan_and_talk())
    by_ip = win.set_index("src_ip")

    scanner = by_ip.loc["10.0.0.66"]
    assert scanner["connection_count"] == 40
    assert scanner["distinct_dst_ports"] == 40
    assert scanner["distinct_dst_ips"] == 1
    assert scanner["deny_ratio"] == 1.0

    talker = by_ip.loc["10.0.0.77"]
    assert talker["distinct_dst_ports"] == 1
    assert talker["deny_ratio"] == 0.0
    assert talker["total_bytes_out"] == 6 * 900_000
    assert talker["mean_bytes_per_conn"] == pytest.approx(
        900_000 + 100
    )  # bytes_in(100) + bytes_out


def test_windows_are_bucketed_and_configurable() -> None:
    df = _events(
        [
            _ev(0, src_ip="10.0.0.1", time=_BASE_NS),
            _ev(1, src_ip="10.0.0.1", time=_BASE_NS + 6 * _MINUTE_NS),  # 6 min later
        ]
    )
    # default 5-minute windows -> two buckets
    assert len(windowed_source_features(df)) == 2
    # a 1-hour window -> one bucket
    one_hour = windowed_source_features(df, window="1h")
    assert len(one_hour) == 1
    assert one_hour.iloc[0]["connection_count"] == 2


def test_window_features_are_broadcast_onto_each_event() -> None:
    feat = extract_features(_scan_and_talk())
    scanner_rows = feat[feat["src_ip"] == "10.0.0.66"]
    assert (scanner_rows["win_distinct_dst_ports"] == 40).all()
    assert (scanner_rows["win_deny_ratio"] == 1.0).all()
    talker_rows = feat[feat["src_ip"] == "10.0.0.77"]
    assert (talker_rows["win_distinct_dst_ports"] == 1).all()
    assert (talker_rows["win_deny_ratio"] == 0.0).all()


# ======================================================================
# load_features — columnar projection + partition pruning
# ======================================================================

# a deliberately WIDE row: the 16 columns features need, plus ~10 the schema
# carries that they must never read.
_WIDE_EXTRAS = {
    "raw_hash": "h" * 64,
    "class_uid": 4001,
    "category_uid": 4,
    "activity_id": 6,
    "type_uid": 400106,
    "src_port": 51000,
    "class_name": "Network Activity",
    "activity_name": "Traffic",
    "disposition": "Blocked",
    "metadata.uid": "m",
    "metadata.product.name": "FortiGate",
    "unmapped_json": "{}",
    "enrichments_json": "{}",
}


def _lake_row(i: int, src: str, port: int, action: int) -> dict[str, Any]:
    return {
        "event_uid": f"L{i}",
        "time": _BASE_NS + i * 1_000_000_000,
        "src_ip": src,
        "dst_ip": "8.8.8.8",
        "dst_port": port,
        "protocol": "tcp",
        "action_id": action,
        "severity_id": 2,
        "bytes_in": 100,
        "bytes_out": 50,
        "source_type": "fortigate_traffic",
        "connection_info.protocol_num": 6,
        "traffic.packets": 3,
        **_WIDE_EXTRAS,
    }


def _write_partition(silver: Path, date: str, source: str, rows: list[dict[str, Any]]) -> None:
    part = silver / f"date={date}" / f"source_type={source}"
    part.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.Table.from_pylist(rows), part / f"part-{uuid.uuid4().hex}.parquet", compression="zstd"
    )


@pytest.fixture
def lake(tmp_path: Path) -> Settings:
    silver = tmp_path / "silver"
    _write_partition(
        silver,
        "2026-09-01",
        "fortigate_traffic",
        [_lake_row(i, "10.0.0.66", 4000 + i, 2) for i in range(15)],
    )
    _write_partition(
        silver,
        "2026-09-02",
        "fortigate_traffic",
        [_lake_row(i, "10.0.0.77", 443, 1) for i in range(4)],
    )
    _write_partition(
        silver,
        "2026-09-01",
        "zeek_conn",
        [_lake_row(i, "10.0.0.88", 53, 1) for i in range(3)],
    )
    return Settings(storage=StorageSettings(silver_path=silver, dlq_path=tmp_path / "dlq"))


def test_load_features_reads_one_partition(lake: Settings) -> None:
    feat = load_features("2026-09-01", "fortigate_traffic", settings=lake)
    assert len(feat) == 15
    assert feat["src_ip"].unique().tolist() == ["10.0.0.66"]
    # the port scan is detectable straight from the lake
    assert (feat["win_distinct_dst_ports"] == 15).all()
    assert (feat["win_deny_ratio"] == 1.0).all()


def test_load_features_prunes_by_date_and_source_type(lake: Settings) -> None:
    d1 = load_features("2026-09-01", "fortigate_traffic", settings=lake)
    d2 = load_features("2026-09-02", "fortigate_traffic", settings=lake)
    assert "10.0.0.77" not in d1["src_ip"].values  # other date excluded
    assert d2["src_ip"].unique().tolist() == ["10.0.0.77"]
    # same date, other source_type is excluded
    assert "10.0.0.88" not in d1["src_ip"].values


def test_load_features_output_has_only_feature_columns_not_the_wide_schema(lake: Settings) -> None:
    feat = load_features("2026-09-01", "fortigate_traffic", settings=lake)
    leaked = {"raw_hash", "class_name", "disposition", "unmapped_json", "metadata.uid", "src_port"}
    assert leaked.isdisjoint(feat.columns)
    expected = {
        "event_uid",
        "src_ip",
        "time",
        *PER_EVENT_FEATURES,
        *(f"win_{w}" for w in WINDOW_FEATURES),
    }
    assert set(feat.columns) == expected


def test_load_features_logs_the_columnar_projection(
    lake: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="ulpf.ml.features"):
        load_features("2026-09-01", "fortigate_traffic", settings=lake)
    msg = next(r.getMessage() for r in caplog.records if "load_features" in r.getMessage())
    # reads far fewer columns than the partition actually holds
    assert "read 12 of " in msg  # 12 of the 16 wanted columns exist in this fixture's schema
    read_n, _, total_n = msg.split("read ")[1].split(" silver columns")[0].partition(" of ")
    assert int(read_n) < int(total_n)


def test_load_features_missing_partition_is_empty(lake: Settings) -> None:
    feat = load_features("1999-01-01", "fortigate_traffic", settings=lake)
    assert len(feat) == 0
    assert "win_distinct_dst_ports" in feat.columns


def test_load_features_no_lake_is_empty(tmp_path: Path) -> None:
    settings = Settings(
        storage=StorageSettings(silver_path=tmp_path / "nothing", dlq_path=tmp_path / "dlq")
    )
    feat = load_features("2026-09-01", "fortigate_traffic", settings=settings)
    assert len(feat) == 0


def test_load_features_honors_window(lake: Settings) -> None:
    # the 15 events are 1s apart (one 5-min bucket already); widen anyway to
    # prove the `window` kwarg threads through to the aggregation.
    feat = load_features("2026-09-01", "fortigate_traffic", settings=lake, window="1h")
    assert (feat["win_connection_count"] == 15).all()
