"""Feature extraction from normalized OCSF events — requirement *h*, "ML-ready".

Two feature families, one call:

**Per event** — cheap arithmetic on a handful of OCSF columns: byte volumes and
their ratio, packet count, duration, the destination port and what *kind* of
port it is, the L4 protocol number, action/severity, the wall-clock hour and
weekday of the activity, whether each endpoint is on private (RFC 1918) space,
and the traffic direction.

**Windowed, per source IP** — the same events regrouped by ``src_ip`` into
fixed time windows (default 5 minutes) and aggregated: how many connections,
to how many distinct destination IPs and *ports*, what fraction were denied,
how many bytes left, the mean bytes per connection, how many distinct
protocols. :func:`extract_features` broadcasts this window row back onto every
event in it (the ``win_*`` columns), because a single connection to
``:4444`` is not suspicious — one source IP touching 300 distinct ports in
five minutes with a 100% deny ratio is. That ``distinct_dst_ports`` /
``deny_ratio`` pair is exactly what turns a port scan from invisible into
obvious.

:func:`load_features` reads straight from the Parquet silver lake with DuckDB,
selecting **only** the ~16 columns these features touch out of the ~90 in the
schema, and pruning to a single ``date=`` / ``source_type=`` partition. That is
what "columnar storage" buys: I/O proportional to the *features used*, not to
the event width — see :mod:`ulpf.sinks.parquet_sink`'s module docstring.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd
import pyarrow as pa

from ulpf.config.settings import Settings, get_settings

_log = logging.getLogger(__name__)

DEFAULT_WINDOW = "5min"

# The per-event feature columns, in output order.
PER_EVENT_FEATURES: tuple[str, ...] = (
    "bytes_in",
    "bytes_out",
    "bytes_ratio",
    "packets",
    "duration",
    "dst_port",
    "is_well_known_port",
    "is_ephemeral_port",
    "protocol_num",
    "action_id",
    "severity_id",
    "hour_of_day",
    "day_of_week",
    "is_private_src",
    "is_private_dst",
    "direction_id",
)

# The windowed per-source-IP aggregates.
WINDOW_FEATURES: tuple[str, ...] = (
    "connection_count",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "deny_ratio",
    "total_bytes_out",
    "mean_bytes_per_conn",
    "distinct_protocols",
)

# Identifier columns carried through so the feature matrix stays joinable.
_ID_COLUMNS: tuple[str, ...] = ("event_uid", "src_ip", "time")

# The *only* silver-lake columns feature extraction reads. This tuple is
# literally the projection list :func:`load_features` hands DuckDB — every
# other column in the flattened OCSF schema is never touched.
FEATURE_SOURCE_COLUMNS: tuple[str, ...] = (
    "event_uid",
    "time",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "action_id",
    "severity_id",
    "bytes_in",
    "bytes_out",
    "duration",
    "connection_info.protocol_num",
    "connection_info.direction_id",
    "traffic.packets",
    "traffic.packets_in",
    "traffic.packets_out",
)

_WELL_KNOWN_MAX = 1023  # IANA system ports 0-1023
_EPHEMERAL_MIN = 49152  # IANA dynamic/private range 49152-65535

# OCSF network_activity DIRECTION_IDS (see ulpf.normalize.ocsf.network_activity).
_DIR_INBOUND, _DIR_OUTBOUND, _DIR_LATERAL, _DIR_UNKNOWN = 1, 2, 3, 0

# Name -> IANA protocol number, for rows that carry only the protocol string.
_PROTOCOL_NUMS: dict[str, int] = {
    "icmp": 1,
    "igmp": 2,
    "ipv4": 4,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "icmpv6": 58,
    "ipv6-icmp": 58,
    "eigrp": 88,
    "ospf": 89,
    "sctp": 132,
}


# ======================================================================
# public API
# ======================================================================


def extract_features(events: pd.DataFrame | pa.Table) -> pd.DataFrame:
    """Per-event feature matrix, one row per input event.

    Columns: ``event_uid``, ``src_ip``, ``time`` (carried through for joins),
    the 16 :data:`PER_EVENT_FEATURES`, and the 7 :data:`WINDOW_FEATURES`
    broadcast from this event's source-IP 5-minute window as ``win_<name>``.
    The result has a fresh ``RangeIndex``.

    Accepts a pandas ``DataFrame`` or a pyarrow ``Table`` of flattened OCSF
    columns (as written by :class:`~ulpf.sinks.parquet_sink.ParquetSink`).
    Missing columns are tolerated — each feature falls back to a sensible
    default rather than raising.
    """
    return _extract(_to_frame(events), DEFAULT_WINDOW)


def windowed_source_features(
    events: pd.DataFrame | pa.Table, *, window: str = DEFAULT_WINDOW
) -> pd.DataFrame:
    """One row per (``src_ip``, time window), with the 7 :data:`WINDOW_FEATURES`.

    ``window`` is any pandas offset alias (``"5min"``, ``"1h"``, ``"30s"``);
    windows are floored, not sliding. ``window_start`` is a UTC ``Timestamp``.
    """
    return _windowed(_to_frame(events), window)


def load_features(
    date: str,
    source_type: str,
    *,
    settings: Settings | None = None,
    window: str = DEFAULT_WINDOW,
) -> pd.DataFrame:
    """Read one silver partition from the Parquet lake and extract features.

    DuckDB opens the Parquet files directly (no server), reads **only**
    :data:`FEATURE_SOURCE_COLUMNS` — the columns the features actually use —
    and the Hive layout prunes the scan to ``date=<date>/source_type=<source_type>/``.
    Nothing else in the ~90-column schema is read off disk.

    Args:
        date: event-date partition, ``YYYY-MM-DD``.
        source_type: source_type partition, e.g. ``"fortigate_traffic"``.
        settings: overrides ``storage.silver_path``; defaults to the process settings.
        window: windowed-feature bucket size (pandas offset alias).
    """
    settings = settings or get_settings()
    silver = Path(settings.storage.silver_path)
    projected = _read_projected_partition(silver, date, source_type)
    return _extract(projected, window)


# ======================================================================
# per-event features
# ======================================================================


def _extract(df: pd.DataFrame, window: str) -> pd.DataFrame:
    if df.empty:
        return _empty_feature_frame()

    per = _per_event_features(df)
    windows = _windowed(df, window)
    return _broadcast_window(per, df, windows, window)


def _per_event_features(df: pd.DataFrame) -> pd.DataFrame:
    bytes_in = _num(df, "bytes_in").fillna(0).clip(lower=0)
    bytes_out = _num(df, "bytes_out").fillna(0).clip(lower=0)
    dst_port = _num(df, "dst_port").fillna(0).clip(lower=0)
    proto_num = _protocol_num(df)
    ts = pd.to_datetime(_num(df, "time"), unit="ns", utc=True)

    out = pd.DataFrame(index=pd.RangeIndex(len(df)))
    for col in _ID_COLUMNS:
        out[col] = df[col].to_numpy() if col in df.columns else pd.NA

    out["bytes_in"] = bytes_in.to_numpy()
    out["bytes_out"] = bytes_out.to_numpy()
    # asymmetry: >>1 = data leaving, <<1 = data arriving. +1 keeps it finite.
    out["bytes_ratio"] = (bytes_out / (bytes_in + 1.0)).to_numpy()
    out["packets"] = _packets(df).to_numpy()
    out["duration"] = _num(df, "duration").fillna(0.0).clip(lower=0).to_numpy()
    out["dst_port"] = dst_port.astype("int64").to_numpy()
    out["is_well_known_port"] = (
        ((dst_port >= 1) & (dst_port <= _WELL_KNOWN_MAX)).astype("int8").to_numpy()
    )
    out["is_ephemeral_port"] = (dst_port >= _EPHEMERAL_MIN).astype("int8").to_numpy()
    out["protocol_num"] = proto_num.to_numpy()
    out["action_id"] = _num(df, "action_id").fillna(0).astype("int64").to_numpy()
    out["severity_id"] = _num(df, "severity_id").fillna(0).astype("int64").to_numpy()
    out["hour_of_day"] = ts.dt.hour.fillna(-1).astype("int16").to_numpy()
    out["day_of_week"] = ts.dt.dayofweek.fillna(-1).astype("int16").to_numpy()  # 0=Mon .. 6=Sun

    priv_src = _is_private_series(df, "src_ip")
    priv_dst = _is_private_series(df, "dst_ip")
    out["is_private_src"] = priv_src.to_numpy()
    out["is_private_dst"] = priv_dst.to_numpy()
    out["direction_id"] = _direction_id(df, priv_src, priv_dst).to_numpy()
    return out


def _packets(df: pd.DataFrame) -> pd.Series:
    total = _num(df, "traffic.packets")
    halves = _num(df, "traffic.packets_in").fillna(0) + _num(df, "traffic.packets_out").fillna(0)
    return total.fillna(halves).fillna(0).clip(lower=0).astype("int64")


def _protocol_num(df: pd.DataFrame) -> pd.Series:
    num = _num(df, "connection_info.protocol_num")
    if "protocol" in df.columns:
        from_name = df["protocol"].astype("string").str.lower().map(_PROTOCOL_NUMS)
        num = num.fillna(from_name)
    return num.fillna(0).astype("int64")


def _direction_id(df: pd.DataFrame, priv_src: pd.Series, priv_dst: pd.Series) -> pd.Series:
    explicit = _num(df, "connection_info.direction_id")
    inferred = pd.Series(
        np.select(
            [
                (priv_src == 1) & (priv_dst == 0),
                (priv_src == 0) & (priv_dst == 1),
                (priv_src == 1) & (priv_dst == 1),
            ],
            [_DIR_OUTBOUND, _DIR_INBOUND, _DIR_LATERAL],
            default=_DIR_UNKNOWN,
        ),
        index=df.index,
    )
    return explicit.fillna(inferred).astype("int64")


def _is_private_series(df: pd.DataFrame, column: str) -> pd.Series:
    """1 where ``column``'s IP is RFC 1918 / loopback / link-local, else 0."""
    if column not in df.columns:
        return pd.Series(0, index=pd.RangeIndex(len(df)), dtype="int8")
    ips = df[column].reset_index(drop=True)
    lookup = {ip: _is_private(ip) for ip in pd.unique(ips.dropna())}
    return ips.map(lookup).fillna(False).astype("int8")


def _is_private(value: object) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


# ======================================================================
# windowed per-source-IP features
# ======================================================================


def _windowed(df: pd.DataFrame, window: str) -> pd.DataFrame:
    if df.empty or "src_ip" not in df.columns or "time" not in df.columns:
        return pd.DataFrame(columns=["src_ip", "window_start", *WINDOW_FEATURES])

    ts = pd.to_datetime(_num(df, "time"), unit="ns", utc=True)
    action_id = _num(df, "action_id").fillna(0)
    bytes_in = _num(df, "bytes_in").fillna(0).clip(lower=0)
    bytes_out = _num(df, "bytes_out").fillna(0).clip(lower=0)

    work = pd.DataFrame(
        {
            "src_ip": df["src_ip"].astype("string").to_numpy(),
            "window_start": ts.dt.floor(window).to_numpy(),
            "dst_ip": df["dst_ip"].astype("string").to_numpy() if "dst_ip" in df.columns else pd.NA,
            "dst_port": _num(df, "dst_port").to_numpy(),
            "protocol_num": _protocol_num(df).to_numpy(),
            "is_deny": (action_id == 2).astype("int8").to_numpy(),
            "bytes_out": bytes_out.to_numpy(),
            "total_bytes": (bytes_in + bytes_out).to_numpy(),
        }
    ).dropna(subset=["src_ip", "window_start"])

    if work.empty:
        return pd.DataFrame(columns=["src_ip", "window_start", *WINDOW_FEATURES])

    grouped = work.groupby(["src_ip", "window_start"], observed=True)
    agg = grouped.agg(
        connection_count=("src_ip", "size"),
        distinct_dst_ips=("dst_ip", "nunique"),
        distinct_dst_ports=("dst_port", "nunique"),
        deny_ratio=("is_deny", "mean"),
        total_bytes_out=("bytes_out", "sum"),
        mean_bytes_per_conn=("total_bytes", "mean"),
        distinct_protocols=("protocol_num", "nunique"),
    ).reset_index()

    agg["connection_count"] = agg["connection_count"].astype("int64")
    for col in ("distinct_dst_ips", "distinct_dst_ports", "distinct_protocols", "total_bytes_out"):
        agg[col] = agg[col].astype("int64")
    return agg[["src_ip", "window_start", *WINDOW_FEATURES]]


def _broadcast_window(
    per: pd.DataFrame, df: pd.DataFrame, windows: pd.DataFrame, window: str
) -> pd.DataFrame:
    ts = pd.to_datetime(_num(df, "time"), unit="ns", utc=True)
    key = pd.MultiIndex.from_arrays(
        [df["src_ip"].astype("string").to_numpy(), ts.dt.floor(window).to_numpy()]
    )
    win_by_key = windows.set_index(["src_ip", "window_start"])
    for feat in WINDOW_FEATURES:
        per[f"win_{feat}"] = win_by_key[feat].reindex(key).to_numpy()
    return per


# ======================================================================
# lake read (columnar projection + partition pruning)
# ======================================================================


def _read_projected_partition(silver: Path, date: str, source_type: str) -> pd.DataFrame:
    files = list(silver.rglob("*.parquet"))
    if not files:
        return pd.DataFrame(columns=list(FEATURE_SOURCE_COLUMNS))

    glob = (silver / "**" / "*.parquet").as_posix()
    con = duckdb.connect(":memory:")
    try:
        con.execute(
            "CREATE VIEW ev AS SELECT * FROM read_parquet("
            + _sql_str(glob)
            + ", union_by_name = true, hive_partitioning = true, "
            "hive_types = {'date': 'VARCHAR'})"
        )
        available = {
            row[0] for row in con.execute("SELECT column_name FROM (DESCRIBE ev)").fetchall()
        }
        wanted = [c for c in FEATURE_SOURCE_COLUMNS if c in available]
        select_list = ", ".join(f'"{c}"' for c in wanted)
        df = con.execute(
            f"SELECT {select_list} FROM ev WHERE date = ? AND source_type = ?",
            [date, source_type],
        ).df()
    finally:
        con.close()

    _log.info(
        "load_features: read %d of %d silver columns from date=%s/source_type=%s (%d rows)",
        len(wanted),
        len(available),
        date,
        source_type,
        len(df),
    )

    for col in FEATURE_SOURCE_COLUMNS:  # so downstream can rely on every name existing
        if col not in df.columns:
            df[col] = pd.NA
    return df


# ======================================================================
# small helpers
# ======================================================================


def _to_frame(events: pd.DataFrame | pa.Table) -> pd.DataFrame:
    df = events.to_pandas() if isinstance(events, pa.Table) else events
    return df.reset_index(drop=True)


def _num(df: pd.DataFrame, column: str) -> pd.Series:
    """A numeric view of ``column`` (all-NaN, length-aligned, when absent)."""
    if column not in df.columns:
        return pd.Series(np.nan, index=pd.RangeIndex(len(df)))
    return pd.to_numeric(df[column], errors="coerce").reset_index(drop=True)


def _sql_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _empty_feature_frame() -> pd.DataFrame:
    columns = [
        *_ID_COLUMNS,
        *PER_EVENT_FEATURES,
        *(f"win_{feat}" for feat in WINDOW_FEATURES),
    ]
    return pd.DataFrame(columns=columns)
