#!/usr/bin/env python
"""Replay a sample log file at a controlled, sustained rate and report real numbers.

    python bench/replay.py --file data/samples/cisco_asa_1m.log --rate 50000 \\
        --duration 60 --transport udp

Point this at an already-running ``ulpf serve`` (it needs both a listener
port to send traffic to, and the management API's ``/metrics`` + ``/health``
to measure from — ``ulpf run`` alone does not expose those).

PACING, NOT BLASTING
--------------------
By default this sends at ``--rate`` events/second, held steady for the whole
run: it computes, at every step, how many events *should* have gone out by
now (``elapsed * rate``) and only sends when it is behind that schedule —
catching up without sleeping when behind, and yielding in short slices when
ahead. That self-corrects for its own overhead instead of accumulating drift
the way a naive "sleep(1/rate) per event" loop does. Sending as fast as
possible (no pacing at all) is opt-in via ``--max-rate`` — never the default,
because "how fast can this possibly go" and "what does this system sustain at
a realistic, steady rate" are different questions, and only the second one
tells you anything about production behavior.

WARM-UP AND THE MEASUREMENT WINDOW
------------------------------------
Traffic is sent for ``--warmup`` seconds (default 10) *before* anything is
measured — this exercises JIT/connection-establishment/buffer-growth effects
so they land on the warm-up, not the reported numbers — then a
``ulpf_*`` metrics snapshot is taken, ``--duration`` seconds (default and
**required minimum 60** — a shorter window is dominated by noise, not signal;
pass ``--allow-short-duration`` to deliberately override for quick local
iteration) of traffic is sent and measured, and a second snapshot is taken.
Every reported number (latency percentiles, parse coverage, DLQ rate,
normalization completeness) is computed from the *delta* between those two
snapshots of the server's own Prometheus counters/histograms — not
re-derived or estimated locally — so what this script reports is exactly
what the running ULPF process itself recorded for this window, nothing else.

WHAT "LATENCY" MEANS HERE
---------------------------
``ulpf_end_to_end_latency_seconds`` (see :mod:`ulpf.core.metrics`) is
observed once per event, in :meth:`ulpf.core.pipeline.Pipeline._run_stages`,
the instant that event finishes its *last* stage (the sink) without being
dropped or dead-lettered — i.e. genuinely "ingest timestamp to sink write
done", the same definition the metric's own docstring gives. Percentiles are
computed from the histogram's bucket counts via the same linear-interpolation
method Prometheus's own ``histogram_quantile()`` uses — accurate to the
bucket boundaries (the default ``prometheus_client`` buckets), not exact to
the microsecond, which is the right trade-off for a metric already being
aggregated server-side across a whole measurement window.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx

try:
    import psutil
except ImportError:  # pragma: no cover - exercised only without the optional extra
    psutil = None  # type: ignore[assignment]

_DEFAULT_MIN_DURATION_S = 60.0
_DEFAULT_WARMUP_S = 10.0
_SETTLE_S = 2.0  # drain time before/after each metrics snapshot - see module docstring
_DEFAULT_PORTS = {"udp": 514, "tcp": 514, "http": 8081}


@dataclass
class BenchmarkConfig:
    """One :func:`run_benchmark` call's worth of settings — the CLI's parsed args, as data.

    :mod:`bench.report` builds these directly (no argparse involved) to drive
    a whole matrix of runs through the exact same measurement method
    :func:`main` uses for one ad-hoc run.
    """

    file: Path
    transport: str
    host: str = "127.0.0.1"
    port: int | None = None
    rate: float = 1000.0
    max_rate: bool = False
    duration: float = _DEFAULT_MIN_DURATION_S
    allow_short_duration: bool = False
    warmup: float = _DEFAULT_WARMUP_S
    api_base_url: str = "http://127.0.0.1:8080"
    server_pid: int | None = None
    rss_poll_interval: float = 0.5
    loop: bool = False
    http_batch_size: int = 500
    tcp_batch_bytes: int = 65536
    source_id: str | None = None


# ======================================================================
# hardware
# ======================================================================


def _cpu_model() -> str:
    """A best-effort human CPU model string, without requiring psutil."""
    system = platform.system()
    if system == "Windows":
        proc = platform.processor()
        if proc and "Family" not in proc and proc != "GenuineIntel" and proc != "AuthenticAMD":
            return proc
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            return str(name).strip()
        except OSError:
            return proc or "unknown"
    if system == "Linux":
        try:
            with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass
    if system == "Darwin":
        model = _run_quiet(["sysctl", "-n", "machdep.cpu.brand_string"])
        if model:
            return model
    return platform.processor() or platform.machine() or "unknown"


def _total_ram_bytes() -> int | None:
    """Best-effort total physical RAM, without requiring psutil."""
    if psutil is not None:
        try:
            return int(psutil.virtual_memory().total)
        except Exception:  # noqa: BLE001 - fall through to the stdlib paths below
            pass
    system = platform.system()
    if system == "Windows":
        return _windows_total_ram()
    if system == "Linux":
        try:
            with open("/proc/meminfo", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
    if system == "Darwin":
        raw = _run_quiet(["sysctl", "-n", "hw.memsize"])
        return int(raw) if raw and raw.isdigit() else None
    return None


def _windows_total_ram() -> int | None:
    try:
        import ctypes

        class _MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = _MemoryStatusEx()
        stat.dwLength = ctypes.sizeof(_MemoryStatusEx)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))  # type: ignore[attr-defined]
        return int(stat.ullTotalPhys)
    except Exception:  # noqa: BLE001 - best-effort only
        return None


def _run_quiet(cmd: list[str]) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


@dataclass
class Hardware:
    cpu_model: str
    cpu_cores: int
    ram_bytes: int | None

    @classmethod
    def detect(cls) -> Hardware:
        return cls(
            cpu_model=_cpu_model(), cpu_cores=os.cpu_count() or 0, ram_bytes=_total_ram_bytes()
        )


# ======================================================================
# peak RSS of the server process (optional, needs --server-pid + psutil)
# ======================================================================


class RssSampler:
    """Polls ``psutil.Process(pid).memory_info().rss`` on a background thread; tracks the peak."""

    def __init__(self, pid: int, *, interval_s: float = 0.5) -> None:
        self._pid = pid
        self._interval = interval_s
        self._peak = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.error: str | None = None

    def start(self) -> None:
        if psutil is None:
            self.error = "psutil is not installed (pip install 'ulpf[bench]')"
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        assert psutil is not None
        try:
            proc = psutil.Process(self._pid)
        except psutil.NoSuchProcess:
            self.error = f"no such process: {self._pid}"
            return
        while not self._stop.is_set():
            try:
                self._peak = max(self._peak, proc.memory_info().rss)
            except psutil.NoSuchProcess:
                self.error = "server process exited during the run"
                return
            self._stop.wait(self._interval)

    def stop(self) -> int | None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        return self._peak or None


# ======================================================================
# Prometheus text-format parsing (just enough for this project's own metrics)
# ======================================================================

_METRIC_LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)\s*$"
)
_LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

Sample = tuple[dict[str, str], float]


def parse_prometheus_text(text: str) -> dict[str, list[Sample]]:
    """``metric name -> [(labels, value), ...]`` from a ``/metrics`` text response."""
    out: dict[str, list[Sample]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = _METRIC_LINE_RE.match(line)
        if not match:
            continue
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        labels = _parse_labels(match.group("labels") or "")
        out.setdefault(match.group("name"), []).append((labels, value))
    return out


def _parse_labels(raw: str) -> dict[str, str]:
    return {k: v.replace('\\"', '"').replace("\\\\", "\\") for k, v in _LABEL_RE.findall(raw)}


@dataclass
class MetricsSnapshot:
    """One scrape of ``/metrics``, at a point in time."""

    taken_at: float
    samples: dict[str, list[Sample]] = field(default_factory=dict)

    def sum_counter(self, name: str, **label_filter: str) -> float:
        """Sum every series for ``name`` whose labels match ``label_filter`` (a superset match)."""
        total = 0.0
        for labels, value in self.samples.get(name, []):
            if all(labels.get(k) == v for k, v in label_filter.items()):
                total += value
        return total

    def histogram_buckets(self, base_name: str) -> list[tuple[float, float]]:
        """``[(le, cumulative_count), ...]`` for ``<base_name>_bucket``, sorted by ``le``."""
        out: list[tuple[float, float]] = []
        for labels, value in self.samples.get(f"{base_name}_bucket", []):
            le_str = labels.get("le")
            if le_str is None:
                continue
            le = math.inf if le_str in ("+Inf", "Inf") else float(le_str)
            out.append((le, value))
        return sorted(out)

    def histogram_sum(self, base_name: str) -> float:
        vals = self.samples.get(f"{base_name}_sum", [])
        return vals[0][1] if vals else 0.0

    def histogram_count(self, base_name: str) -> float:
        vals = self.samples.get(f"{base_name}_count", [])
        return vals[0][1] if vals else 0.0


def fetch_metrics(client: httpx.Client, base_url: str) -> MetricsSnapshot:
    response = client.get(f"{base_url}/metrics", timeout=10.0)
    response.raise_for_status()
    return MetricsSnapshot(taken_at=time.time(), samples=parse_prometheus_text(response.text))


def fetch_health(client: httpx.Client, base_url: str) -> dict[str, Any] | None:
    try:
        response = client.get(f"{base_url}/health", timeout=5.0)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError:
        return None


def diff_histogram_buckets(
    before: list[tuple[float, float]], after: list[tuple[float, float]]
) -> list[tuple[float, float]]:
    """Per-``le`` count delta between two scrapes of the same histogram."""
    before_map = dict(before)
    return sorted((le, max(0.0, count - before_map.get(le, 0.0))) for le, count in after)


def histogram_quantile(buckets: list[tuple[float, float]], q: float) -> float | None:
    """Prometheus's own ``histogram_quantile()`` algorithm: linear interpolation in one bucket."""
    if not buckets:
        return None
    total = buckets[-1][1]
    if total <= 0:
        return None
    target = q * total
    prev_le, prev_count = 0.0, 0.0
    for le, count in buckets:
        if count >= target:
            if math.isinf(le):
                return prev_le  # target falls in the open-ended +Inf bucket - can't interpolate
            if count <= prev_count:
                return le
            frac = (target - prev_count) / (count - prev_count)
            return prev_le + frac * (le - prev_le)
        prev_le, prev_count = le, count
    return buckets[-1][0]


# ======================================================================
# senders
# ======================================================================


class Sender(Protocol):
    def send_one(self, line: bytes) -> None: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...


class UdpSender:
    """One datagram per line - matches how syslog UDP is actually sent."""

    def __init__(self, host: str, port: int) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._addr = (host, port)

    def send_one(self, line: bytes) -> None:
        self._sock.sendto(line, self._addr)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self._sock.close()


class TcpSender:
    """RFC 6587 octet-counting framing (``MSGLEN SP MSG``) over one persistent connection.

    Matches :func:`ulpf.ingest.syslog_tcp.read_frames` exactly - see
    ``scripts/win/send-sample.ps1``'s ``Send-TcpOctetCounted`` for the same
    framing used elsewhere in this project. Frames are buffered and flushed
    in batches to amortize the syscall cost at a high target rate.
    """

    def __init__(self, host: str, port: int, *, batch_bytes: int = 65536) -> None:
        self._sock = socket.create_connection((host, port), timeout=10.0)
        self._buf = bytearray()
        self._batch_bytes = batch_bytes

    def send_one(self, line: bytes) -> None:
        self._buf += str(len(line)).encode("ascii")
        self._buf += b" "
        self._buf += line
        if len(self._buf) >= self._batch_bytes:
            self.flush()

    def flush(self) -> None:
        if self._buf:
            self._sock.sendall(self._buf)
            self._buf.clear()

    def close(self) -> None:
        self.flush()
        self._sock.close()


class HttpSender:
    """Batches lines into ``POST /ingest/raw`` bodies (see :mod:`ulpf.ingest.http_intake`)."""

    def __init__(
        self, base_url: str, *, batch_size: int = 500, source_id: str | None = None
    ) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=10.0)
        self._batch: list[bytes] = []
        self._batch_size = batch_size
        self._params = {"source_id": source_id} if source_id else None

    def send_one(self, line: bytes) -> None:
        self._batch.append(line)
        if len(self._batch) >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._batch:
            return
        response = self._client.post(
            "/ingest/raw", content=b"\n".join(self._batch), params=self._params
        )
        response.raise_for_status()
        self._batch.clear()

    def close(self) -> None:
        self.flush()
        self._client.close()


def build_sender(transport: str, host: str, port: int, config: BenchmarkConfig) -> Sender:
    if transport == "udp":
        return UdpSender(host, port)
    if transport == "tcp":
        return TcpSender(host, port, batch_bytes=config.tcp_batch_bytes)
    if transport == "http":
        return HttpSender(
            f"http://{host}:{port}", batch_size=config.http_batch_size, source_id=config.source_id
        )
    raise ValueError(
        f"unknown transport {transport!r}"
    )  # pragma: no cover - argparse restricts this


# ======================================================================
# pacing
# ======================================================================


@dataclass
class PhaseResult:
    sent: int
    elapsed_s: float


def run_phase(
    sender: Sender,
    lines: Sequence[bytes],
    *,
    rate: float | None,
    duration_s: float,
    loop_source: bool,
    start_index: int = 0,
) -> tuple[PhaseResult, int]:
    """Send at `rate` events/sec (or flat-out if `rate` is None) for `duration_s`.

    Self-correcting pacing: at every step this asks "how many events should
    have gone out by now" (``elapsed * rate``) and only sends when behind
    that schedule, so per-iteration overhead never accumulates into drift the
    way a fixed ``sleep(1/rate)`` per event would. Returns the result plus
    the index into ``lines`` to resume from (so a warm-up phase and the
    measurement phase that follows it don't replay the exact same lines
    unless ``loop_source`` is set).
    """
    n = len(lines)
    idx = start_index
    sent = 0
    start = time.perf_counter()
    last_flush = start
    while True:
        now = time.perf_counter()
        elapsed = now - start
        if elapsed >= duration_s:
            break
        if rate is not None and sent >= elapsed * rate:
            time.sleep(0.0005)
            continue
        if idx >= n:
            if not loop_source:
                break
            idx = 0
        sender.send_one(lines[idx])
        idx += 1
        sent += 1
        if now - last_flush >= 0.2:
            sender.flush()
            last_flush = now
    sender.flush()
    return PhaseResult(sent=sent, elapsed_s=time.perf_counter() - start), idx


# ======================================================================
# report
# ======================================================================


@dataclass
class BenchReport:
    """The measurement window's results, computed entirely from server-side metric deltas.

    ``parse_coverage`` is ``Δulpf_events_normalized_total / Δulpf_events_received_total``
    — the fraction of received events that were fully, authoritatively parsed
    *and* mapped into OCSF (not the earlier advisory sniff pass's own
    counter, which has no signature for grok/dissect sources at all and would
    misreport them as ~0% "parsed" even when every line normalizes cleanly).
    """

    transport: str
    target_rate: float | None
    warmup_s: float
    requested_duration_s: float
    measured_duration_s: float
    sent: int
    achieved_eps: float
    latency_p50_ms: float | None
    latency_p95_ms: float | None
    latency_p99_ms: float | None
    latency_samples: int
    parse_coverage: float | None
    dlq_rate: float | None
    backlog_note: str | None
    normalization_completeness_mean: float | None
    peak_server_rss_bytes: int | None
    rss_note: str | None
    cpu_model: str
    cpu_cores: int
    ram_bytes: int | None
    enrichment_enabled: bool | None
    integrity_active: bool | None
    integrity_off_reason: str | None
    server_reachable: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_report(
    *,
    transport: str,
    target_rate: float | None,
    warmup_s: float,
    requested_duration_s: float,
    phase: PhaseResult,
    before: MetricsSnapshot | None,
    after: MetricsSnapshot | None,
    health: dict[str, Any] | None,
    peak_rss: int | None,
    rss_note: str | None,
    hardware: Hardware,
) -> BenchReport:
    parse_coverage = dlq_rate = completeness_mean = None
    backlog_note = None
    p50 = p95 = p99 = None
    latency_samples = 0
    if before is not None and after is not None:
        received = after.sum_counter("ulpf_events_received_total", transport=transport) - (
            before.sum_counter("ulpf_events_received_total", transport=transport)
        )
        # ulpf_events_normalized_total (not ulpf_events_parsed_total) is "this
        # event was fully, authoritatively parsed and mapped to OCSF": the
        # latter only counts ParseStage's advisory *sniff* pass, which has no
        # grok/dissect signature at all (see ParseStage's own docstring in
        # ulpf/core/pipeline.py) - for a grok-based source like cisco_asa it
        # would read as ~0% "parsed" even when every single line is matched
        # and normalized correctly by NormalizeStage right after it.
        parsed = after.sum_counter("ulpf_events_normalized_total") - before.sum_counter(
            "ulpf_events_normalized_total"
        )
        dlq = after.sum_counter("ulpf_dead_letter_total") - before.sum_counter(
            "ulpf_dead_letter_total"
        )
        if received > 0:
            parse_coverage = parsed / received
            dlq_rate = dlq / received
            outstanding = received - parsed - dlq
            if outstanding > max(1.0, received * 0.02):
                # Not a parsing problem: these events simply had not reached
                # NormalizeStage (or the DLQ) yet when the "after" snapshot
                # was taken - the pipeline fell behind the offered rate
                # during this window. parse_coverage/dlq_rate below reflect
                # that backlog, not necessarily malformed input.
                backlog_note = (
                    f"{outstanding:,.0f} received events had not finished parsing/"
                    "normalizing by the end of the window - the pipeline fell behind "
                    "the offered rate (see parse_coverage/dlq_rate caveat)"
                )

        buckets = diff_histogram_buckets(
            before.histogram_buckets("ulpf_end_to_end_latency_seconds"),
            after.histogram_buckets("ulpf_end_to_end_latency_seconds"),
        )
        latency_samples = int(
            after.histogram_count("ulpf_end_to_end_latency_seconds")
            - before.histogram_count("ulpf_end_to_end_latency_seconds")
        )
        p50, p95, p99 = (
            (q * 1000 if q is not None else None)
            for q in (
                histogram_quantile(buckets, 0.50),
                histogram_quantile(buckets, 0.95),
                histogram_quantile(buckets, 0.99),
            )
        )

        comp_count = after.histogram_count(
            "ulpf_normalization_completeness"
        ) - before.histogram_count("ulpf_normalization_completeness")
        if comp_count > 0:
            comp_sum = after.histogram_sum(
                "ulpf_normalization_completeness"
            ) - before.histogram_sum("ulpf_normalization_completeness")
            completeness_mean = comp_sum / comp_count

    enrichment_enabled = None
    integrity_active = integrity_off_reason = None
    if health is not None:
        enrichers = health.get("enrichers") or []
        enrichment_enabled = any(bool(e.get("enabled")) for e in enrichers) if enrichers else False
        integrity = health.get("integrity") or {}
        integrity_active = integrity.get("active")
        integrity_off_reason = integrity.get("off_reason")

    return BenchReport(
        transport=transport,
        target_rate=target_rate,
        warmup_s=warmup_s,
        requested_duration_s=requested_duration_s,
        measured_duration_s=phase.elapsed_s,
        sent=phase.sent,
        achieved_eps=phase.sent / phase.elapsed_s if phase.elapsed_s > 0 else 0.0,
        latency_p50_ms=p50,
        latency_p95_ms=p95,
        latency_p99_ms=p99,
        latency_samples=latency_samples,
        parse_coverage=parse_coverage,
        dlq_rate=dlq_rate,
        backlog_note=backlog_note,
        normalization_completeness_mean=completeness_mean,
        peak_server_rss_bytes=peak_rss,
        rss_note=rss_note,
        cpu_model=hardware.cpu_model,
        cpu_cores=hardware.cpu_cores,
        ram_bytes=hardware.ram_bytes,
        enrichment_enabled=enrichment_enabled,
        integrity_active=integrity_active,
        integrity_off_reason=integrity_off_reason,
        server_reachable=before is not None and after is not None,
    )


# ======================================================================
# rendering
# ======================================================================


def _fmt_pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def _fmt_ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f} ms"


def _fmt_bytes(value: int | None) -> str:
    if value is None:
        return "n/a"
    scaled = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if scaled < 1024:
            return f"{scaled:.1f} {unit}"
        scaled /= 1024
    return f"{scaled:.1f} PB"


def render_report(report: BenchReport) -> str:
    lines = [
        f"transport={report.transport}  "
        f"target_rate={'max' if report.target_rate is None else f'{report.target_rate:.0f} eps'}  "
        f"warmup={report.warmup_s:.0f}s  window={report.measured_duration_s:.1f}s "
        f"(requested {report.requested_duration_s:.0f}s)",
        "",
        f"  sent                       : {report.sent:,}",
        f"  achieved sustained EPS     : {report.achieved_eps:,.1f}",
        f"  latency p50 / p95 / p99    : {_fmt_ms(report.latency_p50_ms)} / "
        f"{_fmt_ms(report.latency_p95_ms)} / {_fmt_ms(report.latency_p99_ms)} "
        f"(n={report.latency_samples:,})",
        f"  parse coverage             : {_fmt_pct(report.parse_coverage)}",
        f"  DLQ rate                   : {_fmt_pct(report.dlq_rate)}",
        *([f"    note: {report.backlog_note}"] if report.backlog_note else []),
        f"  normalization completeness : {_fmt_pct(report.normalization_completeness_mean)}",
        "  peak server RSS            : "
        + (
            _fmt_bytes(report.peak_server_rss_bytes) if report.rss_note is None else report.rss_note
        ),
        "",
        "hardware: "
        f"CPU: {report.cpu_model} ({report.cpu_cores} cores)  "
        f"RAM: {_fmt_bytes(report.ram_bytes)}  "
        f"enrichment: {'on' if report.enrichment_enabled else 'off'}  "
        f"integrity: {'on' if report.integrity_active else 'off'}"
        + (
            f" ({report.integrity_off_reason})"
            if not report.integrity_active and report.integrity_off_reason
            else ""
        ),
    ]
    if not report.server_reachable:
        lines.append("")
        lines.append(
            "WARNING: the management API (/metrics, /health) was not reachable - "
            "server-side numbers above are unavailable."
        )
    return "\n".join(lines)


# ======================================================================
# CLI
# ======================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay a sample log file at a controlled rate and report real performance.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--file", required=True, type=Path, help="Sample file to replay (one line per event)."
    )
    parser.add_argument("--transport", required=True, choices=["udp", "tcp", "http"])
    parser.add_argument(
        "--rate", type=float, default=1000.0, help="Target sustained events/second."
    )
    parser.add_argument(
        "--max-rate", action="store_true", help="Ignore --rate; send as fast as possible."
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=_DEFAULT_MIN_DURATION_S,
        help="Measurement window, seconds.",
    )
    parser.add_argument(
        "--allow-short-duration",
        action="store_true",
        help=f"Allow --duration below the required minimum ({_DEFAULT_MIN_DURATION_S:.0f}s).",
    )
    parser.add_argument(
        "--warmup",
        type=float,
        default=_DEFAULT_WARMUP_S,
        help="Warm-up seconds, excluded from measurement.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Where the listener is bound.")
    parser.add_argument(
        "--port", type=int, default=None, help="Listener port (default: 514 udp/tcp, 8081 http)."
    )
    parser.add_argument(
        "--api-base-url",
        default="http://127.0.0.1:8080",
        help="The management API base URL (/metrics, /health).",
    )
    parser.add_argument(
        "--server-pid", type=int, default=None, help="ULPF server PID, to sample peak RSS."
    )
    parser.add_argument("--rss-poll-interval", type=float, default=0.5)
    parser.add_argument(
        "--loop", action="store_true", help="Loop the file if it runs out before the window ends."
    )
    parser.add_argument(
        "--http-batch-size", type=int, default=500, help="Lines per HTTP POST /ingest/raw."
    )
    parser.add_argument(
        "--tcp-batch-bytes", type=int, default=65536, help="Frame buffering threshold for TCP."
    )
    parser.add_argument(
        "--source-id", default=None, help="source_id query param for --transport http."
    )
    parser.add_argument("--json", action="store_true", help="Machine-readable report.")
    parser.add_argument(
        "--out", type=Path, default=None, help="Also write the JSON report to this file."
    )
    return parser


def _load_lines(path: Path) -> list[bytes]:
    data = path.read_bytes()
    return [line for line in data.split(b"\n") if line.strip()]


def run_benchmark(
    config: BenchmarkConfig, *, lines: Sequence[bytes] | None = None, quiet: bool = False
) -> BenchReport:
    """Warm up, measure, and report against an already-running ``ulpf serve``.

    This is the one method both :func:`main` (one ad-hoc run) and
    :mod:`bench.report` (a whole matrix of runs) use, so a single replay and
    one cell of the benchmark matrix are always measured identically.

    Args:
        config: Everything :func:`main` would otherwise take from argv.
        lines: Pre-loaded replay lines, to avoid re-reading ``config.file``
            once per matrix cell that reuses the same source file.
        quiet: Suppress the progress/warning lines this normally prints to
            stderr (bench/report.py runs many of these back to back).

    Raises:
        ValueError: ``config.duration`` is below the required minimum and
            ``config.allow_short_duration`` is not set, or the replay file
            has no lines.
    """
    if config.duration < _DEFAULT_MIN_DURATION_S and not config.allow_short_duration:
        raise ValueError(
            f"duration {config.duration:.0f}s is below the required minimum "
            f"({_DEFAULT_MIN_DURATION_S:.0f}s) - a shorter window is dominated by noise, not "
            "signal. Set allow_short_duration=True to override for quick local iteration."
        )

    def _log(message: str) -> None:
        if not quiet:
            print(message, file=sys.stderr)

    port = config.port if config.port is not None else _DEFAULT_PORTS[config.transport]
    rate = None if config.max_rate else config.rate
    hardware = Hardware.detect()

    if lines is None:
        _log(f"loading {config.file} ...")
        lines = _load_lines(config.file)
        _log(f"  {len(lines):,} lines loaded")
    if not lines:
        raise ValueError(f"no non-blank lines to replay (file: {config.file})")

    rss_sampler: RssSampler | None = None
    if config.server_pid is not None:
        rss_sampler = RssSampler(config.server_pid, interval_s=config.rss_poll_interval)
        rss_sampler.start()

    metrics_client = httpx.Client()
    health = fetch_health(metrics_client, config.api_base_url)
    if health is None:
        _log(
            f"WARNING: could not reach {config.api_base_url}/health - hardware/enrichment/"
            "integrity reporting will be incomplete, and if /metrics is also unreachable "
            "server-side numbers cannot be computed at all."
        )

    sender = build_sender(config.transport, config.host, port, config)
    try:
        _log(f"warm-up: {config.warmup:.0f}s @ {'max rate' if rate is None else f'{rate:.0f} eps'}")
        _, next_idx = run_phase(
            sender, lines, rate=rate, duration_s=config.warmup, loop_source=config.loop
        )

        time.sleep(_SETTLE_S)  # let in-flight warm-up events drain before the "before" snapshot
        before = _try_fetch_metrics(metrics_client, config.api_base_url, quiet=quiet)

        _log(
            f"measuring: {config.duration:.0f}s @ "
            f"{'max rate' if rate is None else f'{rate:.0f} eps'}"
        )
        phase, _ = run_phase(
            sender,
            lines,
            rate=rate,
            duration_s=config.duration,
            loop_source=config.loop,
            start_index=next_idx,
        )

        time.sleep(
            _SETTLE_S
        )  # let the tail of the measurement window drain before the "after" snapshot
        after = _try_fetch_metrics(metrics_client, config.api_base_url, quiet=quiet)
    finally:
        sender.close()
        peak_rss = rss_sampler.stop() if rss_sampler is not None else None
        rss_note = None
        if config.server_pid is None:
            rss_note = "not measured (pass --server-pid)"
        elif rss_sampler is not None and rss_sampler.error:
            rss_note = rss_sampler.error
        metrics_client.close()

    if rate is not None and phase.sent < config.rate * config.duration * 0.5:
        _log(
            f"WARNING: only sent {phase.sent:,} of the ~{rate * config.duration:,.0f} events the "
            "target rate implied - the file may be too short (pass loop=True) or the sender "
            "fell behind schedule."
        )

    return compute_report(
        transport=config.transport,
        target_rate=rate,
        warmup_s=config.warmup,
        requested_duration_s=config.duration,
        phase=phase,
        before=before,
        after=after,
        health=health,
        peak_rss=peak_rss,
        rss_note=rss_note,
        hardware=hardware,
    )


def _try_fetch_metrics(
    client: httpx.Client, base_url: str, *, quiet: bool = False
) -> MetricsSnapshot | None:
    try:
        return fetch_metrics(client, base_url)
    except httpx.HTTPError as exc:
        if not quiet:
            print(f"WARNING: could not scrape {base_url}/metrics: {exc}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if not args.file.is_file():
        parser.error(f"--file not found: {args.file}")
    if args.duration < _DEFAULT_MIN_DURATION_S and not args.allow_short_duration:
        parser.error(
            f"--duration {args.duration:.0f}s is below the required minimum "
            f"({_DEFAULT_MIN_DURATION_S:.0f}s) - a shorter window is dominated by noise, not "
            "signal. Pass --allow-short-duration to override for quick local iteration."
        )

    config = BenchmarkConfig(
        file=args.file,
        transport=args.transport,
        host=args.host,
        port=args.port,
        rate=args.rate,
        max_rate=args.max_rate,
        duration=args.duration,
        allow_short_duration=args.allow_short_duration,
        warmup=args.warmup,
        api_base_url=args.api_base_url,
        server_pid=args.server_pid,
        rss_poll_interval=args.rss_poll_interval,
        loop=args.loop,
        http_batch_size=args.http_batch_size,
        tcp_batch_bytes=args.tcp_batch_bytes,
        source_id=args.source_id,
    )
    try:
        report = run_benchmark(config)
    except ValueError as exc:
        parser.error(str(exc))
        return  # pragma: no cover - parser.error() always raises SystemExit

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_report(report))
    if args.out is not None:
        args.out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
