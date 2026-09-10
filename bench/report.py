#!/usr/bin/env python
"""Run a benchmark matrix and write a markdown report — the numbers for Slide 4.

    python bench/report.py --out docs/benchmarks.md

For each cell of the matrix below, this script: generates a sample file for
that source (:mod:`bench.generate`), starts a fresh, isolated ``ulpf serve``
subprocess configured exactly for that cell (worker count, integrity on/off,
enrichment on/off — real env-var overrides, not a simulation), runs one
:func:`bench.replay.run_benchmark` measurement against it (the *same*
warm-up/measure/settle/server-metrics-delta method ``bench/replay.py`` uses
for a single ad-hoc run), then stops that server before starting the next
cell. Every number in the report is therefore a real measurement of a real
``ulpf serve`` process on this machine — nothing here is simulated or
back-of-envelope, except the one clearly-labeled arithmetic comparison in the
headline section.

THE MATRIX
-----------
* **Per source type, at 1 and 4 workers** (``--workers``) — the main
  throughput table, one row per (source, worker count), integrity and
  enrichment both on (a realistic default deployment).
* **Integrity on vs. off** — held on one representative source
  (``--representative-source``, default ``cisco_asa``) at
  ``--overhead-workers`` (default 4), to isolate and report the signed
  Merkle ledger's overhead in throughput/latency/memory.
* **Enrichment on vs. off** — same shape, isolating the enrichment chain's
  (GeoIP/threat-intel/ATT&CK-tagging/network-context) cost.

A cell that already appears in the main table (e.g. the representative
source's default integrity-on/enrichment-on row) is measured once and reused
— it is not re-run for the overhead tables.

WHY THIS MATTERS ENOUGH TO SAY TWICE (see the Caveats section in the
generated report too): every number here comes from ONE machine running ONE
``ulpf serve`` process talking to itself over loopback. That is a real,
honest measurement of single-node behavior — and precisely because it is
real, it is also precisely NOT a cluster measurement. Extrapolating a
single-node number into a cluster capacity claim is not something this
script does, and nothing it produces should be used to do that either.
"""

from __future__ import annotations

import argparse
import contextlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import httpx

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))  # so `python bench/report.py` finds the bench package

from bench import generate as bg  # noqa: E402 - see sys.path.insert above
from bench import replay as rp  # noqa: E402
from ulpf.integrity.signing import KeyPaths, generate_keypair  # noqa: E402

_EVENTS_PER_DAY_TARGET = 1_000_000_000
_SECONDS_PER_DAY = 86_400


# ======================================================================
# the matrix
# ======================================================================


@dataclass(frozen=True)
class MatrixCell:
    """One (source, worker count, integrity, enrichment) combination to measure."""

    source: str
    workers: int
    integrity: bool
    enrichment: bool


def build_matrix(
    *,
    sources: Sequence[str],
    workers_list: Sequence[int],
    representative_source: str,
    overhead_workers: int,
) -> list[MatrixCell]:
    """The full, de-duplicated list of cells this run needs.

    Execution order matters here, not just content: the integrity/enrichment
    overhead comparison reports a percentage delta between two cells, and
    that delta is only trustworthy if system state (thermal throttling, disk
    cache, background GC) hasn't drifted between them. So the representative
    source's own baseline cell is deliberately scheduled *last* among the
    main-table cells, immediately before the off-variant cells it is
    compared against - the whole overhead group runs back-to-back rather
    than being split apart by many minutes of unrelated cells in between.
    """
    cells: list[MatrixCell] = []
    seen: set[MatrixCell] = set()

    def add(cell: MatrixCell) -> None:
        if cell not in seen:
            seen.add(cell)
            cells.append(cell)

    for source in sources:
        if source == representative_source:
            continue  # scheduled last, adjacent to the overhead group below
        for workers in workers_list:
            add(MatrixCell(source, workers, True, True))
    if representative_source in sources:
        for workers in workers_list:
            if workers == overhead_workers:
                continue  # this is the overhead group's baseline - added next
            add(MatrixCell(representative_source, workers, True, True))
    add(MatrixCell(representative_source, overhead_workers, True, True))
    add(MatrixCell(representative_source, overhead_workers, False, True))
    add(MatrixCell(representative_source, overhead_workers, True, False))
    return cells


# ======================================================================
# server lifecycle - a real, isolated `ulpf serve` subprocess per cell
# ======================================================================


@dataclass
class ServerHandle:
    process: subprocess.Popen
    api_base_url: str
    pid: int


def start_server(
    *,
    workers: int,
    integrity_enabled: bool,
    enrichment_enabled: bool,
    api_port: int,
    udp_port: int,
    tcp_port: int,
    http_port: int,
    storage_dir: Path,
    sources_dir: Path,
    keys: KeyPaths | None,
    log_path: Path,
    startup_timeout_s: float,
) -> ServerHandle:
    """Launch ``ulpf serve`` with this cell's exact configuration; block until healthy."""
    import os

    env = os.environ.copy()
    env["ULPF_API__PORT"] = str(api_port)
    env["ULPF_INGEST__SYSLOG_UDP_PORT"] = str(udp_port)
    env["ULPF_INGEST__SYSLOG_TCP_PORT"] = str(tcp_port)
    env["ULPF_INGEST__HTTP_PORT"] = str(http_port)
    env["ULPF_STORAGE__BRONZE_PATH"] = str(storage_dir / "bronze")
    env["ULPF_STORAGE__SILVER_PATH"] = str(storage_dir / "silver")
    env["ULPF_STORAGE__DLQ_PATH"] = str(storage_dir / "dlq")
    env["ULPF_STORAGE__LEDGER_PATH"] = str(storage_dir / "ledger")
    env["ULPF_STORAGE__STATE_PATH"] = str(storage_dir / "state")
    env["ULPF_PARSE__SOURCES_DIR"] = str(sources_dir)
    env["ULPF_ENRICH__ENABLED"] = "true" if enrichment_enabled else "false"
    env["ULPF_INTEGRITY__ENABLED"] = "true" if integrity_enabled and keys is not None else "false"
    if integrity_enabled and keys is not None:
        env["ULPF_INTEGRITY__SIGNING_KEY_PATH"] = str(keys.private)
        env["ULPF_INTEGRITY__PUBLIC_KEY_PATH"] = str(keys.public)

    cmd = [
        sys.executable,
        "-m",
        "ulpf.cli.main",
        "serve",
        "--host",
        "127.0.0.1",
        "--port",
        str(api_port),
        "--workers",
        str(workers),
    ]
    # On Windows a new process group is required to later send CTRL_BREAK_EVENT
    # for a graceful shutdown (plain terminate() there is a hard kill with no
    # chance for Runtime.stop() to flush anything).
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        cmd,
        env=env,
        cwd=str(_REPO_ROOT),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    api_base_url = f"http://127.0.0.1:{api_port}"
    try:
        _wait_until_healthy(process, api_base_url, timeout_s=startup_timeout_s)
    except Exception:
        _force_kill(process)
        raise
    return ServerHandle(process=process, api_base_url=api_base_url, pid=process.pid)


def _wait_until_healthy(process: subprocess.Popen, api_base_url: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    with httpx.Client() as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"ulpf serve exited during startup (exit code {process.returncode})"
                )
            try:
                if client.get(f"{api_base_url}/health", timeout=1.0).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
    raise RuntimeError(f"ulpf serve did not become healthy within {timeout_s:.0f}s")


def stop_server(handle: ServerHandle, *, timeout_s: float = 10.0) -> None:
    """Ask ``ulpf serve`` to shut down gracefully; escalate to a hard kill if it won't."""
    if handle.process.poll() is not None:
        return
    if sys.platform == "win32":
        handle.process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        handle.process.terminate()
    try:
        handle.process.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _force_kill(handle.process)


def _force_kill(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):  # pragma: no cover - last-resort only
            process.wait(timeout=5.0)


# ======================================================================
# running one cell
# ======================================================================


def _default_sample_count(rate: float, warmup_s: float, duration_s: float) -> int:
    """Enough lines that no cell has to loop the file to reach its target rate."""
    return max(2000, int(rate * (warmup_s + duration_s) * 1.5))


def generate_sample_file(source: str, count: int, seed: int, out_path: Path) -> None:
    bg.main(
        [
            "--source",
            source,
            "--count",
            str(count),
            "--out",
            str(out_path),
            "--seed",
            str(seed),
            "--progress-every",
            "0",
        ]
    )


def run_cell(
    cell: MatrixCell,
    *,
    lines: list[bytes],
    ports: dict[str, int],
    transport: str,
    rate: float,
    duration_s: float,
    warmup_s: float,
    sources_dir: Path,
    keys: KeyPaths | None,
    scratch_dir: Path,
    cell_index: int,
    startup_timeout_s: float,
) -> rp.BenchReport:
    """Start an isolated server for `cell`, measure it, tear it down."""
    handle = start_server(
        workers=cell.workers,
        integrity_enabled=cell.integrity,
        enrichment_enabled=cell.enrichment,
        api_port=ports["api"],
        udp_port=ports["udp"],
        tcp_port=ports["tcp"],
        http_port=ports["http"],
        storage_dir=scratch_dir / "data" / f"cell-{cell_index}",
        sources_dir=sources_dir,
        keys=keys,
        log_path=scratch_dir / "logs" / f"cell-{cell_index}.log",
        startup_timeout_s=startup_timeout_s,
    )
    try:
        config = rp.BenchmarkConfig(
            file=scratch_dir / f"{cell.source}.log",  # documentation only; lines= is already loaded
            transport=transport,
            host="127.0.0.1",
            port=ports[transport],
            rate=rate,
            max_rate=False,
            duration=duration_s,
            allow_short_duration=True,
            warmup=warmup_s,
            api_base_url=handle.api_base_url,
            server_pid=handle.pid,
        )
        return rp.run_benchmark(config, lines=lines, quiet=True)
    finally:
        stop_server(handle)


# ======================================================================
# rendering
# ======================================================================


def _fmt_eps(value: float | None) -> str:
    return "n/a" if value is None else f"{value:,.0f}"


def processed_eps(report: rp.BenchReport | None) -> float | None:
    """Events/sec the *server* actually finished normalizing, not just what was sent.

    ``report.achieved_eps`` is the send-side rate; multiplying by
    ``parse_coverage`` (the fraction of received events the server fully
    processed within the window) gives the honest server-throughput figure —
    see :mod:`bench.replay`'s ``BenchReport`` docstring for why the two can
    diverge under backlog.
    """
    if report is None or report.parse_coverage is None:
        return None
    return report.achieved_eps * report.parse_coverage


def _pct_change(baseline: float | None, variant: float | None) -> float | None:
    """``(variant - baseline) / baseline`` as a percentage; `None` if an input is missing/zero."""
    if baseline is None or variant is None or baseline == 0:
        return None
    return (variant - baseline) / baseline * 100.0


def _main_table(
    results: dict[MatrixCell, rp.BenchReport | None],
    sources: Sequence[str],
    workers_list: Sequence[int],
) -> str:
    header = (
        "| source | workers | offered EPS | achieved EPS | processed EPS | "
        "p50 | p95 | p99 | parse coverage | completeness | peak RSS | notes |"
    )
    sep = "|---|---|---|---|---|---|---|---|---|---|---|---|"
    rows = [header, sep]
    for source in sources:
        for workers in workers_list:
            report = results.get(MatrixCell(source, workers, True, True))
            rows.append(_main_row(source, workers, report))
    return "\n".join(rows)


def _main_row(source: str, workers: int, report: rp.BenchReport | None) -> str:
    if report is None:
        return f"| {source} | {workers} | - | - | - | - | - | - | - | - | - | not run (see logs) |"
    note = (
        "backlog" if report.backlog_note else ("unreachable" if not report.server_reachable else "")
    )
    completeness = rp._fmt_pct(report.normalization_completeness_mean)
    return (
        f"| {source} | {workers} | {report.target_rate or 0:.0f} | {report.achieved_eps:,.0f} | "
        f"{_fmt_eps(processed_eps(report))} | {rp._fmt_ms(report.latency_p50_ms)} | "
        f"{rp._fmt_ms(report.latency_p95_ms)} | {rp._fmt_ms(report.latency_p99_ms)} | "
        f"{rp._fmt_pct(report.parse_coverage)} | {completeness} | "
        f"{rp._fmt_bytes(report.peak_server_rss_bytes)} | {note} |"
    )


def _overhead_section(
    title: str,
    axis: str,
    off_report: rp.BenchReport | None,
    on_report: rp.BenchReport | None,
    *,
    off_label: str,
    on_label: str,
) -> str:
    header = (
        "| "
        + axis
        + " | achieved EPS | processed EPS | p50 | p95 | p99 | parse coverage | peak RSS |"
    )
    sep = "|---|---|---|---|---|---|---|---|"

    def row(label: str, report: rp.BenchReport | None) -> str:
        if report is None:
            return f"| {label} | - | - | - | - | - | - | - |"
        return (
            f"| {label} | {report.achieved_eps:,.0f} | {_fmt_eps(processed_eps(report))} | "
            f"{rp._fmt_ms(report.latency_p50_ms)} | {rp._fmt_ms(report.latency_p95_ms)} | "
            f"{rp._fmt_ms(report.latency_p99_ms)} | {rp._fmt_pct(report.parse_coverage)} | "
            f"{rp._fmt_bytes(report.peak_server_rss_bytes)} |"
        )

    lines = [
        f"### {title}",
        "",
        header,
        sep,
        row(off_label, off_report),
        row(on_label, on_report),
        "",
    ]

    throughput_pct = _pct_change(processed_eps(off_report), processed_eps(on_report))
    lat_pct = _pct_change(
        off_report.latency_p95_ms if off_report else None,
        on_report.latency_p95_ms if on_report else None,
    )
    rss_pct = _pct_change(
        off_report.peak_server_rss_bytes if off_report else None,
        on_report.peak_server_rss_bytes if on_report else None,
    )
    if throughput_pct is not None:
        lines.append(f"- **throughput**: {throughput_pct:+.1f}% with {axis} on (vs. off)")
    if lat_pct is not None:
        lines.append(f"- **p95 latency**: {lat_pct:+.1f}% with {axis} on (vs. off)")
    if rss_pct is not None:
        lines.append(f"- **peak RSS**: {rss_pct:+.1f}% with {axis} on (vs. off)")
    if throughput_pct is None and lat_pct is None:
        lines.append("- not enough data to compute an overhead figure (see notes above)")
    lines.append("")
    return "\n".join(lines)


def _headline_section(results: dict[MatrixCell, rp.BenchReport | None], events_per_day: int) -> str:
    required_eps = events_per_day / _SECONDS_PER_DAY
    best_cell: MatrixCell | None = None
    best_eps = -1.0
    for cell, report in results.items():
        eps = processed_eps(report)
        if eps is not None and eps > best_eps:
            best_eps = eps
            best_cell = cell

    lines = [
        "## Headline: throughput vs. a 1-billion-events/day target",
        "",
        f"A perimeter deployment ingesting **{events_per_day:,} events/day** needs to sustain, "
        "on average:",
        "",
        f"    {events_per_day:,} events / {_SECONDS_PER_DAY:,} seconds/day "
        f"= {required_eps:,.0f} events/second, sustained",
        "",
    ]
    if best_cell is not None and best_eps > 0:
        ratio = best_eps / required_eps
        direction = "above" if ratio >= 1 else "below"
        ratio_str = f"{ratio:.2f}x" if ratio >= 0.01 else f"{ratio:.4f}x"
        lines += [
            f"The best single-node **processed** throughput measured in this run was "
            f"**{best_eps:,.0f} events/sec** (`{best_cell.source}` @ {best_cell.workers} "
            f"worker{'s' if best_cell.workers != 1 else ''}, integrity "
            f"{'on' if best_cell.integrity else 'off'}, enrichment "
            f"{'on' if best_cell.enrichment else 'off'}) — "
            f"**{ratio_str}** {direction} the {required_eps:,.0f} eps a 1B-events/day workload "
            "requires from a single node.",
            "",
            "This says only that *one node, measured this way, on this machine* clears (or "
            "doesn't) that bar — see [Caveats](#caveats) for exactly what it does not say.",
            "",
        ]
    else:
        lines += ["No successful measurement was available to compare against this target.", ""]
    return "\n".join(lines)


_CAVEATS = """\
## Caveats

**Read this before this report goes anywhere near a capacity plan.**

- **Single-node only.** Every number above came from one machine running one
  `ulpf serve` process, measured by sending traffic to it over loopback on the
  same machine. No cluster, no multi-node deployment, no horizontal fan-out,
  no network hop between the sender and the listener was tested here.
- **Never extrapolate to a cluster.** "This node did N events/sec, so a
  10-node cluster would do 10N" is not a claim this report makes or supports.
  Real cluster throughput depends on partitioning, network overhead,
  coordination, shared-resource contention (a shared Kafka broker, a shared
  ClickHouse cluster, a shared object store) and failure handling that a
  single loopback process cannot exercise at all. Cluster figures have not
  been tested.
- **The measurement window is short.** See Method below for the exact
  duration used; a short window is noisier than a full production-length
  soak test and is more exposed to warm-up residue, GC pauses, and other
  machines' background load than a long-running measurement would be.
- **This machine, this moment.** CPU, RAM, disk, background load, the Python
  interpreter build, and the exact versions of every dependency at capture
  time all affect these numbers. Re-running this script on different
  hardware, or after a dependency upgrade, can and will produce different
  numbers — that is expected, not a bug in the method.
- **The target rate is a fixed offer, not an auto-tuned ceiling.** Rows
  marked "backlog" in the tables above mean the offered rate exceeded what
  that configuration could sustain within the window; the "processed EPS"
  and "parse coverage" columns make that visible rather than reporting an
  inflated raw send rate as if it were absorbed capacity.
"""


def _method_section(args: argparse.Namespace, elapsed_s: float, cell_count: int) -> str:
    return (
        "## Method\n\n"
        f"- transport: `{args.transport}`; target rate: `{args.rate:.0f}` events/sec (paced, not "
        "blasted - see bench/replay.py)\n"
        f"- warm-up: `{args.warmup:.0f}s` (excluded from measurement); measurement window: "
        f"`{args.duration:.0f}s` per cell\n"
        "- every reported figure is a *delta* between two `/metrics` scrapes of the server's own "
        "Prometheus counters/histograms, taken before and after the measurement window - not "
        "estimated or computed client-side\n"
        "- latency percentiles: linear interpolation over `ulpf_end_to_end_latency_seconds`'s "
        "histogram buckets (Prometheus's own `histogram_quantile()` method), from ingest "
        "timestamp to the event finishing its last pipeline stage\n"
        "- peak RSS: sampled from the `ulpf serve` process every 0.5s for the whole cell "
        "(`psutil`)\n"
        "- each cell ran in its own freshly-started, isolated `ulpf serve` subprocess (own "
        f"bronze/silver/DLQ/ledger/state directories); matrix total wall-clock time: "
        f"{elapsed_s:.0f}s ({elapsed_s / 60:.1f} min) for {cell_count} cells\n"
        "- integrity-on cells used a throwaway Ed25519 keypair generated for this run only\n"
    )


def render_markdown(
    *,
    results: dict[MatrixCell, rp.BenchReport | None],
    sources: Sequence[str],
    workers_list: Sequence[int],
    representative_source: str,
    overhead_workers: int,
    args: argparse.Namespace,
    hardware: rp.Hardware,
    reproduce_cmd: str,
    elapsed_s: float,
) -> str:
    generated_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    integrity_off = results.get(MatrixCell(representative_source, overhead_workers, False, True))
    integrity_on = results.get(MatrixCell(representative_source, overhead_workers, True, True))
    enrichment_off = results.get(MatrixCell(representative_source, overhead_workers, True, False))
    enrichment_on = results.get(MatrixCell(representative_source, overhead_workers, True, True))

    parts = [
        "# ULPF Perimeter Pipeline — Benchmark Report",
        "",
        f"_Generated {generated_at}. Reproduce with:_",
        "",
        "```",
        reproduce_cmd,
        "```",
        "",
        "> **Single-node measurements only — never extrapolate to a cluster.** "
        "See [Caveats](#caveats).",
        "",
        "## Hardware",
        "",
        "| | |",
        "|---|---|",
        f"| CPU | {hardware.cpu_model} ({hardware.cpu_cores} cores) |",
        f"| RAM | {rp._fmt_bytes(hardware.ram_bytes)} |",
        f"| OS | {_os_string()} |",
        "",
        _headline_section(results, args.events_per_day),
        f"## Per-source-type throughput ({', '.join(str(w) for w in workers_list)} workers)",
        "",
        f"Integrity: on · Enrichment: on · transport: `{args.transport}` · "
        f"target rate: `{args.rate:.0f}` eps · window: `{args.duration:.0f}s` "
        f"(+`{args.warmup:.0f}s` warm-up, excluded)",
        "",
        _main_table(results, sources, workers_list),
        "",
        "## Overhead of optional features",
        "",
        f"_Isolated on `{representative_source}` @ {overhead_workers} workers; one axis varied "
        "at a time from the same baseline._",
        "",
        _overhead_section(
            "Integrity (signed Merkle ledger)",
            "integrity",
            integrity_off,
            integrity_on,
            off_label="off",
            on_label="on",
        ),
        _overhead_section(
            "Enrichment (GeoIP / threat-intel / ATT&CK tagging / network context)",
            "enrichment",
            enrichment_off,
            enrichment_on,
            off_label="off",
            on_label="on",
        ),
        _CAVEATS,
        _method_section(args, elapsed_s, len(results)),
    ]
    return "\n".join(parts) + "\n"


def _os_string() -> str:
    import platform

    return f"{platform.system()} {platform.release()} ({platform.machine()})"


# ======================================================================
# CLI
# ======================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a benchmark matrix (source x workers x integrity x enrichment) and "
        "write a markdown report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--out", type=Path, default=Path("docs/benchmarks.md"))
    parser.add_argument(
        "--sources", default=",".join(sorted(bg.ALL_SOURCES)), help="Comma-separated source names."
    )
    parser.add_argument("--workers", default="1,4", help="Comma-separated worker counts.")
    parser.add_argument("--representative-source", default="cisco_asa")
    parser.add_argument("--overhead-workers", type=int, default=4)
    parser.add_argument("--transport", choices=["udp", "tcp", "http"], default="udp")
    parser.add_argument(
        "--rate", type=float, default=200.0, help="Target sustained events/second per cell."
    )
    parser.add_argument(
        "--duration", type=float, default=20.0, help="Measurement window per cell, seconds."
    )
    parser.add_argument(
        "--warmup", type=float, default=5.0, help="Warm-up seconds per cell, excluded."
    )
    parser.add_argument(
        "--sample-count",
        type=int,
        default=None,
        help="Lines per source file (auto-sized if unset).",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--api-port", type=int, default=18080)
    parser.add_argument("--udp-port", type=int, default=15514)
    parser.add_argument("--tcp-port", type=int, default=15514)
    parser.add_argument("--http-port", type=int, default=15081)
    parser.add_argument("--startup-timeout", type=float, default=20.0)
    parser.add_argument("--scratch-dir", type=Path, default=None)
    parser.add_argument(
        "--keep-scratch", action="store_true", help="Don't delete the scratch directory afterward."
    )
    parser.add_argument(
        "--events-per-day",
        type=int,
        default=_EVENTS_PER_DAY_TARGET,
        help="Headline throughput target.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    workers_list = [int(w.strip()) for w in args.workers.split(",") if w.strip()]
    for name in [*sources, args.representative_source]:
        if name not in bg.ALL_SOURCES:
            parser.error(f"unknown source {name!r}; known: {', '.join(sorted(bg.ALL_SOURCES))}")

    scratch = args.scratch_dir or Path(tempfile.mkdtemp(prefix="ulpf-bench-report-"))
    scratch.mkdir(parents=True, exist_ok=True)
    print(f"scratch dir: {scratch}", file=sys.stderr)

    keys: KeyPaths | None = None
    try:
        keys = generate_keypair(scratch / "keys", overwrite=True)
    except Exception as exc:  # noqa: BLE001 - integrity-on cells simply won't run without this
        print(
            f"WARNING: could not generate a benchmark signing keypair ({exc}); "
            "integrity=on cells will be skipped",
            file=sys.stderr,
        )

    sample_count = args.sample_count or _default_sample_count(args.rate, args.warmup, args.duration)
    cells = build_matrix(
        sources=sources,
        workers_list=workers_list,
        representative_source=args.representative_source,
        overhead_workers=args.overhead_workers,
    )
    ports = {
        "api": args.api_port,
        "udp": args.udp_port,
        "tcp": args.tcp_port,
        "http": args.http_port,
    }
    sources_dir = _REPO_ROOT / "configs" / "sources"

    results: dict[MatrixCell, rp.BenchReport | None] = {}
    lines_by_source: dict[str, list[bytes]] = {}
    start = time.time()
    for index, cell in enumerate(cells, start=1):
        print(
            f"[{index}/{len(cells)}] {cell.source} workers={cell.workers} "
            f"integrity={'on' if cell.integrity else 'off'} "
            f"enrichment={'on' if cell.enrichment else 'off'}",
            file=sys.stderr,
        )
        if cell.integrity and keys is None:
            print("  skipped: no signing keypair available", file=sys.stderr)
            results[cell] = None
            continue
        if cell.source not in lines_by_source:
            sample_path = scratch / f"{cell.source}.log"
            generate_sample_file(cell.source, sample_count, args.seed, sample_path)
            lines_by_source[cell.source] = rp._load_lines(sample_path)
        try:
            results[cell] = run_cell(
                cell,
                lines=lines_by_source[cell.source],
                ports=ports,
                transport=args.transport,
                rate=args.rate,
                duration_s=args.duration,
                warmup_s=args.warmup,
                sources_dir=sources_dir,
                keys=keys if cell.integrity else None,
                scratch_dir=scratch,
                cell_index=index,
                startup_timeout_s=args.startup_timeout,
            )
        except Exception as exc:  # noqa: BLE001 - one bad cell must not sink the whole matrix
            print(f"  FAILED: {exc}", file=sys.stderr)
            results[cell] = None
        time.sleep(1.0)  # let the OS fully release this cell's ports before the next start_server

    elapsed = time.time() - start
    print(f"matrix complete in {elapsed:.0f}s ({elapsed / 60:.1f} min)", file=sys.stderr)

    hardware = rp.Hardware.detect()
    reproduce_cmd = "python bench/report.py " + " ".join(
        _shell_quote(a) for a in (argv or sys.argv[1:])
    )
    markdown = render_markdown(
        results=results,
        sources=sources,
        workers_list=workers_list,
        representative_source=args.representative_source,
        overhead_workers=args.overhead_workers,
        args=args,
        hardware=hardware,
        reproduce_cmd=reproduce_cmd or "python bench/report.py --out docs/benchmarks.md",
        elapsed_s=elapsed,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)

    if not args.keep_scratch:
        shutil.rmtree(scratch, ignore_errors=True)
    else:
        print(f"scratch dir kept: {scratch}", file=sys.stderr)


def _shell_quote(arg: str) -> str:
    return f'"{arg}"' if " " in arg else arg


if __name__ == "__main__":
    main()
