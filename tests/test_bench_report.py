"""Tests for bench/report.py.

The full matrix orchestration (spawning real `ulpf serve` subprocesses) is
exercised manually against a live server (see the module's own docstring and
CLAUDE.md's Windows-testing notes) rather than in the automated suite, which
would make every test run take many minutes and depend on free network
ports. These tests instead cover: the matrix-building/de-duplication logic,
report rendering (against hand-built `BenchReport` fixtures, no server
needed), the small pure-math helpers, CLI parsing/validation, and the
server-lifecycle primitives (`start_server`/`stop_server`/`_wait_until_healthy`)
against a trivial local HTTP server standing in for `ulpf serve`.
"""

from __future__ import annotations

import http.server
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from bench import replay as rp
from bench import report as r


def _make_report(
    *,
    achieved_eps: float = 200.0,
    parse_coverage: float | None = 0.98,
    p50: float | None = 5.0,
    p95: float | None = 12.0,
    p99: float | None = 20.0,
    peak_rss: int | None = 60_000_000,
    backlog_note: str | None = None,
    server_reachable: bool = True,
    integrity_active: bool | None = True,
    enrichment_enabled: bool | None = True,
) -> rp.BenchReport:
    return rp.BenchReport(
        transport="udp",
        target_rate=200.0,
        warmup_s=5.0,
        requested_duration_s=20.0,
        measured_duration_s=20.0,
        sent=4000,
        achieved_eps=achieved_eps,
        latency_p50_ms=p50,
        latency_p95_ms=p95,
        latency_p99_ms=p99,
        latency_samples=3900,
        parse_coverage=parse_coverage,
        dlq_rate=0.0,
        backlog_note=backlog_note,
        normalization_completeness_mean=0.95,
        peak_server_rss_bytes=peak_rss,
        rss_note=None,
        cpu_model="Test CPU",
        cpu_cores=8,
        ram_bytes=16_000_000_000,
        enrichment_enabled=enrichment_enabled,
        integrity_active=integrity_active,
        integrity_off_reason=None,
        server_reachable=server_reachable,
    )


# ======================================================================
# matrix building
# ======================================================================


def test_build_matrix_covers_every_source_and_worker_combination() -> None:
    cells = r.build_matrix(
        sources=["cisco_asa", "iptables"],
        workers_list=[1, 4],
        representative_source="cisco_asa",
        overhead_workers=4,
    )
    main_table_cells = {
        r.MatrixCell("cisco_asa", 1, True, True),
        r.MatrixCell("cisco_asa", 4, True, True),
        r.MatrixCell("iptables", 1, True, True),
        r.MatrixCell("iptables", 4, True, True),
    }
    assert main_table_cells.issubset(set(cells))


def test_build_matrix_includes_the_integrity_and_enrichment_overhead_cells() -> None:
    cells = set(
        r.build_matrix(
            sources=["cisco_asa"],
            workers_list=[1, 4],
            representative_source="cisco_asa",
            overhead_workers=4,
        )
    )
    assert r.MatrixCell("cisco_asa", 4, False, True) in cells  # integrity off
    assert r.MatrixCell("cisco_asa", 4, True, False) in cells  # enrichment off


def test_build_matrix_reuses_the_shared_baseline_cell_instead_of_duplicating_it() -> None:
    # cisco_asa @ 4 workers, integrity=on, enrichment=on is needed by the main
    # table AND as the "on" side of both overhead comparisons - it must appear
    # exactly once.
    cells = r.build_matrix(
        sources=["cisco_asa"],
        workers_list=[1, 4],
        representative_source="cisco_asa",
        overhead_workers=4,
    )
    shared = r.MatrixCell("cisco_asa", 4, True, True)
    assert cells.count(shared) == 1


def test_build_matrix_does_not_duplicate_a_representative_source_outside_the_main_table() -> None:
    # representative_source not in the requested sources list at all: its
    # baseline cell should appear exactly once, contributed by the overhead
    # comparisons, not doubled up.
    cells = r.build_matrix(
        sources=["iptables"],
        workers_list=[4],
        representative_source="cisco_asa",
        overhead_workers=4,
    )
    assert cells.count(r.MatrixCell("cisco_asa", 4, True, True)) == 1


def test_matrix_cell_is_hashable_and_usable_as_a_results_dict_key() -> None:
    cell = r.MatrixCell("cisco_asa", 4, True, True)
    d = {cell: _make_report()}
    assert d[r.MatrixCell("cisco_asa", 4, True, True)] is not None


# ======================================================================
# small pure helpers
# ======================================================================


def test_processed_eps_multiplies_achieved_rate_by_parse_coverage() -> None:
    report = _make_report(achieved_eps=100.0, parse_coverage=0.5)
    assert r.processed_eps(report) == 50.0


def test_processed_eps_is_none_when_report_or_coverage_is_missing() -> None:
    assert r.processed_eps(None) is None
    assert r.processed_eps(_make_report(parse_coverage=None)) is None


def test_pct_change_computes_signed_relative_delta() -> None:
    assert r._pct_change(100.0, 110.0) == pytest.approx(10.0)
    assert r._pct_change(100.0, 90.0) == pytest.approx(-10.0)


def test_pct_change_is_none_for_missing_or_zero_baseline() -> None:
    assert r._pct_change(None, 10.0) is None
    assert r._pct_change(10.0, None) is None
    assert r._pct_change(0.0, 10.0) is None


def test_default_sample_count_scales_with_rate_and_window_and_has_a_floor() -> None:
    assert r._default_sample_count(rate=200.0, warmup_s=5.0, duration_s=20.0) == int(200 * 25 * 1.5)
    assert r._default_sample_count(rate=0.001, warmup_s=0.0, duration_s=0.0) == 2000


# ======================================================================
# report rendering (no server needed)
# ======================================================================


class _FakeArgs:
    transport = "udp"
    rate = 200.0
    duration = 20.0
    warmup = 5.0
    events_per_day = 1_000_000_000


def _render(results: dict[r.MatrixCell, rp.BenchReport | None]) -> str:
    hardware = rp.Hardware(cpu_model="Test CPU", cpu_cores=8, ram_bytes=16_000_000_000)
    return r.render_markdown(
        results=results,
        sources=["cisco_asa"],
        workers_list=[1, 4],
        representative_source="cisco_asa",
        overhead_workers=4,
        args=_FakeArgs(),
        hardware=hardware,
        reproduce_cmd="python bench/report.py --out docs/benchmarks.md",
        elapsed_s=123.4,
    )


def test_render_markdown_includes_every_required_section() -> None:
    results = {
        r.MatrixCell("cisco_asa", 1, True, True): _make_report(achieved_eps=100.0),
        r.MatrixCell("cisco_asa", 4, True, True): _make_report(achieved_eps=390.0),
        r.MatrixCell("cisco_asa", 4, False, True): _make_report(achieved_eps=410.0, p95=10.0),
        r.MatrixCell("cisco_asa", 4, True, False): _make_report(achieved_eps=400.0, p95=11.0),
    }
    md = _render(results)
    assert "# ULPF Perimeter Pipeline" in md
    assert "## Hardware" in md
    assert "## Headline: throughput vs. a 1-billion-events/day target" in md
    assert "11,574 events/second" in md
    assert "## Per-source-type throughput" in md
    assert "### Integrity (signed Merkle ledger)" in md
    assert "### Enrichment" in md
    assert "## Caveats" in md
    assert "never extrapolate" in md.lower()
    assert "## Method" in md
    assert "python bench/report.py --out docs/benchmarks.md" in md


def test_render_markdown_reports_a_missing_cell_as_not_run_rather_than_omitting_the_row() -> None:
    results: dict[r.MatrixCell, rp.BenchReport | None] = {
        r.MatrixCell("cisco_asa", 1, True, True): None,
        r.MatrixCell("cisco_asa", 4, True, True): _make_report(),
    }
    md = _render(results)
    assert "not run" in md


def test_render_markdown_computes_a_signed_overhead_percentage() -> None:
    results = {
        r.MatrixCell("cisco_asa", 1, True, True): _make_report(),
        r.MatrixCell("cisco_asa", 4, True, True): _make_report(achieved_eps=200.0, p95=20.0),
        r.MatrixCell("cisco_asa", 4, False, True): _make_report(achieved_eps=250.0, p95=10.0),
        r.MatrixCell("cisco_asa", 4, True, False): _make_report(achieved_eps=200.0, p95=20.0),
    }
    md = _render(results)
    # integrity on (200 processed eps) vs off (250 processed eps): on is 20% slower.
    assert "-20.0% with integrity on" in md
    # p95 doubles from 10ms (off) to 20ms (on): +100%.
    assert "+100.0% with integrity on" in md


def test_render_markdown_flags_backlog_in_the_main_table_notes_column() -> None:
    results = {
        r.MatrixCell("cisco_asa", 1, True, True): _make_report(backlog_note="fell behind"),
        r.MatrixCell("cisco_asa", 4, True, True): _make_report(),
    }
    md = _render(results)
    assert "| backlog |" in md


def test_headline_section_picks_the_best_processed_throughput_across_all_cells() -> None:
    results = {
        r.MatrixCell("cisco_asa", 1, True, True): _make_report(
            achieved_eps=100.0, parse_coverage=1.0
        ),
        r.MatrixCell("cisco_asa", 4, True, True): _make_report(
            achieved_eps=500.0, parse_coverage=1.0
        ),
    }
    section = r._headline_section(results, events_per_day=1_000_000_000)
    assert "500 events/sec" in section
    assert "cisco_asa" in section
    assert "4 workers" in section


def test_headline_section_handles_no_successful_measurements() -> None:
    results: dict[r.MatrixCell, rp.BenchReport | None] = {
        r.MatrixCell("cisco_asa", 1, True, True): None,
    }
    section = r._headline_section(results, events_per_day=1_000_000_000)
    assert "No successful measurement" in section


# ======================================================================
# CLI
# ======================================================================


def test_build_arg_parser_defaults_match_the_task_spec() -> None:
    args = r.build_arg_parser().parse_args(["--out", "docs/benchmarks.md"])
    assert args.out == Path("docs/benchmarks.md")
    assert args.workers == "1,4"
    assert set(args.sources.split(",")) >= {"cisco_asa", "iptables", "aws_vpc_flow"}


def test_main_rejects_an_unknown_source(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        r.main(["--out", str(tmp_path / "out.md"), "--sources", "not_a_real_source"])


def test_main_rejects_an_unknown_representative_source(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        r.main(
            [
                "--out",
                str(tmp_path / "out.md"),
                "--sources",
                "cisco_asa",
                "--representative-source",
                "not_a_real_source",
            ]
        )


# ======================================================================
# server lifecycle
# ======================================================================


class _HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        pass  # keep test output quiet


@pytest.fixture
def health_server() -> Iterator[tuple[http.server.HTTPServer, int]]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield server, port
    server.shutdown()
    thread.join(timeout=5)


def test_wait_until_healthy_returns_once_the_endpoint_responds(
    health_server: tuple[http.server.HTTPServer, int],
) -> None:
    _server, port = health_server
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        r._wait_until_healthy(process, f"http://127.0.0.1:{port}", timeout_s=5.0)
    finally:
        process.kill()
        process.wait(timeout=5)


def test_wait_until_healthy_raises_if_the_process_exits_first() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(1)"])
    process.wait(timeout=5)
    with pytest.raises(RuntimeError, match="exited during startup"):
        r._wait_until_healthy(process, "http://127.0.0.1:1", timeout_s=2.0)


def test_wait_until_healthy_times_out_if_nothing_ever_answers() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        with pytest.raises(RuntimeError, match="did not become healthy"):
            r._wait_until_healthy(process, "http://127.0.0.1:1", timeout_s=1.0)
    finally:
        process.kill()
        process.wait(timeout=5)


def test_force_kill_stops_a_running_process() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    r._force_kill(process)
    assert process.poll() is not None


def test_force_kill_is_a_no_op_on_an_already_exited_process() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    process.wait(timeout=5)
    r._force_kill(process)  # must not raise
    assert process.returncode == 0


def test_stop_server_sends_a_graceful_signal_then_returns_once_exited() -> None:
    # A plain sleep ignores CTRL_BREAK_EVENT/SIGTERM by default and will only
    # stop via the eventual force-kill fallback inside stop_server - this
    # exercises that whole path without needing a real ulpf serve process.
    import signal as signal_mod

    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], creationflags=creationflags
    )
    handle = r.ServerHandle(process=process, api_base_url="http://127.0.0.1:1", pid=process.pid)
    start = time.monotonic()
    r.stop_server(handle, timeout_s=2.0)
    elapsed = time.monotonic() - start
    assert process.poll() is not None
    assert elapsed < 15.0  # the force-kill fallback must actually fire, not hang
    del signal_mod  # imported only to document what stop_server relies on
