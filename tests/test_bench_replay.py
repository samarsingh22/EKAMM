"""Tests for :mod:`bench.replay` — the paced load generator + report builder.

No live ``ulpf serve`` here (that was verified manually end-to-end over
UDP/TCP/HTTP against a real running instance — see the module's own
docstring for the exact measurement methodology this exercises). These tests
cover the parts that do not need a server: Prometheus-text parsing, the
histogram-quantile math, the pacer's scheduling, the wire framing each
sender actually puts on the socket, and ``compute_report``'s pure logic
against synthetic metric snapshots.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

import httpx
import pytest

from bench import replay as bp

# ---------------------------------------------------------------------------
# Prometheus text parsing
# ---------------------------------------------------------------------------

_SAMPLE_TEXT = """\
# HELP ulpf_events_received_total Raw events accepted by a listener.
# TYPE ulpf_events_received_total counter
ulpf_events_received_total{transport="udp"} 120.0
ulpf_events_received_total{transport="http"} 5.0
# HELP ulpf_queue_depth Current number of events waiting.
# TYPE ulpf_queue_depth gauge
ulpf_queue_depth 3.0
# HELP ulpf_end_to_end_latency_seconds Wall-clock time from ingest to sink.
# TYPE ulpf_end_to_end_latency_seconds histogram
ulpf_end_to_end_latency_seconds_bucket{le="0.005"} 2.0
ulpf_end_to_end_latency_seconds_bucket{le="0.01"} 5.0
ulpf_end_to_end_latency_seconds_bucket{le="0.05"} 9.0
ulpf_end_to_end_latency_seconds_bucket{le="+Inf"} 10.0
ulpf_end_to_end_latency_seconds_sum 0.312
ulpf_end_to_end_latency_seconds_count 10.0
"""


def test_parse_prometheus_text_counters_with_and_without_labels() -> None:
    samples = bp.parse_prometheus_text(_SAMPLE_TEXT)
    assert ({"transport": "udp"}, 120.0) in samples["ulpf_events_received_total"]
    assert ({"transport": "http"}, 5.0) in samples["ulpf_events_received_total"]
    assert samples["ulpf_queue_depth"] == [({}, 3.0)]


def test_parse_prometheus_text_histogram_buckets_sum_count() -> None:
    samples = bp.parse_prometheus_text(_SAMPLE_TEXT)
    buckets = {
        labels["le"]: value for labels, value in samples["ulpf_end_to_end_latency_seconds_bucket"]
    }
    assert buckets == {"0.005": 2.0, "0.01": 5.0, "0.05": 9.0, "+Inf": 10.0}
    assert samples["ulpf_end_to_end_latency_seconds_sum"] == [({}, 0.312)]
    assert samples["ulpf_end_to_end_latency_seconds_count"] == [({}, 10.0)]


def test_parse_prometheus_text_ignores_comments_and_blank_lines() -> None:
    samples = bp.parse_prometheus_text("\n# just a comment\n\nulpf_foo 1.0\n")
    assert samples == {"ulpf_foo": [({}, 1.0)]}


# ---------------------------------------------------------------------------
# MetricsSnapshot
# ---------------------------------------------------------------------------


def _snapshot(text: str) -> bp.MetricsSnapshot:
    return bp.MetricsSnapshot(taken_at=0.0, samples=bp.parse_prometheus_text(text))


def test_sum_counter_filters_by_label_and_sums_the_rest() -> None:
    snap = _snapshot(_SAMPLE_TEXT)
    assert snap.sum_counter("ulpf_events_received_total", transport="udp") == 120.0
    assert snap.sum_counter("ulpf_events_received_total") == 125.0  # summed across all transports
    assert snap.sum_counter("ulpf_events_received_total", transport="tcp") == 0.0
    assert snap.sum_counter("no_such_metric") == 0.0


def test_histogram_buckets_sum_count_accessors() -> None:
    snap = _snapshot(_SAMPLE_TEXT)
    buckets = snap.histogram_buckets("ulpf_end_to_end_latency_seconds")
    assert buckets == [(0.005, 2.0), (0.01, 5.0), (0.05, 9.0), (float("inf"), 10.0)]
    assert snap.histogram_sum("ulpf_end_to_end_latency_seconds") == 0.312
    assert snap.histogram_count("ulpf_end_to_end_latency_seconds") == 10.0
    assert snap.histogram_buckets("nonexistent") == []


def test_diff_histogram_buckets_computes_per_bucket_deltas() -> None:
    before = [(0.005, 1.0), (0.01, 2.0), (float("inf"), 3.0)]
    after = [(0.005, 4.0), (0.01, 9.0), (float("inf"), 12.0)]
    assert bp.diff_histogram_buckets(before, after) == [
        (0.005, 3.0),
        (0.01, 7.0),
        (float("inf"), 9.0),
    ]


def test_diff_histogram_buckets_never_goes_negative() -> None:
    # a counter reset (server restart) must not report negative deltas
    before = [(0.005, 100.0)]
    after = [(0.005, 5.0)]
    assert bp.diff_histogram_buckets(before, after) == [(0.005, 0.0)]


# ---------------------------------------------------------------------------
# histogram_quantile
# ---------------------------------------------------------------------------


def test_histogram_quantile_interpolates_within_a_bucket() -> None:
    # 10 observations uniformly filling [0, 0.01]: 5 land at/under 0.005, 5 more up to 0.01
    buckets = [(0.005, 5.0), (0.01, 10.0), (float("inf"), 10.0)]
    p50 = bp.histogram_quantile(buckets, 0.5)
    assert p50 == pytest.approx(0.005)
    p90 = bp.histogram_quantile(buckets, 0.9)
    assert 0.005 < p90 < 0.01


def test_histogram_quantile_empty_or_zero_total_is_none() -> None:
    assert bp.histogram_quantile([], 0.5) is None
    assert bp.histogram_quantile([(0.005, 0.0), (float("inf"), 0.0)], 0.5) is None


def test_histogram_quantile_in_the_open_ended_inf_bucket_returns_last_finite_le() -> None:
    buckets = [(0.005, 1.0), (0.01, 2.0), (float("inf"), 100.0)]
    assert bp.histogram_quantile(buckets, 0.99) == 0.01


# ---------------------------------------------------------------------------
# compute_report
# ---------------------------------------------------------------------------


def _phase(sent: int, elapsed_s: float) -> bp.PhaseResult:
    return bp.PhaseResult(sent=sent, elapsed_s=elapsed_s)


def _hardware() -> bp.Hardware:
    return bp.Hardware(cpu_model="Test CPU", cpu_cores=8, ram_bytes=16 * 1024**3)


def test_compute_report_happy_path_no_backlog() -> None:
    before = _snapshot(
        'ulpf_events_received_total{transport="udp"} 0\n'
        "ulpf_events_normalized_total 0\n"
        "ulpf_dead_letter_total 0\n"
        'ulpf_end_to_end_latency_seconds_bucket{le="0.01"} 0\n'
        'ulpf_end_to_end_latency_seconds_bucket{le="+Inf"} 0\n'
        "ulpf_end_to_end_latency_seconds_sum 0\n"
        "ulpf_end_to_end_latency_seconds_count 0\n"
        "ulpf_normalization_completeness_sum 0\n"
        "ulpf_normalization_completeness_count 0\n"
    )
    after = _snapshot(
        'ulpf_events_received_total{transport="udp"} 100\n'
        "ulpf_events_normalized_total 100\n"
        "ulpf_dead_letter_total 0\n"
        'ulpf_end_to_end_latency_seconds_bucket{le="0.01"} 100\n'
        'ulpf_end_to_end_latency_seconds_bucket{le="+Inf"} 100\n'
        "ulpf_end_to_end_latency_seconds_sum 0.5\n"
        "ulpf_end_to_end_latency_seconds_count 100\n"
        "ulpf_normalization_completeness_sum 95.0\n"
        "ulpf_normalization_completeness_count 100\n"
    )
    report = bp.compute_report(
        transport="udp",
        target_rate=100.0,
        warmup_s=10.0,
        requested_duration_s=60.0,
        phase=_phase(100, 1.0),
        before=before,
        after=after,
        health={
            "enrichers": [{"enabled": True}],
            "integrity": {"active": True, "off_reason": None},
        },
        peak_rss=1234,
        rss_note=None,
        hardware=_hardware(),
    )
    assert report.parse_coverage == 1.0
    assert report.dlq_rate == 0.0
    assert report.backlog_note is None
    assert report.normalization_completeness_mean == pytest.approx(0.95)
    # all 100 observations fall within the single [0, 0.01s] bucket, so
    # Prometheus-style linear interpolation puts the p50 rank at its midpoint
    assert report.latency_p50_ms == pytest.approx(5.0)
    assert report.latency_samples == 100
    assert report.achieved_eps == 100.0
    assert report.enrichment_enabled is True
    assert report.integrity_active is True
    assert report.server_reachable is True


def test_compute_report_flags_a_backlog_when_processing_lagged_receipt() -> None:
    before = _snapshot(
        'ulpf_events_received_total{transport="udp"} 0\n'
        "ulpf_events_normalized_total 0\n"
        "ulpf_dead_letter_total 0\n"
    )
    after = _snapshot(
        'ulpf_events_received_total{transport="udp"} 1000\n'
        "ulpf_events_normalized_total 700\n"  # only 70% kept up
        "ulpf_dead_letter_total 0\n"
    )
    report = bp.compute_report(
        transport="udp",
        target_rate=500.0,
        warmup_s=2.0,
        requested_duration_s=8.0,
        phase=_phase(1000, 8.0),
        before=before,
        after=after,
        health=None,
        peak_rss=None,
        rss_note="not measured (pass --server-pid)",
        hardware=_hardware(),
    )
    assert report.parse_coverage == pytest.approx(0.7)
    assert report.backlog_note is not None
    assert "300" in report.backlog_note


def test_compute_report_without_metrics_reports_unreachable() -> None:
    report = bp.compute_report(
        transport="udp",
        target_rate=None,
        warmup_s=1.0,
        requested_duration_s=60.0,
        phase=_phase(0, 0.0),
        before=None,
        after=None,
        health=None,
        peak_rss=None,
        rss_note=None,
        hardware=_hardware(),
    )
    assert report.server_reachable is False
    assert report.parse_coverage is None
    assert report.latency_p50_ms is None
    assert report.achieved_eps == 0.0


def test_compute_report_enrichment_off_when_every_enricher_is_disabled() -> None:
    report = bp.compute_report(
        transport="http",
        target_rate=1.0,
        warmup_s=0.0,
        requested_duration_s=60.0,
        phase=_phase(1, 1.0),
        before=_snapshot(""),
        after=_snapshot(""),
        health={
            "enrichers": [{"enabled": False}, {"enabled": False}],
            "integrity": {"active": False, "off_reason": "x"},
        },
        peak_rss=None,
        rss_note=None,
        hardware=_hardware(),
    )
    assert report.enrichment_enabled is False
    assert report.integrity_active is False
    assert report.integrity_off_reason == "x"


# ---------------------------------------------------------------------------
# pacing (run_phase)
# ---------------------------------------------------------------------------


class _FakeSender:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.flush_calls = 0

    def send_one(self, line: bytes) -> None:
        self.sent.append(line)

    def flush(self) -> None:
        self.flush_calls += 1

    def close(self) -> None:
        pass


def test_run_phase_paced_sends_close_to_the_target_rate() -> None:
    sender = _FakeSender()
    lines = [f"line-{i}".encode() for i in range(10_000)]
    result, _ = bp.run_phase(sender, lines, rate=200.0, duration_s=0.5, loop_source=False)
    # 200 eps for 0.5s -> ~100 events; generous tolerance for a busy CI box
    assert 70 <= result.sent <= 130
    assert len(sender.sent) == result.sent


def test_run_phase_max_rate_sends_far_more_than_a_paced_run() -> None:
    lines = [f"line-{i}".encode() for i in range(50_000)]
    paced = _FakeSender()
    paced_result, _ = bp.run_phase(paced, lines, rate=200.0, duration_s=0.3, loop_source=False)
    blast = _FakeSender()
    blast_result, _ = bp.run_phase(blast, lines, rate=None, duration_s=0.3, loop_source=False)
    assert blast_result.sent > paced_result.sent * 5


def test_run_phase_stops_at_end_of_file_without_loop() -> None:
    sender = _FakeSender()
    lines = [b"only-line"] * 5
    result, next_idx = bp.run_phase(sender, lines, rate=1000.0, duration_s=1.0, loop_source=False)
    assert result.sent == 5
    assert next_idx == 5


def test_run_phase_loops_the_file_when_asked() -> None:
    sender = _FakeSender()
    lines = [b"a", b"b", b"c"]
    result, _ = bp.run_phase(sender, lines, rate=500.0, duration_s=0.1, loop_source=True)
    assert result.sent > len(lines)  # it had to wrap around at least once


def test_run_phase_resumes_from_start_index() -> None:
    sender = _FakeSender()
    lines = [str(i).encode() for i in range(10)]
    _, next_idx = bp.run_phase(
        sender, lines, rate=None, duration_s=0.01, loop_source=False, start_index=7
    )
    assert sender.sent[0] == b"7"


# ---------------------------------------------------------------------------
# senders - real wire framing
# ---------------------------------------------------------------------------


def test_udp_sender_puts_one_line_per_datagram() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(2.0)
    port = listener.getsockname()[1]
    try:
        sender = bp.UdpSender("127.0.0.1", port)
        sender.send_one(b"hello world")
        sender.send_one(b"a second datagram")
        data1, _ = listener.recvfrom(4096)
        data2, _ = listener.recvfrom(4096)
        assert data1 == b"hello world"
        assert data2 == b"a second datagram"
        sender.close()
    finally:
        listener.close()


def test_tcp_sender_uses_rfc6587_octet_counting_framing() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        sender = bp.TcpSender("127.0.0.1", port, batch_bytes=1)  # flush after every line
        conn, _ = listener.accept()
        sender.send_one(b"first")
        sender.send_one(b"second line")
        conn.settimeout(2.0)
        received = b""
        while len(received) < len(b"5 firstsecond line") - 1:  # crude, just get enough bytes
            chunk = conn.recv(4096)
            if not chunk:
                break
            received += chunk
        sender.close()
        conn.close()
        assert received == b"5 first11 second line"
    finally:
        listener.close()


def test_http_sender_posts_a_batched_newline_joined_body() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"accepted": 2, "event_uids": ["a", "b"]})

    transport = httpx.MockTransport(handler)
    sender = bp.HttpSender("http://test", batch_size=2, source_id="bench")
    sender._client = httpx.Client(base_url="http://test", transport=transport)

    sender.send_one(b"line one")
    sender.send_one(b"line two")  # hits batch_size=2 -> auto-flushes
    sender.close()

    assert len(captured) == 1
    request = captured[0]
    assert request.url.path == "/ingest/raw"
    assert request.url.params["source_id"] == "bench"
    assert request.read() == b"line one\nline two"


# ---------------------------------------------------------------------------
# hardware + RSS sampling
# ---------------------------------------------------------------------------


def test_hardware_detect_returns_plausible_values() -> None:
    hw = bp.Hardware.detect()
    assert isinstance(hw.cpu_model, str) and hw.cpu_model
    assert hw.cpu_cores >= 1
    assert hw.ram_bytes is None or hw.ram_bytes > 0


def test_rss_sampler_tracks_a_real_processs_peak_rss() -> None:
    pytest.importorskip("psutil")
    sampler = bp.RssSampler(pid=__import__("os").getpid(), interval_s=0.05)
    sampler.start()
    _ = bytearray(10_000_000)  # allocate to make sure RSS is nonzero and stable
    time.sleep(0.2)
    peak = sampler.stop()
    assert sampler.error is None
    assert peak is not None and peak > 0


def test_rss_sampler_without_psutil_reports_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bp, "psutil", None)
    sampler = bp.RssSampler(pid=1, interval_s=0.05)
    sampler.start()
    assert sampler.error is not None
    assert "psutil" in sampler.error


def test_rss_sampler_reports_an_error_for_a_nonexistent_pid() -> None:
    pytest.importorskip("psutil")
    sampler = bp.RssSampler(pid=999_999_999, interval_s=0.05)
    sampler.start()
    time.sleep(0.1)
    sampler.stop()
    assert sampler.error is not None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_load_lines_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "sample.log"
    path.write_bytes(b"line one\n\n  \nline two\n")
    assert bp._load_lines(path) == [b"line one", b"line two"]


def test_main_rejects_short_duration_without_the_override(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.log"
    sample.write_text("one line\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        bp.main(["--file", str(sample), "--transport", "udp", "--duration", "5"])
    assert "required minimum" in capsys.readouterr().err


def test_main_rejects_a_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        bp.main(["--file", "does-not-exist.log", "--transport", "udp"])
    assert "not found" in capsys.readouterr().err


def test_build_arg_parser_default_ports_are_resolved_in_main(tmp_path: Path) -> None:
    parser = bp.build_arg_parser()
    ns = parser.parse_args(["--file", "x", "--transport", "http"])
    assert ns.port is None  # main() fills in the per-transport default
    assert bp._DEFAULT_PORTS == {"udp": 514, "tcp": 514, "http": 8081}
