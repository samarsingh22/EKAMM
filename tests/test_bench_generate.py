"""Tests for :mod:`bench.generate` — the synthetic perimeter-log generator.

The strongest tests here reuse the real pipeline: every generated line is
run through :func:`ulpf.cli.inspect.build_report` (the same function
``ulpf inspect`` uses) against the live source registry, so "the generator
produces valid ULPF input" is checked against the actual detect/parse/
normalize/validate chain, not a hand-rolled assumption about the format.
"""

from __future__ import annotations

import ipaddress
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bench import generate as gen
from ulpf.cli.inspect import build_report
from ulpf.parse.dsl.loader import SourceRegistry

_SOURCES_DIR = Path(__file__).resolve().parent.parent / "configs" / "sources"


@pytest.fixture(scope="module")
def registry() -> SourceRegistry:
    reg = SourceRegistry()
    reg.load_all(_SOURCES_DIR)
    return reg


def _assert_matches_and_validates(
    line: str, expected_source: str, registry: SourceRegistry
) -> None:
    report = build_report(line.encode("utf-8"), registry, with_crosswalk=False)
    match = report["match"]
    assert match.get("matched") is True, (
        f"{expected_source}: line did not match any source: {line[:200]}"
    )
    assert match["name"] == expected_source, (
        f"matched {match['name']!r}, expected {expected_source!r}"
    )
    validation = report["validation"]
    assert validation is not None and validation["valid"], f"{expected_source}: {validation}"


def _flow(**overrides: object) -> gen.Flow:
    base = dict(
        ts=datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC),
        src_ip="10.20.5.9",
        src_port=51234,
        dst_ip="203.0.113.9",
        dst_port=443,
        protocol="tcp",
        allowed=True,
        bytes_out=1200,
        bytes_in=3800,
        packets_out=8,
        packets_in=6,
        duration_s=2.5,
        conn_state="SF",
    )
    base.update(overrides)
    return gen.Flow(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# addressing
# ---------------------------------------------------------------------------


def test_doc_ip_is_always_rfc5737_and_never_globally_routable() -> None:
    rng = random.Random(1)
    for _ in range(500):
        ip = ipaddress.ip_address(gen._doc_ip(rng))
        # RFC 5737 documentation space is, like RFC 1918, not globally routable
        # (ipaddress.is_private is True for both - see the module docstring's
        # IP ADDRESSING section); is_global is the property that actually
        # distinguishes "a real internet address" from either.
        assert not ip.is_global
        assert any(
            ip in ipaddress.ip_network(f"{a}.{b}.{c}.0/24") for a, b, c in gen._DOC_NET_OCTETS
        )


def test_internal_ip_is_always_private_rfc1918() -> None:
    rng = random.Random(2)
    for _ in range(500):
        ip = ipaddress.ip_address(gen._internal_ip(rng))
        assert ip.is_private
        assert ip in ipaddress.ip_network("10.0.0.0/8")


def test_ip_pool_hot_addresses_are_drawn_more_often() -> None:
    rng = random.Random(3)
    pool = gen.IpPool(hot=["10.0.0.1"], all=[f"10.0.0.{i}" for i in range(1, 101)], hot_share=0.9)
    draws = [pool.draw(rng) for _ in range(2000)]
    assert draws.count("10.0.0.1") / len(draws) > 0.5  # far above its 1/100 uniform share


# ---------------------------------------------------------------------------
# flow-shaped renderers, verified against the real pipeline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source,render",
    [
        ("cisco_asa", gen.render_cisco_asa),
        ("fortigate_traffic", gen.render_fortigate),
        ("panos_traffic_v10", gen.render_panos_v10),
        ("panos_traffic_v11", gen.render_panos_v11),
        ("aws_vpc_flow", gen.render_aws_vpc_flow),
        ("iptables", gen.render_iptables),
        ("suricata_eve_flow", gen.render_suricata_eve_flow),
        ("zeek_conn", gen.render_zeek_conn),
    ],
)
def test_flow_renderer_allowed_and_denied_both_validate(
    source, render, registry: SourceRegistry
) -> None:
    allowed_line = render(_flow(allowed=True, conn_state="SF"), 1)
    denied_line = render(_flow(allowed=False, conn_state="S0", bytes_out=0, bytes_in=0), 2)
    _assert_matches_and_validates(allowed_line, source, registry)
    _assert_matches_and_validates(denied_line, source, registry)


def test_flow_renderers_carry_the_src_and_dst_ip_through(registry: SourceRegistry) -> None:
    flow = _flow(src_ip="10.20.9.9", dst_ip="198.51.100.42")
    for render, source in [
        (gen.render_cisco_asa, "cisco_asa"),
        (gen.render_fortigate, "fortigate_traffic"),
        (gen.render_aws_vpc_flow, "aws_vpc_flow"),
        (gen.render_iptables, "iptables"),
        (gen.render_suricata_eve_flow, "suricata_eve_flow"),
        (gen.render_zeek_conn, "zeek_conn"),
    ]:
        line = render(flow, 7)
        report = build_report(line.encode("utf-8"), registry, with_crosswalk=False)
        ocsf = report["normalized"]
        assert ocsf["src_endpoint"]["ip"] == "10.20.9.9", source
        assert ocsf["dst_endpoint"]["ip"] == "198.51.100.42", source


# ---------------------------------------------------------------------------
# non-flow renderers
# ---------------------------------------------------------------------------


def test_zeek_dns_renderer_validates(registry: SourceRegistry) -> None:
    query = gen.DnsQuery(
        ts=datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC),
        client_ip="10.20.1.1",
        resolver_ip="10.20.0.53",
        query="example.com",
        qtype="A",
        rcode="NOERROR",
        answers=["203.0.113.5"],
    )
    _assert_matches_and_validates(gen.render_zeek_dns(query, 1), "zeek_dns", registry)


def test_zeek_http_renderer_validates(registry: SourceRegistry) -> None:
    req = gen.HttpRequest(
        ts=datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC),
        client_ip="10.20.1.1",
        server_ip="203.0.113.5",
        method="GET",
        host="example.com",
        uri="/",
        status=200,
        user_agent="curl/8.6.0",
        response_bytes=1200,
    )
    _assert_matches_and_validates(gen.render_zeek_http(req, 1), "zeek_http", registry)


def test_suricata_eve_alert_renderer_validates(registry: SourceRegistry) -> None:
    alert = gen.Alert(
        ts=datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC),
        signature="ET SCAN Suspicious Multiple Ports Scan",
        category="Attempted Network Scan",
        severity=1,
        src_ip="203.0.113.9",
        src_port=51234,
        dst_ip="10.20.1.1",
        dst_port=22,
        protocol="tcp",
        blocked=True,
    )
    _assert_matches_and_validates(
        gen.render_suricata_eve_alert(alert, 1), "suricata_eve_alert", registry
    )


# ---------------------------------------------------------------------------
# attack scenarios - the recognisable signal itself
# ---------------------------------------------------------------------------


def test_port_scan_hits_many_distinct_ports_on_one_victim_mostly_denied() -> None:
    rng = random.Random(11)
    internal, external = gen.build_internal_pool(rng), gen.build_external_pool(rng)
    flows = gen.gen_port_scan(rng, datetime(2026, 9, 1, tzinfo=UTC), internal, external, count=500)

    assert len({f.src_ip for f in flows}) == 1  # one attacker
    assert len({f.dst_ip for f in flows}) == 1  # one victim
    assert len({f.dst_port for f in flows}) > 400  # many distinct ports
    deny_ratio = sum(1 for f in flows if not f.allowed) / len(flows)
    assert deny_ratio > 0.9


def test_brute_force_repeats_one_port_on_one_victim_mostly_denied() -> None:
    rng = random.Random(12)
    internal, external = gen.build_internal_pool(rng), gen.build_external_pool(rng)
    flows = gen.gen_brute_force(
        rng, datetime(2026, 9, 1, tzinfo=UTC), internal, external, count=400
    )

    assert len({f.src_ip for f in flows}) == 1
    assert len({f.dst_ip for f in flows}) == 1
    assert {f.dst_port for f in flows} <= {22, 3389}
    assert len({f.dst_port for f in flows}) == 1  # one target port per run
    deny_ratio = sum(1 for f in flows if not f.allowed) / len(flows)
    assert deny_ratio > 0.85


def test_data_exfil_is_sustained_asymmetric_and_allowed() -> None:
    rng = random.Random(13)
    internal, external = gen.build_internal_pool(rng), gen.build_external_pool(rng)
    flows = gen.gen_data_exfil(rng, datetime(2026, 9, 1, tzinfo=UTC), internal, external, count=40)

    assert len({f.src_ip for f in flows}) == 1  # one compromised host
    assert len({f.dst_ip for f in flows}) == 1  # one destination
    assert all(f.allowed for f in flows)
    assert all(f.bytes_out > f.bytes_in * 10 for f in flows)  # heavily outbound-skewed
    # sustained: spread over minutes, not one burst
    span = (flows[-1].ts - flows[0].ts).total_seconds()
    assert span > 300


# ---------------------------------------------------------------------------
# end-to-end generate_one() (small counts, real pipeline verification)
# ---------------------------------------------------------------------------


def _args(**overrides: object) -> gen.GenerateArgs:
    base = dict(
        source="cisco_asa",
        count=20,
        out=Path("unused"),
        window_seconds=3600,
        end=datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC),
        seed=99,
        attack_scenario="none",
        attack_count=None,
        attack_offset=0.85,
        allow_rate=0.85,
        progress_every=0,
    )
    base.update(overrides)
    return gen.GenerateArgs(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize("source", ["cisco_asa", "aws_vpc_flow", "zeek_conn", "zeek_dns"])
def test_generate_one_writes_valid_lines_within_the_window(
    tmp_path: Path, registry: SourceRegistry, source: str
) -> None:
    out = tmp_path / f"{source}.log"
    args = _args(source=source, count=15, out=out)
    written = gen.generate_one(source, out, args)

    assert written == 15
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 15
    for line in lines:
        _assert_matches_and_validates(line, source, registry)


def test_generate_one_with_attack_scenario_adds_events_on_top(tmp_path: Path) -> None:
    out = tmp_path / "cisco_asa.log"
    args = _args(
        source="cisco_asa", count=50, out=out, attack_scenario="port_scan", attack_count=100
    )
    written = gen.generate_one("cisco_asa", out, args)
    assert written == 150  # 50 baseline + 100 injected


def test_generate_one_same_seed_is_reproducible(tmp_path: Path) -> None:
    out1, out2 = tmp_path / "a.log", tmp_path / "b.log"
    args = _args(count=30, out=out1)
    gen.generate_one("cisco_asa", out1, args)
    gen.generate_one("cisco_asa", out2, args)
    assert out1.read_text(encoding="utf-8") == out2.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------


def test_parse_window_accepts_the_documented_units() -> None:
    assert gen.parse_window("30m") == 1800
    assert gen.parse_window("24h") == 86400
    assert gen.parse_window("7d") == 7 * 86400


def test_parse_window_rejects_garbage() -> None:
    with pytest.raises(ValueError, match="invalid --window"):
        gen.parse_window("banana")


def test_known_registry_sources_matches_the_generators_own_source_list() -> None:
    assert gen._known_registry_sources() == gen.ALL_SOURCES


def test_main_rejects_an_unknown_source(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        gen.main(["--source", "not_a_real_source", "--count", "1"])
    assert "unsupported source" in capsys.readouterr().err


def test_main_requires_a_source(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        gen.main([])
    assert "--source is required" in capsys.readouterr().err


def test_main_generates_a_real_file(tmp_path: Path) -> None:
    out = tmp_path / "cisco_asa.log"
    gen.main(["--source", "cisco_asa", "--count", "10", "--out", str(out), "--progress-every", "0"])
    assert out.is_file()
    assert len(out.read_text(encoding="utf-8").splitlines()) == 10


def test_main_source_all_writes_one_file_per_source_into_the_out_directory(tmp_path: Path) -> None:
    gen.main(["--source", "all", "--count", "5", "--out", str(tmp_path), "--progress-every", "0"])
    for name in gen.ALL_SOURCES:
        out = tmp_path / f"{name}_5.log"
        assert out.is_file(), name
        assert len(out.read_text(encoding="utf-8").splitlines()) == 5


def test_main_source_all_rejects_a_file_shaped_out_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit):
        gen.main(["--source", "all", "--count", "1", "--out", str(tmp_path / "x.log")])
    assert "must be a directory" in capsys.readouterr().err


def test_end_now_is_close_to_the_real_current_time() -> None:
    end = gen._parse_end("now")
    assert abs((end - datetime.now(UTC)).total_seconds()) < 5


def test_end_accepts_an_explicit_iso_timestamp() -> None:
    end = gen._parse_end("2026-01-01T00:00:00")
    assert end == datetime(2026, 1, 1, tzinfo=UTC)


def test_spread_timestamps_stays_within_the_window() -> None:
    rng = random.Random(21)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = start + timedelta(hours=1)
    timestamps = gen.spread_timestamps(rng, 200, start, end)
    assert len(timestamps) == 200
    assert timestamps == sorted(timestamps)
    assert all(start <= ts <= end for ts in timestamps)
