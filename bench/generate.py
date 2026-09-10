#!/usr/bin/env python
"""Synthetic perimeter-log generator, at scale, for every implemented ULPF source.

    python bench/generate.py --source cisco_asa --count 1000000 --out data/samples/cisco_asa_1m.log

WHY A GENERATOR, NOT MORE HAND-WRITTEN FIXTURES
------------------------------------------------
``scripts/win/send-sample.ps1`` has one hand-typed line per source — perfect
for "does the parser still work", useless for "does the pipeline hold up at a
million events, and does the anomaly detector actually have something to
find". This script produces realistic-at-scale traffic instead of a single
repeated shape:

* **Realistic distributions**, not uniform noise: an ~85/15 allow/deny mix
  (``--allow-rate``), source IPs following a Zipf-ish "a few noisy talkers
  carry most of the traffic" pattern, destination ports weighted to common
  services (443/80/22/53/3389/... with a long tail), byte counts drawn
  log-normally (most connections small, a heavy tail of large transfers,
  never a uniform blob), and timestamps spread across a configurable
  ``--window`` (default 24h) ending at ``--end`` (default now, UTC).
* **``--attack-scenario``** injects a recognisable, labeled-by-construction
  incident on top of that baseline — see PORT SCAN / BRUTE FORCE / DATA
  EXFILTRATION below. Without one of these, an anomaly detector has nothing
  unusual to find; with one, :mod:`ulpf.ml.anomaly` and
  :mod:`ulpf.ml.drift` have a ground-truth incident to actually catch, which
  is the whole point of generating this data in the first place.

IP ADDRESSING
--------------
Internal ("our network") endpoints use real RFC 1918 space (``10.20.0.0/16``)
— the conventional, realistic choice for a corporate LAN in a sample log.
Every public-facing endpoint — internet destinations, and the attacker's own
address in an inbound attack scenario — is drawn **only** from RFC 5737
documentation space (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24): never a
real, routable address, per this generator's brief.

HONEST CAVEAT: Python's ``ipaddress.ip_address(...).is_private`` — what
:mod:`ulpf.ml.features`'s ``is_private_src`` / ``is_private_dst`` features use
— treats *both* RFC 1918 and RFC 5737 as "not globally routable" and reports
``True`` for either. So in data built entirely from this generator, every
flow's ``direction_id`` feature computes as Lateral (both endpoints "private"),
never Outbound/Inbound, regardless of which non-routable range either side
uses. That is an unavoidable consequence of "never a real, routable address"
applied to *every* endpoint, not something choosing a different range here
would fix — a genuinely correct Outbound/Inbound signal would need a real
public destination address, which the RFC 5737-only requirement rules out.
The rest of the feature set (``win_distinct_dst_ports``, ``win_deny_ratio``,
``bytes_ratio``, port/byte shape, ...) still carries the anomaly signal fine;
only ``direction_id`` itself is flat across this synthetic data.

ATTACK SCENARIOS (``--attack-scenario {port_scan,brute_force,data_exfil,all}``)
----------------------------------------------------------------------------------
* **port_scan**   — one external attacker IP against one internal victim,
  hundreds of distinct destination ports, almost entirely denied, tiny
  per-probe byte counts, tight timing. Turns ``win_distinct_dst_ports`` and
  ``win_deny_ratio`` into an obvious outlier (see :mod:`ulpf.ml.features`'s
  own docstring on that exact pair).
* **brute_force** — one external attacker IP against one internal victim's
  22 or 3389, hundreds to thousands of repeated attempts, mostly denied with
  an occasional "got through", steady inter-attempt timing.
* **data_exfil**  — one internal host, one external destination, a sustained
  run of large, mostly-allowed outbound transfers spread over tens of
  minutes (a real exfiltration is not one giant packet — it is many
  connections with a stubbornly asymmetric bytes_out >> bytes_in ratio).

Each scenario is placed late in the window (``--attack-offset``, default 85%
of the way through) so a "last hour" dashboard view lands right on it, and is
injected *on top of* ``--count`` baseline events, not instead of them.

Not every source can represent "denied": ``suricata_eve_flow`` and
``zeek_conn`` are passive observation, not a firewall verdict (``action_id``
is a constant "Allowed" in both YAMLs), so a scenario shows there through
connection-state / byte-volume shape instead — ``FLOW_RENDERERS`` covers all
eight flow-shaped sources uniformly either way. ``suricata_eve_alert``
additionally gets synthesized detections (see ``gen_scenario_alerts``)
referencing the same attacker/victim/service as the injected scenario;
``zeek_dns`` / ``zeek_http`` (``DNS_SOURCES`` / ``HTTP_SOURCES``) get baseline
traffic only — a DNS/HTTP log has no natural shape for these three scenarios.
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypeVar

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SOURCES_DIR = _REPO_ROOT / "configs" / "sources"

# ======================================================================
# addressing (see the module docstring's IP ADDRESSING section)
# ======================================================================

_DOC_NET_OCTETS = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]  # RFC 5737 /24s


def _doc_ip(rng: random.Random) -> str:
    """One address from a uniformly-random RFC 5737 /24 — never a real, routable one."""
    a, b, c = rng.choice(_DOC_NET_OCTETS)
    return f"{a}.{b}.{c}.{rng.randint(1, 254)}"


def _internal_ip(rng: random.Random) -> str:
    """One address in 10.20.0.0/16 — the synthetic "corporate LAN"."""
    return f"10.20.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


# ======================================================================
# weighted distributions
# ======================================================================

# (port, weight) — a realistic service mix; anything not drawn from here
# falls back to a random ephemeral-range "long tail" port.
_SERVICE_PORTS: list[tuple[int, int]] = [
    (443, 40),
    (80, 22),
    (53, 8),
    (22, 7),
    (3389, 4),
    (25, 3),
    (8080, 3),
    (8443, 2),
    (445, 2),
    (3306, 2),
    (21, 2),
    (5432, 1),
    (23, 1),
    (110, 1),
    (143, 1),
    (993, 1),
    (995, 1),
    (5900, 1),
]
_LONG_TAIL_SHARE = 0.12  # fraction of destination ports that are just "some other port"

_PROTOCOLS: list[tuple[str, int]] = [("tcp", 75), ("udp", 20), ("icmp", 5)]

_DOMAINS = [
    "example.com",
    "login.microsoftonline.com",
    "api.github.com",
    "www.google.com",
    "cdn.cloudflare.net",
    "update.mozilla.org",
    "s3.amazonaws.com",
    "graph.facebook.com",
    "outlook.office365.com",
    "docs.python.org",
    "pypi.org",
    "slack.com",
    "zoom.us",
    "teams.microsoft.com",
    "windowsupdate.microsoft.com",
    "npmjs.org",
]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/8.6.0",
    "python-requests/2.32.0",
]
_HTTP_METHODS: list[tuple[str, int]] = [
    ("GET", 70),
    ("POST", 18),
    ("HEAD", 6),
    ("PUT", 3),
    ("DELETE", 2),
    ("OPTIONS", 1),
]
_HTTP_STATUSES: list[tuple[int, int]] = [
    (200, 70),
    (304, 10),
    (301, 6),
    (404, 8),
    (403, 3),
    (500, 2),
    (502, 1),
]


_T = TypeVar("_T")


def _weighted_choice(rng: random.Random, options: list[tuple[_T, int]]) -> _T:
    values = [v for v, _ in options]
    weights = [w for _, w in options]
    return rng.choices(values, weights=weights, k=1)[0]


def weighted_dst_port(rng: random.Random) -> int:
    """A destination port skewed toward common services, with a long tail."""
    if rng.random() < _LONG_TAIL_SHARE:
        return rng.randint(1024, 65535)
    return _weighted_choice(rng, _SERVICE_PORTS)


def ephemeral_port(rng: random.Random) -> int:
    return rng.randint(1024, 65535)


def weighted_protocol(rng: random.Random) -> str:
    return _weighted_choice(rng, _PROTOCOLS)


def lognormal_bytes(
    rng: random.Random, *, mu: float, sigma: float, lo: int = 40, hi: int = 50_000_000
) -> int:
    """A byte count drawn log-normally: most connections small, a heavy tail of large ones."""
    return max(lo, min(hi, int(rng.lognormvariate(mu, sigma))))


def lognormal_duration(rng: random.Random, *, mu: float = 1.3, sigma: float = 1.1) -> float:
    return max(0.01, min(3600.0, rng.lognormvariate(mu, sigma)))


# ======================================================================
# IP pools ("a few noisy talkers carry most of the traffic")
# ======================================================================


@dataclass
class IpPool:
    """A Zipf-ish pool: `hot` addresses are drawn `hot_share` of the time, the rest uniformly."""

    hot: list[str]
    all: list[str]
    hot_share: float

    def draw(self, rng: random.Random) -> str:
        if rng.random() < self.hot_share:
            return rng.choice(self.hot)
        return rng.choice(self.all)


def build_internal_pool(
    rng: random.Random, *, size: int = 250, hot_count: int = 8, hot_share: float = 0.55
) -> IpPool:
    all_ips = [_internal_ip(rng) for _ in range(size)]
    return IpPool(hot=rng.sample(all_ips, hot_count), all=all_ips, hot_share=hot_share)


def build_external_pool(
    rng: random.Random, *, size: int = 300, hot_count: int = 6, hot_share: float = 0.5
) -> IpPool:
    all_ips = [_doc_ip(rng) for _ in range(size)]
    return IpPool(hot=rng.sample(all_ips, hot_count), all=all_ips, hot_share=hot_share)


# ======================================================================
# record shapes
# ======================================================================


@dataclass
class Flow:
    """One network connection/flow — the shape every "flow-like" source renders."""

    ts: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # "tcp" | "udp" | "icmp"
    allowed: bool
    bytes_out: int
    bytes_in: int
    packets_out: int
    packets_in: int
    duration_s: float
    conn_state: str = "SF"  # Zeek-style; only zeek_conn's renderer reads this


@dataclass
class DnsQuery:
    ts: datetime
    client_ip: str
    resolver_ip: str
    query: str
    qtype: str
    rcode: str
    answers: list[str]


@dataclass
class HttpRequest:
    ts: datetime
    client_ip: str
    server_ip: str
    method: str
    host: str
    uri: str
    status: int
    user_agent: str
    response_bytes: int


@dataclass
class Alert:
    ts: datetime
    signature: str
    category: str
    severity: int  # Suricata scale: 1 (high) .. 4 (low)
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    blocked: bool


# ======================================================================
# baseline generation
# ======================================================================


def spread_timestamps(
    rng: random.Random, count: int, start: datetime, end: datetime
) -> list[datetime]:
    """`count` timestamps drawn uniformly over [start, end], sorted (a log file is time-ordered)."""
    span = (end - start).total_seconds()
    if span <= 0:
        return [start] * count
    offsets = sorted(rng.uniform(0, span) for _ in range(count))
    return [start + timedelta(seconds=o) for o in offsets]


def gen_baseline_flow(
    rng: random.Random, ts: datetime, internal: IpPool, external: IpPool, *, allow_rate: float
) -> Flow:
    """One ordinary connection: mostly our network talking outbound to the internet."""
    inbound = (
        rng.random() < 0.08
    )  # a slice of baseline traffic is externally-initiated (inbound web etc.)
    if inbound:
        src_ip, dst_ip = external.draw(rng), internal.draw(rng)
    else:
        src_ip, dst_ip = internal.draw(rng), external.draw(rng)

    allowed = rng.random() < allow_rate
    protocol = weighted_protocol(rng)
    duration = lognormal_duration(rng)
    if allowed:
        bytes_out = lognormal_bytes(rng, mu=7.5, sigma=1.6)
        bytes_in = lognormal_bytes(rng, mu=8.5, sigma=1.8)  # responses tend to outweigh requests
    else:
        bytes_out, bytes_in = 0, 0
        duration = min(duration, 0.05)  # a denied connection never really opens

    return Flow(
        ts=ts,
        src_ip=src_ip,
        src_port=ephemeral_port(rng),
        dst_ip=dst_ip,
        dst_port=weighted_dst_port(rng),
        protocol=protocol,
        allowed=allowed,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        packets_out=max(1, bytes_out // rng.randint(400, 1400)),
        packets_in=max(0, bytes_in // rng.randint(400, 1400)),
        duration_s=duration,
        conn_state="SF" if allowed else rng.choice(["S0", "REJ", "RSTR"]),
    )


def gen_baseline_dns(rng: random.Random, ts: datetime, internal: IpPool) -> DnsQuery:
    resolver = "10.20.0.53"
    query = rng.choice(_DOMAINS)
    nxdomain = rng.random() < 0.03
    answers = [] if nxdomain else [_doc_ip(rng) for _ in range(rng.randint(1, 2))]
    return DnsQuery(
        ts=ts,
        client_ip=internal.draw(rng),
        resolver_ip=resolver,
        query=query,
        qtype="A",
        rcode="NXDOMAIN" if nxdomain else "NOERROR",
        answers=answers,
    )


def gen_baseline_http(
    rng: random.Random, ts: datetime, internal: IpPool, external: IpPool
) -> HttpRequest:
    status = _weighted_choice(rng, _HTTP_STATUSES)
    return HttpRequest(
        ts=ts,
        client_ip=internal.draw(rng),
        server_ip=external.draw(rng),
        method=_weighted_choice(rng, _HTTP_METHODS),
        host=rng.choice(_DOMAINS),
        uri=rng.choice(
            ["/", "/index.html", "/api/v1/status", "/login", "/assets/app.js", "/favicon.ico"]
        ),
        status=status,
        user_agent=rng.choice(_USER_AGENTS),
        response_bytes=lognormal_bytes(rng, mu=7.0, sigma=1.5, hi=2_000_000),
    )


def gen_baseline_alert(
    rng: random.Random, ts: datetime, internal: IpPool, external: IpPool
) -> Alert:
    sig, category, severity = rng.choice(
        [
            ("ET INFO TLS Handshake Failure", "Not Suspicious Traffic", 3),
            ("ET POLICY Executable served from Webroot", "Potentially Bad Traffic", 3),
            ("ET INFO Possible External IP Lookup", "Not Suspicious Traffic", 4),
            ("ET POLICY Dropbox Client Sync Traffic", "Potentially Bad Traffic", 4),
        ]
    )
    return Alert(
        ts=ts,
        signature=sig,
        category=category,
        severity=severity,
        src_ip=internal.draw(rng),
        src_port=ephemeral_port(rng),
        dst_ip=external.draw(rng),
        dst_port=weighted_dst_port(rng),
        protocol="tcp",
        blocked=False,
    )


# ======================================================================
# attack scenarios
# ======================================================================


def gen_port_scan(
    rng: random.Random, start: datetime, internal: IpPool, external: IpPool, *, count: int | None
) -> list[Flow]:
    """One external attacker sweeping hundreds of ports on one internal victim, mostly denied."""
    attacker, victim = external.draw(rng), internal.draw(rng)
    n_ports = count or rng.randint(300, 900)
    ports = rng.sample(range(1, 65536), min(n_ports, 65000))
    flows, t = [], start
    for port in ports:
        t += timedelta(seconds=rng.uniform(0.01, 0.25))
        allowed = rng.random() < 0.03  # a handful of probes happen to hit an open port
        flows.append(
            Flow(
                ts=t,
                src_ip=attacker,
                src_port=ephemeral_port(rng),
                dst_ip=victim,
                dst_port=port,
                protocol="tcp",
                allowed=allowed,
                bytes_out=rng.randint(40, 80) if allowed else 0,
                bytes_in=rng.randint(0, 120) if allowed else 0,
                packets_out=1,
                packets_in=1 if allowed else 0,
                duration_s=0.05,
                conn_state="SF" if allowed else "S0",
            )
        )
    return flows


def gen_brute_force(
    rng: random.Random, start: datetime, internal: IpPool, external: IpPool, *, count: int | None
) -> list[Flow]:
    """One external attacker repeatedly hammering SSH or RDP on one internal victim."""
    attacker, victim = external.draw(rng), internal.draw(rng)
    port = rng.choice([22, 3389])
    n_attempts = count or rng.randint(300, 1500)
    flows, t = [], start
    for _ in range(n_attempts):
        t += timedelta(seconds=rng.uniform(0.2, 2.5))
        allowed = (
            rng.random() < 0.04
        )  # the login itself still fails; TCP just completes occasionally
        flows.append(
            Flow(
                ts=t,
                src_ip=attacker,
                src_port=ephemeral_port(rng),
                dst_ip=victim,
                dst_port=port,
                protocol="tcp",
                allowed=allowed,
                bytes_out=rng.randint(200, 600),
                bytes_in=rng.randint(100, 400) if allowed else 0,
                packets_out=rng.randint(3, 8),
                packets_in=rng.randint(2, 6) if allowed else 0,
                duration_s=rng.uniform(0.3, 2.0),
                conn_state="REJ" if not allowed else "RSTR",
            )
        )
    return flows


def gen_data_exfil(
    rng: random.Random, start: datetime, internal: IpPool, external: IpPool, *, count: int | None
) -> list[Flow]:
    """One compromised internal host sending large, mostly-allowed outbound transfers, sustained."""
    source_host, drop_server = internal.draw(rng), external.draw(rng)
    n_transfers = count or rng.randint(25, 80)
    flows, t = [], start
    for _ in range(n_transfers):
        t += timedelta(seconds=rng.uniform(20, 90))  # sustained: tens of minutes, not one burst
        bytes_out = lognormal_bytes(rng, mu=16.0, sigma=1.0, lo=500_000, hi=200_000_000)
        flows.append(
            Flow(
                ts=t,
                src_ip=source_host,
                src_port=ephemeral_port(rng),
                dst_ip=drop_server,
                dst_port=443,
                protocol="tcp",
                allowed=True,
                bytes_out=bytes_out,
                bytes_in=rng.randint(200, 2000),
                packets_out=max(10, bytes_out // 1200),
                packets_in=rng.randint(5, 20),
                duration_s=rng.uniform(5, 60),
                conn_state="SF",
            )
        )
    return flows


_SCENARIOS: dict[str, Callable[..., list[Flow]]] = {
    "port_scan": gen_port_scan,
    "brute_force": gen_brute_force,
    "data_exfil": gen_data_exfil,
}
_SCENARIO_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "port_scan": [
        ("ET SCAN Suspicious Multiple Ports Scan", "Attempted Network Scan"),
        ("GPL SCAN nmap TCP", "Attempted Information Leak"),
    ],
    "brute_force": [
        ("ET SCAN SSH BruteForce Tool", "Attempted Administrator Privilege Gain"),
        ("ET POLICY Excessive RDP Login Attempts", "Potentially Bad Traffic"),
    ],
    "data_exfil": [
        (
            "ET POLICY Large Outbound Data Transfer - Possible Data Exfiltration",
            "Potentially Bad Traffic",
        ),
        ("ET POLICY Unusually Large Encrypted Upload", "A Network Trojan was detected"),
    ],
}


def gen_scenario_alerts(rng: random.Random, scenario: str, flows: Sequence[Flow]) -> list[Alert]:
    """A handful of IDS detections tied to the scenario's flows (per incident, not per packet)."""
    if not flows:
        return []
    n_alerts = max(3, min(20, len(flows) // 50))
    sample = rng.sample(list(flows), min(n_alerts, len(flows)))
    alerts = []
    for flow in sample:
        sig, category = rng.choice(_SCENARIO_SIGNATURES[scenario])
        alerts.append(
            Alert(
                ts=flow.ts,
                signature=sig,
                category=category,
                severity=rng.choice([1, 2]),
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                blocked=not flow.allowed,
            )
        )
    return alerts


# ======================================================================
# per-source renderers - flow-shaped sources
# ======================================================================


def _syslog_ts(dt: datetime) -> str:
    """RFC 3164-style ``Mon  2 15:04:05`` — no year, single-digit days space-padded."""
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def _hms(seconds: float) -> str:
    total = max(0, int(seconds))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}"


def render_cisco_asa(flow: Flow, idx: int) -> str:
    ts = _syslog_ts(flow.ts)
    proto = flow.protocol.upper()
    conn_id = 10_000 + idx
    if flow.allowed:
        total_bytes = flow.bytes_in + flow.bytes_out
        dur = _hms(flow.duration_s)
        body = (
            f"Teardown {proto} connection {conn_id} for outside:{flow.dst_ip}/{flow.dst_port} "
            f"to inside:{flow.src_ip}/{flow.src_port} duration {dur} bytes {total_bytes}"
        )
        sev, code = 6, 302014
    else:
        body = (
            f"Deny {flow.protocol} src outside:{flow.src_ip}/{flow.src_port} "
            f'dst inside:{flow.dst_ip}/{flow.dst_port} by access-group "inside_access_in" '
            f"[0x{idx & 0xFFFFFFFF:08x}, 0x0]"
        )
        sev, code = 4, 106023
    return f"<134>{ts} fw01 %ASA-{sev}-{code}: {body}"


def render_fortigate(flow: Flow, idx: int) -> str:
    del idx
    proto_num = {"tcp": 6, "udp": 17, "icmp": 1}[flow.protocol]
    action = "accept" if flow.allowed else "deny"
    return (
        f"<189>date={flow.ts.strftime('%Y-%m-%d')} time={flow.ts.strftime('%H:%M:%S')} "
        f'devname="FGT60F" devid="FGT60FTK20000001" logid="0000000013" type="traffic" '
        f'subtype="forward" srcip={flow.src_ip} srcport={flow.src_port} dstip={flow.dst_ip} '
        f'dstport={flow.dst_port} proto={proto_num} action="{action}" policyid=9 '
        f"sentbyte={flow.bytes_out} rcvdbyte={flow.bytes_in}"
    )


def _render_panos(flow: Flow, idx: int, *, v11: bool) -> str:
    action = "allow" if flow.allowed else "deny"
    sid = 100_000 + idx
    total_bytes = flow.bytes_in + flow.bytes_out
    packets = flow.packets_in + flow.packets_out
    ts = flow.ts.strftime("%Y/%m/%d %H:%M:%S")
    start_ts = (flow.ts - timedelta(seconds=flow.duration_s)).strftime("%Y/%m/%d %H:%M:%S")
    rule_gap = ",,,,ssl," if v11 else ",,,ssl,"
    body = (
        f"1,{ts},001801234567,TRAFFIC,end,2622,{ts},"
        f"{flow.src_ip},{flow.dst_ip},198.51.100.7,{flow.dst_ip},allow-web{rule_gap}"
        f"vsys1,trust,untrust,ethernet1/2,ethernet1/1,forward-all,,{sid},1,{flow.src_port},{flow.dst_port},"
        f"51235,{flow.dst_port},0x400053,{flow.protocol},{action},{total_bytes},{flow.bytes_out},"
        f"{flow.bytes_in},{packets},{start_ts},{int(flow.duration_s)},"
        f"web-advertisements,0,7000000123,0x0,192.0.2.0-192.0.2.255,United States,0,7,5,tcp-fin"
    )
    if v11:
        body += ",0,1001,0"
    header = f"<14>1 {flow.ts.strftime('%Y-%m-%dT%H:%M:%SZ')} pa-fw1 - - - - "
    return header + body


def render_panos_v10(flow: Flow, idx: int) -> str:
    return _render_panos(flow, idx, v11=False)


def render_panos_v11(flow: Flow, idx: int) -> str:
    return _render_panos(flow, idx, v11=True)


def render_aws_vpc_flow(flow: Flow, idx: int) -> str:
    del idx
    start = int(flow.ts.timestamp())
    end = start + max(1, int(flow.duration_s))
    proto_num = {"tcp": 6, "udp": 17, "icmp": 1}[flow.protocol]
    action = "ACCEPT" if flow.allowed else "REJECT"
    total_bytes = flow.bytes_in + flow.bytes_out
    total_packets = flow.packets_in + flow.packets_out
    return (
        f"2 123456789010 eni-0abc1234def567890 {flow.src_ip} {flow.dst_ip} "
        f"{flow.src_port} {flow.dst_port} {proto_num} {total_packets} {total_bytes} "
        f"{start} {end} {action} OK"
    )


def render_iptables(flow: Flow, idx: int) -> str:
    act = "accept" if flow.allowed else "drop"
    proto = flow.protocol.upper()
    ident = (54321 + idx) & 0xFFFF
    return (
        f"<4>{_syslog_ts(flow.ts)} gw kernel: act={act} chain=INPUT rule=90 IN=eth0 OUT= "
        f"MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC={flow.src_ip} DST={flow.dst_ip} "
        f"LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID={ident} DF PROTO={proto} "
        f"SPT={flow.src_port} DPT={flow.dst_port} WINDOW=29200 RES=0x00 SYN URGP=0"
    )


def render_suricata_eve_flow(flow: Flow, idx: int) -> str:
    fid = 1_000_000_000 + idx
    state = "new" if flow.conn_state in ("S0",) else "closed"
    record = {
        "timestamp": flow.ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "flow_id": fid,
        "in_iface": "eth0",
        "event_type": "flow",
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dest_ip": flow.dst_ip,
        "dest_port": flow.dst_port,
        "proto": flow.protocol.upper(),
        "app_proto": "tls" if flow.dst_port == 443 else "unknown",
        "flow": {
            "pkts_toserver": flow.packets_out,
            "pkts_toclient": flow.packets_in,
            "bytes_toserver": flow.bytes_out,
            "bytes_toclient": flow.bytes_in,
            "start": flow.ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "end": (flow.ts + timedelta(seconds=flow.duration_s)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f+0000"
            ),
            "age": max(1, int(flow.duration_s)),
            "state": state,
            "reason": "timeout",
            "alerted": False,
        },
    }
    return json.dumps(record, separators=(",", ":"))


def render_zeek_conn(flow: Flow, idx: int) -> str:
    record = {
        "ts": flow.ts.timestamp(),
        "uid": f"C{idx & 0xFFFFFFFF:08x}",
        "id.orig_h": flow.src_ip,
        "id.orig_p": flow.src_port,
        "id.resp_h": flow.dst_ip,
        "id.resp_p": flow.dst_port,
        "proto": flow.protocol,
        "service": "ssl" if flow.dst_port == 443 else ("dns" if flow.dst_port == 53 else "-"),
        "duration": flow.duration_s,
        "orig_bytes": flow.bytes_out,
        "resp_bytes": flow.bytes_in,
        "conn_state": flow.conn_state,
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": flow.packets_out,
        "orig_ip_bytes": flow.bytes_out,
        "resp_pkts": flow.packets_in,
        "resp_ip_bytes": flow.bytes_in,
        "tunnel_parents": [],
    }
    return json.dumps(record, separators=(",", ":"))


# ======================================================================
# per-source renderers - non-flow sources
# ======================================================================


def render_zeek_dns(query: DnsQuery, idx: int) -> str:
    record = {
        "ts": query.ts.timestamp(),
        "uid": f"CD{idx & 0xFFFFFFFF:08x}",
        "id.orig_h": query.client_ip,
        "id.orig_p": ephemeral_port(random.Random(idx)),
        "id.resp_h": query.resolver_ip,
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": 40000 + idx,
        "rtt": 0.02,
        "query": query.query,
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": 1,
        "qtype_name": query.qtype,
        "rcode": 3 if query.rcode == "NXDOMAIN" else 0,
        "rcode_name": query.rcode,
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": query.answers,
        "TTLs": [300.0 for _ in query.answers],
        "rejected": False,
    }
    return json.dumps(record, separators=(",", ":"))


def render_zeek_http(req: HttpRequest, idx: int) -> str:
    record = {
        "ts": req.ts.timestamp(),
        "uid": f"CH{idx & 0xFFFFFFFF:08x}",
        "id.orig_h": req.client_ip,
        "id.orig_p": ephemeral_port(random.Random(idx)),
        "id.resp_h": req.server_ip,
        "id.resp_p": 80,
        "trans_depth": 1,
        "method": req.method,
        "host": req.host,
        "uri": req.uri,
        "referrer": f"http://{req.host}/",
        "version": "1.1",
        "user_agent": req.user_agent,
        "request_body_len": 0,
        "response_body_len": req.response_bytes,
        "status_code": req.status,
        "status_msg": "OK" if req.status < 300 else "Error",
        "tags": [],
        "resp_fuids": [],
        "resp_mime_types": ["text/html"],
    }
    return json.dumps(record, separators=(",", ":"))


def render_suricata_eve_alert(alert: Alert, idx: int) -> str:
    record = {
        "timestamp": alert.ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "flow_id": 2_000_000_000 + idx,
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": alert.src_ip,
        "src_port": alert.src_port,
        "dest_ip": alert.dst_ip,
        "dest_port": alert.dst_port,
        "proto": alert.protocol.upper(),
        "pkt_src": "wire/pcap",
        "alert": {
            "action": "blocked" if alert.blocked else "allowed",
            "gid": 1,
            "signature_id": 2_100_000 + idx,
            "rev": 3,
            "signature": alert.signature,
            "category": alert.category,
            "severity": alert.severity,
            "metadata": {"created_at": ["2024_01_01"], "updated_at": ["2024_01_01"]},
        },
        "flow": {
            "pkts_toserver": 4,
            "pkts_toclient": 3,
            "bytes_toserver": 480,
            "bytes_toclient": 260,
        },
        "stream": 0,
        "tx_id": 0,
    }
    return json.dumps(record, separators=(",", ":"))


# ======================================================================
# source registry
# ======================================================================

FLOW_RENDERERS: dict[str, Callable[[Flow, int], str]] = {
    "cisco_asa": render_cisco_asa,
    "fortigate_traffic": render_fortigate,
    "panos_traffic_v10": render_panos_v10,
    "panos_traffic_v11": render_panos_v11,
    "aws_vpc_flow": render_aws_vpc_flow,
    "iptables": render_iptables,
    "suricata_eve_flow": render_suricata_eve_flow,
    "zeek_conn": render_zeek_conn,
}
DNS_SOURCES = {"zeek_dns"}
HTTP_SOURCES = {"zeek_http"}
ALERT_SOURCES = {"suricata_eve_alert"}
ALL_SOURCES = set(FLOW_RENDERERS) | DNS_SOURCES | HTTP_SOURCES | ALERT_SOURCES


def _known_registry_sources() -> set[str]:
    """Every source definition name under configs/sources/*.yaml (never hand-duplicated)."""
    names = set()
    for path in _SOURCES_DIR.glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "name" in data:
            names.add(str(data["name"]))
    return names


# ======================================================================
# orchestration
# ======================================================================


@dataclass
class GenerateArgs:
    source: str
    count: int
    out: Path
    window_seconds: int
    end: datetime
    seed: int
    attack_scenario: str
    attack_count: int | None
    attack_offset: float
    allow_rate: float
    progress_every: int


_WINDOW_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_WINDOW_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_window(value: str) -> int:
    match = _WINDOW_RE.match(value)
    if not match:
        raise ValueError(f"invalid --window {value!r} (expected e.g. 30m, 24h, 7d)")
    n, unit = match.groups()
    return int(n) * _WINDOW_UNIT_SECONDS[unit.lower()]


def _scenarios_to_run(name: str) -> list[str]:
    if name == "none":
        return []
    if name == "all":
        return list(_SCENARIOS)
    return [name]


def _open_writer(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".gz":
        return gzip.open(path, "wt", encoding="utf-8", newline="\n")
    return path.open("w", encoding="utf-8", newline="\n")


def generate_one(source: str, out_path: Path, args: GenerateArgs) -> int:
    """Generate one source's file; returns the number of lines written."""
    rng = random.Random(f"{args.seed}:{source}")  # deterministic per (seed, source) pair
    start = args.end - timedelta(seconds=args.window_seconds)
    internal = build_internal_pool(rng)
    external = build_external_pool(rng)

    scenarios = _scenarios_to_run(args.attack_scenario)
    scenario_flows: list[Flow] = []
    for i, scenario_name in enumerate(scenarios):
        offset = args.attack_offset + i * (1.0 - args.attack_offset) / max(1, len(scenarios))
        scenario_start = start + timedelta(seconds=args.window_seconds * min(0.97, offset))
        scenario_flows += _SCENARIOS[scenario_name](
            rng, scenario_start, internal, external, count=args.attack_count
        )

    if source in FLOW_RENDERERS:
        return _write_flow_source(
            source, out_path, args, rng, start, internal, external, scenario_flows
        )
    if source in DNS_SOURCES:
        return _write_dns_source(out_path, args, rng, start, internal)
    if source in HTTP_SOURCES:
        return _write_http_source(out_path, args, rng, start, internal, external)
    if source in ALERT_SOURCES:
        return _write_alert_source(
            out_path, args, rng, start, internal, external, scenarios, scenario_flows
        )
    raise ValueError(
        f"no generator registered for {source!r}"
    )  # pragma: no cover - guarded by main()


def _write_flow_source(
    source: str,
    out_path: Path,
    args: GenerateArgs,
    rng: random.Random,
    start: datetime,
    internal: IpPool,
    external: IpPool,
    scenario_flows: list[Flow],
) -> int:
    timestamps = spread_timestamps(rng, args.count, start, args.end)
    flows = [
        gen_baseline_flow(rng, ts, internal, external, allow_rate=args.allow_rate)
        for ts in timestamps
    ]
    flows.extend(scenario_flows)
    flows.sort(key=lambda f: f.ts)
    render = FLOW_RENDERERS[source]
    with _open_writer(out_path) as handle:
        for idx, flow in enumerate(flows):
            handle.write(render(flow, idx))
            handle.write("\n")
            _report_progress(idx, len(flows), args.progress_every)
    return len(flows)


def _write_dns_source(
    out_path: Path, args: GenerateArgs, rng: random.Random, start: datetime, internal: IpPool
) -> int:
    timestamps = spread_timestamps(rng, args.count, start, args.end)
    with _open_writer(out_path) as handle:
        for idx, ts in enumerate(timestamps):
            handle.write(render_zeek_dns(gen_baseline_dns(rng, ts, internal), idx))
            handle.write("\n")
            _report_progress(idx, len(timestamps), args.progress_every)
    return len(timestamps)


def _write_http_source(
    out_path: Path,
    args: GenerateArgs,
    rng: random.Random,
    start: datetime,
    internal: IpPool,
    external: IpPool,
) -> int:
    timestamps = spread_timestamps(rng, args.count, start, args.end)
    with _open_writer(out_path) as handle:
        for idx, ts in enumerate(timestamps):
            handle.write(render_zeek_http(gen_baseline_http(rng, ts, internal, external), idx))
            handle.write("\n")
            _report_progress(idx, len(timestamps), args.progress_every)
    return len(timestamps)


def _write_alert_source(
    out_path: Path,
    args: GenerateArgs,
    rng: random.Random,
    start: datetime,
    internal: IpPool,
    external: IpPool,
    scenarios: list[str],
    scenario_flows: list[Flow],
) -> int:
    timestamps = spread_timestamps(rng, args.count, start, args.end)
    alerts = [gen_baseline_alert(rng, ts, internal, external) for ts in timestamps]
    if scenarios:
        # attribute each scenario's own slice of scenario_flows to its own alert signatures
        offset_start = 0
        per_scenario = len(scenario_flows) // max(1, len(scenarios))
        for scenario_name in scenarios:
            chunk = scenario_flows[offset_start : offset_start + per_scenario] or scenario_flows
            alerts.extend(gen_scenario_alerts(rng, scenario_name, chunk))
            offset_start += per_scenario
    alerts.sort(key=lambda a: a.ts)
    with _open_writer(out_path) as handle:
        for idx, alert in enumerate(alerts):
            handle.write(render_suricata_eve_alert(alert, idx))
            handle.write("\n")
            _report_progress(idx, len(alerts), args.progress_every)
    return len(alerts)


def _report_progress(idx: int, total: int, every: int) -> None:
    if every > 0 and (idx + 1) % every == 0:
        print(f"  ... {idx + 1:,}/{total:,}", file=sys.stderr)


# ======================================================================
# CLI
# ======================================================================


def _parse_end(value: str) -> datetime:
    if value == "now":
        return datetime.now(UTC).replace(microsecond=0)
    parsed = datetime.fromisoformat(value)
    # A naive ISO string is documented as already UTC - treat it as such
    # rather than as local wall-clock time (which .astimezone() would assume).
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate realistic synthetic perimeter logs at scale for any known source.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source",
        required=False,
        help=f"A source name, or 'all'. Supported: {', '.join(sorted(ALL_SOURCES))}.",
    )
    parser.add_argument("--count", type=int, default=10_000, help="Baseline event count.")
    parser.add_argument("--out", type=Path, help="Output file (a directory when --source all).")
    parser.add_argument("--window", default="24h", help="Timestamp spread, e.g. 30m, 24h, 7d.")
    parser.add_argument("--end", default="now", help="Window end, ISO-8601 UTC or 'now'.")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed (reproducible by default).")
    parser.add_argument(
        "--attack-scenario",
        choices=["none", "port_scan", "brute_force", "data_exfil", "all"],
        default="none",
        help="Inject a recognisable attack pattern on top of the baseline traffic.",
    )
    parser.add_argument(
        "--attack-count",
        type=int,
        default=None,
        help="Override the scenario's event count (auto per type if unset).",
    )
    parser.add_argument(
        "--attack-offset",
        type=float,
        default=0.85,
        help="Fraction into --window where the scenario starts.",
    )
    parser.add_argument(
        "--allow-rate", type=float, default=0.85, help="Baseline allow probability."
    )
    parser.add_argument(
        "--progress-every", type=int, default=100_000, help="Progress line interval (0 disables)."
    )
    parser.add_argument(
        "--list-sources", action="store_true", help="Print every supported source name and exit."
    )
    return parser


def _resolve_out_path(source: str, out: Path | None, count: int, *, multi: bool) -> Path:
    """The file to write ``source`` to.

    ``multi`` is true under ``--source all``: ``out`` (default
    ``data/samples/``) is then always a *directory*, one file per source;
    otherwise ``out`` (default ``data/samples/<source>_<count>.log``) is the
    exact file path.
    """
    if multi:
        base_dir = out if out is not None else Path("data/samples")
        return base_dir / f"{source}_{count}.log"
    return out if out is not None else Path("data/samples") / f"{source}_{count}.log"


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    ns = parser.parse_args(argv)

    if ns.list_sources:
        for name in sorted(ALL_SOURCES):
            print(name)
        return

    if not ns.source:
        parser.error("--source is required (or pass --list-sources)")

    registry_sources = _known_registry_sources()
    requested = sorted(ALL_SOURCES) if ns.source == "all" else [ns.source]
    for name in requested:
        if name not in ALL_SOURCES:
            parser.error(
                f"unsupported source {name!r}; supported: {', '.join(sorted(ALL_SOURCES))}"
            )
        if name not in registry_sources:  # pragma: no cover - only fires if configs/sources/ drifts
            parser.error(f"{name!r} has a generator but no configs/sources/{name}.yaml was found")

    args = GenerateArgs(
        source=ns.source,
        count=ns.count,
        out=ns.out,
        window_seconds=parse_window(ns.window),
        end=_parse_end(ns.end),
        seed=ns.seed,
        attack_scenario=ns.attack_scenario,
        attack_count=ns.attack_count,
        attack_offset=ns.attack_offset,
        allow_rate=ns.allow_rate,
        progress_every=ns.progress_every,
    )
    if ns.source == "all" and ns.out is not None and ns.out.suffix:
        parser.error("--out must be a directory when --source all")

    for name in requested:
        out_path = _resolve_out_path(name, ns.out, ns.count, multi=ns.source == "all")
        print(f"generating {name} -> {out_path}", file=sys.stderr)
        written = generate_one(name, out_path, args)
        print(f"  wrote {written:,} lines", file=sys.stderr)


if __name__ == "__main__":
    main()
