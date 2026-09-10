# ULPF Perimeter Pipeline — Benchmark Report

_Generated 2026-09-10 23:19 UTC. Reproduce with:_

```
python bench/report.py --out docs/benchmarks.md --transport tcp
```

> **Single-node measurements only — never extrapolate to a cluster.** See [Caveats](#caveats).

## Hardware

| | |
|---|---|
| CPU | 12th Gen Intel(R) Core(TM) i5-12450H (12 cores) |
| RAM | 15.7 GB |
| OS | Windows 10 (AMD64) |

## Headline: throughput vs. a 1-billion-events/day target

A perimeter deployment ingesting **1,000,000,000 events/day** needs to sustain, on average:

    1,000,000,000 events / 86,400 seconds/day = 11,574 events/second, sustained

The best single-node **processed** throughput measured in this run was **200 events/sec** (`cisco_asa` @ 4 workers, integrity on, enrichment on) — **0.02x** below the 11,574 eps a 1B-events/day workload requires from a single node.

This says only that *one node, measured this way, on this machine* clears (or doesn't) that bar — see [Caveats](#caveats) for exactly what it does not say.

## Per-source-type throughput (1, 4 workers)

Integrity: on · Enrichment: on · transport: `tcp` · target rate: `200` eps · window: `20s` (+`5s` warm-up, excluded)

| source | workers | offered EPS | achieved EPS | processed EPS | p50 | p95 | p99 | parse coverage | completeness | peak RSS | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| aws_vpc_flow | 1 | 200 | 200 | 200 | 74.43 ms | 224.20 ms | 244.84 ms | 100.00% | 95.00% | 4.1 MB |  |
| aws_vpc_flow | 4 | 200 | 200 | 200 | 179.06 ms | 489.71 ms | 681.51 ms | 100.00% | 95.00% | 4.1 MB |  |
| cisco_asa | 1 | 200 | 200 | 200 | 658.16 ms | 2269.94 ms | 2453.99 ms | 100.00% | 95.00% | 4.1 MB |  |
| cisco_asa | 4 | 200 | 200 | 200 | 855.37 ms | 2328.52 ms | 2465.70 ms | 100.00% | 95.00% | 4.1 MB |  |
| fortigate_traffic | 1 | 200 | 200 | 200 | 1773.08 ms | 4552.77 ms | 4910.55 ms | 100.00% | 100.00% | 4.1 MB |  |
| fortigate_traffic | 4 | 200 | 200 | 200 | 83.14 ms | 229.44 ms | 245.89 ms | 100.00% | 100.00% | 4.1 MB |  |
| iptables | 1 | 200 | 200 | 200 | 76.20 ms | 225.98 ms | 245.20 ms | 100.00% | 100.00% | 4.1 MB |  |
| iptables | 4 | 200 | 200 | 200 | 111.75 ms | 239.89 ms | 327.59 ms | 100.00% | 100.00% | 4.1 MB |  |
| panos_traffic_v10 | 1 | 200 | 200 | 200 | 143.83 ms | 427.27 ms | 493.39 ms | 100.00% | 100.00% | 4.1 MB |  |
| panos_traffic_v10 | 4 | 200 | 200 | 200 | 923.77 ms | 2334.62 ms | 2466.92 ms | 100.00% | 100.00% | 4.1 MB |  |
| panos_traffic_v11 | 1 | 200 | 200 | 200 | 83.97 ms | 233.60 ms | 249.22 ms | 100.00% | 100.00% | 4.1 MB |  |
| panos_traffic_v11 | 4 | 200 | 200 | 200 | 143.98 ms | 362.26 ms | 472.45 ms | 100.00% | 100.00% | 4.1 MB |  |
| suricata_eve_alert | 1 | 200 | 200 | 200 | 92.72 ms | 234.73 ms | 248.01 ms | 100.00% | 75.00% | 4.2 MB |  |
| suricata_eve_alert | 4 | 200 | 200 | 200 | 126.43 ms | 391.77 ms | 478.35 ms | 100.00% | 75.00% | 4.1 MB |  |
| suricata_eve_flow | 1 | 200 | 200 | 200 | 86.34 ms | 232.04 ms | 246.41 ms | 100.00% | 90.00% | 4.1 MB |  |
| suricata_eve_flow | 4 | 200 | 200 | 200 | 95.02 ms | 234.13 ms | 246.95 ms | 100.00% | 90.00% | 4.1 MB |  |
| zeek_conn | 1 | 200 | 200 | 200 | 87.70 ms | 235.67 ms | 261.90 ms | 100.00% | 90.00% | 4.1 MB |  |
| zeek_conn | 4 | 200 | 200 | 200 | 89.79 ms | 232.60 ms | 246.52 ms | 100.00% | 90.00% | 4.1 MB |  |
| zeek_dns | 1 | 200 | 200 | 200 | 99.69 ms | 248.02 ms | 443.18 ms | 100.00% | 89.47% | 4.1 MB |  |
| zeek_dns | 4 | 200 | 200 | 200 | 91.13 ms | 232.99 ms | 246.60 ms | 100.00% | 89.47% | 4.1 MB |  |
| zeek_http | 1 | 200 | 200 | 200 | 469.26 ms | 956.65 ms | 992.59 ms | 100.00% | 100.00% | 4.1 MB |  |
| zeek_http | 4 | 200 | 200 | 200 | 299.43 ms | 701.83 ms | 827.59 ms | 100.00% | 100.00% | 4.1 MB |  |

## Overhead of optional features

_Isolated on `cisco_asa` @ 4 workers; one axis varied at a time from the same baseline._

### Integrity (signed Merkle ledger)

| integrity | achieved EPS | processed EPS | p50 | p95 | p99 | parse coverage | peak RSS |
|---|---|---|---|---|---|---|---|
| off | 200 | 196 | 628.17 ms | 2312.62 ms | 2462.52 ms | 98.22% | 4.1 MB |
| on | 200 | 200 | 855.37 ms | 2328.52 ms | 2465.70 ms | 100.00% | 4.1 MB |

- **throughput**: +1.8% with integrity on (vs. off)
- **p95 latency**: +0.7% with integrity on (vs. off)
- **peak RSS**: +0.4% with integrity on (vs. off)

### Enrichment (GeoIP / threat-intel / ATT&CK tagging / network context)

| enrichment | achieved EPS | processed EPS | p50 | p95 | p99 | parse coverage | peak RSS |
|---|---|---|---|---|---|---|---|
| off | 200 | 200 | 62.95 ms | 213.86 ms | 242.77 ms | 100.00% | 4.1 MB |
| on | 200 | 200 | 855.37 ms | 2328.52 ms | 2465.70 ms | 100.00% | 4.1 MB |

- **throughput**: +0.0% with enrichment on (vs. off)
- **p95 latency**: +988.8% with enrichment on (vs. off)
- **peak RSS**: +0.2% with enrichment on (vs. off)

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

## Method

- transport: `tcp`; target rate: `200` events/sec (paced, not blasted - see bench/replay.py)
- warm-up: `5s` (excluded from measurement); measurement window: `20s` per cell
- every reported figure is a *delta* between two `/metrics` scrapes of the server's own Prometheus counters/histograms, taken before and after the measurement window - not estimated or computed client-side
- latency percentiles: linear interpolation over `ulpf_end_to_end_latency_seconds`'s histogram buckets (Prometheus's own `histogram_quantile()` method), from ingest timestamp to the event finishing its last pipeline stage
- peak RSS: sampled from the `ulpf serve` process every 0.5s for the whole cell (`psutil`)
- each cell ran in its own freshly-started, isolated `ulpf serve` subprocess (own bronze/silver/DLQ/ledger/state directories); matrix total wall-clock time: 891s (14.9 min) for 24 cells
- integrity-on cells used a throwaway Ed25519 keypair generated for this run only

