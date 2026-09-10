"""Application settings for ULPF.

Settings load from ``configs/ulpf.yaml`` and may be overridden by environment
variables prefixed with ``ULPF_``. Nested sections use a double-underscore
delimiter, e.g. ``ULPF_INGEST__SYSLOG_UDP_PORT=1514``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _REPO_ROOT / "configs" / "ulpf.yaml"
_RUNTIME_DIR = Path("data/runtime")


class IngestSettings(BaseModel):
    """Network listener ports and intake queue bounds."""

    syslog_udp_port: int = 514
    # UDP syslog is lossy under burst: the kernel receive buffer is finite and
    # unread datagrams are silently dropped once it fills, with no signal to
    # either side that it happened (see ulpf/ingest/syslog_udp.py). Raising
    # SO_RCVBUF gives the kernel more headroom to absorb a burst before a
    # slow-to-drain queue starts dropping datagrams; it does not make UDP
    # lossless. CLAUDE.md: benchmark and verification runs must use TCP.
    syslog_udp_recv_buffer_bytes: int = 4 * 1024 * 1024
    syslog_tcp_port: int = 514
    syslog_tls_port: int = 6514
    http_port: int = 8081
    http_max_body_bytes: int = 8 * 1024 * 1024
    queue_max_size: int = 100_000
    file_tail_paths: list[str] = Field(default_factory=list)


class StorageSettings(BaseModel):
    """Filesystem locations for pipeline output, all under ``data/runtime/``."""

    bronze_path: Path = _RUNTIME_DIR / "bronze"
    silver_path: Path = _RUNTIME_DIR / "silver"
    dlq_path: Path = _RUNTIME_DIR / "dlq"
    ledger_path: Path = _RUNTIME_DIR / "ledger"
    state_path: Path = _RUNTIME_DIR / "state"


class ParseSettings(BaseModel):
    """Parser onboarding directory and per-parse limits."""

    sources_dir: Path = Path("configs/sources")
    hot_reload: bool = True
    grok_timeout_ms: int = 100


class IntegritySettings(BaseModel):
    """Cryptographic integrity (hash chain / Merkle) batching controls.

    A batch of raw-event hashes is sealed into the signed ledger when it reaches
    ``batch_size`` events **or** ``batch_timeout_seconds`` elapse, whichever
    comes first. ``signing_key_path`` is the Ed25519 private key
    (``ulpf keys generate``); with no key the integrity stage self-disables.
    """

    enabled: bool = True
    batch_size: int = 1000
    batch_timeout_seconds: float = 10.0
    signing_key_path: Path | None = None
    # Public key for `ulpf verify` (an auditor need not hold the private key).
    # Falls back to the public half of signing_key_path when unset.
    public_key_path: Path | None = None


class EnrichSettings(BaseModel):
    """Enrichment data sources and the hard per-enricher time budget.

    Paths are optional (an enricher with no data falls back to a no-op).
    ``timeout_ms`` is the wall-clock ceiling for a single enricher on a single
    event; overrunning it skips that enricher for that event (never blocks the
    hot path).
    """

    geoip_db_path: Path | None = None
    geoip_asn_db_path: Path | None = None
    ioc_path: Path | None = None
    ioc_dir: Path = Path("configs/iocs")
    assets_path: Path = Path("configs/assets.yaml")
    attack_map_path: Path = Path("configs/attack_map.yaml")
    enabled: bool = True
    timeout_ms: int = 50

    # Per-enricher toggles (all no-ops when ``enabled`` is False).
    network_context: bool = True
    geoip: bool = True
    threat_intel: bool = True
    attack_tagger: bool = True


class PipelineSettings(BaseModel):
    """Worker fan-out and batch sizing for the processing pipeline."""

    worker_count: int = 4
    batch_size: int = 500


class BufferSettings(BaseModel):
    """Selects and configures the hand-off between listeners and the pipeline.

    ``backend="in_process"`` (the default) is a single bounded ``asyncio.Queue``
    living inside this process — zero external services, matching ULPF's
    air-gap-by-default posture (CLAUDE.md: "no network calls at runtime in the
    hot path"). ``backend="kafka"`` durably persists every raw event to a Kafka
    topic before the pipeline consumes it — see
    :mod:`ulpf.ingest.buffer.kafka_buffer`'s module docstring for what that
    buys (replay after a parser fix, several pipeline processes sharing one
    consumer group) and what it costs (an external service, an extra hop).

    The ``kafka_*`` fields are only read when ``backend == "kafka"``; they stay
    inert (and ``aiokafka`` stays uninstalled, if the optional ``ulpf[kafka]``
    extra was never added) otherwise.
    """

    backend: Literal["in_process", "kafka"] = "in_process"

    # producer + consumer: where and what
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic: str = "ulpf.raw"
    kafka_partitions: int = 6
    kafka_replication_factor: int = 1

    # producer tuning: how much to batch before a send, and how long to wait
    # for a batch to fill (see kafka_buffer.py's docstring for the trade-off).
    kafka_batch_size: int = 16_384  # bytes, aiokafka's `max_batch_size`
    kafka_linger_ms: int = 20
    kafka_acks: str = "all"  # "0" | "1" | "all" — "all" waits for every in-sync replica

    # consumer: the group this process joins, and how it reads
    kafka_consumer_group: str = "ulpf-pipeline"
    kafka_max_poll_records: int = 500
    kafka_auto_offset_reset: Literal["earliest", "latest"] = "earliest"


class MlSettings(BaseModel):
    """Anomaly-detection model location, the anomalies lake, and the scoring loop.

    ``model_path`` is a single joblib file (see :mod:`ulpf.ml.anomaly`).
    ``anomalies_path`` is a third Parquet tier — Hive-partitioned ``date=`` by
    the event's own time, like silver — holding per-event scores and top-3
    explanations, joinable back to silver/bronze/the signed ledger by
    ``event_uid``. ``scoring_enabled`` turns on a background task
    (:class:`~ulpf.ml.jobs.AnomalyScoringLoop`, owned by the runtime) that
    re-scores the last ``scoring_window_minutes`` every
    ``scoring_interval_seconds``. ``drift_state_path`` persists the EWMA
    template-rate baseline between ``GET /api/v1/anomalies/drift`` calls.
    """

    model_path: Path = _RUNTIME_DIR / "models" / "anomaly.joblib"
    anomalies_path: Path = _RUNTIME_DIR / "anomalies"
    drift_state_path: Path = _RUNTIME_DIR / "state" / "drift_baseline.json"
    contamination: float | str = 0.02
    scoring_enabled: bool = False
    scoring_interval_seconds: float = 60.0
    scoring_window_minutes: float = 5.0
    drift_window_minutes: float = 5.0
    drift_z_threshold: float = 3.0


class TlsSettings(BaseModel):
    """TLS material for the RFC 5425 syslog-over-TLS listener (port 6514)."""

    cert_path: Path | None = None
    key_path: Path | None = None
    client_ca_path: Path | None = None
    require_client_cert: bool = False
    minimum_version: str = "TLSv1_2"


class ApiSettings(BaseModel):
    """FastAPI bind address for the management/query API (``ulpf serve``)."""

    host: str = "0.0.0.0"
    port: int = 8080
    # the Vite dev server's default origin(s); override for a deployed UI
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )


class ClickHouseSettings(BaseModel):
    """Optional ClickHouse sink over its HTTP interface (disabled by default).

    When ``enabled`` is False the pipeline runs on the Parquet lake + DuckDB
    alone. Batched inserts flush at ``batch_rows`` **or** ``batch_seconds``;
    failures retry with exponential backoff up to ``max_retries``, and once
    ClickHouse has been unreachable for ``unavailable_backpressure_seconds`` the
    sink blocks writers (backpressure) instead of dropping — anything still
    undelivered at shutdown is spooled to ``storage.state_path``.
    """

    enabled: bool = False
    url: str = "http://localhost:8123"
    database: str = "ulpf"
    table: str = "events"
    user: str = "default"
    password: str = ""
    batch_rows: int = 5000
    batch_seconds: float = 5.0
    max_buffer_rows: int = 50_000
    max_retries: int = 6
    backoff_base_seconds: float = 0.5
    backoff_max_seconds: float = 30.0
    request_timeout_seconds: float = 10.0
    unavailable_backpressure_seconds: float = 60.0


class OpenSearchSettings(BaseModel):
    """Optional OpenSearch/Elasticsearch sink for the ECS crosswalk (disabled by default).

    This is a **best-effort export**, not a system of record — unlike
    :class:`ClickHouseSettings` it never blocks the pipeline. If the cluster is
    unreachable at :meth:`~ulpf.sinks.opensearch_sink.OpenSearchSink.start` the
    sink logs a warning and disables itself for the run; if a batch still fails
    after ``max_retries`` it is logged and dropped rather than backing up.
    """

    enabled: bool = False
    url: str = "http://localhost:9200"
    index_prefix: str = "ulpf-ecs"
    user: str | None = None
    password: str | None = None
    api_key: str | None = None
    verify_tls: bool = True
    batch_docs: int = 500
    batch_seconds: float = 5.0
    max_retries: int = 3
    backoff_base_seconds: float = 0.5
    backoff_max_seconds: float = 10.0
    request_timeout_seconds: float = 10.0


class SplunkHecSettings(BaseModel):
    """Optional Splunk HTTP Event Collector sink for the CIM crosswalk (disabled by default).

    A **best-effort export** like :class:`OpenSearchSettings`: self-disables if
    unreachable at startup, and drops (with a log) a batch that still fails
    after ``max_retries`` rather than blocking the pipeline.
    """

    enabled: bool = False
    url: str = "https://localhost:8088"
    token: str = ""
    source: str = "ulpf"
    host: str = "ulpf"
    index: str | None = None
    verify_tls: bool = True
    batch_events: int = 100
    batch_seconds: float = 5.0
    max_retries: int = 3
    backoff_base_seconds: float = 0.5
    backoff_max_seconds: float = 10.0
    request_timeout_seconds: float = 10.0


class Settings(BaseSettings):
    """Root settings object aggregating every configuration section."""

    model_config = SettingsConfigDict(
        env_prefix="ULPF_",
        env_nested_delimiter="__",
        yaml_file=_CONFIG_PATH,
        extra="ignore",
    )

    ingest: IngestSettings = Field(default_factory=IngestSettings)
    tls: TlsSettings = Field(default_factory=TlsSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    parse: ParseSettings = Field(default_factory=ParseSettings)
    integrity: IntegritySettings = Field(default_factory=IntegritySettings)
    enrich: EnrichSettings = Field(default_factory=EnrichSettings)
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    buffer: BufferSettings = Field(default_factory=BufferSettings)
    ml: MlSettings = Field(default_factory=MlSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    clickhouse: ClickHouseSettings = Field(default_factory=ClickHouseSettings)
    opensearch: OpenSearchSettings = Field(default_factory=OpenSearchSettings)
    splunk_hec: SplunkHecSettings = Field(default_factory=SplunkHecSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order sources so env vars win over the YAML file, which wins over defaults."""
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings`, built once and cached.

    Call ``get_settings.cache_clear()`` to force a reload (used by tests).
    """
    return Settings()
