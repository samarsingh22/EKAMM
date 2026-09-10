"""The pluggable hand-off between listeners and the processing pipeline.

See :mod:`ulpf.ingest.buffer.base` for the :class:`BufferBackend` protocol and
:mod:`ulpf.ingest.buffer.kafka_buffer` for what Kafka buys over the in-process
default (topics/partitions/offsets/consumer groups, and why retention makes
replay-after-a-parser-fix possible).

:func:`build_buffer_backend` is the one place a config value
(``settings.buffer.backend``) turns into a concrete backend. ``aiokafka`` is
imported lazily, only on the ``"kafka"`` branch, so an in-process (default)
deployment never needs the optional ``ulpf[kafka]`` extra installed.
"""

from __future__ import annotations

from ulpf.config.settings import Settings
from ulpf.ingest.buffer.base import BufferBackend
from ulpf.ingest.buffer.in_process import InProcessBuffer

__all__ = ["BufferBackend", "InProcessBuffer", "build_buffer_backend"]


def build_buffer_backend(settings: Settings) -> BufferBackend:
    """Return the :class:`BufferBackend` selected by ``settings.buffer.backend``.

    ``"in_process"`` (the default) needs nothing further. ``"kafka"`` imports
    :mod:`ulpf.ingest.buffer.kafka_buffer` on demand — if the optional
    ``aiokafka`` dependency is not installed this raises a clear
    :class:`ImportError` naming the ``ulpf[kafka]`` extra, rather than a
    confusing failure deep inside module import machinery.
    """
    backend = settings.buffer.backend
    if backend == "in_process":
        return InProcessBuffer(settings)
    if backend == "kafka":
        from ulpf.ingest.buffer.kafka_buffer import KafkaBuffer

        return KafkaBuffer(settings)
    raise ValueError(
        f"unknown buffer backend {backend!r}"
    )  # pragma: no cover - Settings validates this
