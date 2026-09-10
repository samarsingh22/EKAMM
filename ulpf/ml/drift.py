"""Template-rate drift detection — built on ULPF's own Drain3 template catalog.

Why this instead of a generic anomaly library: the signal here is *our
parser's* output. :class:`~ulpf.parse.templates.store.TemplateStore` already
clusters every unstructured perimeter line into a stable template and stamps
each occurrence with a timestamp. Watching how each template's *rate* moves
against its own rolling baseline turns that catalog into a detector with no
model to train and no features to engineer — and every alert points straight
back at a concrete log shape with real sample lines an analyst can read.

Two cases it is built to catch:

* **A rare template spiking.** A shape that normally trickles — a handful of
  events an hour — suddenly firing hundreds of times: a new scan signature, a
  device melting down, a misconfiguration that just shipped.
* **A common template dropping to zero.** The one that matters most. If a
  firewall's "connection allowed" line normally lands 200 times a minute and
  now lands zero, volume-based monitoring just sees *less* data and stays
  quiet — an attacker who disables or filters logging is invisible to it.
  Here it is the loudest possible signal: a large negative z-score against a
  well-established baseline.

METHOD
------
Per template, an exponentially weighted moving average of its per-minute rate
is the baseline. Each :meth:`TemplateDriftDetector.detect` (or
:meth:`~TemplateDriftDetector.update`) call takes one window's observed count,
and the deviation is a Poisson z-score on counts —
``z = (observed - expected) / sqrt(expected)`` with
``expected = baseline_rate * window_minutes`` — the same rate model
:mod:`ulpf.api.routes.templates`' ``GET /drift`` uses, so the number an
analyst sees on the dashboard and the number that fires an alert are computed
the same way. ``|z| >= z_threshold`` (default 3.0) fires: ``spike`` above,
``drop`` below.

A template that fires keeps its baseline **frozen** for that window
(``freeze_on_signal``, default on), so a logging outage stays flagged for as
long as it lasts instead of the EWMA quietly decaying the baseline down to
meet the silence.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from ulpf.config.settings import Settings
from ulpf.parse.templates.store import TemplateStore

# (source_id, template_id) — a Drain3 cluster id is unique only within one
# source's parse tree, so both halves are needed to key a template globally.
TemplateKey = tuple[str, str]

_DEFAULT_Z_THRESHOLD = 3.0
_DEFAULT_ALPHA = 0.3
_DEFAULT_WARMUP_WINDOWS = 3
_DEFAULT_WINDOW_MINUTES = 5.0
_NS_PER_MINUTE = 60_000_000_000


@dataclass(frozen=True)
class DriftSignal:
    """One template whose current-window rate broke from its rolling baseline."""

    template_id: str
    source_id: str
    template: str
    baseline_rate: float  # EWMA events/minute, as it stood before this window
    current_rate: float  # observed events/minute this window
    z_score: float
    direction: str  # "spike" | "drop"
    observed: int
    expected: float
    window_minutes: float
    sample_lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """The signal as a plain dict (for JSON / the dashboard)."""
        return asdict(self)


class TemplateDriftDetector:
    """Rolling per-template rate baselines with spike / silence detection.

    Stateful: feed it one window at a time in order, via :meth:`detect` (reads
    the live template catalog) or :meth:`update` (explicit counts, for tests
    and replay). Not thread-safe — a single owner drives it.
    """

    def __init__(
        self,
        *,
        z_threshold: float = _DEFAULT_Z_THRESHOLD,
        alpha: float = _DEFAULT_ALPHA,
        warmup_windows: int = _DEFAULT_WARMUP_WINDOWS,
        freeze_on_signal: bool = True,
        clock: Callable[[], int] = time.time_ns,
    ) -> None:
        """Configure the detector.

        Args:
            z_threshold: ``|z|`` at or above which a window fires. Default 3.0.
            alpha: EWMA weight on the newest window, in ``(0, 1]`` — higher
                adapts faster and forgets sooner. Default 0.3.
            warmup_windows: windows folded into a template's baseline before it
                is eligible to fire, so a half-formed baseline cannot alert.
            freeze_on_signal: when a template fires, leave its baseline
                untouched for that window (keeps an outage flagged instead of
                decaying the baseline toward the silence).
            clock: UTC epoch-nanoseconds source (injectable for tests).
        """
        if not 0.0 < alpha <= 1.0:
            raise ValueError(f"alpha must be in (0, 1], got {alpha}")
        if z_threshold <= 0.0:
            raise ValueError(f"z_threshold must be positive, got {z_threshold}")
        self.z_threshold = z_threshold
        self.alpha = alpha
        self.warmup_windows = max(1, warmup_windows)
        self.freeze_on_signal = freeze_on_signal
        self._clock = clock
        self._baseline: dict[TemplateKey, float] = {}  # events per minute
        self._windows: dict[TemplateKey, int] = {}  # windows folded into baseline
        self._templates: dict[TemplateKey, str] = {}  # latest template text
        self._samples: dict[TemplateKey, list[str]] = {}  # latest stored examples

    # -- public API -----------------------------------------------------

    def detect(
        self,
        window_minutes: float = _DEFAULT_WINDOW_MINUTES,
        *,
        store: TemplateStore | None = None,
        settings: Settings | None = None,
        now_ns: int | None = None,
    ) -> list[DriftSignal]:
        """Pull one window's per-template counts from the catalog and score them.

        Pass a ready ``store`` or ``settings`` to open one. Every template the
        catalog knows is counted — a template with no occurrence in the window
        scores zero, which is exactly how a gone-silent template is caught.
        Returned signals are sorted by ``|z_score|`` descending.
        """
        if store is None:
            if settings is None:
                raise ValueError("detect() needs either store= or settings=")
            store = TemplateStore(settings)
        now = self._clock() if now_ns is None else now_ns
        window_start = now - int(window_minutes * _NS_PER_MINUTE)

        counts: dict[TemplateKey, int] = {}
        templates: dict[TemplateKey, str] = {}
        samples: dict[TemplateKey, list[str]] = {}
        for row in store.list_templates(order_by="count"):
            key = (row["source_id"], row["template_id"])
            recent = row.get("recent_ns", [])
            counts[key] = sum(1 for ts in recent if window_start <= ts <= now)
            templates[key] = row["template"]
            samples[key] = list(row.get("sample_lines", []))
        return self.update(window_minutes, counts, templates=templates, sample_lines=samples)

    def update(
        self,
        window_minutes: float,
        counts: Mapping[TemplateKey, int],
        *,
        templates: Mapping[TemplateKey, str] | None = None,
        sample_lines: Mapping[TemplateKey, list[str]] | None = None,
    ) -> list[DriftSignal]:
        """Score one window's observed counts, then fold them into each baseline.

        Every template seen so far is evaluated, not just the keys in
        ``counts`` — a missing key counts as zero. ``templates`` and
        ``sample_lines`` refresh the text/examples carried on any signal.
        """
        if window_minutes <= 0.0:
            raise ValueError(f"window_minutes must be positive, got {window_minutes}")
        templates = templates or {}
        sample_lines = sample_lines or {}

        signals: list[DriftSignal] = []
        for key in sorted(set(self._baseline) | set(counts)):
            if key in templates:
                self._templates[key] = templates[key]
            if sample_lines.get(key):
                self._samples[key] = list(sample_lines[key])

            observed = int(counts.get(key, 0))
            observed_rate = observed / window_minutes
            baseline_rate = self._baseline.get(key)
            if baseline_rate is None:  # first sighting — seed, nothing to compare
                self._baseline[key] = observed_rate
                self._windows[key] = 1
                continue

            windows_seen = self._windows.get(key, 0)
            signal = None
            if windows_seen >= self.warmup_windows:
                signal = self._score(key, window_minutes, observed, observed_rate, baseline_rate)
            if signal is not None:
                signals.append(signal)

            if not (signal is not None and self.freeze_on_signal):
                self._baseline[key] = (
                    self.alpha * observed_rate + (1.0 - self.alpha) * baseline_rate
                )
                self._windows[key] = windows_seen + 1

        signals.sort(key=lambda s: abs(s.z_score), reverse=True)
        return signals

    def baseline_rate(self, key: TemplateKey) -> float | None:
        """Current EWMA rate (events/minute) for ``key``, or ``None`` if unseen."""
        return self._baseline.get(key)

    def snapshot(self) -> dict[str, Any]:
        """Serializable state — persist this so a restart keeps its baselines."""
        return {
            "params": {
                "z_threshold": self.z_threshold,
                "alpha": self.alpha,
                "warmup_windows": self.warmup_windows,
                "freeze_on_signal": self.freeze_on_signal,
            },
            "templates": [
                {
                    "source_id": source_id,
                    "template_id": template_id,
                    "baseline_rate": rate,
                    "windows": self._windows.get((source_id, template_id), 0),
                    "template": self._templates.get((source_id, template_id), ""),
                    "sample_lines": self._samples.get((source_id, template_id), []),
                }
                for (source_id, template_id), rate in self._baseline.items()
            ],
        }

    @classmethod
    def restore(
        cls, state: Mapping[str, Any], *, clock: Callable[[], int] = time.time_ns
    ) -> TemplateDriftDetector:
        """Rebuild a detector from :meth:`snapshot` output."""
        detector = cls(clock=clock, **dict(state.get("params", {})))
        for row in state.get("templates", []):
            key = (row["source_id"], row["template_id"])
            detector._baseline[key] = float(row["baseline_rate"])
            detector._windows[key] = int(row.get("windows", 0))
            if row.get("template"):
                detector._templates[key] = row["template"]
            if row.get("sample_lines"):
                detector._samples[key] = list(row["sample_lines"])
        return detector

    # -- internals -----------------------------------------------------

    def _score(
        self,
        key: TemplateKey,
        window_minutes: float,
        observed: int,
        observed_rate: float,
        baseline_rate: float,
    ) -> DriftSignal | None:
        """Poisson z-score of ``observed`` against the baseline; ``None`` if within threshold."""
        expected = baseline_rate * window_minutes
        if expected <= 0.0:
            # No established rate: a Poisson z-score is undefined, and a first
            # burst is "new template" territory, not drift. Stay silent.
            return None
        z = (observed - expected) / math.sqrt(expected)
        if abs(z) < self.z_threshold:
            return None
        return DriftSignal(
            template_id=key[1],
            source_id=key[0],
            template=self._templates.get(key, ""),
            baseline_rate=round(baseline_rate, 6),
            current_rate=round(observed_rate, 6),
            z_score=round(z, 4),
            direction="spike" if z > 0.0 else "drop",
            observed=observed,
            expected=round(expected, 4),
            window_minutes=window_minutes,
            sample_lines=list(self._samples.get(key, [])),
        )
