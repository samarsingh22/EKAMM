"""Tests for :mod:`ulpf.ml.drift` — template-rate drift detection.

The two headline scenarios: a rare template that suddenly spikes, and a
common template that drops to silence (an attacker or a fault killing a log
stream that volume monitoring would never notice).
"""

from __future__ import annotations

import pytest

from ulpf.config.settings import Settings, StorageSettings
from ulpf.ml.drift import DriftSignal, TemplateDriftDetector
from ulpf.parse.templates.store import TemplateStore

_KEY = ("acme_fw", "7")
_TEMPLATE = "GET <*> HTTP/1.1 <*>"
_SAMPLES = ["GET /index.html HTTP/1.1 200", "GET /login HTTP/1.1 302"]
_WINDOW = 5.0  # minutes


def _feed_baseline(det: TemplateDriftDetector, count: int, windows: int) -> None:
    """Drive `windows` identical windows through the detector to settle a baseline."""
    for _ in range(windows):
        det.update(
            _WINDOW,
            {_KEY: count},
            templates={_KEY: _TEMPLATE},
            sample_lines={_KEY: _SAMPLES},
        )


# ---------------------------------------------------------------------------
# simulated spike
# ---------------------------------------------------------------------------


def test_rare_template_spike_fires() -> None:
    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=3)
    _feed_baseline(det, count=2, windows=8)  # ~0.4 events/min, dead steady

    signals = det.update(_WINDOW, {_KEY: 80}, templates={_KEY: _TEMPLATE})

    assert len(signals) == 1
    sig = signals[0]
    assert isinstance(sig, DriftSignal)
    assert sig.direction == "spike"
    assert sig.z_score > 3.0
    assert sig.observed == 80
    assert sig.current_rate == pytest.approx(16.0)
    assert sig.baseline_rate == pytest.approx(0.4)
    assert sig.template == _TEMPLATE
    assert sig.sample_lines == _SAMPLES


def test_steady_traffic_never_fires() -> None:
    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=3)
    counts = [10, 11, 9, 10, 12, 8, 10, 11, 9, 10, 10, 11, 9]
    fired: list[DriftSignal] = []
    for n in counts:
        fired += det.update(_WINDOW, {_KEY: n}, templates={_KEY: _TEMPLATE})
    assert fired == []


def test_spike_inside_warmup_is_only_learned_not_flagged() -> None:
    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=5)
    _feed_baseline(det, count=2, windows=2)  # still within warmup
    signals = det.update(_WINDOW, {_KEY: 200}, templates={_KEY: _TEMPLATE})
    assert signals == []
    # ...and the huge window was folded into the baseline instead.
    learned = det.baseline_rate(_KEY)
    assert learned is not None and learned > 2.0


# ---------------------------------------------------------------------------
# simulated silence
# ---------------------------------------------------------------------------


def test_common_template_dropping_to_zero_fires_drop() -> None:
    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=3)
    _feed_baseline(det, count=500, windows=6)  # 100 events/min, well established

    # The template produces nothing this window — not even present in `counts`.
    signals = det.update(_WINDOW, {}, templates={})

    assert len(signals) == 1
    sig = signals[0]
    assert sig.direction == "drop"
    assert sig.z_score < -3.0
    assert sig.observed == 0
    assert sig.current_rate == 0.0
    assert sig.baseline_rate == pytest.approx(100.0)
    # historical examples of the now-silent template are still attached
    assert sig.sample_lines == _SAMPLES


def test_silence_keeps_firing_while_it_lasts_when_frozen() -> None:
    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=3, freeze_on_signal=True)
    _feed_baseline(det, count=500, windows=6)

    fired = [len(det.update(_WINDOW, {})) for _ in range(15)]
    assert all(n == 1 for n in fired)  # every silent window still screams
    assert det.baseline_rate(_KEY) == pytest.approx(100.0)  # baseline never decayed


def test_without_freeze_the_baseline_decays_and_silence_goes_quiet() -> None:
    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=3, freeze_on_signal=False)
    _feed_baseline(det, count=500, windows=6)

    fired = [len(det.update(_WINDOW, {})) for _ in range(15)]
    assert fired[0] == 1  # first silent window is caught
    assert fired[-1] == 0  # but the EWMA has since decayed to meet the silence
    decayed = det.baseline_rate(_KEY)
    assert decayed is not None and decayed < 5.0


# ---------------------------------------------------------------------------
# store-backed detect()
# ---------------------------------------------------------------------------


def _settings(tmp_path) -> Settings:
    return Settings(storage=StorageSettings(state_path=tmp_path / "state"))


def test_detect_reads_counts_from_the_template_store(tmp_path) -> None:
    clk = [1_000 * _minute_ns()]
    store = TemplateStore(_settings(tmp_path), clock=lambda: clk[0])
    for line in ("conn from 10.0.0.1", "conn from 10.0.0.2", "conn from 10.0.0.9"):
        store.record(4, "conn from <*>", "edge_fw", line)
    key = ("edge_fw", "4")

    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=3)
    for _ in range(6):
        det.update(1.0, {key: 200}, templates={key: "conn from <*>"})

    # Jump far past the window: none of the 3 recorded timestamps fall inside it.
    later = clk[0] + 30 * _minute_ns()
    signals = det.detect(window_minutes=1.0, store=store, now_ns=later)

    assert len(signals) == 1
    assert signals[0].direction == "drop"
    assert signals[0].template == "conn from <*>"
    assert signals[0].sample_lines[0] == "conn from 10.0.0.1"


def test_detect_counts_only_occurrences_inside_the_window(tmp_path) -> None:
    minute = _minute_ns()
    clk = [500 * minute]
    store = TemplateStore(_settings(tmp_path), clock=lambda: clk[0])
    key = ("edge_fw", "4")

    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=1)
    det.update(1.0, {key: 3})  # seed a tiny baseline (3/min)
    det.update(1.0, {key: 3})

    clk[0] += 10 * minute
    for _ in range(40):  # a burst, all stamped "now"
        store.record(4, "conn from <*>", "edge_fw", "conn from 10.0.0.1")

    signals = det.detect(window_minutes=1.0, store=store, now_ns=clk[0])
    assert len(signals) == 1
    assert signals[0].direction == "spike"
    assert signals[0].observed == 40


# ---------------------------------------------------------------------------
# snapshot / restore + validation
# ---------------------------------------------------------------------------


def test_snapshot_restore_round_trip_reproduces_signals() -> None:
    det = TemplateDriftDetector(z_threshold=3.0, warmup_windows=3)
    _feed_baseline(det, count=500, windows=6)

    restored = TemplateDriftDetector.restore(det.snapshot())
    assert restored.baseline_rate(_KEY) == pytest.approx(det.baseline_rate(_KEY))

    a = det.update(_WINDOW, {})
    b = restored.update(_WINDOW, {})
    assert [s.to_dict() for s in a] == [s.to_dict() for s in b]


def test_signal_to_dict_has_the_documented_keys() -> None:
    det = TemplateDriftDetector(warmup_windows=3)
    _feed_baseline(det, count=2, windows=6)
    sig = det.update(_WINDOW, {_KEY: 90}, templates={_KEY: _TEMPLATE})[0].to_dict()
    for k in (
        "template_id",
        "template",
        "baseline_rate",
        "current_rate",
        "z_score",
        "direction",
        "sample_lines",
    ):
        assert k in sig


def test_constructor_and_update_validate_inputs() -> None:
    with pytest.raises(ValueError, match="alpha"):
        TemplateDriftDetector(alpha=0.0)
    with pytest.raises(ValueError, match="alpha"):
        TemplateDriftDetector(alpha=1.5)
    with pytest.raises(ValueError, match="z_threshold"):
        TemplateDriftDetector(z_threshold=0.0)
    with pytest.raises(ValueError, match="window_minutes"):
        TemplateDriftDetector().update(0.0, {})
    with pytest.raises(ValueError, match="store= or settings="):
        TemplateDriftDetector().detect()


def _minute_ns() -> int:
    return 60_000_000_000
