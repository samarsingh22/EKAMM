"""Phase-7 end-to-end: the auto-parser loop, headline test.

A completely novel perimeter format — a fictional "AcmeGuard" firewall,
invented for this test and shipped with no hand-written YAML anywhere in this
repo — proves the full onboarding loop with **zero hand-written parsing
code**:

1. 500 AcmeGuard lines are generated.
2. Fed through the real pipeline (:class:`~ulpf.normalize.stage.NormalizeStage`):
   with no source definition matching, every one still lands as a
   ``unknown:<template_id>`` OCSF skeleton — never dead-lettered, never lost
   (requirement a).
3. :func:`~ulpf.parse.templates.suggest.suggest_source_definition` drafts a
   complete YAML definition from those same 500 lines.
4. :func:`~ulpf.parse.templates.score.score_suggestion` measures the draft
   against its own samples — ``parse_rate`` clears 90%.
5. The YAML is written straight into the live ``sources_dir`` (standing in
   for ``configs/sources/``) at runtime; the registry's hot-reload watcher
   (:meth:`~ulpf.parse.dsl.loader.SourceRegistry.start_watching`) picks it up
   with no restart (requirement e).
6. The *same* 500 lines are re-run through the *same* pipeline: this time
   every one matches the new definition by name and normalizes to a real
   OCSF 4001 record with completeness well above the class's bare minimum.
7. The wall-clock time from "have 500 unmapped lines" to "fully onboarded and
   re-normalized" is measured and printed — the new-source-onboarding-time
   KPI for the presentation.

This is requirement (i) (reduced parser development effort) demonstrated on
a source nobody has ever configured, start to finish, in one test.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import yaml

from ulpf.config.settings import ParseSettings, PipelineSettings, Settings, StorageSettings
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.stage import NormalizeStage
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.templates.score import score_suggestion
from ulpf.parse.templates.suggest import suggest_source_definition
from ulpf.sinks.dlq import DeadLetterQueue

_REPO = Path(__file__).resolve().parent.parent
_SOURCE_ID = "acmeguard-1"
_N = 500
_HOT_RELOAD_TIMEOUT_S = 5.0


def _acmeguard_lines(n: int) -> list[str]:
    """``n`` lines of a fictional AcmeGuard firewall - a format ULPF has never seen.

    ``key=value`` shaped (like FortiGate/pfSense), with one free-text verdict
    word (``ALLOW``/``DENY``) and everything else a mask already covers (two
    IPs, two ports, two growing byte counters) - realistic, and entirely
    unrelated to any file in ``configs/sources/``.
    """
    lines = []
    for i in range(n):
        minute, second = divmod(i, 60)
        lines.append(
            f"<134>Sep 15 09:{minute % 60:02d}:{second:02d} acmeguard-01 AGUARD: "
            f"verdict={'ALLOW' if i % 4 else 'DENY'} "
            f"srcip=10.44.{i % 50}.{i % 254 + 1} srcport={40000 + i} "
            f"dstip=203.0.113.{i % 20 + 1} dstport=443 "
            f"proto=tcp sentbyte={200 + i * 31} rcvdbyte={100 + i * 17} zone=WAN-LAN"
        )
    return lines


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            state_path=tmp_path / "state",
        ),
        parse=ParseSettings(sources_dir=tmp_path / "sources"),
        pipeline=PipelineSettings(worker_count=1),
    )


async def _normalize_all(
    lines: list[str], stage: NormalizeStage, coordinator: ParseCoordinator
) -> list:
    """Run every line through parse -> normalize; never ``None`` (see requirement a)."""
    results = []
    for line in lines:
        raw = make_raw_event(line.encode(), source_id=_SOURCE_ID, transport="udp")
        parsed = coordinator.parse(raw)
        normalized = await stage.process(parsed)
        assert normalized is not None, f"event dropped: {line}"
        results.append(normalized)
    return results


async def test_phase7_autoparser_onboards_a_never_before_seen_format_end_to_end(
    tmp_path: Path, capsys
) -> None:
    settings = _settings(tmp_path)
    settings.parse.sources_dir.mkdir(parents=True, exist_ok=True)
    lines = _acmeguard_lines(_N)

    registry = SourceRegistry()
    registry.load_all(settings.parse.sources_dir)  # empty: AcmeGuard has no YAML anywhere
    coordinator = ParseCoordinator()
    normalize_stage = NormalizeStage(settings, registry)

    # ------------------------------------------------------------------
    # 1 & 2. feed the pipeline: every line lands as unknown:<template_id>,
    #        nothing is dead-lettered or otherwise lost
    # ------------------------------------------------------------------
    before = await _normalize_all(lines, normalize_stage, coordinator)
    assert len(before) == _N
    for event in before:
        assert event.source_type.startswith("unknown:")
        assert event.ocsf["class_uid"] == 4001  # still a real OCSF skeleton
    assert DeadLetterQueue(settings).stats()["total"] == 0  # requirement (a): nothing lost

    onboarding_start = time.perf_counter()

    # ------------------------------------------------------------------
    # 3. suggest a complete source definition from those same 500 lines
    # ------------------------------------------------------------------
    yaml_text = suggest_source_definition(
        _SOURCE_ID, sample_lines=lines, vendor="AcmeCorp", product="AcmeGuard"
    )
    definition = load_source_definition(yaml.safe_load(yaml_text))  # must already be valid

    # this vendor really has no hand-written YAML in the repo
    real_sources = _REPO / "configs" / "sources"
    if real_sources.is_dir():
        assert not any("acmeguard" in p.stem for p in real_sources.glob("*.yaml"))

    # ------------------------------------------------------------------
    # 4. score the draft against its own samples
    # ------------------------------------------------------------------
    score = score_suggestion(yaml_text, lines)
    assert score.parse_rate > 0.9, (score.parse_rate, score.warnings)

    # ------------------------------------------------------------------
    # 5. write it into the live sources_dir; wait for the hot-reload watcher
    # ------------------------------------------------------------------
    out_path = settings.parse.sources_dir / f"{definition.name}.yaml"
    registry.start_watching()
    try:
        out_path.write_text(yaml_text, encoding="utf-8")
        deadline = time.monotonic() + _HOT_RELOAD_TIMEOUT_S
        while registry.get(definition.name) is None and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
    finally:
        registry.stop_watching()
    assert registry.get(definition.name) is not None, "hot reload did not pick up the new file"

    # ------------------------------------------------------------------
    # 6. re-run the SAME 500 lines: now they normalize to real OCSF 4001
    #    under the generated source_type, not "unknown:*"
    # ------------------------------------------------------------------
    validator = OcsfValidator(record_metrics=False)
    after = await _normalize_all(lines, normalize_stage, coordinator)
    completeness_scores = []
    for event in after:
        assert event.source_type == definition.name
        assert event.ocsf["class_uid"] == 4001
        completeness_scores.append(validator.validate(event.ocsf).completeness)
    avg_completeness = sum(completeness_scores) / len(completeness_scores)
    assert avg_completeness > 0.6
    assert DeadLetterQueue(settings).stats()["total"] == 0  # still nothing lost, second pass too

    # ------------------------------------------------------------------
    # 7. the onboarding-time KPI: suggest -> scored -> hot-reloaded -> re-normalized
    # ------------------------------------------------------------------
    onboarding_elapsed_s = time.perf_counter() - onboarding_start
    summary = (
        "AUTO-PARSER ONBOARDING KPI (phase 7)\n"
        f"  source                 : {_SOURCE_ID} (AcmeGuard - a format ULPF ships no YAML for)\n"
        f"  samples                : {_N}\n"
        f"  generated definition   : {definition.name}  (engine={definition.parse.engine})\n"
        f"  score.parse_rate       : {score.parse_rate:8.1%}\n"
        f"  score.completeness     : {score.completeness:8.1%}\n"
        f"  score.confidence       : {score.confidence:8.1%}\n"
        f"  post-onboarding completeness (live pipeline): {avg_completeness:8.1%}\n"
        f"  onboarding time (suggest -> scored -> hot-reloaded -> re-normalized): "
        f"{onboarding_elapsed_s * 1000:8.1f} ms\n"
    )
    with capsys.disabled():
        print("\n" + summary)
    (_REPO / "bench").mkdir(exist_ok=True)
    (_REPO / "bench" / "autoparser_onboarding.txt").write_text(summary, encoding="utf-8")

    # a KPI worth presenting: onboarding is seconds, not the hours/days of
    # hand-writing a grok pattern and an OCSF mapping
    assert onboarding_elapsed_s < 30.0
