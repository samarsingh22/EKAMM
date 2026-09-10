"""Drain3-based template mining for lines no structured engine could parse.

Every source YAML in ``configs/sources/`` declares a fixed shape: a grok
pattern, a column list, a set of expected JSON keys. A line that matches no
``detect`` rule still gets a bronze copy (requirement a) and flows through as
``source_type="unknown"`` with ``needs_template_mining=True``
(:class:`~ulpf.core.models.ParsedEvent`) — it is never dead-lettered just for
being unstructured. :class:`TemplateMiner` is what turns that firehose of raw
text into a manageable, queryable set of templates: "what shapes of line is
this box actually sending, and which ones are new since yesterday?"

HOW DRAIN WORKS
---------------
Drain (the algorithm; `Drain3 <https://github.com/logpai/Drain3>`_ is the
maintained implementation this module wraps) organizes every line it has seen
into clusters, each owning one **template** — the line with every variable
token replaced by a wildcard. Its trick for staying fast as the number of
templates grows into the thousands is a **fixed-depth parse tree**, built top
down:

1. **Root.** One child per distinct *token count*. A 6-token line and an
   11-token line can never end up in the same cluster — token count is the
   cheapest, most discriminating split available.
2. **Next ``depth`` levels.** Below the token-count node, one child per
   distinct *leading token*, read left to right, for up to ``depth`` levels
   (``depth=5`` here: the first five tokens of the line, in order).
3. **Leaves.** Each leaf holds a short list of candidate cluster templates.
   The new line is compared token-by-token against each candidate; if the
   fraction of matching tokens meets ``sim_th`` it joins that cluster (any
   token that already differed, or now differs, becomes ``<*>`` in the
   template) — otherwise a new cluster starts.

Because step 2 only ever looks at at most ``depth`` tokens, and step 3 only
compares within one small leaf bucket, lookup and update cost stays roughly
constant as the number of templates learned grows — it does **not** degrade
into a linear scan over every template ever seen, which is what makes Drain
usable as a permanent, always-on stage rather than an offline batch job.

KNOWN LIMITATION: leading-token bias
-------------------------------------
Because the tree descends by **leading** tokens, two lines whose fixed part
comes first and variable part comes later cluster together beautifully:

    ``cupsd shutdown succeeded``
    ``irqbalance shutdown succeeded``

share tokens 2-3 but differ at token 1, so Drain (correctly) needs two
clusters here — that part is unavoidable, the messages genuinely start with a
different word. The real failure mode is the mirror image: a line whose
**variable part comes first**, before the descriptive tail. Two
otherwise-identical events dispatched under different subsystem tags land in
different token-count-or-leading-token buckets and can never merge into one
template no matter how similar the rest of the line is — the classic case
being the *reverse* of the example above, e.g. a per-daemon prefix:

    ``cupsd[1823]: shutdown succeeded``
    ``irqbalance[2091]: shutdown succeeded``

If ``[1823]``/``[2091]`` were left unmasked, Drain would key off "cupsd" vs
"irqbalance" as leading tokens regardless — the fan-out that actually matters
is when the SAME subsystem's PID changes every run and nothing masks it, or a
sequence/session number sits at the front of the line: every occurrence looks
like a brand-new leading token, so what should be *one* template silently
becomes hundreds of one-line "clusters", defeating the entire point of
mining. This is exactly why the masking rules in ``configs/drain3.ini`` run
**before** a line ever reaches the tree — masking a variable token to a fixed
placeholder (``<NUM>``, ``<HEX>``, ...) is the only way to keep it from
corrupting the tree's leading-token split. Masking is therefore not a nice-to
-have here; it is the difference between Drain mining five templates or five
thousand.

CONFIGURATION
-------------
``configs/drain3.ini`` — see that file's own comments for the full masking
order and why it matters. In short: ``depth=5``, ``sim_th=0.45``,
``max_children=100``, and an ordered mask list (UUID, MAC, IP, TIMESTAMP,
QUOTED, PORT, BYTES, HEX, NUM — most specific first).

PERSISTENCE AND ISOLATION
--------------------------
Each :class:`TemplateMiner` is scoped to **one** ``source_id`` and persists to
its own file, ``<state_path>/drain3.<source_id>.bin`` (the
``data/runtime/state/drain3.bin`` naming convention, namespaced per source so
two unrelated devices never share, and cannot corrupt, one another's tree —
:class:`TemplateMinerRegistry` is the intended way to obtain one per
``source_id`` and reuse it across calls. A snapshot is written on every
cluster-affecting change (a new cluster, or a template that widened to admit
a new line) and can be forced with :meth:`TemplateMiner.flush`, so learned
templates survive a process restart.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import TypedDict

from drain3 import TemplateMiner as _Drain3Engine
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

from ulpf.config.settings import Settings

_log = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path("configs/drain3.ini")
_STATE_SUBDIR_PREFIX = "drain3."
_STATE_SUFFIX = ".bin"
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]")


class MinedTemplate(TypedDict):
    """The result of mining one line."""

    template_id: int
    template: str
    change_type: str
    cluster_count: int
    param_list: list[str]


def _safe_source_name(source_id: str) -> str:
    """Filesystem-safe rendering of ``source_id`` for the persistence filename."""
    return _UNSAFE_NAME_CHARS.sub("_", source_id) or "unknown"


def _load_config(config_path: Path) -> TemplateMinerConfig:
    """Load Drain3's config object from ``config_path`` (depth/sim_th/masks/...)."""
    config = TemplateMinerConfig()
    config.load(str(config_path))
    return config


def load_drain3_config(config_path: Path | None = None) -> TemplateMinerConfig:
    """Public accessor for the same config :class:`TemplateMiner` loads.

    Lets a caller that needs a throwaway, unpersisted Drain3 engine (see
    :mod:`ulpf.parse.templates.suggest`) build one with the exact same
    depth/sim_th/masking rules as every live per-source tree, without wiring
    up a :class:`TemplateMiner` (and its persistence file) for a one-off pass.
    """
    return _load_config(config_path or _DEFAULT_CONFIG_PATH)


class TemplateMiner:
    """One Drain3 parse tree, scoped to and persisted for a single ``source_id``.

    Never share one instance across sources — see the module docstring's
    "PERSISTENCE AND ISOLATION" section. Use :class:`TemplateMinerRegistry` to
    get one per ``source_id`` without wiring the paths up by hand.
    """

    def __init__(
        self,
        source_id: str,
        settings: Settings,
        *,
        config_path: Path | None = None,
    ) -> None:
        """Build (or resume, if a snapshot exists) the tree for ``source_id``.

        Args:
            source_id: Identifies the log source this tree belongs to; also
                names its persistence file.
            settings: Supplies ``storage.state_path`` for the snapshot file.
            config_path: Override for ``configs/drain3.ini`` (tests).
        """
        self.source_id = source_id
        state_dir = Path(settings.storage.state_path)
        state_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = (
            state_dir / f"{_STATE_SUBDIR_PREFIX}{_safe_source_name(source_id)}{_STATE_SUFFIX}"
        )
        config = _load_config(config_path or _DEFAULT_CONFIG_PATH)
        persistence = FilePersistence(str(self._state_path))
        self._engine = _Drain3Engine(persistence, config=config)
        self._lock = threading.Lock()

    @property
    def state_path(self) -> Path:
        """Where this source's learned templates are persisted."""
        return self._state_path

    def mine(self, line: str) -> MinedTemplate:
        """Mask ``line``, match/update the tree, and return the resulting template.

        Never raises for a malformed line — Drain3 treats any text as a
        sequence of whitespace-separated tokens, so there is no failure mode
        to dead-letter; template mining is advisory, not a gate on the event.
        """
        with self._lock:
            result = self._engine.add_log_message(line)
            template: str = result["template_mined"]
            param_list = self._engine.get_parameter_list(template, line)
        return MinedTemplate(
            template_id=result["cluster_id"],
            template=template,
            change_type=result["change_type"],
            cluster_count=result["cluster_count"],
            param_list=param_list,
        )

    def flush(self) -> None:
        """Force a snapshot write regardless of whether the last line changed anything.

        ``add_log_message`` already snapshots on every cluster-affecting
        change; this covers the remaining case (a run of lines that only ever
        matched existing templates unchanged) so a clean shutdown never loses
        a tree that was, in fact, fully learned.
        """
        with self._lock:
            self._engine.save_state("flush")


class TemplateMinerRegistry:
    """One :class:`TemplateMiner` per ``source_id``, created on first use.

    This is the isolation boundary: two sources never share a tree, a
    persistence file, or a lock, so one source's traffic volume or line shape
    cannot degrade or pollute another's templates.
    """

    def __init__(self, settings: Settings, *, config_path: Path | None = None) -> None:
        """Configure how future miners will be built; none exist yet."""
        self._settings = settings
        self._config_path = config_path
        self._miners: dict[str, TemplateMiner] = {}
        self._lock = threading.Lock()

    def get(self, source_id: str) -> TemplateMiner:
        """Return the miner for ``source_id``, creating it on first request."""
        with self._lock:
            miner = self._miners.get(source_id)
            if miner is None:
                miner = TemplateMiner(source_id, self._settings, config_path=self._config_path)
                self._miners[source_id] = miner
            return miner

    def flush_all(self) -> None:
        """Force a snapshot for every miner created so far (clean shutdown)."""
        with self._lock:
            miners = list(self._miners.values())
        for miner in miners:
            miner.flush()
