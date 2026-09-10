"""Semantic inference for the wildcard positions in a mined template.

:class:`~ulpf.parse.templates.miner.TemplateMiner` tells you a line looks like
``connect from <IP>:<PORT> proto <NUM> action <QUOTED>``; this module looks at
the *actual values* seen at each ``<...>`` position across many samples and
guesses what each one **means** — ``source_ip``, ``port``, ``protocol``,
``action`` — so the "unmapped traffic" dashboard can propose a starter source
YAML instead of leaving an operator to eyeball raw text.

:func:`infer_field_types` returns one :class:`FieldGuess` per wildcard, in
template order. Each carries a ``confidence`` in ``[0, 1]`` equal to **how
consistently its rule held across the samples** — the fraction of non-empty
values at that position that satisfied the rule. Nothing here is
authoritative; it is a hint for whoever (or whatever) writes the real source
definition, which still goes through the normal detect/parse/normalize/
validate path.

RULES (highest priority first, per position):

* a value that parses as an IPv4/IPv6 address -> ``ip_address``; the first such
  position in the line becomes ``source_ip``, the second ``destination_ip``;
* an integer that is a known IANA protocol number, with low cardinality across
  samples -> ``protocol``;
* a word from a small closed set (allow/deny/accept/drop/block/...) -> ``action``;
* a value that parses as a timestamp -> ``timestamp``;
* an integer in ``0..65535`` adjacent to an IP (or to another port) -> ``port``;
* large integers that vary and trend upward -> ``byte_count``;
* a low-cardinality non-numeric string next to an ``interface``/``intf``/
  ``iface``/``port`` keyword -> ``interface_name``;
* anything else -> ``unknown`` (with confidence = how sure we are it is *not*
  one of the above).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypedDict

from ulpf.core.errors import ParseError
from ulpf.core.timeutil import parse_timestamp

_MASK_RE = re.compile(r"<([^>]*)>")
_MAX_EXAMPLES = 5
_KEYWORD_LOOKBEHIND = 24  # chars of template text before a wildcard to scan for keywords

# Common perimeter IANA protocol numbers (RFC-assigned). A protocol column has
# only a handful of distinct values, all from this set.
_IANA_PROTOCOLS: frozenset[int] = frozenset(
    {1, 2, 4, 6, 17, 41, 47, 50, 51, 58, 88, 89, 103, 112, 115, 132}
)
_ACTION_WORDS: frozenset[str] = frozenset(
    {
        "allow",
        "allowed",
        "deny",
        "denied",
        "accept",
        "accepted",
        "drop",
        "dropped",
        "block",
        "blocked",
        "permit",
        "permitted",
        "reject",
        "rejected",
        "pass",
        "passed",
    }
)
_INTERFACE_KEYWORDS: tuple[str, ...] = ("interface", "intf", "iface")

# Per-rule floor on the consistency fraction for the rule to "hold".
_TH_IP = 0.75
_TH_PROTOCOL = 0.9
_TH_ACTION = 0.75
_TH_TIMESTAMP = 0.7
_TH_PORT = 0.7
_TH_BYTES = 0.9
_TH_INTERFACE = 0.6


class FieldGuess(TypedDict):
    """One wildcard position's inferred meaning."""

    position: int
    mask_type: str
    inferred_semantic: str
    confidence: float
    example_values: list[str]


# ======================================================================
# public entry point
# ======================================================================


def infer_field_types(template: str, sample_values: list[list[str]]) -> list[FieldGuess]:
    """Infer what each ``<...>`` position in ``template`` actually is.

    Args:
        template: A mined template, e.g. ``"connect from <IP>:<PORT> proto <NUM>"``.
        sample_values: One list of parameter values per sample line, in
            template order (as produced by ``TemplateMiner.mine()[\"param_list\"]``).
            Rows shorter than the wildcard count contribute what they have.

    Returns:
        One :class:`FieldGuess` per wildcard, in template order.
    """
    marks = list(_MASK_RE.finditer(template))
    guesses = [
        _Guess(position=i, mask_type=m.group(1), values=_column(sample_values, i))
        for i, m in enumerate(marks)
    ]

    for guess in guesses:
        _classify_primary(guess)
    # ports are structural (need an IP neighbour) and more specific than the
    # generic byte_count rule, so they get first refusal on a "big int" column
    # before byte_count would otherwise claim it (e.g. a port right after an IP).
    _refine_ports(guesses)
    for guess in guesses:
        if not guess._locked:
            _classify_bytecount(guess)
    _refine_interfaces(guesses, template, marks)
    _assign_ip_roles(guesses)
    for guess in guesses:
        if guess.inferred_semantic == "unknown":
            guess.confidence = _unknown_confidence(guess.values)

    return [guess.to_dict() for guess in guesses]


# ======================================================================
# internal
# ======================================================================


@dataclass
class _Guess:
    position: int
    mask_type: str
    values: list[str]
    inferred_semantic: str = "unknown"
    confidence: float = 0.0
    _locked: bool = field(default=False, repr=False)  # a value rule already claimed it

    def set(self, semantic: str, confidence: float) -> None:
        self.inferred_semantic = semantic
        self.confidence = round(max(0.0, min(1.0, confidence)), 2)
        self._locked = True

    def to_dict(self) -> FieldGuess:
        return FieldGuess(
            position=self.position,
            mask_type=self.mask_type,
            inferred_semantic=self.inferred_semantic,
            confidence=self.confidence,
            example_values=_dedupe(self.values)[:_MAX_EXAMPLES],
        )


def _column(sample_values: list[list[str]], index: int) -> list[str]:
    """Non-empty values seen at wildcard ``index`` across every sample row."""
    out: list[str] = []
    for row in sample_values:
        if index < len(row):
            value = "" if row[index] is None else str(row[index])
            if value.strip():
                out.append(value)
    return out


def _dedupe(values: list[str]) -> list[str]:
    """Distinct values, first-seen order preserved."""
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


def _frac(values: list[str], predicate: Callable[[str], bool]) -> float:
    """Fraction of ``values`` satisfying ``predicate`` (0.0 for an empty column)."""
    if not values:
        return 0.0
    return sum(1 for value in values if predicate(value)) / len(values)


# -- value predicates ------------------------------------------------


def _is_ip(value: str) -> bool:
    """A real IPv4/IPv6 literal — not a bare integer (which ``ipaddress`` also accepts)."""
    text = value.strip()
    if "." not in text and ":" not in text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_uint(value: str) -> bool:
    return value.strip().isdigit()


def _is_port_int(value: str) -> bool:
    text = value.strip()
    return text.isdigit() and 0 <= int(text) <= 65535


def _is_action(value: str) -> bool:
    return value.strip().strip("\"'").lower() in _ACTION_WORDS


def _is_timestamp(value: str, mask_type: str) -> bool:
    """Parseable as a timestamp. A bare integer only counts if the mask says TIMESTAMP."""
    text = value.strip()
    if text.isdigit() and mask_type.upper() != "TIMESTAMP":
        return False  # would parse as an epoch int and shadow byte_count
    try:
        parse_timestamp(text)
    except (ParseError, ValueError, TypeError, OverflowError):
        return False
    return True


def _monotonic_score(values: list[str]) -> float:
    """In sample order, the share of adjacent int pairs that increase (1.0 = strictly rising)."""
    ints = [int(v) for v in values if _is_uint(v)]
    steps = list(zip(ints, ints[1:], strict=False))
    changing = [(a, b) for a, b in steps if a != b]
    if not changing:
        return 0.0
    return sum(1 for a, b in changing if b > a) / len(changing)


# -- per-position value classification -----------------------------


def _classify_primary(guess: _Guess) -> None:
    """IP / protocol / action / timestamp: rules that need only this position's values.

    Deliberately excludes ``byte_count`` and ``port`` — both can match a plain
    "big-ish integer" column, and ``port`` (structural: needs an IP neighbour)
    must get first refusal before the generic ``byte_count`` rule would claim
    it; see :func:`infer_field_types`.
    """
    values, mask = guess.values, guess.mask_type
    if not values:
        return

    ip_frac = _frac(values, _is_ip)
    if ip_frac >= _TH_IP:
        guess.set("ip_address", ip_frac)
        return

    proto = _protocol_confidence(values)
    if proto is not None:
        guess.set("protocol", proto)
        return

    action_frac = _frac(values, _is_action)
    if action_frac >= _TH_ACTION and len(set(_dedupe(values))) <= 8:
        guess.set("action", action_frac)
        return

    ts_frac = _frac(values, lambda v: _is_timestamp(v, mask))
    if mask.upper() == "TIMESTAMP":
        guess.set("timestamp", max(ts_frac, 0.5))
        return
    if ts_frac >= _TH_TIMESTAMP:
        guess.set("timestamp", ts_frac)


def _classify_bytecount(guess: _Guess) -> None:
    """``byte_count``, for positions the primary pass and port refinement left unclaimed."""
    conf = _bytecount_confidence(guess.values, guess.mask_type)
    if conf is not None:
        guess.set("byte_count", conf)


def _protocol_confidence(values: list[str]) -> float | None:
    """``protocol`` iff every value is a small IANA proto number and cardinality is low."""
    if _frac(values, _is_uint) < 0.95:
        return None
    nums = {int(v) for v in values if _is_uint(v)}
    if not nums or not nums <= _IANA_PROTOCOLS or len(nums) > 4:
        return None
    in_set = _frac(values, lambda v: _is_uint(v) and int(v) in _IANA_PROTOCOLS)
    if in_set < _TH_PROTOCOL:
        return None
    return in_set * (1.0 if len(nums) <= 2 else 0.85)


def _bytecount_confidence(values: list[str], mask_type: str) -> float | None:
    """``byte_count`` = mostly integers that vary and trend upward (large, unless mask=BYTES)."""
    int_frac = _frac(values, _is_uint)
    if int_frac < _TH_BYTES:
        return None
    nums = [int(v) for v in values if _is_uint(v)]
    distinct = len(set(nums))
    varied = distinct >= max(3, 0.5 * len(nums))
    if mask_type.upper() != "BYTES":
        if not varied or max(nums) < 1000:
            return None
    elif distinct < 2:
        return None
    mono = _monotonic_score(values)
    return int_frac * (0.7 + 0.3 * mono)


# -- structural refinements ---------------------------------------


def _refine_ports(guesses: list[_Guess]) -> None:
    """An int-in-range position adjacent to an IP (or, transitively, to a port) -> ``port``."""

    def is_ip_role(g: _Guess) -> bool:
        return g.inferred_semantic in ("ip_address", "source_ip", "destination_ip")

    def try_claim(g: _Guess, neighbours: list[_Guess]) -> bool:
        if g._locked or not g.values:
            return False
        port_frac = _frac(g.values, _is_port_int)
        forced = g.mask_type.upper() == "PORT"
        if port_frac < (_TH_PORT if not forced else 0.5):
            return False
        touches = any(is_ip_role(n) or n.inferred_semantic == "port" for n in neighbours)
        if not (touches or forced):
            return False
        g.set("port", max(port_frac, 0.5) if forced else port_frac)
        return True

    # left-to-right then right-to-left so a port next to a port-next-to-an-IP is caught
    for _ in range(2):
        for i, g in enumerate(guesses):
            neighbours = guesses[max(0, i - 1) : i] + guesses[i + 1 : i + 2]
            try_claim(g, neighbours)
        guesses.reverse()
    guesses.sort(key=lambda g: g.position)


def _refine_interfaces(guesses: list[_Guess], template: str, marks: list[re.Match[str]]) -> None:
    """A low-cardinality non-numeric string next to an ``interface``/``port`` keyword."""
    for i, (guess, mark) in enumerate(zip(guesses, marks, strict=False)):
        if guess._locked or not guess.values:
            continue
        # bounded by the PREVIOUS wildcard, so an earlier position's keyword
        # (e.g. "... interface <*> session <HEX>") cannot bleed into this one
        segment_start = marks[i - 1].end() if i > 0 else 0
        segment = template[segment_start : mark.start()]
        preceding = segment[-_KEYWORD_LOOKBEHIND:].lower()
        has_iface_kw = any(kw in preceding for kw in _INTERFACE_KEYWORDS)
        has_port_kw = re.search(r"\bport\b", preceding) is not None
        if not (has_iface_kw or has_port_kw):
            continue
        nonnum_frac = _frac(guess.values, lambda v: not _is_uint(v))
        distinct = len(set(_dedupe(guess.values)))
        if nonnum_frac < 0.8 or distinct > 10:
            continue  # a "port" keyword before actual port numbers, or free text
        guess.set("interface_name", nonnum_frac * (1.0 if distinct <= 6 else 0.7))


def _assign_ip_roles(guesses: list[_Guess]) -> None:
    """First IP -> ``source_ip``; second -> ``destination_ip``; the rest stay ``ip_address``."""
    ips = [
        g for g in sorted(guesses, key=lambda g: g.position) if g.inferred_semantic == "ip_address"
    ]
    if ips:
        ips[0].inferred_semantic = "source_ip"
    if len(ips) > 1:
        ips[1].inferred_semantic = "destination_ip"


def _unknown_confidence(values: list[str]) -> float:
    """How sure we are the column is *not* any known type: ``1 - best near-miss fraction``."""
    if not values:
        return 0.0
    best = max(
        _frac(values, _is_ip),
        _frac(values, _is_action),
        _frac(values, _is_port_int),
        _frac(values, lambda v: _is_timestamp(v, "")),
        _frac(values, _is_uint),
    )
    return round(max(0.0, 1.0 - best), 2)
