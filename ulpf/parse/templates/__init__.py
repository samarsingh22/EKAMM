"""Log-template mining (Drain3) for free-text lines the parse engines cannot structure.

See :mod:`ulpf.parse.templates.miner` for the wrapper and its docstring for how
Drain works and its known limitation, :mod:`ulpf.parse.templates.store` for
the persisted, queryable catalog of what has been mined,
:mod:`ulpf.parse.templates.inference` for guessing what each wildcard means,
:mod:`ulpf.parse.templates.suggest` for turning that into a draft source
definition, and :mod:`ulpf.parse.templates.score` for measuring how well that
draft actually works.
"""

from __future__ import annotations

from ulpf.parse.templates.inference import FieldGuess, infer_field_types
from ulpf.parse.templates.miner import MinedTemplate, TemplateMiner, TemplateMinerRegistry
from ulpf.parse.templates.score import (
    DEFAULT_PARSE_RATE_THRESHOLD,
    SuggestionScore,
    score_suggestion,
)
from ulpf.parse.templates.store import TemplateRecord, TemplateStore
from ulpf.parse.templates.suggest import (
    SuggestError,
    resolve_sample_lines,
    suggest_source_definition,
)

__all__ = [
    "DEFAULT_PARSE_RATE_THRESHOLD",
    "FieldGuess",
    "MinedTemplate",
    "SuggestError",
    "SuggestionScore",
    "TemplateMiner",
    "TemplateMinerRegistry",
    "TemplateRecord",
    "TemplateStore",
    "infer_field_types",
    "resolve_sample_lines",
    "score_suggestion",
    "suggest_source_definition",
]
