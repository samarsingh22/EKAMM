"""``/suggest`` — draft and score a source definition over HTTP.

Part of ``ulpf.api``, the management/query API (see
:mod:`ulpf.ingest.http_intake`'s module docstring for why that runs as a
separate ASGI app from ingest). This is the same capability as
``ulpf suggest-parser`` (:mod:`ulpf.cli.suggest_parser`), for a dashboard or
other caller that cannot shell out to the CLI:

* ``POST /suggest/parser`` — draft a definition from ``sample_lines`` or a
  stored ``template_id``, and return it alongside its
  :func:`~ulpf.parse.templates.score.score_suggestion` score. Never returns
  invalid YAML — a definition that fails to validate or fails to build from
  too few samples comes back as ``400``, not a partial result.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel, Field

from ulpf.config.settings import Settings
from ulpf.parse.templates.score import score_suggestion
from ulpf.parse.templates.suggest import (
    SuggestError,
    resolve_sample_lines,
    suggest_source_definition,
)


class SuggestRequest(BaseModel):
    """Body for ``POST /suggest/parser``."""

    source_id: str
    sample_lines: list[str] | None = None
    template_id: str | None = None
    name: str | None = None
    vendor: str | None = None
    product: str | None = None


class SuggestScore(BaseModel):
    """Wire shape of :class:`~ulpf.parse.templates.score.SuggestionScore`."""

    parse_rate: float
    completeness: float
    required_fields_covered: float
    confidence: float
    warnings: list[str] = Field(default_factory=list)


class SuggestResponse(BaseModel):
    """Response body for ``POST /suggest/parser``."""

    yaml: str
    score: SuggestScore


def build_suggest_router(settings: Settings) -> APIRouter:
    """The ``/suggest`` router, bound to ``settings`` for the template store."""
    router = APIRouter(prefix="/suggest", tags=["suggest"])

    @router.post("/parser", response_model=SuggestResponse)
    def suggest_parser(payload: SuggestRequest) -> SuggestResponse:
        try:
            lines = resolve_sample_lines(
                payload.source_id,
                template_id=payload.template_id,
                sample_lines=payload.sample_lines,
                settings=settings,
            )
            yaml_text = suggest_source_definition(
                payload.source_id,
                sample_lines=lines,
                name=payload.name,
                vendor=payload.vendor,
                product=payload.product,
            )
            score = score_suggestion(yaml_text, lines)
        except (ValueError, SuggestError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return SuggestResponse(yaml=yaml_text, score=SuggestScore(**score.to_dict()))

    return router


def create_suggest_app(settings: Settings) -> FastAPI:
    """A standalone app serving just ``/suggest`` (for tests, or its own mount)."""
    app = FastAPI(title="ULPF Suggest API", version="0.1.0")
    app.include_router(build_suggest_router(settings))
    return app
