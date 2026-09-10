"""The ULPF management/query API — a FastAPI app, separate from ingest.

See :mod:`ulpf.ingest.http_intake`'s module docstring for why the ingest
surface and this one run as separate ASGI apps on separate ports: very
different traffic, auth, and blast-radius profiles. This app is what
``ulpf serve`` binds on ``settings.api.port`` (default 8080) — the dashboard
UI, dead-letter/template review tools, and anything else that queries or
manages a running ULPF instance talk to this app, never to the ingest one.

:func:`create_app` builds one app, wiring:

* **lifespan** — on startup, builds and starts a :class:`~ulpf.core.runtime.Runtime`
  (the pipeline, every listener, hot-reloading registries, and background
  tasks); on shutdown, stops it cleanly. The running ``Runtime`` is reachable
  from any request via ``request.app.state.runtime``.
* **CORS** — allows ``settings.api.cors_origins`` (defaults to the Vite dev
  server's origin) so the dashboard UI can call this API from a different
  origin during development.
* **``GET /health``** — liveness + a snapshot of what is actually running:
  uptime, version, listeners, sinks, enrichers, and how many source
  definitions are loaded.
* **``GET /metrics``** — the same Prometheus registry every metric in
  :mod:`ulpf.core.metrics` reports into, in the standard text exposition
  format.
* **structured request logging** — one JSON log line per request (method,
  path, status, duration), via :mod:`ulpf.core.logging`.
* **a global exception handler** — any exception that escapes a route
  handler is logged with its traceback and answered with a clean JSON error,
  never a bare 500 with an HTML stack trace.

Feature routers mount under ``/api/v1``:

* :func:`~ulpf.api.suggest.build_suggest_router` — draft and score a source
  definition from sample lines.
* :func:`~ulpf.api.routes.events.build_events_router` — browse, inspect, and
  trace normalized events.
* :func:`~ulpf.api.routes.sources.build_sources_router` — browse, validate,
  try, and hot-reload source definitions.
* :func:`~ulpf.api.routes.templates.build_templates_router` — the unmapped-
  traffic onboarding worklist: mined templates, field-type inference, parser
  suggestion, and frequency drift.
* :func:`~ulpf.api.routes.integrity.build_integrity_router` — the signed
  Merkle ledger's status, chain/event verification, and per-event proofs.
* :func:`~ulpf.api.routes.dlq.build_dlq_router` — browse, count, and replay
  dead letters.
* :func:`~ulpf.api.routes.ingest.build_ingest_router` — inject sample lines
  or replay a file straight into the live pipeline; listener status.
* :func:`~ulpf.api.routes.anomalies.build_anomalies_router` — anomaly-detection
  results with per-alert explanations, the score-over-time chart, template
  drift, and a training trigger.

More are added the same way as they are built.

Finally, when ``ui/dist`` exists (``make ui-build``), the built React
dashboard is served at ``/`` with an SPA fallback so client-side routes
survive a refresh; absent that directory this is a no-op and ``ulpf serve``
stays API-only for development.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from ulpf import __version__ as _FALLBACK_VERSION
from ulpf.api.routes.anomalies import build_anomalies_router
from ulpf.api.routes.dlq import build_dlq_router
from ulpf.api.routes.events import build_events_router
from ulpf.api.routes.ingest import build_ingest_router
from ulpf.api.routes.integrity import build_integrity_router
from ulpf.api.routes.sources import build_sources_router
from ulpf.api.routes.templates import build_templates_router
from ulpf.api.suggest import build_suggest_router
from ulpf.config.settings import Settings
from ulpf.core.errors import UlpfError
from ulpf.core.runtime import Runtime

_log = logging.getLogger(__name__)

_API_PREFIX = "/api/v1"

# The built dashboard. Defaults to ``<root>/ui/dist`` next to ``<root>/ulpf``
# (repo checkout); ``ULPF_UI_DIST`` overrides for a container image that
# installs the package and copies the build elsewhere. Tests monkeypatch this
# to exercise the "no dashboard" (dev) path.
_UI_DIST = Path(
    os.environ.get("ULPF_UI_DIST") or Path(__file__).resolve().parents[2] / "ui" / "dist"
).resolve()


def _resolve_version() -> str:
    """Installed distribution version, falling back to the package constant."""
    try:
        return _pkg_version("ulpf")
    except PackageNotFoundError:
        return _FALLBACK_VERSION


def create_app(settings: Settings) -> FastAPI:
    """Build the management/query API app, bound to ``settings``."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Start the pipeline/registries/background tasks; stop them cleanly on exit.

        ``Runtime`` is built *here*, not at app-construction time: some of what
        it owns (e.g. the integrity ledger's sqlite index) is bound to the
        thread/task that creates it, and that must be the same one that later
        tears it down — the lifespan's async context guarantees that; building
        it eagerly in :func:`create_app` would not (a real risk under any ASGI
        server that runs the lifespan off the thread that imported the app).
        """
        runtime = Runtime(settings)
        app.state.runtime = runtime
        app.state.started_at = time.monotonic()
        await runtime.start()
        _log.info(
            "ulpf api started",
            extra={
                "http_port": settings.api.port,
                "sources_loaded": runtime.sources_loaded,
                "sinks": runtime.sink_names,
            },
        )
        try:
            yield
        finally:
            await runtime.stop()
            _log.info("ulpf api stopped")

    app = FastAPI(title="ULPF Management API", version=_resolve_version(), lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _install_request_logging(app)
    _install_exception_handlers(app)
    _install_health_and_metrics(app)

    app.include_router(build_suggest_router(settings), prefix=_API_PREFIX)
    app.include_router(build_events_router(settings), prefix=_API_PREFIX)
    app.include_router(build_sources_router(settings), prefix=_API_PREFIX)
    app.include_router(build_templates_router(settings), prefix=_API_PREFIX)
    app.include_router(build_integrity_router(settings), prefix=_API_PREFIX)
    app.include_router(build_dlq_router(settings), prefix=_API_PREFIX)
    app.include_router(build_ingest_router(settings), prefix=_API_PREFIX)
    app.include_router(build_anomalies_router(settings), prefix=_API_PREFIX)

    _mount_dashboard(app)  # registered last so its SPA catch-all never shadows the API

    return app


# ======================================================================
# static dashboard (ui/dist) with SPA fallback
# ======================================================================


# Paths that must keep their real status code instead of falling back to the SPA:
# the API surface, and ``/assets`` (a missing hashed bundle is a genuine 404).
_SPA_NON_APP_PREFIXES = ("/api/", "/assets/", "/health", "/metrics", "/docs", "/redoc", "/openapi")


def _mount_dashboard(app: FastAPI) -> None:
    """Serve the built React dashboard (``ui/dist``) at ``/`` with SPA fallback.

    No-op when ``ui/dist`` is absent, so ``ulpf serve`` still runs API-only in
    development (there the Vite dev server proxies ``/api`` back to it).

    The fallback is a **404 handler**, not a catch-all route: it only fires
    once every registered route has already declined a request, so it can
    never shadow ``/api/v1/*``, ``/health``, ``/metrics``, ``/docs`` — or a
    route added to the app after :func:`create_app` returns.
    """
    dist = _UI_DIST
    index = dist / "index.html"
    if not index.is_file():
        _log.info("dashboard not served: %s not found (run `make ui-build`)", index)
        return

    # hashed JS/CSS/etc. — a missing asset here is a genuine 404
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="ui-assets")

    @app.exception_handler(StarletteHTTPException)
    async def _spa_or_http_error(request: Request, exc: StarletteHTTPException) -> Response:
        path = request.url.path
        wants_spa = (
            exc.status_code == 404
            and request.method in ("GET", "HEAD")
            and not path.startswith(_SPA_NON_APP_PREFIXES)
        )
        if wants_spa:
            return FileResponse(index)  # a client-side route -> let React Router take over
        return JSONResponse(
            {"detail": exc.detail},
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.get("/", include_in_schema=False)
    async def _dashboard_index() -> FileResponse:
        return FileResponse(index)

    _log.info("serving dashboard from %s", dist)


# ======================================================================
# structured request logging
# ======================================================================


def _install_request_logging(app: FastAPI) -> None:
    @app.middleware("http")
    async def _log_requests(request: Request, call_next: Any) -> Response:
        """One structured JSON log line per request: method, path, status, duration."""
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        _log.info(
            "http request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "client": request.client.host if request.client else None,
            },
        )
        return response


# ======================================================================
# error handling — always a clean JSON body, never a bare traceback
# ======================================================================


def _install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(UlpfError)
    async def _ulpf_error(request: Request, exc: UlpfError) -> JSONResponse:
        """A recognized ULPF domain error: a client-facing 400, not a 500."""
        _log.warning(
            "request failed with a ulpf error",
            extra={"path": request.url.path, "error": type(exc).__name__, "detail": str(exc)},
        )
        return JSONResponse(
            status_code=400, content={"error": type(exc).__name__, "detail": str(exc)}
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        """Anything else: log the full traceback, answer with a clean, generic 500."""
        _log.exception(
            "unhandled exception", extra={"path": request.url.path, "error": type(exc).__name__}
        )
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": "an unexpected error occurred"},
        )


# ======================================================================
# GET /health, GET /metrics
# ======================================================================


def _sinks_status(runtime: Runtime) -> list[dict[str, Any]]:
    required = set(runtime.required_sink_names)
    return [{"name": name, "required": name in required} for name in runtime.sink_names]


def _install_health_and_metrics(app: FastAPI) -> None:
    @app.get("/health", tags=["health"])
    async def health(request: Request) -> dict[str, Any]:
        """Liveness plus a snapshot of what is actually running."""
        runtime: Runtime = request.app.state.runtime
        uptime_s = time.monotonic() - request.app.state.started_at
        return {
            "status": "ok",
            "uptime_s": round(uptime_s, 3),
            "version": app.version,
            "listeners": runtime.listener_descriptors,
            "sinks": _sinks_status(runtime),
            "enrichers": runtime.enricher_status(),
            "sources_loaded": runtime.sources_loaded,
        }

    @app.get("/metrics", tags=["health"])
    async def metrics() -> Response:
        """Every ``ulpf_*`` metric, in Prometheus text exposition format."""
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
