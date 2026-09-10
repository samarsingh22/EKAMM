"""``/api/v1/ingest`` — inject test/demo traffic straight into the live pipeline.

Distinct from :mod:`ulpf.ingest.http_intake` (the always-on, external-facing
listener on its own port): this router talks to the **same running**
:class:`~ulpf.core.runtime.Runtime` the management API's own lifespan started
(``request.app.state.runtime``), submitting straight to
:attr:`~ulpf.core.runtime.Runtime.pipeline` rather than through a listener —
this is the dashboard's "paste a log line and watch it normalize" feature and
the demo's replay control, not a production ingest path.

Endpoints
---------
* ``POST /sample``         — inject ``lines`` directly; returns the accepted
  count and each line's ``event_uid``.
* ``POST /replay``         — stream a file under ``data/samples/`` into the
  pipeline at ``rate_eps`` events/second, as a background task; returns a
  ``task_id``.
* ``GET /replay/{task_id}`` — that task's progress.
* ``DELETE /replay/{task_id}`` — cancel it.
* ``GET /listeners``       — every bound listener
  (:attr:`~ulpf.core.runtime.Runtime.listener_descriptors`) plus its
  ``ulpf_events_received_total`` / ``ulpf_bytes_received_total`` counters.

PATH SAFETY
-----------
``POST /replay``'s ``file`` is resolved against ``samples_dir`` (default
``data/samples/``) and then checked with :meth:`Path.is_relative_to` against
that directory's own resolved path — after resolution, not before, so this
catches both ``..`` traversal *and* an absolute path (which would otherwise
silently replace the whole join per :class:`pathlib.Path`'s own ``/``
semantics), and (since ``resolve()`` follows symlinks) a symlink planted
inside ``samples_dir`` that points back out of it. Anything outside is a
``400``, never read.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ulpf.config.settings import Settings
from ulpf.core.errors import PipelineStoppedError
from ulpf.core.metrics import BYTES_RECEIVED, EVENTS_RECEIVED, snapshot
from ulpf.core.models import RawEvent
from ulpf.core.runtime import Runtime
from ulpf.ingest.http_intake import IngestResult
from ulpf.integrity.hashing import make_raw_event

_DEFAULT_SAMPLES_DIR = Path("data/samples")
_DEFAULT_SOURCE_ID = "api-sample"


# ======================================================================
# wire models
# ======================================================================


class SampleRequest(BaseModel):
    """Body for ``POST /sample``."""

    lines: list[str]
    source_id: str | None = None


class ReplayRequest(BaseModel):
    """Body for ``POST /replay``."""

    file: str
    rate_eps: int = Field(default=100, ge=0, description="0 = as fast as possible.")


class ReplayStartResponse(BaseModel):
    """Response body for ``POST /replay``."""

    task_id: str


class ReplayProgress(BaseModel):
    """Response body for ``GET``/``DELETE /replay/{task_id}``."""

    task_id: str
    file: str
    rate_eps: int
    status: str  # "running" | "completed" | "stopped" | "failed"
    lines_total: int
    lines_sent: int
    started_ns: int
    finished_ns: int | None
    error: str | None


class ListenerStatus(BaseModel):
    """One entry of ``GET /listeners``."""

    name: str
    protocol: str
    port: int
    events_received: int
    bytes_received: int


# ======================================================================
# background replay task state
# ======================================================================


@dataclass
class _ReplayState:
    """One replay task's mutable progress — updated in place by ``_run_replay``."""

    task_id: str
    file: str
    rate_eps: int
    lines_total: int
    status: str = "running"
    lines_sent: int = 0
    started_ns: int = 0
    finished_ns: int | None = None
    error: str | None = None

    def to_progress(self) -> ReplayProgress:
        return ReplayProgress(
            task_id=self.task_id,
            file=self.file,
            rate_eps=self.rate_eps,
            status=self.status,
            lines_total=self.lines_total,
            lines_sent=self.lines_sent,
            started_ns=self.started_ns,
            finished_ns=self.finished_ns,
            error=self.error,
        )


# ======================================================================
# router
# ======================================================================


def build_ingest_router(settings: Settings, *, samples_dir: Path | None = None) -> APIRouter:
    """The ``/ingest`` router. ``samples_dir`` (default ``data/samples/``) is injectable."""
    router = APIRouter(prefix="/ingest", tags=["ingest"])
    root = samples_dir or _DEFAULT_SAMPLES_DIR
    # Task registries are closure-local, not module-global: one instance per
    # router build, matching every other stateful router in this package.
    states: dict[str, _ReplayState] = {}
    tasks: dict[str, asyncio.Task[None]] = {}

    @router.post("/sample", response_model=IngestResult)
    async def sample(payload: SampleRequest, request: Request) -> IngestResult:
        """Inject ``lines`` straight into the running pipeline."""
        runtime = _runtime(request)
        source_id = payload.source_id or _DEFAULT_SOURCE_ID
        uids: list[str] = []
        for line in payload.lines:
            if not line.strip():
                continue
            event = _submit_line(line, source_id)
            try:
                await runtime.pipeline.submit(event)
            except PipelineStoppedError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            uids.append(event.event_uid)
        return IngestResult(accepted=len(uids), event_uids=uids)

    @router.post("/replay", response_model=ReplayStartResponse)
    async def start_replay(payload: ReplayRequest, request: Request) -> ReplayStartResponse:
        """Start streaming a ``data/samples/`` file into the pipeline; returns a task id."""
        runtime = _runtime(request)
        path = _resolve_sample_path(root, payload.file)
        lines = [
            line
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]

        task_id = uuid.uuid4().hex
        state = _ReplayState(
            task_id=task_id,
            file=payload.file,
            rate_eps=payload.rate_eps,
            lines_total=len(lines),
            started_ns=time.time_ns(),
        )
        states[task_id] = state
        tasks[task_id] = asyncio.create_task(_run_replay(state, lines, runtime))
        return ReplayStartResponse(task_id=task_id)

    @router.get("/replay/{task_id}", response_model=ReplayProgress)
    async def replay_progress(task_id: str) -> ReplayProgress:
        state = states.get(task_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"replay task {task_id!r} not found")
        return state.to_progress()

    @router.delete("/replay/{task_id}", response_model=ReplayProgress)
    async def stop_replay(task_id: str) -> ReplayProgress:
        state = states.get(task_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"replay task {task_id!r} not found")
        task = tasks.get(task_id)
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        return state.to_progress()

    @router.get("/listeners", response_model=list[ListenerStatus])
    async def listeners(request: Request) -> list[ListenerStatus]:
        runtime = _runtime(request)
        counters = snapshot()
        return [
            ListenerStatus(
                name=entry["name"],
                protocol=entry["protocol"],
                port=entry["port"],
                events_received=int(
                    _counter(counters, "ulpf_events_received_total", entry["protocol"])
                ),
                bytes_received=int(
                    _counter(counters, "ulpf_bytes_received_total", entry["protocol"])
                ),
            )
            for entry in runtime.listener_descriptors
        ]

    return router


def _runtime(request: Request) -> Runtime:
    """The live runtime the management API's lifespan started."""
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(status_code=503, detail="runtime not started")
    return runtime


def _counter(counters: dict[str, float], name: str, transport: str) -> float:
    return counters.get(f'{name}{{transport="{transport}"}}', 0.0)


# ======================================================================
# POST /sample
# ======================================================================


def _submit_line(line: str, source_id: str) -> RawEvent:
    """Build the RawEvent for one injected line, counting it like any other listener."""
    raw = line.encode("utf-8", errors="replace")
    EVENTS_RECEIVED.labels(transport="http").inc()
    BYTES_RECEIVED.labels(transport="http").inc(len(raw))
    return make_raw_event(raw, source_id=source_id, transport="http")


# ======================================================================
# POST /replay — path safety
# ======================================================================


def _resolve_sample_path(samples_dir: Path, requested: str) -> Path:
    """Resolve ``requested`` under ``samples_dir``; refuse anything that escapes it.

    See the module docstring's PATH SAFETY section for why the check happens
    on the *resolved* path, after the join, rather than pattern-matching the
    input string.
    """
    if not requested or not requested.strip():
        raise HTTPException(status_code=400, detail="file is required")
    root = samples_dir.resolve()
    candidate = (samples_dir / requested).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(
            status_code=400, detail=f"file must resolve under {samples_dir}/ — got {requested!r}"
        )
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail=f"no such sample file: {requested!r}")
    return candidate


# ======================================================================
# POST /replay — the background task itself
# ======================================================================


async def _run_replay(state: _ReplayState, lines: list[str], runtime: Runtime) -> None:
    """Stream ``lines`` into ``runtime.pipeline`` at ``state.rate_eps`` events/second."""
    interval = 1.0 / state.rate_eps if state.rate_eps > 0 else 0.0
    try:
        for line in lines:
            event = _submit_line(line, f"replay:{state.file}")
            await runtime.pipeline.submit(event)
            state.lines_sent += 1
            if interval:
                await asyncio.sleep(interval)
        state.status = "completed"
    except asyncio.CancelledError:
        state.status = "stopped"
        raise
    except Exception as exc:  # noqa: BLE001 - a background task must never fail silently
        state.status = "failed"
        state.error = str(exc)
    finally:
        state.finished_ns = time.time_ns()
