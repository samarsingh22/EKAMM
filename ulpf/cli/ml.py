"""``ulpf ml`` — train the anomaly-detection model and score events against it.

* ``ulpf ml train --date-from 2026-09-01 --date-to 2026-09-07`` — load features
  from the silver lake for that event-date range, fit
  :class:`~ulpf.ml.anomaly.AnomalyDetector`, and save it (with metadata) to
  ``settings.ml.model_path``.
* ``ulpf ml score --date 2026-09-08`` — score that day's events and append the
  results to the anomalies lake (``settings.ml.anomalies_path``).

Both are thin wrappers over :mod:`ulpf.ml.jobs`; the same functions back the
``/api/v1/anomalies`` routes and the background scoring loop.
"""

from __future__ import annotations

import json
from typing import Any

import typer

from ulpf.config.settings import Settings, get_settings
from ulpf.ml import jobs

ml_app = typer.Typer(help="Anomaly-detection model training and scoring.", no_args_is_help=True)


def _load_settings() -> Settings:
    """Indirection so tests can point the command at a temp configuration."""
    return get_settings()


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    """Print ``payload`` as indented JSON, or one ``key: value`` line per entry."""
    if as_json:
        typer.echo(json.dumps(payload, indent=2))
        return
    for key, value in payload.items():
        typer.echo(f"{key}: {value}")


@ml_app.command("train")
def train(
    date_from: str = typer.Option(..., "--date-from", help="First event date (YYYY-MM-DD)."),
    date_to: str = typer.Option(..., "--date-to", help="Last event date, inclusive (YYYY-MM-DD)."),
    contamination: float | None = typer.Option(
        None,
        "--contamination",
        help="Override settings.ml.contamination (expected outlier fraction).",
    ),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Load features across a date range, fit the detector, and save the model."""
    settings = _load_settings()
    try:
        result = jobs.train(
            settings, date_from=date_from, date_to=date_to, contamination=contamination
        )
    except jobs.MlJobError as exc:
        typer.secho(f"train failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    _emit(result.to_dict(), json_out)


@ml_app.command("score")
def score(
    date: str = typer.Option(..., "--date", help="Event date to score (YYYY-MM-DD)."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Score one day's events and append the results to the anomalies lake."""
    settings = _load_settings()
    try:
        result = jobs.score_day(settings, date=date)
    except jobs.MlJobError as exc:
        typer.secho(f"score failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    _emit(result.to_dict(), json_out)
