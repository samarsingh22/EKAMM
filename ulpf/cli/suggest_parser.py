"""``ulpf suggest-parser`` — draft a source YAML from real, unmapped traffic.

Three ways to pick the input samples:

    ulpf suggest-parser --file samples.log                    # raw lines from a file
    ulpf suggest-parser --source-id acmefw-1                  # that source's busiest template
    ulpf suggest-parser --source-id acmefw-1 --template-id 3  # one specific template

    ulpf suggest-parser --file samples.log --dry-run           # print, write nothing
    ulpf suggest-parser --file samples.log --out configs/sources/acmefw.yaml

Wraps :func:`~ulpf.parse.templates.suggest.suggest_source_definition` — see
its module docstring for the generation strategy. The result is always
validated against :class:`~ulpf.parse.dsl.schema.SourceDefinition` before it
is printed or written; this command cannot hand you invalid YAML.

Every draft is then scored (:func:`~ulpf.parse.templates.score.score_suggestion`)
against the very samples it was built from — trust the measurement, not the
generation. The score is appended to the YAML as trailing comment lines (so it
travels with ``--out`` too) and, when writing to ``--out``, this command
**refuses to write** if ``parse_rate`` is below ``--min-parse-rate`` (default
:data:`~ulpf.parse.templates.score.DEFAULT_PARSE_RATE_THRESHOLD`) unless
``--force`` is given — a low-scoring draft should be reviewed, not silently
dropped into ``configs/sources/``.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from ulpf.config.settings import Settings, get_settings
from ulpf.parse.templates.score import (
    DEFAULT_PARSE_RATE_THRESHOLD,
    SuggestionScore,
    score_suggestion,
)
from ulpf.parse.templates.store import TemplateStore
from ulpf.parse.templates.suggest import (
    SuggestError,
    resolve_sample_lines,
    suggest_source_definition,
)

_DEFAULT_SAMPLES = 200


def _load_settings() -> Settings:
    """Indirection so tests can point the command at a temp configuration."""
    return get_settings()


def _read_lines(path: Path, limit: int) -> list[str]:
    """Up to ``limit`` non-blank lines from ``path``, decoded leniently."""
    lines: list[str] = []
    with path.open("rb") as handle:
        for raw in handle:
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if text.strip():
                lines.append(text)
            if len(lines) >= limit:
                break
    return lines


def _resolve_template_id(settings: Settings, source_id: str, template_id: str | None) -> str:
    """The given ``template_id``, or (if omitted) this source's busiest template."""
    if template_id is not None:
        return template_id
    store = TemplateStore(settings)
    rows = store.list_templates(source_id=source_id, order_by="count")
    if not rows:
        raise SuggestError(f"no templates recorded yet for source_id {source_id!r}")
    return rows[0]["template_id"]


def _score_comment_block(score: SuggestionScore, min_parse_rate: float) -> str:
    """Trailing ``#``-comment lines carrying the score — safe to append after a YAML doc."""
    lines = [
        "",
        "# --- score (ulpf.parse.templates.score.score_suggestion) ---",
        f"# parse_rate:              {score.parse_rate:.2%}"
        + ("  <- below --min-parse-rate" if score.parse_rate < min_parse_rate else ""),
        f"# completeness:            {score.completeness:.2%}",
        f"# required_fields_covered: {score.required_fields_covered:.2%}",
        f"# confidence:              {score.confidence:.2%}",
    ]
    for warning in score.warnings:
        lines.append(f"#   ! {warning}")
    return "\n".join(lines) + "\n"


def _render_score(console: Console, score: SuggestionScore, min_parse_rate: float) -> None:
    style = "green" if score.parse_rate >= min_parse_rate else "red"
    console.print(
        Panel(
            f"parse_rate [bold {style}]{score.parse_rate:.0%}[/]  ·  "
            f"completeness {score.completeness:.0%}  ·  "
            f"required_fields_covered {score.required_fields_covered:.0%}  ·  "
            f"confidence {score.confidence:.0%}",
            title="score",
            border_style=style,
        )
    )
    for warning in score.warnings:
        console.print(f"  [yellow]![/] {warning}")


def suggest_parser(
    file: Path | None = typer.Option(
        None, "--file", exists=True, dir_okay=False, help="Log file to sample raw lines from."
    ),
    source_id: str | None = typer.Option(
        None, "--source-id", help="Source to draft a definition for (required with --template-id)."
    ),
    template_id: str | None = typer.Option(
        None, "--template-id", help="One specific mined template (needs --source-id)."
    ),
    samples: int = typer.Option(
        _DEFAULT_SAMPLES, "--samples", min=1, help="Max lines to read from --file."
    ),
    out: Path | None = typer.Option(
        None, "--out", help="Write the YAML here, e.g. configs/sources/acmefw.yaml."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print to stdout only; never write --out."
    ),
    min_parse_rate: float = typer.Option(
        DEFAULT_PARSE_RATE_THRESHOLD,
        "--min-parse-rate",
        min=0.0,
        max=1.0,
        help="Refuse to write --out if the score's parse_rate falls below this.",
    ),
    force: bool = typer.Option(
        False, "--force", help="Write --out even if the score is below --min-parse-rate."
    ),
    name: str | None = typer.Option(None, "--name", help="Override the generated source name."),
    vendor: str | None = typer.Option(None, "--vendor", help="Vendor name for the definition."),
    product: str | None = typer.Option(None, "--product", help="Product name for the definition."),
) -> None:
    """Draft a source-definition YAML from sample raw log lines, and score it."""
    if file is None and template_id is None and source_id is None:
        raise typer.BadParameter("pass one of --file, --source-id, or --template-id")
    if file is not None and (source_id is not None or template_id is not None):
        raise typer.BadParameter("--file is exclusive with --source-id/--template-id")

    settings = _load_settings()
    console = Console()

    try:
        if file is not None:
            lines = _read_lines(file, samples)
            yaml_text = suggest_source_definition(
                source_id or file.stem,
                sample_lines=lines,
                name=name,
                vendor=vendor,
                product=product,
            )
        else:
            if source_id is None:
                raise typer.BadParameter("--template-id requires --source-id")
            resolved_template_id = _resolve_template_id(settings, source_id, template_id)
            # resolved twice (here, and inside suggest_source_definition) so the
            # header can still name the real template_id while scoring gets the
            # identical lines back — both reads are cheap in-memory lookups
            lines = resolve_sample_lines(
                source_id, template_id=resolved_template_id, settings=settings
            )
            yaml_text = suggest_source_definition(
                source_id,
                template_id=resolved_template_id,
                settings=settings,
                name=name,
                vendor=vendor,
                product=product,
            )
        score = score_suggestion(yaml_text, lines)
    except SuggestError as exc:
        console.print(Panel(f"[bold red]{exc}[/]", title="suggest-parser", border_style="red"))
        raise typer.Exit(code=1) from exc

    scored_text = yaml_text + _score_comment_block(score, min_parse_rate)

    if dry_run or out is None:
        # plain echo, not a Rich/Syntax render: this must stay byte-identical,
        # re-parseable YAML, never wrapped or highlighted for a terminal
        typer.echo(scored_text)
        if out is None and not dry_run:
            console.print(
                Panel(
                    "[yellow]No --out given — printed only. Pass --out configs/sources/<name>.yaml "
                    "to write it.[/]",
                    border_style="yellow",
                )
            )
        raise typer.Exit(code=0)

    _render_score(console, score, min_parse_rate)
    if not force and not score.meets_threshold(parse_rate=min_parse_rate):
        console.print(
            Panel(
                f"[bold red]refusing to write {out}[/]\n"
                f"parse_rate {score.parse_rate:.0%} is below "
                f"--min-parse-rate {min_parse_rate:.0%}. Review the warnings above, fix the "
                "samples/definition, or pass --force to write anyway.",
                title="suggest-parser",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(scored_text, encoding="utf-8")
    console.print(
        Panel(
            f"[bold green]wrote[/] {out}\n"
            "review the [yellow]# REVIEW REQUIRED[/] comments before deploying it.",
            title="suggest-parser",
            border_style="green",
        )
    )
    raise typer.Exit(code=0)
