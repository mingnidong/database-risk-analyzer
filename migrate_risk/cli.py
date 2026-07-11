"""CLI entry point for migrate-risk."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from migrate_risk import __version__
from migrate_risk.analyzer import analyze_migration
from migrate_risk.models import RiskLevel
from migrate_risk.report import write_report
from migrate_risk.scoring import meets_fail_threshold

app = typer.Typer(
    name="migrate-risk",
    help="Find dangerous database migrations before they lock production.",
    no_args_is_help=True,
)
console = Console()


class OutputFormat(StrEnum):
    text = "text"
    json = "json"
    html = "html"


class FailOnLevel(StrEnum):
    medium = "medium"
    high = "high"
    critical = "critical"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"migrate-risk {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """migrate-risk static analyzer CLI."""


@app.command("analyze")
def analyze(
    migration_file: Annotated[
        Path,
        typer.Argument(help="Path to migration SQL file", exists=True, readable=True),
    ],
    schema: Annotated[
        Path | None,
        typer.Option("--schema", help="Optional path to schema.sql"),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Optional path to config.json"),
    ] = None,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: text, json, or html"),
    ] = OutputFormat.text,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional output file path"),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit nonzero on high-risk findings"),
    ] = False,
    database: Annotated[
        str,
        typer.Option("--database", help="Database dialect (default: postgres)"),
    ] = "postgres",
    fail_on: Annotated[
        FailOnLevel | None,
        typer.Option("--fail-on", help="Exit nonzero when risk meets threshold"),
    ] = None,
) -> None:
    """Analyze a migration SQL file for risky patterns."""
    if schema and not schema.exists():
        console.print(f"[red]Schema file not found:[/red] {schema}")
        raise typer.Exit(code=1)
    if config and not config.exists():
        console.print(f"[red]Config file not found:[/red] {config}")
        raise typer.Exit(code=1)

    try:
        analysis = analyze_migration(
            migration_file,
            schema_path=schema,
            config_path=config,
            database=database,
        )
    except Exception as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    content = write_report(analysis, format.value, output, console)

    if format == OutputFormat.text and output is None:
        console.print(content)
    elif format != OutputFormat.text and output is None:
        typer.echo(content)
    elif output:
        console.print(f"[green]Report written to[/green] {output}")

    threshold = None
    if strict:
        threshold = RiskLevel.HIGH
    elif fail_on:
        threshold = RiskLevel(fail_on.value)

    if threshold and meets_fail_threshold(analysis.overall_risk, threshold):
        console.print(
            f"[red]Exiting: overall risk {analysis.overall_risk.value.upper()} "
            f"meets fail threshold {threshold.value.upper()}[/red]"
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
