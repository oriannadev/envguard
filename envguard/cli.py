"""Command-line interface for envguard.

Built with Click for clean argument parsing and help text.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .reporter import format_json, format_sarif, format_text
from .rules import Severity
from .scanner import scan_directory


@click.group()
@click.version_option(version=__version__, prog_name="envguard")
def main() -> None:
    """envguard -- scan codebases for accidentally committed secrets."""


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    default=".",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
@click.option(
    "--sarif",
    "output_sarif",
    is_flag=True,
    default=False,
    help="Output results in SARIF v2.1.0 format.",
)
@click.option(
    "--severity",
    "min_severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default="low",
    help="Minimum severity level to report (default: low).",
)
def scan(
    path: str,
    output_json: bool,
    output_sarif: bool,
    min_severity: str,
) -> None:
    """Scan a directory for leaked secrets.

    PATH defaults to the current working directory.

    \b
    Examples:
        envguard scan .
        envguard scan ./my-project --json
        envguard scan . --severity high
    """
    target = Path(path)
    severity_threshold = Severity.from_string(min_severity)
    machine_output = output_json or output_sarif
    console = Console(stderr=True)

    # Show the banner only for human-readable (text) output so that
    # machine-readable formats (JSON, SARIF) stay parseable when piped.
    if not machine_output:
        console.print(
            f"[bold]envguard[/bold] v{__version__}"
            f" -- scanning [cyan]{target}[/cyan]\n"
        )

    try:
        findings = scan_directory(target, min_severity=severity_threshold)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)

    # Render output.
    if output_sarif:
        click.echo(format_sarif(findings))
    elif output_json:
        click.echo(format_json(findings))
    else:
        format_text(findings, console=Console())

    # Exit code 1 when secrets are found -- useful for CI gating.
    if findings:
        sys.exit(1)
