"""Output formatting for scan results.

Supports three output modes:
* **text** -- human-readable Rich-formatted table for terminal use.
* **json** -- machine-readable JSON array for scripting and dashboards.
* **sarif** -- SARIF v2.1.0 for integration with GitHub Code Scanning
  and other static-analysis platforms.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .rules import Severity
from .scanner import Finding

# Severity -> Rich colour mapping for terminal output.
_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.LOW: "dim",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


# ---------------------------------------------------------------------------
# Plain-text (Rich) output
# ---------------------------------------------------------------------------

def format_text(findings: list[Finding], console: Console | None = None) -> None:
    """Print findings as a Rich-formatted table to *console*.

    If no *console* is provided, a new one writing to ``stdout`` is created.
    """
    if console is None:
        console = Console()

    if not findings:
        console.print("\n[bold green]No secrets detected.[/bold green]\n")
        return

    table = Table(
        title="Secrets Detected",
        title_style="bold red",
        show_lines=True,
        expand=True,
    )
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Rule", width=22)
    table.add_column("File", width=36)
    table.add_column("Line", justify="right", width=5)
    table.add_column("Match", width=30)

    for f in findings:
        sev_text = Text(f.severity.name, style=_SEVERITY_STYLES[f.severity])
        table.add_row(
            sev_text,
            f.rule_name,
            f.rel_path,
            str(f.line_number),
            f.match,
        )

    console.print()
    console.print(table)

    # Summary line
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    parts: list[str] = []
    for sev in reversed(list(Severity)):
        if counts[sev]:
            parts.append(f"[{_SEVERITY_STYLES[sev]}]{counts[sev]} {sev.name}[/]")

    summary = " | ".join(parts)
    console.print(
        f"\n[bold]Total:[/bold] {len(findings)} finding(s) -- {summary}\n"
    )


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def format_json(findings: list[Finding]) -> str:
    """Serialise findings to a JSON string."""
    records: list[dict[str, Any]] = [
        {
            "rule": f.rule_name,
            "severity": f.severity.name.lower(),
            "description": f.description,
            "file": f.rel_path,
            "line": f.line_number,
            "match": f.match,
        }
        for f in findings
    ]
    return json.dumps(records, indent=2)


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

_SARIF_SEVERITY_MAP: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def format_sarif(findings: list[Finding]) -> str:
    """Serialise findings to SARIF v2.1.0 JSON.

    The output is compatible with GitHub Code Scanning's SARIF upload action.
    """
    # Build unique rule index.
    seen_rules: dict[str, int] = {}
    rule_descriptors: list[dict[str, Any]] = []
    for f in findings:
        if f.rule_name not in seen_rules:
            seen_rules[f.rule_name] = len(rule_descriptors)
            rule_descriptors.append(
                {
                    "id": f.rule_name,
                    "shortDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": _SARIF_SEVERITY_MAP[f.severity],
                    },
                }
            )

    results: list[dict[str, Any]] = [
        {
            "ruleId": f.rule_name,
            "ruleIndex": seen_rules[f.rule_name],
            "level": _SARIF_SEVERITY_MAP[f.severity],
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.rel_path},
                        "region": {
                            "startLine": f.line_number,
                        },
                    }
                }
            ],
        }
        for f in findings
    ]

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "envguard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/oriannadev/envguard",
                        "rules": rule_descriptors,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2)
