"""Core scanning engine.

Walks a directory tree, applies detection rules to each line of every
eligible file, and returns structured findings.  The scanner is intentionally
decoupled from output formatting so that the same results can be rendered in
multiple formats (plain text, JSON, SARIF).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .allowlist import AllowlistEntry, is_allowlisted, load_allowlist
from .gitignore import parse_gitignore, should_skip
from .rules import Rule, Severity, get_rules


@dataclass(frozen=True)
class Finding:
    """A single secret detected in a file.

    Attributes:
        rule_name:   The ``Rule.name`` that matched.
        severity:    Severity level of the matched rule.
        description: Human-readable description from the rule.
        filepath:    Absolute path to the file containing the secret.
        rel_path:    Path relative to the scan root (used in reports).
        line_number: 1-based line number where the match occurred.
        line:        The full text of the matching line (trimmed).
        match:       The specific substring that matched the pattern.
    """

    rule_name: str
    severity: Severity
    description: str
    filepath: str
    rel_path: str
    line_number: int
    line: str
    match: str


# Maximum individual file size to scan (5 MB).  Larger files are almost
# certainly not source code and would slow down the scan for no benefit.
_MAX_FILE_SIZE = 5 * 1024 * 1024


def _is_text_file(path: Path) -> bool:
    """Heuristic check: read a small chunk and look for null bytes."""
    try:
        with path.open("rb") as fh:
            chunk = fh.read(1024)
        return b"\x00" not in chunk
    except OSError:
        return False


def _redact(match_text: str, visible: int = 8) -> str:
    """Partially redact a matched secret for safe display.

    Shows the first *visible* characters followed by asterisks so that
    the user can identify the key without the full secret appearing in
    logs or CI output.
    """
    if len(match_text) <= visible:
        return match_text
    return match_text[:visible] + "*" * min(len(match_text) - visible, 16)


def scan_file(
    filepath: Path,
    root: Path,
    rules: list[Rule],
    allowlist: list[AllowlistEntry],
    min_severity: Severity = Severity.LOW,
) -> list[Finding]:
    """Scan a single file against all *rules* and return findings.

    Findings that are allowlisted or below *min_severity* are excluded.
    """
    rel_path = str(filepath.relative_to(root))
    findings: list[Finding] = []

    try:
        with filepath.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                stripped = line.rstrip("\n\r")
                for rule in rules:
                    if rule.severity < min_severity:
                        continue
                    for m in rule.pattern.finditer(stripped):
                        if is_allowlisted(rule.name, rel_path, allowlist):
                            continue
                        findings.append(
                            Finding(
                                rule_name=rule.name,
                                severity=rule.severity,
                                description=rule.description,
                                filepath=str(filepath),
                                rel_path=rel_path,
                                line_number=line_no,
                                line=stripped,
                                match=_redact(m.group()),
                            )
                        )
    except OSError:
        # File disappeared or became unreadable mid-scan -- skip silently.
        pass

    return findings


def scan_directory(
    root: Path,
    min_severity: Severity = Severity.LOW,
) -> list[Finding]:
    """Recursively scan *root* for secrets.

    This is the main entry point for the scanning engine.  It:
    1. Loads ``.gitignore`` patterns and the ``.envguardrc`` allowlist.
    2. Walks the directory tree, skipping ignored and binary files.
    3. Applies every detection rule to each eligible file.
    4. Returns a list of :class:`Finding` objects sorted by severity
       (critical first) then by file path and line number.
    """
    root = root.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Directory not found: {root}")

    rules = get_rules()
    gitignore_patterns = parse_gitignore(root)
    allowlist = load_allowlist(root)
    findings: list[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune always-skipped directories in-place so os.walk won't descend.
        dirnames[:] = [
            d
            for d in dirnames
            if not should_skip(Path(dirpath) / d / "_placeholder", root, gitignore_patterns)
        ]

        for filename in filenames:
            filepath = Path(dirpath) / filename

            if should_skip(filepath, root, gitignore_patterns):
                continue

            # Skip very large or binary files.
            try:
                if filepath.stat().st_size > _MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            if not _is_text_file(filepath):
                continue

            findings.extend(
                scan_file(filepath, root, rules, allowlist, min_severity)
            )

    # Sort: critical first, then by path and line number for stable output.
    findings.sort(key=lambda f: (-f.severity, f.rel_path, f.line_number))
    return findings
