"""Allowlist support via ``.envguardrc`` configuration files.

Teams can place a ``.envguardrc`` (JSON) file in their project root to
suppress known false positives.  The schema is intentionally simple:

.. code-block:: json

    {
        "allowlist": [
            {
                "rule": "openai-api-key",
                "path": "tests/test_fixtures/fake_env",
                "reason": "Test fixture with intentionally fake keys"
            },
            {
                "path": "tests/test_fixtures/",
                "reason": "All fixture files contain fake secrets for testing"
            }
        ]
    }

Each entry can specify:
* ``rule`` -- suppress a specific rule name (optional, matches all rules if absent).
* ``path`` -- a path prefix; any finding whose file path starts with this
  value is suppressed (optional, matches all paths if absent).
* ``reason`` -- a human-readable note explaining why this is allowlisted
  (optional, but recommended).

At least one of ``rule`` or ``path`` must be present for the entry to be
meaningful.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AllowlistEntry:
    """A single allowlist item parsed from ``.envguardrc``."""

    rule: str | None
    path: str | None
    reason: str | None


def load_allowlist(root: Path) -> list[AllowlistEntry]:
    """Load allowlist entries from ``.envguardrc`` in *root*.

    Returns an empty list if the file does not exist or cannot be parsed.
    Malformed entries are silently skipped so that a single bad entry does
    not break the entire scan.
    """
    rc_path = root / ".envguardrc"
    if not rc_path.is_file():
        return []

    try:
        with rc_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

    entries: list[AllowlistEntry] = []
    for item in data.get("allowlist", []):
        if not isinstance(item, dict):
            continue
        entries.append(
            AllowlistEntry(
                rule=item.get("rule"),
                path=item.get("path"),
                reason=item.get("reason"),
            )
        )
    return entries


def is_allowlisted(
    rule_name: str,
    rel_path: str,
    allowlist: list[AllowlistEntry],
) -> bool:
    """Return ``True`` if a finding should be suppressed.

    A finding matches an allowlist entry when **all** specified fields in the
    entry match the finding.  Fields that are ``None`` in the entry are
    treated as wildcards.
    """
    for entry in allowlist:
        rule_match = entry.rule is None or entry.rule == rule_name
        path_match = entry.path is None or rel_path.startswith(entry.path)
        if rule_match and path_match:
            return True
    return False
