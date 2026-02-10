""".gitignore-aware file filtering.

Parses ``.gitignore`` files and determines which paths should be excluded
from scanning.  This prevents the scanner from wasting time on vendored
dependencies, build artefacts, and other files that would never be committed.
"""

from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path


# Directories that are *always* skipped regardless of .gitignore content.
# These are large, rarely contain user code, and dramatically slow scans.
ALWAYS_SKIP_DIRS: set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
}

# Binary / non-text extensions that should never be scanned.
BINARY_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".sqlite", ".db",
}


def parse_gitignore(root: Path) -> list[str]:
    """Read a ``.gitignore`` file from *root* and return its patterns.

    Blank lines and comments (``#``) are stripped.  Returns an empty list
    if the file does not exist.
    """
    gitignore_path = root / ".gitignore"
    if not gitignore_path.is_file():
        return []

    patterns: list[str] = []
    with gitignore_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                patterns.append(stripped)
    return patterns


def _matches_pattern(rel_path: str, pattern: str) -> bool:
    """Check if *rel_path* matches a single gitignore-style *pattern*.

    Supports basic gitignore semantics:
    * A trailing ``/`` matches directories -- any path component that matches
      the pattern name causes the entire path to be skipped.
    * Patterns without a ``/`` match against the basename *and* each
      directory component in the path.
    * Patterns containing a ``/`` (other than a trailing one) match against
      the full relative path.
    * Standard ``fnmatch`` wildcards (``*``, ``?``, ``[...]``).
    """
    is_dir_pattern = pattern.endswith("/")
    clean = pattern.rstrip("/")

    # Patterns with an internal slash match the full relative path.
    if "/" in clean:
        return fnmatch(rel_path, pattern) or fnmatch(rel_path, clean)

    # Directory patterns: match against any path component (directory name).
    if is_dir_pattern:
        parts = rel_path.replace("\\", "/").split("/")
        return any(fnmatch(part, clean) for part in parts)

    # Simple patterns: match the basename or any path component.
    basename = os.path.basename(rel_path)
    if fnmatch(basename, clean):
        return True

    # Also check path components so that e.g. "*.log" in a gitignore
    # does not need a trailing "/" to match a directory named "*.log".
    parts = rel_path.replace("\\", "/").split("/")
    return any(fnmatch(part, clean) for part in parts)


def should_skip(
    filepath: Path,
    root: Path,
    gitignore_patterns: list[str],
) -> bool:
    """Decide whether *filepath* should be excluded from scanning.

    A file is skipped if:
    1. It lives inside an always-skipped directory (e.g. ``.git``).
    2. It has a known binary extension.
    3. It matches a pattern from the project's ``.gitignore``.
    """
    rel = filepath.relative_to(root)
    parts = rel.parts

    # 1. Always-skip directories
    for part in parts:
        if part in ALWAYS_SKIP_DIRS:
            return True

    # 2. Binary extensions
    if filepath.suffix.lower() in BINARY_EXTENSIONS:
        return True

    # 3. Gitignore patterns
    rel_str = str(rel)
    for pattern in gitignore_patterns:
        # Negation patterns (leading ``!``) are intentionally not supported
        # to keep the implementation simple and predictable.
        if pattern.startswith("!"):
            continue
        if _matches_pattern(rel_str, pattern):
            return True

    return False
