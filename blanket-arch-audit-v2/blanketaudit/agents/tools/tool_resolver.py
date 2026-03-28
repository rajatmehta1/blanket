"""Resolve external tool executables.

Checks common locations beyond PATH: project root, venv Scripts, etc.
This avoids requiring users to manually configure PATH on Windows.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Project root: two levels up from this file (tools/ -> agents/ -> blanketaudit/ -> project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Extra directories to search for executables
_EXTRA_SEARCH_DIRS: list[Path] = [
    _PROJECT_ROOT,                                 # project root (gitleaks.exe, osv-scanner.exe)
    _PROJECT_ROOT / ".venv" / "Scripts",           # Windows venv
    _PROJECT_ROOT / ".venv" / "bin",               # Unix venv
    _PROJECT_ROOT / "blanketaudit" / ".venv" / "Scripts",  # nested venv
    _PROJECT_ROOT / "blanketaudit" / ".venv" / "bin",
    Path(sys.prefix) / "Scripts",                  # active venv Scripts
    Path(sys.prefix) / "bin",                      # active venv bin
]


def resolve_tool(name: str) -> str:
    """Return the full path to an external tool executable.

    Searches PATH first (via shutil.which), then falls back to common
    locations like the project root and virtualenv Scripts directory.

    Returns the tool name unchanged if not found anywhere (so subprocess
    will raise FileNotFoundError as usual).
    """
    # 1. Standard PATH lookup
    found = shutil.which(name)
    if found:
        return found

    # 2. Check extra directories
    exe_names = [name]
    if os.name == "nt":
        exe_names.append(f"{name}.exe")

    for search_dir in _EXTRA_SEARCH_DIRS:
        for exe_name in exe_names:
            candidate = search_dir / exe_name
            if candidate.is_file():
                resolved = str(candidate)
                logger.info(
                    "tool_resolver.found",
                    tool=name,
                    path=resolved,
                    msg=f"Found {name} at {resolved} (not on PATH)",
                )
                return resolved

    logger.warning("tool_resolver.not_found", tool=name)
    return name  # Return original name; will fail at subprocess call
