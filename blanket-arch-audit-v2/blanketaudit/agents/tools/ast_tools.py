"""AST node inspection tools for LangGraph agents.

These tools let agents inspect specific methods, classes, and code
structures at given file locations.  They work with the extracted
AnalysisContext data (no tree-sitter needed at query time).
All tools return JSON strings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Module-level context reference — set by orchestrator.
_analysis_contexts: list[Any] = []


def set_analysis_contexts(contexts: list) -> None:
    """Set the analysis contexts for tool functions."""
    global _analysis_contexts
    _analysis_contexts = contexts


# ── Tool functions ───────────────────────────────────────────


def inspect_node(file_path: str, line: int) -> str:
    """Inspect what entity (method/class) exists at a specific line in a file.

    Returns JSON with the entity details if found at that line.
    """
    for ctx in _analysis_contexts:
        # Check methods
        for m in getattr(ctx, "methods", []):
            if _matches(m, file_path, line):
                return json.dumps({
                    "type": "method",
                    "name": _get(m, "qualified_name"),
                    "file_path": _get(m, "file_path"),
                    "line_start": _get(m, "line_start"),
                    "line_end": _get(m, "line_end"),
                    "parameters": _get(m, "parameters", []),
                    "return_type": _get(m, "return_type", ""),
                    "decorators": _get(m, "decorators", []),
                    "complexity": _get(m, "complexity", 0),
                    "is_entry_point": _get(m, "is_entry_point", False),
                })
        # Check classes
        for c in getattr(ctx, "classes", []):
            if _matches(c, file_path, line):
                return json.dumps({
                    "type": "class",
                    "name": _get(c, "name"),
                    "file_path": _get(c, "file_path"),
                    "line_start": _get(c, "line_start"),
                    "line_end": _get(c, "line_end"),
                    "methods": _get(c, "methods", []),
                    "bases": _get(c, "bases", []),
                    "decorators": _get(c, "decorators", []),
                })

    return json.dumps({"error": f"No entity found at {file_path}:{line}"})


def get_method_info(qualified_name: str) -> str:
    """Get detailed info about a method by its qualified name.

    Returns JSON with method details including parameters, complexity, etc.
    """
    for ctx in _analysis_contexts:
        for m in getattr(ctx, "methods", []):
            qn = getattr(m, "qualified_name", None) or m.get("qualified_name", "")
            if qn == qualified_name:
                return json.dumps({
                    "name": _get(m, "name"),
                    "qualified_name": qn,
                    "file_path": _get(m, "file_path"),
                    "line_start": _get(m, "line_start"),
                    "line_end": _get(m, "line_end"),
                    "parameters": _get(m, "parameters", []),
                    "return_type": _get(m, "return_type", ""),
                    "decorators": _get(m, "decorators", []),
                    "complexity": _get(m, "complexity", 0),
                    "is_entry_point": _get(m, "is_entry_point", False),
                    "loc": _get(m, "loc", 0),
                })

    return json.dumps({"error": f"Method not found: {qualified_name}"})


def get_class_info(class_name: str) -> str:
    """Get detailed info about a class by name.

    Returns JSON with class details including methods, bases, etc.
    """
    for ctx in _analysis_contexts:
        for c in getattr(ctx, "classes", []):
            name = getattr(c, "name", None) or c.get("name", "")
            if name == class_name:
                return json.dumps({
                    "name": name,
                    "file_path": _get(c, "file_path"),
                    "line_start": _get(c, "line_start"),
                    "line_end": _get(c, "line_end"),
                    "methods": _get(c, "methods", []),
                    "bases": _get(c, "bases", []),
                    "decorators": _get(c, "decorators", []),
                    "loc": _get(c, "loc", 0),
                })

    return json.dumps({"error": f"Class not found: {class_name}"})


def get_file_methods(file_path: str) -> str:
    """List all methods in a specific file.

    Returns JSON with ``methods`` list.
    """
    methods: list[dict] = []
    for ctx in _analysis_contexts:
        for m in getattr(ctx, "methods", []):
            fp = getattr(m, "file_path", None) or m.get("file_path", "")
            if fp == file_path:
                methods.append({
                    "name": _get(m, "name"),
                    "qualified_name": _get(m, "qualified_name"),
                    "line_start": _get(m, "line_start"),
                    "complexity": _get(m, "complexity", 0),
                    "is_entry_point": _get(m, "is_entry_point", False),
                })

    return json.dumps({"file": file_path, "methods": methods, "count": len(methods)})


def get_imports(file_path: str) -> str:
    """List all imports in a specific file.

    Returns JSON with ``imports`` list.
    """
    imports: list[dict] = []
    for ctx in _analysis_contexts:
        for imp in getattr(ctx, "imports", []):
            sf = getattr(imp, "source_file", None) or imp.get("source_file", "")
            if sf == file_path:
                imports.append({
                    "module": _get(imp, "imported_module"),
                    "names": _get(imp, "imported_names", []),
                    "line": _get(imp, "line_number", 0),
                    "is_relative": _get(imp, "is_relative", False),
                })

    return json.dumps({"file": file_path, "imports": imports, "count": len(imports)})


def read_file_content(file_path: str, repo_path: str, start_line: int = 1, end_line: int = 0) -> str:
    """Read source code from a file within the repository.

    Returns JSON with ``content`` string.
    """
    try:
        full_path = Path(repo_path) / file_path
        if not full_path.exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()

        if end_line <= 0:
            end_line = len(lines)
        start_line = max(1, start_line)
        end_line = min(len(lines), end_line)

        content = "\n".join(lines[start_line - 1 : end_line])
        return json.dumps({
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": len(lines),
            "content": content,
        })
    except Exception as exc:
        return json.dumps({"error": str(exc)[:200]})


# ── Helpers ──────────────────────────────────────────────────


def _get(obj: Any, attr: str, default: Any = "") -> Any:
    """Get attribute from Pydantic model or dict."""
    if hasattr(obj, attr):
        return getattr(obj, attr)
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return default


def _matches(entity: Any, file_path: str, line: int) -> bool:
    """Check if an entity spans the given file and line."""
    fp = _get(entity, "file_path")
    ls = _get(entity, "line_start", 0)
    le = _get(entity, "line_end", 0)
    return fp == file_path and ls <= line <= le
