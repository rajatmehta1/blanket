"""
Code parser — clones a git repo (or uses a local path) and parses Python files via AST.
Produces structured file data for downstream analysis agents.
"""
from __future__ import annotations

import ast
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from app.models.state import AuditState

logger = logging.getLogger(__name__)

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".eggs", "dist", "build"}


async def parse_repository(state: AuditState) -> dict:
    """LangGraph node: clone repo and parse all Python files."""
    repo_url = state["repo_url"]
    agent_logs: List[str] = []
    errors: List[str] = []

    agent_logs.append(f"[Parser] Starting ingestion for {repo_url}")

    # determine if local path or remote URL
    if os.path.isdir(repo_url):
        repo_dir = repo_url
        repo_name = Path(repo_url).name
        agent_logs.append(f"[Parser] Using local directory: {repo_dir}")
    else:
        repo_dir = tempfile.mkdtemp(prefix="blanket_audit_")
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        agent_logs.append(f"[Parser] Cloning {repo_url} into {repo_dir}")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, repo_dir],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            error_msg = f"[Parser] Git clone failed: {e.stderr}"
            logger.error(error_msg)
            return {"errors": [error_msg], "agent_logs": agent_logs, "parsed_files": [], "repo_metadata": {}}

    # collect metadata
    py_files = _find_python_files(repo_dir)
    all_files = _find_all_files(repo_dir)
    languages = _detect_languages(all_files)

    repo_metadata = {
        "full_name": repo_name,
        "local_path": repo_dir,
        "total_files": len(all_files),
        "python_files": len(py_files),
        "languages": languages,
    }

    # parse each Python file
    parsed_files: List[Dict[str, Any]] = []
    for fp in py_files:
        try:
            parsed = _parse_python_file(fp, repo_dir)
            if parsed:
                parsed_files.append(parsed)
        except Exception as e:
            errors.append(f"[Parser] Failed to parse {fp}: {e}")

    agent_logs.append(f"[Parser] Parsed {len(parsed_files)}/{len(py_files)} Python files")

    return {
        "repo_metadata": repo_metadata,
        "parsed_files": parsed_files,
        "agent_logs": agent_logs,
        "errors": errors,
    }


def _find_python_files(root: str) -> List[str]:
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f.endswith(".py"):
                result.append(os.path.join(dirpath, f))
    return result


def _find_all_files(root: str) -> List[str]:
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        result.extend(filenames)
    return result


def _detect_languages(filenames: List[str]) -> List[str]:
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".java": "Java", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
        ".cpp": "C++", ".c": "C", ".cs": "C#", ".php": "PHP",
    }
    found = set()
    for f in filenames:
        ext = os.path.splitext(f)[1].lower()
        if ext in ext_map:
            found.add(ext_map[ext])
    return sorted(found)


def _parse_python_file(filepath: str, repo_root: str) -> Dict[str, Any] | None:
    """Parse a single Python file and extract structure."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return None

    rel_path = os.path.relpath(filepath, repo_root)
    classes = []
    functions = []
    imports = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            bases = [ast.dump(b) for b in node.bases]
            classes.append({
                "name": node.name,
                "methods": methods,
                "method_count": len(methods),
                "bases": bases,
                "lineno": node.lineno,
            })
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # only top-level functions (not methods)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arg_count = len(node.args.args)
                body_lines = node.end_lineno - node.lineno + 1 if node.end_lineno else 0
                functions.append({
                    "name": node.name,
                    "arg_count": arg_count,
                    "line_count": body_lines,
                    "lineno": node.lineno,
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                })
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.append(module)

    return {
        "path": rel_path,
        "line_count": len(source.splitlines()),
        "classes": classes,
        "functions": functions,
        "imports": imports,
    }
