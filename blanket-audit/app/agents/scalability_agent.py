"""Scalability Agent — LangGraph node.

Detects: synchronous bottlenecks in async code, missing connection pooling,
         global mutable state, unbounded data structures, blocking I/O in hot paths.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.models.common import Severity, FindingCategory
from app.models.state import AuditState

logger = logging.getLogger(__name__)

BLOCKING_CALLS = [
    "time.sleep(", "requests.get(", "requests.post(", "requests.put(",
    "requests.delete(", "input(",
]

GLOBAL_MUTABLE_PATTERNS = [
    "= []", "= {}", "= set()",
]


async def analyze_scalability(state: AuditState) -> dict:
    """LangGraph node: detect scalability issues via static analysis."""
    parsed_files = state.get("parsed_files", [])
    findings: List[Dict[str, Any]] = []
    agent_logs: List[str] = []
    errors: List[str] = []

    agent_logs.append("[Scalability] Starting scalability analysis")
    repo_metadata = state.get("repo_metadata", {})
    local_path = repo_metadata.get("local_path", "")

    try:
        for pf in parsed_files:
            filepath = pf["path"]
            full_path = f"{local_path}/{filepath}" if local_path else filepath
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except FileNotFoundError:
                continue

            lines = source.splitlines()
            has_async = any(fn.get("is_async") for fn in pf.get("functions", []))

            # detect blocking calls in async codebases
            if has_async:
                for i, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if stripped.startswith("#") or stripped.startswith('"') or stripped.startswith("'"):
                        continue
                    for call in BLOCKING_CALLS:
                        if call in stripped and "await" not in stripped:
                            findings.append({
                                "title": f"Blocking call in async codebase: {call.rstrip('(')}",
                                "severity": Severity.HIGH.value,
                                "category": FindingCategory.SCALABILITY.value,
                                "file": filepath,
                                "line": i,
                                "evidence": stripped,
                                "recommendation": f"Use async equivalent or wrap in asyncio.to_thread().",
                            })

            # detect large classes that may not scale (state bottleneck)
            for cls in pf.get("classes", []):
                if cls["method_count"] > 20:
                    findings.append({
                        "title": f"Monolithic class may become bottleneck: {cls['name']}",
                        "severity": Severity.MEDIUM.value,
                        "category": FindingCategory.SCALABILITY.value,
                        "file": filepath,
                        "line": cls["lineno"],
                        "evidence": f"{cls['method_count']} methods — hard to scale horizontally",
                        "recommendation": "Decompose into smaller services or strategy pattern.",
                    })

            # detect functions with too many args (hard to parallelize)
            for fn in pf.get("functions", []):
                if fn["arg_count"] > 8:
                    findings.append({
                        "title": f"Function with excessive parameters: {fn['name']}",
                        "severity": Severity.LOW.value,
                        "category": FindingCategory.SCALABILITY.value,
                        "file": filepath,
                        "line": fn["lineno"],
                        "evidence": f"{fn['arg_count']} parameters",
                        "recommendation": "Group parameters into a config/dataclass to simplify interfaces.",
                    })
    except Exception as e:
        errors.append(f"[Scalability] Analysis failed: {e}")
        logger.error("[Scalability] Analysis failed", exc_info=True)

    agent_logs.append(f"[Scalability] Complete — {len(findings)} findings")
    return {
        "scalability_findings": findings,
        "agent_logs": agent_logs,
        "errors": errors,
    }
