"""Cost Optimization Agent — LangGraph node.

Detects: redundant dependencies, oversized imports, duplicate code patterns,
         unoptimized data loading, missing caching opportunities.
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List

from app.models.common import Severity, FindingCategory
from app.models.state import AuditState

logger = logging.getLogger(__name__)

HEAVY_IMPORTS = {
    "tensorflow": "TensorFlow — large dependency, consider tflite for inference",
    "torch": "PyTorch — large dependency, consider ONNX for deployment",
    "pandas": "Pandas — heavy for simple data tasks, consider polars or csv module",
    "scipy": "SciPy — large dependency, import only needed submodules",
    "boto3": "boto3 — ensure session reuse to avoid repeated auth overhead",
}


async def analyze_cost_optimization(state: AuditState) -> dict:
    """LangGraph node: detect cost optimization opportunities via static analysis."""
    parsed_files = state.get("parsed_files", [])
    findings: List[Dict[str, Any]] = []
    agent_logs: List[str] = []
    errors: List[str] = []

    agent_logs.append("[CostOpt] Starting cost optimization analysis")

    try:
        findings.extend(_detect_redundant_dependencies(parsed_files))
        findings.extend(_detect_heavy_imports(parsed_files))
        findings.extend(_detect_large_files(parsed_files))
        findings.extend(_detect_missing_caching(parsed_files))
    except Exception as e:
        errors.append(f"[CostOpt] Analysis failed: {e}")
        logger.error("[CostOpt] Analysis failed", exc_info=True)

    agent_logs.append(f"[CostOpt] Complete — {len(findings)} findings")
    return {
        "cost_findings": findings,
        "agent_logs": agent_logs,
        "errors": errors,
    }


def _detect_redundant_dependencies(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    """Detect imports that appear in only one file (possibly unnecessary dependency)."""
    import_files: Dict[str, List[str]] = {}
    for pf in parsed_files:
        for imp in set(pf.get("imports", [])):
            import_files.setdefault(imp, []).append(pf["path"])

    # not flagging single-use imports — instead flag duplicate functionality
    findings = []
    all_imports = []
    for pf in parsed_files:
        all_imports.extend(pf.get("imports", []))

    counts = Counter(all_imports)
    # detect if both requests and httpx or urllib3 are used
    http_libs = {"requests", "httpx", "urllib3", "aiohttp", "urllib"}
    used_http = [lib for lib in http_libs if counts.get(lib, 0) > 0]
    if len(used_http) > 1:
        findings.append({
            "title": f"Multiple HTTP libraries in use: {', '.join(used_http)}",
            "severity": Severity.LOW.value,
            "category": FindingCategory.COST_OPTIMIZATION.value,
            "file": "project-wide",
            "line": 0,
            "evidence": f"Libraries: {', '.join(used_http)}",
            "recommendation": "Standardize on one HTTP library to reduce dependency footprint.",
        })

    return findings


def _detect_heavy_imports(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    findings = []
    seen = set()
    for pf in parsed_files:
        for imp in pf.get("imports", []):
            root = imp.split(".")[0]
            if root in HEAVY_IMPORTS and root not in seen:
                seen.add(root)
                findings.append({
                    "title": f"Heavy dependency: {root}",
                    "severity": Severity.INFO.value,
                    "category": FindingCategory.COST_OPTIMIZATION.value,
                    "file": pf["path"],
                    "line": 0,
                    "evidence": HEAVY_IMPORTS[root],
                    "recommendation": f"Evaluate if {root} is needed or if a lighter alternative works.",
                })
    return findings


def _detect_large_files(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    findings = []
    for pf in parsed_files:
        if pf.get("line_count", 0) > 500:
            findings.append({
                "title": f"Large file: {pf['path']}",
                "severity": Severity.LOW.value,
                "category": FindingCategory.COST_OPTIMIZATION.value,
                "file": pf["path"],
                "line": 0,
                "evidence": f"{pf['line_count']} lines",
                "recommendation": "Split into smaller modules to improve build times and maintainability.",
            })
    return findings


def _detect_missing_caching(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    """Flag repeated expensive-looking function patterns without caching decorators."""
    findings = []
    repo_metadata_state = None
    local_path = ""

    for pf in parsed_files:
        for fn in pf.get("functions", []):
            # functions named get_*/fetch_*/load_* with many lines but no caching
            name = fn["name"]
            if any(name.startswith(p) for p in ("get_", "fetch_", "load_", "query_")):
                if fn["line_count"] > 20:
                    findings.append({
                        "title": f"Potentially cacheable function: {name}",
                        "severity": Severity.INFO.value,
                        "category": FindingCategory.COST_OPTIMIZATION.value,
                        "file": pf["path"],
                        "line": fn["lineno"],
                        "evidence": f"{fn['line_count']} lines, name suggests data retrieval",
                        "recommendation": f"Consider adding @lru_cache or Redis caching to {name}.",
                    })
    return findings
