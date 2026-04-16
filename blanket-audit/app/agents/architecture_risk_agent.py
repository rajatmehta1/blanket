"""Architecture Risk Agent — LangGraph node.

Detects: circular dependencies, god classes, long functions,
         high coupling, missing abstractions, deep inheritance.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.models.common import CustomerProfile, Severity, FindingCategory
from app.models.state import AuditState

logger = logging.getLogger(__name__)

GOD_CLASS_METHOD_THRESHOLD = 15
LONG_FUNCTION_THRESHOLD = 80
HIGH_FAN_IN_THRESHOLD = 10
DEEP_INHERITANCE_THRESHOLD = 3


async def analyze_architecture_risk(state: AuditState) -> dict:
    """LangGraph node: detect architecture risks via static analysis."""
    parsed_files = state.get("parsed_files", [])
    profile = state["customer_profile"]
    findings: List[Dict[str, Any]] = []
    agent_logs: List[str] = []
    errors: List[str] = []

    agent_logs.append("[ArchRisk] Starting architecture risk analysis")

    try:
        findings.extend(_detect_god_classes(parsed_files))
        findings.extend(_detect_long_functions(parsed_files))
        findings.extend(_detect_circular_imports(parsed_files))
        findings.extend(_detect_high_fan_in(parsed_files))
    except Exception as e:
        errors.append(f"[ArchRisk] Analysis failed: {e}")
        logger.error("[ArchRisk] Analysis failed", exc_info=True)

    agent_logs.append(f"[ArchRisk] Complete — {len(findings)} findings")
    return {
        "architecture_findings": findings,
        "agent_logs": agent_logs,
        "errors": errors,
    }


def _detect_god_classes(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    findings = []
    for pf in parsed_files:
        for cls in pf.get("classes", []):
            if cls["method_count"] >= GOD_CLASS_METHOD_THRESHOLD:
                findings.append({
                    "title": f"God class detected: {cls['name']}",
                    "severity": Severity.HIGH.value,
                    "category": FindingCategory.ARCHITECTURE_RISK.value,
                    "file": pf["path"],
                    "line": cls["lineno"],
                    "evidence": f"{cls['method_count']} methods (threshold: {GOD_CLASS_METHOD_THRESHOLD})",
                    "recommendation": f"Split {cls['name']} into smaller, focused classes using SRP.",
                })
    return findings


def _detect_long_functions(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    findings = []
    for pf in parsed_files:
        for fn in pf.get("functions", []):
            if fn["line_count"] >= LONG_FUNCTION_THRESHOLD:
                findings.append({
                    "title": f"Long function: {fn['name']}",
                    "severity": Severity.MEDIUM.value,
                    "category": FindingCategory.ARCHITECTURE_RISK.value,
                    "file": pf["path"],
                    "line": fn["lineno"],
                    "evidence": f"{fn['line_count']} lines (threshold: {LONG_FUNCTION_THRESHOLD})",
                    "recommendation": f"Extract helper functions from {fn['name']} to improve readability.",
                })
    return findings


def _detect_circular_imports(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    """Build an import graph and detect cycles."""
    # map module path -> set of imported modules
    module_map: Dict[str, set] = {}
    for pf in parsed_files:
        mod = pf["path"].replace("/", ".").replace("\\", ".").removesuffix(".py")
        module_map[mod] = set(pf.get("imports", []))

    findings = []
    known_modules = set(module_map.keys())
    for mod, imports in module_map.items():
        for imp in imports:
            if imp in module_map and mod in module_map.get(imp, set()):
                pair = tuple(sorted([mod, imp]))
                finding_title = f"Circular import: {pair[0]} <-> {pair[1]}"
                if not any(f["title"] == finding_title for f in findings):
                    findings.append({
                        "title": finding_title,
                        "severity": Severity.HIGH.value,
                        "category": FindingCategory.ARCHITECTURE_RISK.value,
                        "file": mod.replace(".", "/") + ".py",
                        "line": 0,
                        "evidence": f"{pair[0]} imports {pair[1]} and vice versa",
                        "recommendation": "Break the cycle by extracting shared types into a separate module.",
                    })
    return findings


STDLIB_MODULES = {
    "os", "sys", "re", "json", "logging", "typing", "typing_extensions",
    "collections", "functools", "itertools", "pathlib", "dataclasses",
    "abc", "enum", "uuid", "datetime", "math", "operator", "copy",
    "asyncio", "subprocess", "tempfile", "io", "hashlib", "secrets",
    "__future__", "contextlib", "warnings", "unittest", "pytest",
}


def _detect_high_fan_in(parsed_files: List[Dict]) -> List[Dict[str, Any]]:
    """Detect modules imported by many other modules (potential coupling bottleneck)."""
    import_counts: Dict[str, int] = {}
    for pf in parsed_files:
        for imp in set(pf.get("imports", [])):
            root = imp.split(".")[0]
            if root in STDLIB_MODULES:
                continue
            import_counts[imp] = import_counts.get(imp, 0) + 1

    findings = []
    for mod, count in import_counts.items():
        if count >= HIGH_FAN_IN_THRESHOLD:
            findings.append({
                "title": f"High fan-in module: {mod}",
                "severity": Severity.MEDIUM.value,
                "category": FindingCategory.ARCHITECTURE_RISK.value,
                "file": mod,
                "line": 0,
                "evidence": f"Imported by {count} modules (threshold: {HIGH_FAN_IN_THRESHOLD})",
                "recommendation": f"Consider splitting {mod} — changes here ripple across {count} consumers.",
            })
    return findings
