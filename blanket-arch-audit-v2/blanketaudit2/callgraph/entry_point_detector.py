"""Framework-specific entry point detection.

Detects HTTP entry points from framework decorators/annotations.
Works with data already extracted by language extractors, plus
additional pattern matching for frameworks the extractors may not
fully cover.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from blanketaudit2.ingestion.models import (
    AnalysisContext,
    EntryPointInfo,
    MethodInfo,
)

logger = structlog.get_logger()

# -- Framework detection patterns ------------------------------------------

# Python frameworks
_PYTHON_ENTRY_DECORATORS = {
    "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "router.get", "router.post", "router.put", "router.delete", "router.patch",
    "app.route",
    # Django
    "api_view", "action",
}

# Java Spring annotations
_JAVA_ENTRY_ANNOTATIONS = {
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
    "RequestMapping",
}

# TypeScript/JS Express patterns
_EXPRESS_METHODS = {"get", "post", "put", "delete", "patch", "all"}

# Map decorator/annotation to HTTP method
_HTTP_METHOD_MAP: dict[str, str] = {
    "get": "GET", "post": "POST", "put": "PUT",
    "delete": "DELETE", "patch": "PATCH",
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH",
}

# Route extraction regex -- finds first quoted string in decorator/annotation
_ROUTE_RE = re.compile(r"""['"]([/\w{}:*\-\.]+)['"]""")


def _extract_route(decorator_text: str) -> str:
    """Pull the route path from a decorator or annotation string."""
    match = _ROUTE_RE.search(decorator_text)
    return match.group(1) if match else ""


def _detect_http_method(decorator_text: str) -> str:
    """Infer HTTP method from a decorator/annotation string."""
    lower = decorator_text.lower()
    for key, method in _HTTP_METHOD_MAP.items():
        if key.lower() in lower:
            return method
    return ""


def _detect_framework(decorator_text: str, language: str) -> str:
    """Infer the framework name from decorator + language."""
    lower = decorator_text.lower()
    if language == "python":
        if "router." in lower or "app." in lower:
            return "fastapi"
        if "api_view" in lower:
            return "django"
    elif language == "java":
        if any(ann.lower() in lower for ann in _JAVA_ENTRY_ANNOTATIONS):
            return "spring"
    elif language in ("typescript", "javascript"):
        return "express"
    return "unknown"


class EntryPointDetector:
    """Detect HTTP entry points from extracted methods.

    Works in two passes:
    1. Use entry points already flagged by language extractors.
    2. Pattern-match remaining methods for decorators/annotations
       the extractors may have missed.
    """

    def detect(self, context: AnalysisContext) -> list[EntryPointInfo]:
        """Return all detected entry points for a repo."""
        seen: set[str] = set()
        results: list[EntryPointInfo] = []

        # Pass 1: Already-detected entry points from extractors
        for ep in context.entry_points:
            key = f"{ep.file_path}::{ep.method_name}::{ep.http_method}"
            if key not in seen:
                seen.add(key)
                results.append(ep)

        # Pass 2: Scan methods for entry point decorators/annotations
        for method in context.methods:
            if method.is_entry_point:
                continue  # Already handled in pass 1
            for dec in method.decorators:
                if self._is_entry_decorator(dec, _infer_language(method.file_path)):
                    http_method = _detect_http_method(dec)
                    route = _extract_route(dec)
                    framework = _detect_framework(dec, _infer_language(method.file_path))
                    ep = EntryPointInfo(
                        method_name=method.qualified_name,
                        file_path=method.file_path,
                        repo_name=method.repo_name,
                        http_method=http_method,
                        route=route,
                        framework=framework,
                        line_number=method.line_start,
                    )
                    key = f"{ep.file_path}::{ep.method_name}::{ep.http_method}"
                    if key not in seen:
                        seen.add(key)
                        results.append(ep)

        # Pass 3: Check for main() / if __name__ == "__main__" patterns
        for method in context.methods:
            if method.name == "main" and not method.is_entry_point:
                key = f"{method.file_path}::{method.qualified_name}::MAIN"
                if key not in seen:
                    seen.add(key)
                    results.append(EntryPointInfo(
                        method_name=method.qualified_name,
                        file_path=method.file_path,
                        repo_name=method.repo_name,
                        framework="main",
                        line_number=method.line_start,
                    ))

        logger.info(
            "entry_points.detected",
            repo=context.repo_name,
            count=len(results),
        )
        return results

    @staticmethod
    def _is_entry_decorator(decorator: str, language: str) -> bool:
        """Check if a decorator/annotation is an entry point marker."""
        lower = decorator.lower()
        if language == "python":
            return any(ep in lower for ep in ("app.get", "app.post", "app.put",
                        "app.delete", "app.patch", "router.get", "router.post",
                        "router.put", "router.delete", "router.patch", "app.route",
                        "api_view"))
        if language == "java":
            return any(ann.lower() in lower for ann in _JAVA_ENTRY_ANNOTATIONS)
        if language in ("typescript", "javascript"):
            # Express: handled by extractor typically, but check here too
            return any(f".{m}" in lower for m in _EXPRESS_METHODS)
        return False


def _infer_language(file_path: str) -> str:
    """Infer language from file extension."""
    if file_path.endswith(".py"):
        return "python"
    if file_path.endswith((".ts", ".tsx")):
        return "typescript"
    if file_path.endswith((".js", ".jsx")):
        return "javascript"
    if file_path.endswith(".java"):
        return "java"
    if file_path.endswith(".go"):
        return "go"
    if file_path.endswith(".rs"):
        return "rust"
    return ""
