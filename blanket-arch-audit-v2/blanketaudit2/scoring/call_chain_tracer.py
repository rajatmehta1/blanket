"""Trace the call chain from entry point to finding location.

Builds an ordered list of CallChainStep objects showing how a request
flows from an HTTP entry point through the call graph to the vulnerable
code.  Each step is classified by type (entry, method, cross_repo,
taint, sink, external, propagation).
"""

from __future__ import annotations

from collections import deque
from typing import Any

import structlog

from blanketaudit2.models.finding import AuditFinding, CallChainStep

logger = structlog.get_logger()


class CallChainTracer:
    """Trace call chains from entry points to finding locations."""

    async def trace(
        self,
        finding: AuditFinding,
        graph_store: Any,
    ) -> list[CallChainStep]:
        """Build the call chain from entry point to the finding.

        1. Find the method containing the finding (from file:line)
        2. Find entry points that reach this method (reverse BFS)
        3. Pick the shortest path
        4. Classify each step by type
        """
        if graph_store is None:
            return self._minimal_chain(finding)

        target = self._find_target_method(finding)
        if not target:
            return self._minimal_chain(finding)

        try:
            # Get entry points
            all_entries = await graph_store.get_entry_points()
            if not all_entries:
                return self._minimal_chain(finding)

            # Try to find a path from each entry to the target
            best_chain: list[str] | None = None
            best_entry: dict = {}

            for entry in all_entries[:10]:  # Limit search
                entry_name = entry.get("name", "")
                chains = await graph_store.get_call_chain(entry_name, target, max_depth=8)
                if chains:
                    chain = chains[0]  # Shortest
                    if best_chain is None or len(chain) < len(best_chain):
                        best_chain = chain
                        best_entry = entry

            if best_chain:
                return self._classify_chain(best_chain, best_entry, finding)

            return self._minimal_chain(finding)

        except Exception as exc:
            logger.warning("call_chain.trace_failed", error=str(exc)[:200])
            return self._minimal_chain(finding)

    def _classify_chain(
        self,
        chain: list[str],
        entry: dict,
        finding: AuditFinding,
    ) -> list[CallChainStep]:
        """Classify each step in the chain."""
        steps: list[CallChainStep] = []
        prev_repo = ""

        for i, method_id in enumerate(chain):
            repo = self._extract_repo(method_id)
            is_first = i == 0
            is_last = i == len(chain) - 1

            if is_first:
                step_type = "entry"
            elif repo != prev_repo and prev_repo:
                step_type = "cross_repo"
            elif is_last:
                step_type = "sink"
            else:
                step_type = "method"

            # Clean up method display name
            display_name = self._display_name(method_id, entry if is_first else {})

            steps.append(CallChainStep(
                method=display_name,
                step_type=step_type,
                repo=repo or "unknown",
            ))
            prev_repo = repo

        return steps

    @staticmethod
    def _minimal_chain(finding: AuditFinding) -> list[CallChainStep]:
        """Fallback: a single-step chain at the finding location."""
        if not finding.evidence:
            return []
        ev = finding.evidence[0]
        return [CallChainStep(
            method=f"{ev.file_path}:{ev.line_start}",
            step_type="sink",
            repo=ev.repo_name,
        )]

    @staticmethod
    def _find_target_method(finding: AuditFinding) -> str:
        """Extract target method ID from finding evidence."""
        if not finding.evidence:
            return ""
        ev = finding.evidence[0]
        return f"{ev.repo_name}::{ev.file_path}::line{ev.line_start}"

    @staticmethod
    def _extract_repo(method_id: str) -> str:
        """Extract repo name from a qualified method ID."""
        parts = method_id.split("::")
        return parts[0] if parts else ""

    @staticmethod
    def _display_name(method_id: str, entry: dict) -> str:
        """Format a method ID for display."""
        # If it's an entry point with route info, show the route
        route = entry.get("route", "")
        if route:
            return route

        # Otherwise, show the qualified name
        parts = method_id.split("::")
        if len(parts) >= 3:
            return parts[-1]  # Just the method name
        return method_id
