"""Build CallGraphSummary for the report.

Delegates to GraphAnalyzer.build_summary() which does the actual work.
This module exists as a convenience wrapper matching the CLAUDE.md structure.
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit2.models.callgraph import CallGraphSummary, DeadCodeSummary

logger = structlog.get_logger()


class CallGraphSummaryBuilder:
    """Build a CallGraphSummary from a call graph for the report."""

    def build(
        self,
        call_graph: Any = None,
        cross_repo_matches: list | None = None,
    ) -> CallGraphSummary:
        """Build summary from a CallGraph object.

        If a GraphAnalyzer-compatible graph is provided, delegates to it.
        Otherwise returns an empty summary.
        """
        if call_graph is not None:
            try:
                from blanketaudit2.callgraph.graph_analyzer import GraphAnalyzer
                analyzer = GraphAnalyzer(call_graph)
                return analyzer.build_summary(cross_repo_matches)
            except Exception as exc:
                logger.warning("callgraph_summary.build_failed", error=str(exc)[:200])

        return CallGraphSummary(
            entry_points=[],
            cross_repo_edges=[],
            circular_dependencies=[],
            dead_methods=DeadCodeSummary(count=0, total_lines=0, top_files=[]),
            single_points_of_failure=[],
        )
