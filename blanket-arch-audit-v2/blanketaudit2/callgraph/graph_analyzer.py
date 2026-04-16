"""Call graph analysis — blast radius, taint paths, cycles, dead code.

In-memory implementation using the CallGraph from static_builder.
This is the fallback when Neo4j is not available.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

import structlog

from blanketaudit2.callgraph.static_builder import CallGraph
from blanketaudit2.models.callgraph import (
    CallGraphSummary,
    CrossRepoEdge,
    DeadCodeSummary,
    EntryPointSummary,
)
from blanketaudit2.models.finding import BlastRadius

logger = structlog.get_logger()


@dataclass
class TaintPath:
    """A path from a source to a sink through the call graph."""

    source: str
    sink: str
    path: list[str]
    length: int


class GraphAnalyzer:
    """Analyze the in-memory call graph for security-relevant patterns.

    All methods are pure functions on the CallGraph — no database needed.
    """

    def __init__(self, graph: CallGraph) -> None:
        self.graph = graph

    # ── Blast radius ─────────────────────────────────────────

    def blast_radius(self, method_id: str) -> BlastRadius:
        """Compute how many entry points can reach *method_id*.

        Uses reverse BFS from method_id through the callers adjacency list
        to find all entry points that transitively call this method.
        """
        reaching_entries: set[str] = set()
        reaching_repos: set[str] = set()
        visited: set[str] = set()
        queue: deque[str] = deque([method_id])

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            if current in self.graph.entry_points:
                reaching_entries.add(current)

            # Extract repo from qualified ID "repo::file::method"
            parts = current.split("::", 1)
            if parts:
                reaching_repos.add(parts[0])

            # Walk callers (reverse edges)
            for caller in self.graph.callers.get(current, []):
                if caller not in visited:
                    queue.append(caller)

        return BlastRadius(
            entry_points=len(reaching_entries),
            repos_affected=len(reaching_repos),
            daily_calls="unknown",
            affected_users="unknown",
        )

    # ── Taint paths ──────────────────────────────────────────

    def taint_paths(
        self,
        source: str,
        sink: str,
        max_depth: int = 20,
    ) -> list[TaintPath]:
        """Find all paths from *source* to *sink* (DFS, depth-limited).

        Returns a list of TaintPath objects. Empty if no path exists.
        """
        results: list[TaintPath] = []
        self._dfs_paths(source, sink, [source], set(), max_depth, results)
        return results

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path: list[str],
        visited: set[str],
        max_depth: int,
        results: list[TaintPath],
    ) -> None:
        if len(path) > max_depth:
            return
        if current == target and len(path) > 1:
            results.append(
                TaintPath(
                    source=path[0],
                    sink=target,
                    path=list(path),
                    length=len(path) - 1,
                )
            )
            return

        visited.add(current)
        for callee in self.graph.callees.get(current, []):
            if callee not in visited or callee == target:
                path.append(callee)
                self._dfs_paths(callee, target, path, visited, max_depth, results)
                path.pop()
        visited.discard(current)

    # ── Circular dependencies ────────────────────────────────

    def find_cycles(self, max_cycles: int = 50) -> list[list[str]]:
        """Find circular dependencies (cycles) in the call graph.

        Uses DFS-based cycle detection. Returns up to *max_cycles* cycles.
        Each cycle is a list of method IDs forming the loop.
        """
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        for method_id in self.graph.methods:
            if method_id not in visited and len(cycles) < max_cycles:
                self._dfs_cycles(
                    method_id, visited, rec_stack, path, cycles, max_cycles
                )

        logger.info("callgraph.cycles_found", count=len(cycles))
        return cycles

    def _dfs_cycles(
        self,
        node: str,
        visited: set[str],
        rec_stack: set[str],
        path: list[str],
        cycles: list[list[str]],
        max_cycles: int,
    ) -> None:
        if len(cycles) >= max_cycles:
            return

        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for callee in self.graph.callees.get(node, []):
            if len(cycles) >= max_cycles:
                break
            if callee not in visited:
                self._dfs_cycles(
                    callee, visited, rec_stack, path, cycles, max_cycles
                )
            elif callee in rec_stack:
                # Found a cycle — extract it from where the callee first
                # appears in the current path up to the end, closing the loop.
                cycle_start = path.index(callee)
                cycle = path[cycle_start:] + [callee]
                cycles.append(cycle)

        path.pop()
        rec_stack.discard(node)

    # ── Dead code ────────────────────────────────────────────

    def find_dead_code(self) -> list[str]:
        """Find methods unreachable from any entry point.

        Uses forward BFS from all entry points. Methods not visited are dead.
        """
        reachable: set[str] = set()
        queue: deque[str] = deque(self.graph.entry_points)

        while queue:
            current = queue.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            for callee in self.graph.callees.get(current, []):
                if callee not in reachable:
                    queue.append(callee)

        all_methods = set(self.graph.methods.keys())
        dead = all_methods - reachable

        logger.info(
            "callgraph.dead_code",
            total_methods=len(all_methods),
            reachable=len(reachable),
            dead=len(dead),
        )
        return sorted(dead)

    # ── Critical paths ───────────────────────────────────────

    def find_critical_paths(
        self, sinks: set[str] | None = None
    ) -> list[list[str]]:
        """Find paths from entry points to important sinks.

        If *sinks* is not provided, all leaf methods (methods with no outgoing
        calls) reachable from entry points are considered sinks.

        Returns a list of paths (each path is a list of method IDs from entry
        to sink). Only the shortest path per (entry, sink) pair is returned.
        """
        if sinks is None:
            # Default sinks: leaf methods reachable from entry points
            reachable = self._reachable_from_entries()
            sinks = {
                m
                for m in reachable
                if not self.graph.callees.get(m, [])
            }

        paths: list[list[str]] = []
        for entry in self.graph.entry_points:
            for sink in sinks:
                path = self._bfs_shortest_path(entry, sink)
                if path is not None:
                    paths.append(path)
        return paths

    def _bfs_shortest_path(self, start: str, target: str) -> list[str] | None:
        """BFS shortest path from *start* to *target*."""
        if start == target:
            return [start]
        visited: set[str] = {start}
        queue: deque[list[str]] = deque([[start]])

        while queue:
            path = queue.popleft()
            current = path[-1]
            for callee in self.graph.callees.get(current, []):
                if callee == target:
                    return path + [callee]
                if callee not in visited:
                    visited.add(callee)
                    queue.append(path + [callee])
        return None

    def _reachable_from_entries(self) -> set[str]:
        """Return all methods reachable from any entry point."""
        reachable: set[str] = set()
        queue: deque[str] = deque(self.graph.entry_points)
        while queue:
            current = queue.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            for callee in self.graph.callees.get(current, []):
                if callee not in reachable:
                    queue.append(callee)
        return reachable

    # ── Single points of failure ─────────────────────────────

    def find_single_points_of_failure(self) -> list[str]:
        """Find methods that are the sole connector between entry points and
        downstream callees.

        A method is a SPOF if:
        - It is reachable from at least one entry point
        - It is NOT itself an entry point
        - It has exactly one caller (no redundancy)
        - It has at least one callee (it connects to something downstream)

        This is a simplified articulation-point heuristic: if the single caller
        were removed or this method failed, the downstream subgraph becomes
        unreachable from the entry point path.
        """
        reachable_from_entry = self._reachable_from_entries()
        spofs: list[str] = []

        for method_id in self.graph.methods:
            if method_id in self.graph.entry_points:
                continue
            if method_id not in reachable_from_entry:
                continue
            callers = self.graph.callers.get(method_id, [])
            callees_out = self.graph.callees.get(method_id, [])
            # Single caller + has callees -> potential SPOF
            if len(callers) == 1 and len(callees_out) >= 1:
                spofs.append(method_id)

        return spofs

    # ── Max call depth ───────────────────────────────────────

    def max_call_depth(self) -> int:
        """Compute the maximum call chain depth from any entry point."""
        max_depth = 0
        for entry in self.graph.entry_points:
            depth = self._bfs_depth(entry)
            max_depth = max(max_depth, depth)
        return max_depth

    def _bfs_depth(self, start: str) -> int:
        """BFS to find max depth from *start*."""
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        max_d = 0

        while queue:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            max_d = max(max_d, depth)
            for callee in self.graph.callees.get(current, []):
                if callee not in visited:
                    queue.append((callee, depth + 1))

        return max_d

    # ── Summary builder ──────────────────────────────────────

    def build_summary(
        self, cross_repo_matches: list[Any] | None = None
    ) -> CallGraphSummary:
        """Build a CallGraphSummary for the report.

        Parameters
        ----------
        cross_repo_matches:
            List of CrossRepoMatch objects from the cross-repo matcher.
        """
        # Entry point summaries
        entry_summaries: list[EntryPointSummary] = []
        for ep_id in self.graph.entry_points:
            method = self.graph.methods.get(ep_id)
            repo = ep_id.split("::")[0] if "::" in ep_id else ""
            depth = self._bfs_depth(ep_id)
            # Check if any callee is in a different repo
            cross = any(
                not c.startswith(f"{repo}::")
                for c in self.graph.callees.get(ep_id, [])
            )
            route = ""
            if method and method.decorators:
                # Try to extract route from first decorator containing a path
                for dec in method.decorators:
                    if "/" in dec:
                        m = re.search(r"""['"](/[^'"]+)['"]""", dec)
                        if m:
                            route = m.group(1)
                            break
            if not route:
                # Fall back to the method portion of the qualified ID
                route = ep_id.split("::")[-1] if "::" in ep_id else ep_id
            entry_summaries.append(
                EntryPointSummary(
                    route=route,
                    repo=repo,
                    depth=depth,
                    cross_repo=cross,
                )
            )

        # Cross-repo edges
        cross_edges: list[CrossRepoEdge] = []
        if cross_repo_matches:
            for match in cross_repo_matches:
                cross_edges.append(
                    CrossRepoEdge(
                        from_method=f"{match.client_repo}::{match.client_method}",
                        to_method=f"{match.server_repo}::{match.server_method}",
                        via=f"{match.http_method} {match.route}",
                    )
                )

        # Cycles
        cycles = self.find_cycles(max_cycles=20)
        cycle_descriptions = [" -> ".join(c) for c in cycles]

        # Dead code
        dead = self.find_dead_code()
        dead_loc = sum(
            self.graph.methods[m].loc for m in dead if m in self.graph.methods
        )
        # Top files with most dead methods
        file_counts: dict[str, int] = {}
        for m in dead:
            method = self.graph.methods.get(m)
            if method:
                file_counts[method.file_path] = (
                    file_counts.get(method.file_path, 0) + 1
                )
        top_files = sorted(
            file_counts, key=lambda f: file_counts[f], reverse=True
        )[:10]

        # SPOFs
        spofs = self.find_single_points_of_failure()

        return CallGraphSummary(
            entry_points=entry_summaries,
            cross_repo_edges=cross_edges,
            circular_dependencies=cycle_descriptions,
            dead_methods=DeadCodeSummary(
                count=len(dead),
                total_lines=dead_loc,
                top_files=top_files,
            ),
            single_points_of_failure=spofs,
        )
