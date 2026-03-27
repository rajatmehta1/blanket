"""Build intra-repo method-level call graph from AST extraction data.

Design doc Tier 2.5: construct caller->callee edges using a symbol table
and import map for cross-file resolution within a single repo.
Unresolved calls are logged, never crashed.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from blanketaudit.ingestion.models import (
    AnalysisContext,
    CallInfo,
    ImportInfo,
    MethodInfo,
)

logger = structlog.get_logger()


@dataclass
class CallEdge:
    """A resolved caller->callee edge in the call graph."""
    caller: str           # Fully qualified: "repo::file::Class.method"
    callee: str           # Fully qualified: "repo::file::Class.method"
    caller_repo: str
    callee_repo: str
    file_path: str
    line_number: int
    call_type: str = "direct"
    resolved: bool = True  # False if callee couldn't be resolved


@dataclass
class CallGraph:
    """In-memory call graph for one or more repos."""
    edges: list[CallEdge] = field(default_factory=list)
    # Adjacency lists for fast traversal
    callers: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))   # callee -> [callers]
    callees: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))   # caller -> [callees]
    # All known methods
    methods: dict[str, MethodInfo] = field(default_factory=dict)  # qualified_id -> MethodInfo
    # Entry points
    entry_points: set[str] = field(default_factory=set)

    def add_edge(self, edge: CallEdge) -> None:
        self.edges.append(edge)
        self.callees[edge.caller].append(edge.callee)
        self.callers[edge.callee].append(edge.caller)

    def add_method(self, qualified_id: str, method: MethodInfo) -> None:
        self.methods[qualified_id] = method
        if method.is_entry_point:
            self.entry_points.add(qualified_id)

    @property
    def method_count(self) -> int:
        return len(self.methods)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


class SymbolTable:
    """Maps short names / qualified names to fully-qualified method IDs.

    A qualified ID is: "repo::relative_path::QualifiedName"
    e.g. "patient-api::src/service.py::PatientService.search"
    """

    def __init__(self) -> None:
        # qualified_id -> MethodInfo
        self._methods: dict[str, MethodInfo] = {}
        # short name -> list of qualified_ids (may be ambiguous)
        self._by_name: dict[str, list[str]] = defaultdict(list)
        # qualified_name (Class.method or func) -> list of qualified_ids
        self._by_qualified_name: dict[str, list[str]] = defaultdict(list)

    def register(self, repo_name: str, method: MethodInfo) -> str:
        """Register a method and return its fully-qualified ID."""
        qid = f"{repo_name}::{method.file_path}::{method.qualified_name}"
        self._methods[qid] = method
        self._by_name[method.name].append(qid)
        self._by_qualified_name[method.qualified_name].append(qid)
        return qid

    def resolve(self, callee_name: str, caller_file: str, repo_name: str,
                import_map: dict[str, str]) -> str | None:
        """Resolve a callee name to a fully-qualified ID.

        Resolution order:
        1. Exact match on qualified_name within same file
        2. Import map lookup (callee module resolved via imports)
        3. Exact match on qualified_name across repo
        4. Short name match (ambiguous -- pick first in same repo)
        """
        # 1. Same-file qualified match
        for qid, m in self._methods.items():
            if m.qualified_name == callee_name and m.file_path == caller_file and m.repo_name == repo_name:
                return qid

        # 2. Import map: if callee is "module.func", check if "module" was imported
        if "." in callee_name:
            parts = callee_name.split(".", 1)
            alias = parts[0]
            member = parts[1]
            if alias in import_map:
                imported_module = import_map[alias]
                # Try to find member in that module's file
                for qid, m in self._methods.items():
                    if m.name == member and imported_module in m.file_path and m.repo_name == repo_name:
                        return qid

        # 3. Qualified name match across repo
        candidates = self._by_qualified_name.get(callee_name, [])
        repo_candidates = [c for c in candidates if c.startswith(f"{repo_name}::")]
        if repo_candidates:
            return repo_candidates[0]

        # 4. Short name match
        candidates = self._by_name.get(callee_name, [])
        repo_candidates = [c for c in candidates if c.startswith(f"{repo_name}::")]
        if repo_candidates:
            return repo_candidates[0]
        if candidates:
            return candidates[0]

        return None


def _build_import_map(imports: list[ImportInfo], file_path: str) -> dict[str, str]:
    """Build a mapping of alias -> module path for a specific file's imports."""
    result: dict[str, str] = {}
    for imp in imports:
        if imp.source_file != file_path:
            continue
        # "import os" -> {"os": "os"}
        # "from pathlib import Path" -> {"Path": "pathlib"}
        if imp.imported_names:
            for name in imp.imported_names:
                clean = name.split(" as ")[-1].strip() if " as " in name else name
                result[clean] = imp.imported_module
        else:
            module = imp.imported_module
            alias = module.rsplit(".", 1)[-1]
            result[alias] = module
    return result


class StaticCallGraphBuilder:
    """Construct a method-level call graph from AST extraction results.

    Best-effort: unresolved calls are logged with resolved=False,
    never cause crashes.
    """

    def build(self, contexts: list[AnalysisContext]) -> CallGraph:
        """Build a call graph from one or more repo analysis contexts."""
        graph = CallGraph()
        symbol_table = SymbolTable()

        # Phase 1: Register all methods
        for ctx in contexts:
            for method in ctx.methods:
                qid = symbol_table.register(ctx.repo_name, method)
                graph.add_method(qid, method)

        # Phase 2: Resolve calls to edges
        resolved_count = 0
        unresolved_count = 0

        for ctx in contexts:
            # Group imports by file for fast lookup
            file_import_maps: dict[str, dict[str, str]] = {}
            for file_path in {c.file_path for c in ctx.calls}:
                file_import_maps[file_path] = _build_import_map(ctx.imports, file_path)

            for call in ctx.calls:
                import_map = file_import_maps.get(call.file_path, {})

                # Resolve caller
                caller_qid = symbol_table.resolve(
                    call.caller, call.file_path, ctx.repo_name, import_map
                )
                if not caller_qid:
                    caller_qid = f"{ctx.repo_name}::{call.file_path}::{call.caller}"

                # Resolve callee
                callee_qid = symbol_table.resolve(
                    call.callee, call.file_path, ctx.repo_name, import_map
                )

                is_resolved = callee_qid is not None
                if not is_resolved:
                    callee_qid = f"<unresolved>::{call.callee}"
                    unresolved_count += 1
                else:
                    resolved_count += 1

                edge = CallEdge(
                    caller=caller_qid,
                    callee=callee_qid,
                    caller_repo=ctx.repo_name,
                    callee_repo=ctx.repo_name,
                    file_path=call.file_path,
                    line_number=call.line_number,
                    call_type=call.call_type,
                    resolved=is_resolved,
                )
                graph.add_edge(edge)

        logger.info(
            "callgraph.built",
            methods=graph.method_count,
            edges=graph.edge_count,
            resolved=resolved_count,
            unresolved=unresolved_count,
        )
        return graph

    def build_single(self, context: AnalysisContext) -> CallGraph:
        """Convenience: build graph from a single repo context."""
        return self.build([context])
