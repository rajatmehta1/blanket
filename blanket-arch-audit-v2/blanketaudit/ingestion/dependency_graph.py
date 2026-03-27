"""FILE-LEVEL dependency graph from import/require analysis.

Builds an adjacency-list graph of which file imports which file.
Used by: triage scorer (import count), incremental scanner
(reverse-dependency closure), architecture agent (coupling).
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

import structlog

from blanketaudit.ingestion.models import ImportInfo

logger = structlog.get_logger()


class DependencyGraphBuilder:
    """Build a file-level dependency graph from import data."""

    def __init__(self) -> None:
        # file → set of files it imports
        self._graph: dict[str, set[str]] = defaultdict(set)
        # file → set of files that import it
        self._reverse: dict[str, set[str]] = defaultdict(set)
        self._file_paths: set[str] = set()

    def build(
        self,
        imports: list[ImportInfo],
        file_paths: set[str],
    ) -> dict[str, set[str]]:
        """Build the graph from import data.

        Returns ``{source_file: {imported_files}}``.
        """
        self._file_paths = file_paths
        self._graph.clear()
        self._reverse.clear()

        for imp in imports:
            source = imp.source_file
            module = imp.imported_module
            target = self._resolve_module(module)

            if target and target != source:
                self._graph[source].add(target)
                self._reverse[target].add(source)

        logger.info(
            "dep_graph.built",
            files=len(file_paths),
            edges=sum(len(v) for v in self._graph.values()),
        )
        return dict(self._graph)

    def reverse_deps(self, file_path: str) -> set[str]:
        """Return all files that transitively depend on file_path."""
        visited: set[str] = set()
        queue: deque[str] = deque([file_path])
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            for dep in self._reverse.get(current, set()):
                if dep not in visited:
                    queue.append(dep)
        visited.discard(file_path)
        return visited

    def import_count(self, file_path: str) -> int:
        """How many files import this file (direct)."""
        return len(self._reverse.get(file_path, set()))

    def import_counts(self) -> dict[str, int]:
        """Return {file_path: number_of_importers} for all files."""
        return {fp: len(importers) for fp, importers in self._reverse.items()}

    def _resolve_module(self, module: str) -> str | None:
        """Try to map a module name to a known file path."""
        candidates = [
            module.replace(".", "/") + ".py",
            module.replace(".", "/") + "/__init__.py",
            module.replace(".", "/"),
        ]
        for c in candidates:
            if c in self._file_paths:
                return c
        return None
