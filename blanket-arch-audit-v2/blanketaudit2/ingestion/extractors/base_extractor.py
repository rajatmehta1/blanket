"""Shared AST walking logic for entity extraction.

All language-specific extractors inherit from BaseExtractor and share
helpers for tree-sitter node traversal and model construction.
"""
from __future__ import annotations

import abc
from pathlib import Path
from typing import Any

import structlog

from blanketaudit2.ingestion.models import (
    CallInfo,
    ClassInfo,
    EntryPointInfo,
    ImportInfo,
    MethodInfo,
)

logger = structlog.get_logger()


class ExtractionResult:
    """Collected extraction data from one file."""

    def __init__(self, file_path: str, repo_name: str) -> None:
        self.file_path = file_path
        self.repo_name = repo_name
        self.classes: list[ClassInfo] = []
        self.methods: list[MethodInfo] = []
        self.calls: list[CallInfo] = []
        self.imports: list[ImportInfo] = []
        self.entry_points: list[EntryPointInfo] = []


class BaseExtractor(abc.ABC):
    """Base class for language-specific entity extractors.

    Subclasses implement ``extract()`` which walks a tree-sitter Tree
    and populates an ExtractionResult.
    """

    def __init__(self, repo_name: str = "") -> None:
        self.repo_name = repo_name

    @abc.abstractmethod
    def extract(self, file_path: str, tree: Any, source: bytes) -> ExtractionResult:
        """Walk the AST and extract entities from a single file.

        Parameters
        ----------
        file_path : str
            Relative path of the file within the repository.
        tree : tree_sitter.Tree
            Parsed AST from tree-sitter.
        source : bytes
            Raw source bytes (needed to read node text).
        """
        ...

    # ── Tree-sitter helpers ──────────────────────────────────

    @staticmethod
    def node_text(node: Any, source: bytes) -> str:
        """Extract the text of a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    @staticmethod
    def find_children(node: Any, type_name: str) -> list[Any]:
        """Return all direct children of *node* with the given type."""
        return [c for c in node.children if c.type == type_name]

    @staticmethod
    def find_first_child(node: Any, type_name: str) -> Any | None:
        """Return the first direct child of *node* with the given type, or None."""
        for c in node.children:
            if c.type == type_name:
                return c
        return None

    @staticmethod
    def walk_descendants(node: Any, type_name: str) -> list[Any]:
        """Recursively find all descendant nodes of the given type."""
        results: list[Any] = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == type_name:
                results.append(current)
            stack.extend(reversed(current.children))
        return results

    @staticmethod
    def node_line(node: Any) -> int:
        """Return 1-based line number of a node."""
        return node.start_point[0] + 1

    @staticmethod
    def node_end_line(node: Any) -> int:
        """Return 1-based end line number of a node."""
        return node.end_point[0] + 1

    def _count_complexity(self, node: Any, branch_types: set[str]) -> int:
        """Count cyclomatic complexity by counting branch nodes + 1."""
        count = 1  # Base complexity
        for descendant in self.walk_descendants(node, ""):
            pass
        # Walk all descendants manually
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in branch_types:
                count += 1
            stack.extend(reversed(current.children))
        return count
