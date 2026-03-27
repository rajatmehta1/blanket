"""Tree-sitter multi-language AST parsing.

Design doc §2.1 Tier 2: parse every source file into a language-agnostic AST.
V1 supports: Python, TypeScript/JavaScript, Java.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from blanketaudit.ingestion.models import FileMetadata

logger = structlog.get_logger()

# Language name → tree-sitter language module import path
_LANGUAGE_MODULES: dict[str, str] = {
    "python": "tree_sitter_python",
    "typescript": "tree_sitter_typescript",
    "javascript": "tree_sitter_typescript",  # TS grammar handles JS too
    "java": "tree_sitter_java",
}

# Cached tree-sitter Language objects
_languages: dict[str, Any] = {}
# Cached Parser objects per language
_parsers: dict[str, Any] = {}


def _get_parser(language: str) -> Any | None:
    """Lazy-load a tree-sitter parser for *language*. Returns None if unsupported."""
    if language in _parsers:
        return _parsers[language]

    module_name = _LANGUAGE_MODULES.get(language)
    if not module_name:
        return None

    try:
        import importlib
        import tree_sitter

        lang_mod = importlib.import_module(module_name)

        # tree-sitter-python etc. expose a language() function
        if language in ("typescript", "javascript"):
            # tree_sitter_typescript exposes language_typescript() and language_tsx()
            lang_fn = getattr(lang_mod, "language_typescript", None) or getattr(lang_mod, "language", None)
        else:
            lang_fn = getattr(lang_mod, "language", None)

        if lang_fn is None:
            logger.warning("ast_indexer.no_language_fn", language=language, module=module_name)
            return None

        ts_language = tree_sitter.Language(lang_fn())
        parser = tree_sitter.Parser(ts_language)
        _parsers[language] = parser
        return parser

    except (ImportError, Exception) as exc:
        logger.warning("ast_indexer.parser_init_failed", language=language, error=str(exc)[:200])
        _parsers[language] = None  # Cache the failure so we don't retry
        return None


class ASTIndexer:
    """Parse source files using Tree-sitter grammars.

    V1 supported languages: Python, TypeScript/JavaScript, Java.
    Unsupported languages are silently skipped with a warning log.
    """

    def __init__(self) -> None:
        self._trees: dict[str, Any] = {}  # file_path → parsed Tree

    def index_file(self, file_path: str | Path, language: str) -> Any | None:
        """Parse a single file. Returns the tree-sitter Tree or None."""
        file_path = Path(file_path)
        parser = _get_parser(language)
        if parser is None:
            return None

        try:
            source = file_path.read_bytes()
            tree = parser.parse(source)
            key = str(file_path)
            self._trees[key] = tree
            return tree
        except (OSError, Exception) as exc:
            logger.warning(
                "ast_indexer.parse_failed",
                file=str(file_path),
                language=language,
                error=str(exc)[:200],
            )
            return None

    def index_project(self, files: list[FileMetadata], repo_path: str | Path) -> dict[str, Any]:
        """Parse all supported source files.

        Returns a dict of ``{relative_path: Tree}`` for successfully parsed files.
        Skips unparseable files with a warning log.
        """
        repo_path = Path(repo_path)
        results: dict[str, Any] = {}
        parsed = 0
        skipped = 0

        for fm in files:
            if not fm.language or fm.language not in _LANGUAGE_MODULES:
                skipped += 1
                continue

            full_path = repo_path / fm.path
            tree = self.index_file(full_path, fm.language)
            if tree is not None:
                results[fm.path] = tree
                parsed += 1
            else:
                skipped += 1

        logger.info(
            "ast_indexer.project_indexed",
            parsed=parsed,
            skipped=skipped,
            total=len(files),
        )
        return results

    def get_tree(self, file_path: str) -> Any | None:
        """Get a previously parsed tree by file path."""
        return self._trees.get(file_path)
