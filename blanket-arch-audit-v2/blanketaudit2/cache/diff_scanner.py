"""Git diff + reverse-dependency closure for incremental scanning.

Design doc §12.1: identify changed files since last scan, then compute
the closure of affected files via reverse dependency traversal.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import structlog

from blanketaudit2.ingestion.models import FileMetadata

logger = structlog.get_logger()


class DiffScanner:
    """Identify changed files and compute the affected set for incremental scanning."""

    # ── Git diff ─────────────────────────────────────────────

    async def get_changed_files(
        self,
        repo_path: Path | str,
        last_commit: str,
    ) -> set[str]:
        """Return relative paths of files changed between *last_commit* and HEAD.

        Uses ``git diff --name-only``.  Returns an empty set if the git
        command fails (e.g., shallow clone without the commit).
        """
        repo_path = Path(repo_path)
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", str(repo_path),
                "diff", "--name-only", f"{last_commit}..HEAD",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.warning(
                    "diff_scanner.git_diff_failed",
                    returncode=proc.returncode,
                    stderr=stderr.decode()[:200],
                )
                return set()

            changed = set()
            for line in stdout.decode().strip().splitlines():
                line = line.strip()
                if line:
                    changed.add(line.replace("\\", "/"))

            logger.info("diff_scanner.changed", count=len(changed))
            return changed

        except (OSError, FileNotFoundError) as exc:
            logger.warning("diff_scanner.git_not_available", error=str(exc)[:200])
            return set()

    # ── Reverse-dependency closure ───────────────────────────

    def compute_affected_files(
        self,
        changed: set[str],
        reverse_deps: dict[str, set[str]],
    ) -> set[str]:
        """Compute the transitive closure of files affected by *changed*.

        Parameters
        ----------
        changed:
            Set of file paths that were directly modified.
        reverse_deps:
            ``{file_path: set_of_files_that_import_it}`` — the reverse
            dependency graph.

        Returns
        -------
        Union of *changed* files plus all files that transitively depend
        on any changed file.
        """
        affected: set[str] = set(changed)
        queue: deque[str] = deque(changed)

        while queue:
            current = queue.popleft()
            for dependent in reverse_deps.get(current, set()):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)

        logger.info(
            "diff_scanner.affected",
            changed=len(changed),
            total_affected=len(affected),
            added_by_deps=len(affected) - len(changed),
        )
        return affected

    # ── File partitioning ────────────────────────────────────

    def partition_files(
        self,
        all_files: list[FileMetadata],
        affected: set[str],
        cached_keys: set[str] | None = None,
    ) -> tuple[list[FileMetadata], list[FileMetadata]]:
        """Split files into those needing a scan and those served from cache.

        Parameters
        ----------
        all_files:
            Every file in the repo.
        affected:
            Files that changed or depend on changed files.
        cached_keys:
            Set of file paths whose results are in the cache.

        Returns
        -------
        ``(to_scan, from_cache)`` — two lists of ``FileMetadata``.
        """
        cached_keys = cached_keys or set()
        to_scan: list[FileMetadata] = []
        from_cache: list[FileMetadata] = []

        for f in all_files:
            if f.path in affected:
                to_scan.append(f)
            elif f.path in cached_keys:
                from_cache.append(f)
            else:
                # Not changed and not cached — needs fresh scan
                to_scan.append(f)

        logger.info(
            "diff_scanner.partitioned",
            to_scan=len(to_scan),
            from_cache=len(from_cache),
            total=len(all_files),
        )
        return to_scan, from_cache

    # ── Reverse-dep graph builder ────────────────────────────

    @staticmethod
    def build_reverse_deps(
        imports: list[Any],
        file_paths: set[str],
    ) -> dict[str, set[str]]:
        """Build a reverse dependency map from import data.

        Parameters
        ----------
        imports:
            List of ``ImportInfo`` objects.
        file_paths:
            Set of all known file paths in the repo.

        Returns
        -------
        ``{imported_module_file: {files_that_import_it}}``
        """
        reverse: dict[str, set[str]] = defaultdict(set)

        for imp in imports:
            # Try to resolve imported_module to a file path
            # Simple heuristic: module "foo.bar" → "foo/bar.py"
            module_path = imp.imported_module.replace(".", "/")
            candidates = [
                f"{module_path}.py",
                f"{module_path}/__init__.py",
                module_path,
            ]
            for candidate in candidates:
                norm = candidate.replace("\\", "/")
                if norm in file_paths:
                    reverse[norm].add(imp.source_file)
                    break

        return dict(reverse)
