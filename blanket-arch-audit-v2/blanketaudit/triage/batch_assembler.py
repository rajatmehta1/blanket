"""Bin-pack files into token-limited batches for LLM processing.

Design doc §7.3:
- Group same-directory files together (contextual coherence)
- Sort by size descending, pack greedily (first-fit decreasing)
- Leave response_token_reserve for LLM response
- Only Tier 1 and Tier 2 files go into batches (Tier 3 = static only)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Literal

import structlog

from blanketaudit.config import get_settings
from blanketaudit.ingestion.models import FileMetadata

logger = structlog.get_logger()

# Rough heuristic: ~4 characters per token for English / code.
_CHARS_PER_TOKEN = 4


def estimate_tokens(file: FileMetadata) -> int:
    """Estimate token count for a file based on its size.

    Uses ``size_bytes`` if available, otherwise falls back to
    ``loc * 40`` (average ~40 chars/line).
    """
    if file.size_bytes > 0:
        return max(1, file.size_bytes // _CHARS_PER_TOKEN)
    if file.loc > 0:
        return max(1, (file.loc * 40) // _CHARS_PER_TOKEN)
    return 100  # Default minimum for unknown files


def _directory(path: str) -> str:
    """Extract the parent directory from a file path."""
    parts = path.replace("\\", "/").rsplit("/", 1)
    return parts[0] if len(parts) > 1 else ""


class BatchAssembler:
    """Bin-pack files into batches that fit within token limits.

    Only Tier 1 and Tier 2 files are batched.  Tier 3 files are
    excluded (they get static-only analysis with zero LLM cost).
    """

    def __init__(
        self,
        max_batch_tokens: int | None = None,
        response_reserve: int | None = None,
    ) -> None:
        cfg = get_settings().triage
        self.max_batch_tokens = max_batch_tokens if max_batch_tokens is not None else cfg.max_batch_tokens
        self.response_reserve = response_reserve if response_reserve is not None else cfg.response_token_reserve
        self._effective_limit = self.max_batch_tokens - self.response_reserve

    def assemble(
        self,
        files: list[FileMetadata],
        tiers: dict[str, int],
        *,
        tier_filter: set[int] | None = None,
    ) -> list[list[FileMetadata]]:
        """Pack files into batches ≤ effective token limit.

        Parameters
        ----------
        files:
            All files in the project.
        tiers:
            ``{file_path: tier_number}`` from ``TierAssigner``.
        tier_filter:
            Which tiers to include.  Defaults to ``{1, 2}``.

        Returns
        -------
        List of batches, each batch a list of ``FileMetadata``.
        """
        allowed_tiers = tier_filter or {1, 2}

        # Filter to eligible files
        eligible = [f for f in files if tiers.get(f.path, 3) in allowed_tiers]

        if not eligible:
            return []

        # Group by directory for contextual coherence
        dir_groups: dict[str, list[FileMetadata]] = defaultdict(list)
        for f in eligible:
            dir_groups[_directory(f.path)].append(f)

        # Within each group, sort by estimated tokens descending (first-fit decreasing)
        sorted_groups: list[list[FileMetadata]] = []
        for dir_path in sorted(dir_groups):
            group = sorted(dir_groups[dir_path], key=lambda f: estimate_tokens(f), reverse=True)
            sorted_groups.append(group)

        # Flatten groups but try to keep same-directory files together
        batches: list[list[FileMetadata]] = []
        current_batch: list[FileMetadata] = []
        current_tokens = 0

        for group in sorted_groups:
            for f in group:
                tokens = estimate_tokens(f)

                # If a single file exceeds the limit, give it its own batch
                if tokens >= self._effective_limit:
                    if current_batch:
                        batches.append(current_batch)
                        current_batch = []
                        current_tokens = 0
                    batches.append([f])
                    continue

                # Does it fit in the current batch?
                if current_tokens + tokens <= self._effective_limit:
                    current_batch.append(f)
                    current_tokens += tokens
                else:
                    # Start a new batch
                    if current_batch:
                        batches.append(current_batch)
                    current_batch = [f]
                    current_tokens = tokens

        if current_batch:
            batches.append(current_batch)

        logger.info(
            "triage.batches_assembled",
            eligible_files=len(eligible),
            batches=len(batches),
            max_batch_tokens=self.max_batch_tokens,
        )
        return batches

    def batch_token_counts(self, batches: list[list[FileMetadata]]) -> list[int]:
        """Return the estimated token count for each batch."""
        return [sum(estimate_tokens(f) for f in batch) for batch in batches]
