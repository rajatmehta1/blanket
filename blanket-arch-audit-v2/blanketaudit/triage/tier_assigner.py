"""Assign files to analysis tiers based on triage score.

Design doc §7.2:
- Tier 1 (score > tier1_threshold): Full AI analysis with all policy checks
- Tier 2 (score > tier2_threshold): Static tools + light AI (summary only)
- Tier 3 (score ≤ tier2_threshold): Static tools only, zero LLM calls
"""

from __future__ import annotations

from typing import Literal

import structlog

from blanketaudit.config import get_settings
from blanketaudit.ingestion.models import FileMetadata

logger = structlog.get_logger()

TierNumber = Literal[1, 2, 3]


class TierAssigner:
    """Assign files to analysis tiers based on score thresholds."""

    def __init__(
        self,
        tier1_threshold: int | None = None,
        tier2_threshold: int | None = None,
    ) -> None:
        cfg = get_settings().triage
        self.tier1_threshold = tier1_threshold if tier1_threshold is not None else cfg.tier1_threshold
        self.tier2_threshold = tier2_threshold if tier2_threshold is not None else cfg.tier2_threshold

    def assign_one(self, score: int) -> TierNumber:
        """Assign a single file to a tier based on its score."""
        if score > self.tier1_threshold:
            return 1
        if score > self.tier2_threshold:
            return 2
        return 3

    def assign(
        self,
        files: list[FileMetadata],
        scores: dict[str, int],
    ) -> dict[str, TierNumber]:
        """Assign every file to a tier.

        Returns ``{file_path: tier_number}``.
        """
        tiers: dict[str, TierNumber] = {}
        counts = {1: 0, 2: 0, 3: 0}

        for f in files:
            score = scores.get(f.path, 0)
            tier = self.assign_one(score)
            tiers[f.path] = tier
            counts[tier] += 1

        logger.info(
            "triage.tiers_assigned",
            tier1=counts[1],
            tier2=counts[2],
            tier3=counts[3],
            total=len(tiers),
        )
        return tiers

    def summary(self, tiers: dict[str, TierNumber]) -> dict[int, int]:
        """Return ``{tier: file_count}``."""
        counts = {1: 0, 2: 0, 3: 0}
        for tier in tiers.values():
            counts[tier] += 1
        return counts
