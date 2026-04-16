"""Gate 2: Evidence verification — file exists, line valid, code matches.

Design doc §11.2: verify every Evidence against the actual repository.
If ALL evidence fails → reject the finding.
If SOME fails → keep finding with only verified evidence.
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit2.models.finding import AuditFinding, Evidence

logger = structlog.get_logger()

# Minimum fuzzy match ratio to accept a code snippet (0-100 scale).
_MIN_SIMILARITY = 80


def _fuzzy_ratio(a: str, b: str) -> int:
    """Compute fuzzy string similarity (0-100).

    Uses thefuzz if available, falls back to a simple ratio.
    """
    try:
        from thefuzz import fuzz
        return fuzz.ratio(a, b)
    except ImportError:
        # Simple fallback: character-level similarity
        if not a and not b:
            return 100
        if not a or not b:
            return 0
        matches = sum(1 for ca, cb in zip(a, b) if ca == cb)
        return int(100 * (2 * matches) / (len(a) + len(b)))


class EvidenceGate:
    """Gate 2: verify every Evidence against actual repository files.

    Checks:
    a) ``file_path`` exists in the repo file map.
    b) ``line_end`` ≤ actual line count.
    c) ``code_snippet`` ≈ actual content at those lines (≥80% fuzzy match).
    """

    def __init__(self, min_similarity: int = _MIN_SIMILARITY) -> None:
        self.min_similarity = min_similarity

    def validate(
        self,
        finding: AuditFinding,
        repo_files: dict[str, str],
    ) -> AuditFinding | None:
        """Verify evidence and return finding with only valid evidence.

        Parameters
        ----------
        finding:
            The finding to validate.
        repo_files:
            ``{relative_file_path: file_content}`` mapping.

        Returns
        -------
        The finding with invalid evidence removed, or *None* if all
        evidence is invalid.
        """
        verified: list[Evidence] = []

        for ev in finding.evidence:
            if not self._verify_one(ev, repo_files, finding.id):
                continue
            verified.append(ev)

        if not verified:
            logger.warning(
                "gate2.all_evidence_invalid",
                finding_id=finding.id,
                original_count=len(finding.evidence),
            )
            return None

        if len(verified) < len(finding.evidence):
            logger.info(
                "gate2.partial_evidence",
                finding_id=finding.id,
                original=len(finding.evidence),
                verified=len(verified),
            )

        return finding.model_copy(update={"evidence": verified})

    def _verify_one(
        self,
        ev: Evidence,
        repo_files: dict[str, str],
        finding_id: str,
    ) -> bool:
        """Verify a single Evidence object.  Returns True if valid."""

        # (a) File exists
        content = repo_files.get(ev.file_path)
        if content is None:
            logger.warning(
                "gate2.file_missing",
                finding_id=finding_id,
                file=ev.file_path,
            )
            return False

        lines = content.split("\n")

        # (b) Line range valid
        if ev.line_end > len(lines):
            logger.warning(
                "gate2.line_out_of_range",
                finding_id=finding_id,
                file=ev.file_path,
                line_end=ev.line_end,
                actual_lines=len(lines),
            )
            return False

        # (c) Code snippet fuzzy match
        actual_snippet = "\n".join(lines[ev.line_start - 1 : ev.line_end])
        similarity = _fuzzy_ratio(
            ev.code_snippet.strip(),
            actual_snippet.strip(),
        )

        if similarity < self.min_similarity:
            logger.warning(
                "gate2.snippet_mismatch",
                finding_id=finding_id,
                file=ev.file_path,
                similarity=similarity,
                threshold=self.min_similarity,
            )
            return False

        return True
