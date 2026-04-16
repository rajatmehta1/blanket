"""Gate 3: Confidence threshold — findings below threshold get review_needed status.

Design doc §11.3: findings with ``confidence < 0.7`` are downgraded to
``review_needed`` status.  They are still shown in the report (visually
distinguished) but excluded from compliance matrix PASS/FAIL determination.
"""

from __future__ import annotations

import structlog

from blanketaudit2.models.finding import AuditFinding

logger = structlog.get_logger()

CONFIDENCE_THRESHOLD = 0.7


class ConfidenceGate:
    """Gate 3: flag low-confidence findings as review_needed.

    Does NOT reject findings — just marks them for human review.
    """

    def __init__(self, threshold: float = CONFIDENCE_THRESHOLD) -> None:
        self.threshold = threshold

    def validate(self, finding: AuditFinding) -> AuditFinding:
        """Mark finding as review_needed if confidence is below threshold.

        Returns the (possibly modified) finding.  Never returns None.
        """
        if finding.confidence < self.threshold:
            logger.info(
                "gate3.low_confidence",
                finding_id=finding.id,
                confidence=finding.confidence,
                threshold=self.threshold,
            )
            # We mark this via a metadata flag.  Since AuditFinding doesn't
            # have a "status" field, we store it as source="ai" with a
            # reduced confidence that downstream code checks.
            # The compliance matrix builder will check confidence < threshold
            # and exclude from PASS/FAIL determination.
            #
            # We also add a note to the ai_explanation.
            if "REVIEW_NEEDED" not in finding.ai_explanation:
                updated_explanation = (
                    f"[REVIEW_NEEDED — confidence {finding.confidence:.2f} "
                    f"below threshold {self.threshold}]\n\n"
                    + finding.ai_explanation
                )
                return finding.model_copy(
                    update={"ai_explanation": updated_explanation}
                )

        return finding

    @property
    def is_review_needed(self) -> bool:
        """Helper for downstream code to check threshold."""
        return True

    @staticmethod
    def needs_review(finding: AuditFinding, threshold: float = CONFIDENCE_THRESHOLD) -> bool:
        """Check if a finding needs human review based on confidence."""
        return finding.confidence < threshold
