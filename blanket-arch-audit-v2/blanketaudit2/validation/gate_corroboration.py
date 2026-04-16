"""Gate 4: Cross-agent corroboration — lone critical → demote to high.

Design doc §11.4: a critical finding from a SINGLE agent is demoted to
high severity.  Critical should be corroborated — e.g., PHI exposure
flagged by compliance agent + data-flow alert from security agent.

Corroboration is determined by overlap in file + line range.
"""

from __future__ import annotations

from collections import defaultdict

import structlog

from blanketaudit2.models.finding import AuditFinding

logger = structlog.get_logger()

# How close two findings' line ranges need to be to count as
# corroborating the same issue (within N lines).
_LINE_PROXIMITY = 10


def _location_key(finding: AuditFinding) -> str:
    """Build a coarse location key for grouping related findings."""
    if not finding.evidence:
        return f"no_evidence::{finding.title}"
    ev = finding.evidence[0]
    return f"{ev.file_path}::{ev.line_start // _LINE_PROXIMITY}"


def _evidence_overlaps(a: AuditFinding, b: AuditFinding) -> bool:
    """Check if two findings have overlapping evidence locations."""
    for ea in a.evidence:
        for eb in b.evidence:
            if ea.file_path != eb.file_path:
                continue
            # Check line range overlap (with proximity tolerance)
            a_start = ea.line_start - _LINE_PROXIMITY
            a_end = ea.line_end + _LINE_PROXIMITY
            if eb.line_start <= a_end and eb.line_end >= a_start:
                return True
    return False


class CorroborationGate:
    """Gate 4: demote lone critical findings to high severity.

    A finding is considered "corroborated" if another finding from a
    different category/agent covers the same file and overlapping line
    range.  Only affects ``critical`` severity.
    """

    def validate(self, findings: list[AuditFinding]) -> list[AuditFinding]:
        """Process all findings.  Demote uncorroborated criticals.

        Returns a new list with severity adjustments applied.
        """
        if not findings:
            return findings

        # Separate critical from non-critical
        criticals = [f for f in findings if f.severity == "critical"]
        others = [f for f in findings if f.severity != "critical"]

        if not criticals:
            return findings

        # For each critical, check if it's corroborated by any other finding
        # (different category = different agent produced it)
        result: list[AuditFinding] = list(others)
        demoted = 0

        for critical in criticals:
            corroborated = self._is_corroborated(critical, findings)

            if corroborated:
                # Keep as critical — source upgraded to "corroborated"
                result.append(
                    critical.model_copy(update={"source": "corroborated"})
                )
            else:
                # Demote to high
                demoted += 1
                logger.info(
                    "gate4.demoted",
                    finding_id=critical.id,
                    reason="uncorroborated_critical",
                    original="critical",
                    new="high",
                )
                result.append(
                    critical.model_copy(update={"severity": "high"})
                )

        if demoted:
            logger.info(
                "gate4.summary",
                total_criticals=len(criticals),
                demoted=demoted,
                kept=len(criticals) - demoted,
            )

        return result

    @staticmethod
    def _is_corroborated(
        finding: AuditFinding,
        all_findings: list[AuditFinding],
    ) -> bool:
        """Check if *finding* is corroborated by a finding from a different category."""
        for other in all_findings:
            if other.id == finding.id:
                continue
            # Must be from a different category (= different agent)
            if other.category == finding.category:
                continue
            if _evidence_overlaps(finding, other):
                return True
        return False
