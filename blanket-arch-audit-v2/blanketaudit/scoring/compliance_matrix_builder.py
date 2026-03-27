"""Build ComplianceMatrix from findings and compliance controls.

Groups findings by framework, maps each compliance ref to a control
status (PASS/PARTIAL/FAIL/GAP), and produces the matrix for report
Section 5.
"""

from __future__ import annotations

from collections import defaultdict

import structlog

from blanketaudit.models.compliance import ComplianceControlStatus, ComplianceMatrix
from blanketaudit.models.finding import AuditFinding
from blanketaudit.validation.gate_confidence import CONFIDENCE_THRESHOLD

logger = structlog.get_logger()


class ComplianceMatrixBuilder:
    """Build per-framework compliance matrices from validated findings."""

    def build(
        self,
        findings: list[AuditFinding],
        frameworks: list[str],
    ) -> list[ComplianceMatrix]:
        """Build compliance matrices for all active frameworks.

        For each framework, group findings by clause and determine
        the control status.
        """
        # Index findings by framework → clause
        fw_clauses: dict[str, dict[str, list[AuditFinding]]] = defaultdict(lambda: defaultdict(list))

        for f in findings:
            for ref in f.compliance_refs:
                fw_clauses[ref.framework][ref.clause].append(f)

        matrices: list[ComplianceMatrix] = []
        for fw in frameworks:
            fw_upper = fw.upper()
            # Find matching framework key (case-insensitive)
            matched_key = None
            for key in fw_clauses:
                if key.upper() == fw_upper:
                    matched_key = key
                    break

            clauses = fw_clauses.get(matched_key, {}) if matched_key else {}
            sections = self._build_sections(fw, clauses)
            matrices.append(ComplianceMatrix(framework=fw, sections=sections))

        logger.info(
            "compliance_matrix.built",
            frameworks=len(matrices),
            total_controls=sum(len(m.sections) for m in matrices),
        )
        return matrices

    def _build_sections(
        self,
        framework: str,
        clauses: dict[str, list[AuditFinding]],
    ) -> list[ComplianceControlStatus]:
        """Build control status list for one framework."""
        sections: list[ComplianceControlStatus] = []

        for clause, clause_findings in sorted(clauses.items()):
            status = self._determine_status(clause_findings)
            # Get title from the first finding's ref
            title = clause
            for f in clause_findings:
                for ref in f.compliance_refs:
                    if ref.clause == clause:
                        title = ref.title
                        break

            detail = self._build_detail(clause_findings, status)

            sections.append(ComplianceControlStatus(
                control_id=f"{framework}-{clause}".replace(" ", "-"),
                framework=framework,
                clause=clause,
                title=title,
                status=status,
                finding_count=len(clause_findings),
                detail=detail,
            ))

        return sections

    @staticmethod
    def _determine_status(findings: list[AuditFinding]) -> str:
        """Determine control status from findings.

        - No findings → pass
        - All low confidence → review_needed
        - Any critical/high → fail
        - Mix of severities → partial
        - All medium/low → partial
        """
        if not findings:
            return "pass"

        # Low-confidence findings excluded from PASS/FAIL
        confident = [f for f in findings if f.confidence >= CONFIDENCE_THRESHOLD]
        if not confident:
            return "review_needed"

        severities = {f.severity for f in confident}
        if "critical" in severities:
            return "fail"
        if "high" in severities:
            return "fail"
        if "medium" in severities:
            return "partial"
        return "pass"

    @staticmethod
    def _build_detail(findings: list[AuditFinding], status: str) -> str:
        """Build a human-readable detail string."""
        if not findings:
            return "No issues detected for this control."
        count = len(findings)
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        parts = [f"{v} {k}" for k, v in sorted(sev_counts.items())]
        return f"{count} finding(s): {', '.join(parts)}. Status: {status}."
