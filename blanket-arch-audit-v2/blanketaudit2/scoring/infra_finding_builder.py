"""Separate infrastructure findings into simplified InfraFinding cards.

Extracts Docker, K8s, CI/CD, and Terraform findings from the full
finding list and converts them to the simplified InfraFinding model
for report Section 7.
"""

from __future__ import annotations

import structlog

from blanketaudit2.models.finding import AuditFinding
from blanketaudit2.models.report import InfraFinding

logger = structlog.get_logger()

# Policy IDs and keywords that indicate infrastructure findings
_INFRA_POLICY_PREFIXES = ("QUAL-010", "QUAL-011", "QUAL-012", "QUAL-013", "QUAL-014")
_INFRA_KEYWORDS = (
    "docker", "container", "k8s", "kubernetes", "helm",
    "ci/cd", "github actions", "gitlab ci", "pipeline",
    "terraform", "infrastructure", "base image", "resource limit",
)


def _is_infra_finding(finding: AuditFinding) -> bool:
    """Check if a finding is infrastructure-related."""
    if finding.category == "infrastructure":
        return True
    if any(finding.policy_id.startswith(p) for p in _INFRA_POLICY_PREFIXES):
        return True
    title_lower = finding.title.lower()
    if any(kw in title_lower for kw in _INFRA_KEYWORDS):
        return True
    return False


class InfraFindingBuilder:
    """Extract and simplify infrastructure findings."""

    def extract(
        self,
        findings: list[AuditFinding],
    ) -> tuple[list[InfraFinding], list[AuditFinding]]:
        """Split findings into infra cards and remaining code findings.

        Returns ``(infra_findings, code_findings)``.
        """
        infra: list[InfraFinding] = []
        code: list[AuditFinding] = []

        for f in findings:
            if _is_infra_finding(f):
                infra.append(self._to_infra_card(f))
            else:
                code.append(f)

        logger.info(
            "infra_builder.extracted",
            infra=len(infra),
            code=len(code),
        )
        return infra, code

    @staticmethod
    def _to_infra_card(finding: AuditFinding) -> InfraFinding:
        """Convert a full AuditFinding to a simplified InfraFinding card."""
        file_path = ""
        if finding.evidence:
            file_path = finding.evidence[0].file_path

        fix = finding.fix_code or finding.remediation or ""

        return InfraFinding(
            severity=finding.severity,
            title=finding.title[:200],
            file=file_path,
            detail=finding.description[:500],
            fix=fix[:500] if fix else f"See {finding.policy_id} remediation guide.",
        )
