"""Gate 1: Pydantic schema validation + compliance control_id whitelist.

Design doc §11.1: parse raw LLM output into AuditFinding.  Reject findings
with unknown compliance control IDs.
"""

from __future__ import annotations

import re
from typing import Any

import structlog
from pydantic import ValidationError

from blanketaudit.models.finding import AuditFinding

logger = structlog.get_logger()

# ── Compliance control ID patterns per framework ─────────────
# These regex patterns validate that a control_id looks plausible
# for its declared framework.  We don't maintain a full whitelist
# of every clause — just ensure the format is sane.

_CONTROL_ID_PATTERNS: dict[str, re.Pattern] = {
    "HIPAA": re.compile(r"^§?164\.\d{3}"),           # §164.312(a)(1)
    "SOC2": re.compile(r"^CC\d"),                      # CC6.1, CC7.2
    "PCI-DSS": re.compile(r"^Req\s*\d", re.I),        # Req 6.5.1
    "GDPR": re.compile(r"^Art\.?\s*\d", re.I),        # Art. 25, Art 32
    "SOX": re.compile(r"^§?\d{3}|^SOX", re.I),        # §302, §404, SOX-302
    "ISO27001": re.compile(r"^A?\.\d|^A\d", re.I),    # A.8.1, A12.3
    "NIST": re.compile(r"^(SP|PR|DE|RS|ID)", re.I),   # SP 800-53, PR.AC-1
}


class SchemaGate:
    """Gate 1: validate finding schema and compliance control IDs.

    Steps:
    1. Parse the raw dict into an ``AuditFinding`` Pydantic model.
    2. For each ``compliance_ref``, verify the ``clause`` matches the
       expected pattern for its framework.
    3. Remove invalid compliance refs (don't reject the entire finding).
    """

    def __init__(self, strict_control_ids: bool = True) -> None:
        self.strict_control_ids = strict_control_ids

    def validate(self, raw_finding: dict[str, Any]) -> AuditFinding | None:
        """Parse and validate a raw finding dict.

        Returns a validated ``AuditFinding`` or *None* if the schema is
        fundamentally invalid (missing required fields, wrong types).
        """
        # Step 1: Pydantic schema validation
        try:
            finding = AuditFinding.model_validate(raw_finding)
        except ValidationError as exc:
            logger.warning(
                "gate1.schema_invalid",
                errors=str(exc)[:500],
                finding_id=raw_finding.get("id", "?"),
            )
            return None

        # Step 2: Validate compliance control IDs
        if self.strict_control_ids and finding.compliance_refs:
            valid_refs = []
            for ref in finding.compliance_refs:
                if self._validate_control_id(ref.framework, ref.clause):
                    valid_refs.append(ref)
                else:
                    logger.warning(
                        "gate1.invalid_control_id",
                        finding_id=finding.id,
                        framework=ref.framework,
                        clause=ref.clause,
                    )
            finding = finding.model_copy(update={"compliance_refs": valid_refs})

        logger.debug(
            "gate1.passed",
            finding_id=finding.id,
            compliance_refs=len(finding.compliance_refs),
        )
        return finding

    @staticmethod
    def _validate_control_id(framework: str, clause: str) -> bool:
        """Check if a clause matches the expected pattern for its framework."""
        pattern = _CONTROL_ID_PATTERNS.get(framework.upper())
        if pattern is None:
            # Unknown framework but allowed by ComplianceRef validator
            return True
        return bool(pattern.match(clause))
