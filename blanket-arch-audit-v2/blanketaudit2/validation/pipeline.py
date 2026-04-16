"""Run all 4 hallucination gates sequentially.

Design doc §11: Finding → Gate 1 (schema) → Gate 2 (evidence) →
Gate 3 (confidence) → Gate 4 (corroboration) → Validated finding.
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit2.models.finding import AuditFinding
from blanketaudit2.validation.gate_confidence import ConfidenceGate
from blanketaudit2.validation.gate_corroboration import CorroborationGate
from blanketaudit2.validation.gate_evidence import EvidenceGate
from blanketaudit2.validation.gate_schema import SchemaGate

logger = structlog.get_logger()


class ValidationPipeline:
    """Run all 4 hallucination gates on a list of findings.

    Gate 1 (Schema): Parse dict → AuditFinding, validate control IDs.
    Gate 2 (Evidence): Verify file paths, line ranges, code snippets.
    Gate 3 (Confidence): Flag low-confidence as REVIEW_NEEDED.
    Gate 4 (Corroboration): Demote lone criticals to high.
    """

    def __init__(
        self,
        schema_gate: SchemaGate | None = None,
        evidence_gate: EvidenceGate | None = None,
        confidence_gate: ConfidenceGate | None = None,
        corroboration_gate: CorroborationGate | None = None,
    ) -> None:
        self.schema_gate = schema_gate or SchemaGate()
        self.evidence_gate = evidence_gate or EvidenceGate()
        self.confidence_gate = confidence_gate or ConfidenceGate()
        self.corroboration_gate = corroboration_gate or CorroborationGate()

    def validate(
        self,
        raw_findings: list[dict[str, Any]],
        repo_files: dict[str, str],
    ) -> list[AuditFinding]:
        """Run all 4 gates sequentially.

        Parameters
        ----------
        raw_findings:
            List of raw finding dicts (from LLM output parsing).
        repo_files:
            ``{relative_file_path: file_content}`` for evidence verification.

        Returns
        -------
        List of validated, gate-processed ``AuditFinding`` objects.
        """
        # Gates 1-3: per-finding validation
        after_gates_1_to_3: list[AuditFinding] = []
        rejected = 0

        for raw in raw_findings:
            # Gate 1: Schema validation
            finding = self.schema_gate.validate(raw)
            if finding is None:
                rejected += 1
                continue

            # Gate 2: Evidence verification
            finding = self.evidence_gate.validate(finding, repo_files)
            if finding is None:
                rejected += 1
                continue

            # Gate 3: Confidence threshold
            finding = self.confidence_gate.validate(finding)
            # Gate 3 never rejects — just marks

            after_gates_1_to_3.append(finding)

        # Gate 4: Cross-finding corroboration (needs all findings at once)
        validated = self.corroboration_gate.validate(after_gates_1_to_3)

        logger.info(
            "validation.pipeline_complete",
            input=len(raw_findings),
            passed=len(validated),
            rejected=rejected,
        )
        return validated

    def validate_single(
        self,
        raw_finding: dict[str, Any],
        repo_files: dict[str, str],
    ) -> AuditFinding | None:
        """Validate a single finding through Gates 1-3 (no corroboration)."""
        finding = self.schema_gate.validate(raw_finding)
        if finding is None:
            return None
        finding = self.evidence_gate.validate(finding, repo_files)
        if finding is None:
            return None
        finding = self.confidence_gate.validate(finding)
        return finding
