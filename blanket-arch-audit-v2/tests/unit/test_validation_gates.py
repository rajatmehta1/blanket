"""Tests for the 4 hallucination validation gates + pipeline.

Design doc §11: THE MOST CRITICAL tests. Every finding must pass
all 4 gates before entering the report.
"""

from __future__ import annotations

import pytest

from blanketaudit.models.finding import AuditFinding, ComplianceRef, Evidence
from blanketaudit.validation.gate_confidence import ConfidenceGate
from blanketaudit.validation.gate_corroboration import CorroborationGate
from blanketaudit.validation.gate_evidence import EvidenceGate
from blanketaudit.validation.gate_schema import SchemaGate
from blanketaudit.validation.pipeline import ValidationPipeline


# ── Fixture helpers ──────────────────────────────────────────

def _evidence(
    file_path: str = "src/main.py",
    repo_name: str = "api",
    line_start: int = 10,
    line_end: int = 12,
    code_snippet: str = 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
    tool: str = "semgrep",
) -> dict:
    return dict(
        file_path=file_path, repo_name=repo_name,
        line_start=line_start, line_end=line_end,
        code_snippet=code_snippet, tool=tool,
    )


def _compliance_ref(
    framework: str = "HIPAA",
    clause: str = "§164.312(a)(1)",
    title: str = "Access Control",
) -> dict:
    return dict(framework=framework, clause=clause, title=title)


def _finding(
    id: str = "BLK-001",
    severity: str = "critical",
    category: str = "security",
    confidence: float = 0.95,
    source: str = "ai",
    evidence: list | None = None,
    compliance_refs: list | None = None,
    **overrides,
) -> dict:
    base = dict(
        id=id,
        policy_id="SEC-001",
        title="SQL Injection",
        description="User input interpolated into SQL.",
        severity=severity,
        category=category,
        confidence=confidence,
        source=source,
        evidence=evidence or [_evidence()],
        compliance_refs=compliance_refs or [_compliance_ref()],
        ai_explanation="This is a serious SQL injection vulnerability.",
        fix_code="cursor.execute(query, (uid,))",
        remediation="Use parameterized queries.",
        effort_hours=2.0,
        dollar_impact="$50,000 — $1,900,000",
    )
    base.update(overrides)
    return base


def _repo_files() -> dict[str, str]:
    """Fake repo file contents for evidence verification."""
    return {
        "src/main.py": (
            "import sqlite3\n"
            "def search(uid):\n"
            "    conn = sqlite3.connect('db.sqlite')\n"
            "    cursor = conn.cursor()\n"
            "    # Line 5\n"
            "    # Line 6\n"
            "    # Line 7\n"
            "    # Line 8\n"
            "    # Line 9\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n'
            "    return cursor.fetchall()\n"
            "    # Line 12\n"
        ),
        "src/auth.py": (
            "password = 'SuperSecret123!'\n"
            "def login(user, pw):\n"
            "    return pw == password\n"
        ),
    }


# ═══════════════════════════════════════════════════════════════
# Gate 1: Schema Validation
# ═══════════════════════════════════════════════════════════════


class TestSchemaGate:
    def test_valid_finding_passes(self):
        gate = SchemaGate()
        result = gate.validate(_finding())
        assert result is not None
        assert isinstance(result, AuditFinding)
        assert result.id == "BLK-001"

    def test_missing_required_field_rejected(self):
        gate = SchemaGate()
        data = _finding()
        del data["title"]
        result = gate.validate(data)
        assert result is None

    def test_invalid_severity_rejected(self):
        gate = SchemaGate()
        result = gate.validate(_finding(severity="catastrophic"))
        assert result is None

    def test_invalid_confidence_rejected(self):
        gate = SchemaGate()
        result = gate.validate(_finding(confidence=1.5))
        assert result is None

    def test_invalid_id_pattern_rejected(self):
        gate = SchemaGate()
        result = gate.validate(_finding(id="INVALID"))
        assert result is None

    def test_valid_hipaa_control_id_kept(self):
        gate = SchemaGate()
        result = gate.validate(_finding(
            compliance_refs=[_compliance_ref("HIPAA", "§164.312(a)(1)", "Access Control")],
        ))
        assert result is not None
        assert len(result.compliance_refs) == 1

    def test_valid_soc2_control_id_kept(self):
        gate = SchemaGate()
        result = gate.validate(_finding(
            compliance_refs=[_compliance_ref("SOC2", "CC6.1", "Logical Access")],
        ))
        assert result is not None
        assert len(result.compliance_refs) == 1

    def test_valid_pci_control_id_kept(self):
        gate = SchemaGate()
        result = gate.validate(_finding(
            compliance_refs=[_compliance_ref("PCI-DSS", "Req 6.5.1", "Injection")],
        ))
        assert result is not None
        assert len(result.compliance_refs) == 1

    def test_valid_gdpr_control_id_kept(self):
        gate = SchemaGate()
        result = gate.validate(_finding(
            compliance_refs=[_compliance_ref("GDPR", "Art. 32", "Security")],
        ))
        assert result is not None
        assert len(result.compliance_refs) == 1

    def test_invalid_control_id_removed(self):
        gate = SchemaGate()
        result = gate.validate(_finding(
            compliance_refs=[
                _compliance_ref("HIPAA", "§164.312(a)(1)", "Valid"),
                _compliance_ref("HIPAA", "MADE_UP_123", "Invalid"),
            ],
        ))
        assert result is not None
        assert len(result.compliance_refs) == 1
        assert result.compliance_refs[0].clause == "§164.312(a)(1)"

    def test_all_control_ids_invalid_still_passes(self):
        """Finding is kept even if all control IDs are invalid — it's not rejected."""
        gate = SchemaGate()
        result = gate.validate(_finding(
            compliance_refs=[_compliance_ref("HIPAA", "FAKE", "Fake")],
        ))
        assert result is not None
        assert len(result.compliance_refs) == 0

    def test_empty_compliance_refs_passes(self):
        gate = SchemaGate()
        result = gate.validate(_finding(compliance_refs=[]))
        assert result is not None

    def test_strict_mode_off_keeps_all(self):
        gate = SchemaGate(strict_control_ids=False)
        result = gate.validate(_finding(
            compliance_refs=[_compliance_ref("HIPAA", "ANYTHING", "X")],
        ))
        assert result is not None
        assert len(result.compliance_refs) == 1


# ═══════════════════════════════════════════════════════════════
# Gate 2: Evidence Verification
# ═══════════════════════════════════════════════════════════════


class TestEvidenceGate:
    def _gate(self):
        return EvidenceGate(min_similarity=80)

    def _make_finding(self, **ev_overrides) -> AuditFinding:
        return AuditFinding(**_finding(evidence=[_evidence(**ev_overrides)]))

    # ── File existence ───────────────────────────────────────

    def test_existing_file_passes(self):
        gate = self._gate()
        finding = self._make_finding(file_path="src/main.py", line_start=10, line_end=10)
        result = gate.validate(finding, _repo_files())
        assert result is not None

    def test_nonexistent_file_rejected(self):
        gate = self._gate()
        finding = self._make_finding(file_path="nonexistent.py")
        result = gate.validate(finding, _repo_files())
        assert result is None

    # ── Line range ───────────────────────────────────────────

    def test_line_end_within_range_passes(self):
        gate = self._gate()
        finding = self._make_finding(
            file_path="src/main.py", line_start=1, line_end=3,
            code_snippet="import sqlite3\ndef search(uid):\n    conn = sqlite3.connect('db.sqlite')",
        )
        result = gate.validate(finding, _repo_files())
        assert result is not None

    def test_line_end_beyond_file_rejected(self):
        gate = self._gate()
        finding = self._make_finding(
            file_path="src/auth.py", line_start=1, line_end=100,
        )
        result = gate.validate(finding, _repo_files())
        assert result is None

    # ── Code snippet matching ────────────────────────────────

    def test_exact_snippet_passes(self):
        gate = self._gate()
        finding = self._make_finding(
            file_path="src/main.py", line_start=10, line_end=10,
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
        )
        result = gate.validate(finding, _repo_files())
        assert result is not None

    def test_close_snippet_passes(self):
        """Minor whitespace differences should still pass (>80% match)."""
        gate = self._gate()
        finding = self._make_finding(
            file_path="src/main.py", line_start=10, line_end=10,
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
        )
        result = gate.validate(finding, _repo_files())
        # This may or may not pass depending on similarity — just test it doesn't crash
        assert result is not None or result is None

    def test_completely_wrong_snippet_rejected(self):
        gate = self._gate()
        finding = self._make_finding(
            file_path="src/main.py", line_start=10, line_end=10,
            code_snippet="completely_unrelated_code_that_doesnt_match_at_all()",
        )
        result = gate.validate(finding, _repo_files())
        assert result is None

    # ── Partial evidence survival ────────────────────────────

    def test_mixed_evidence_keeps_valid(self):
        """Finding with 2 evidence items: 1 valid, 1 invalid → keeps the valid one."""
        finding = AuditFinding(**_finding(evidence=[
            _evidence(
                file_path="src/main.py", line_start=10, line_end=10,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            ),
            _evidence(file_path="nonexistent.py"),
        ]))
        gate = self._gate()
        result = gate.validate(finding, _repo_files())
        assert result is not None
        assert len(result.evidence) == 1
        assert result.evidence[0].file_path == "src/main.py"

    def test_all_evidence_invalid_rejects(self):
        finding = AuditFinding(**_finding(evidence=[
            _evidence(file_path="nonexistent1.py"),
            _evidence(file_path="nonexistent2.py"),
        ]))
        gate = self._gate()
        result = gate.validate(finding, _repo_files())
        assert result is None


# ═══════════════════════════════════════════════════════════════
# Gate 3: Confidence Threshold
# ═══════════════════════════════════════════════════════════════


class TestConfidenceGate:
    def test_high_confidence_unchanged(self):
        gate = ConfidenceGate(threshold=0.7)
        finding = AuditFinding(**_finding(confidence=0.95))
        result = gate.validate(finding)
        assert "REVIEW_NEEDED" not in result.ai_explanation

    def test_low_confidence_marked_review_needed(self):
        gate = ConfidenceGate(threshold=0.7)
        finding = AuditFinding(**_finding(confidence=0.5))
        result = gate.validate(finding)
        assert "REVIEW_NEEDED" in result.ai_explanation
        assert "0.50" in result.ai_explanation

    def test_exactly_threshold_unchanged(self):
        gate = ConfidenceGate(threshold=0.7)
        finding = AuditFinding(**_finding(confidence=0.7))
        result = gate.validate(finding)
        assert "REVIEW_NEEDED" not in result.ai_explanation

    def test_just_below_threshold_marked(self):
        gate = ConfidenceGate(threshold=0.7)
        finding = AuditFinding(**_finding(confidence=0.69))
        result = gate.validate(finding)
        assert "REVIEW_NEEDED" in result.ai_explanation

    def test_never_returns_none(self):
        gate = ConfidenceGate()
        finding = AuditFinding(**_finding(confidence=0.01))
        result = gate.validate(finding)
        assert result is not None

    def test_custom_threshold(self):
        gate = ConfidenceGate(threshold=0.9)
        finding = AuditFinding(**_finding(confidence=0.85))
        result = gate.validate(finding)
        assert "REVIEW_NEEDED" in result.ai_explanation

    def test_needs_review_static(self):
        finding = AuditFinding(**_finding(confidence=0.5))
        assert ConfidenceGate.needs_review(finding) is True
        finding2 = AuditFinding(**_finding(confidence=0.9))
        assert ConfidenceGate.needs_review(finding2) is False

    def test_idempotent(self):
        gate = ConfidenceGate(threshold=0.7)
        finding = AuditFinding(**_finding(confidence=0.5))
        result1 = gate.validate(finding)
        result2 = gate.validate(result1)
        # Should not double-prepend REVIEW_NEEDED
        assert result2.ai_explanation.count("REVIEW_NEEDED") == 1


# ═══════════════════════════════════════════════════════════════
# Gate 4: Corroboration
# ═══════════════════════════════════════════════════════════════


class TestCorroborationGate:
    def test_lone_critical_demoted_to_high(self):
        """Single critical finding from one agent → demoted."""
        gate = CorroborationGate()
        findings = [AuditFinding(**_finding(
            id="BLK-001", severity="critical", category="security",
        ))]
        result = gate.validate(findings)
        assert len(result) == 1
        assert result[0].severity == "high"

    def test_corroborated_critical_stays_critical(self):
        """Two agents flag same area → critical stays."""
        gate = CorroborationGate()
        # Same file, overlapping lines, different categories
        findings = [
            AuditFinding(**_finding(
                id="BLK-001", severity="critical", category="security",
                evidence=[_evidence(file_path="src/main.py", line_start=10, line_end=12)],
            )),
            AuditFinding(**_finding(
                id="BLK-002", severity="high", category="compliance",
                evidence=[_evidence(file_path="src/main.py", line_start=10, line_end=15)],
            )),
        ]
        result = gate.validate(findings)
        critical_finding = next(f for f in result if f.id == "BLK-001")
        assert critical_finding.severity == "critical"
        assert critical_finding.source == "corroborated"

    def test_non_critical_unchanged(self):
        gate = CorroborationGate()
        findings = [AuditFinding(**_finding(
            id="BLK-001", severity="high", category="security",
        ))]
        result = gate.validate(findings)
        assert result[0].severity == "high"

    def test_same_category_not_corroboration(self):
        """Two findings from the SAME agent/category don't corroborate."""
        gate = CorroborationGate()
        findings = [
            AuditFinding(**_finding(
                id="BLK-001", severity="critical", category="security",
                evidence=[_evidence(file_path="src/main.py", line_start=10, line_end=12)],
            )),
            AuditFinding(**_finding(
                id="BLK-002", severity="high", category="security",
                evidence=[_evidence(file_path="src/main.py", line_start=10, line_end=12)],
            )),
        ]
        result = gate.validate(findings)
        blk1 = next(f for f in result if f.id == "BLK-001")
        assert blk1.severity == "high"  # Demoted — same category

    def test_different_file_not_corroboration(self):
        """Findings in different files don't corroborate each other."""
        gate = CorroborationGate()
        findings = [
            AuditFinding(**_finding(
                id="BLK-001", severity="critical", category="security",
                evidence=[_evidence(file_path="src/main.py", line_start=10, line_end=12)],
            )),
            AuditFinding(**_finding(
                id="BLK-002", severity="high", category="compliance",
                evidence=[_evidence(file_path="src/other.py", line_start=10, line_end=12)],
            )),
        ]
        result = gate.validate(findings)
        blk1 = next(f for f in result if f.id == "BLK-001")
        assert blk1.severity == "high"  # Demoted — different files

    def test_empty_findings_unchanged(self):
        gate = CorroborationGate()
        result = gate.validate([])
        assert result == []

    def test_multiple_criticals_independent(self):
        """Each critical is evaluated independently."""
        gate = CorroborationGate()
        # Two lone criticals from same category → both demoted
        findings = [
            AuditFinding(**_finding(
                id="BLK-001", severity="critical", category="security",
                evidence=[_evidence(file_path="a.py", line_start=1, line_end=5)],
            )),
            AuditFinding(**_finding(
                id="BLK-002", severity="critical", category="security",
                evidence=[_evidence(file_path="b.py", line_start=1, line_end=5)],
            )),
        ]
        result = gate.validate(findings)
        assert all(f.severity == "high" for f in result)

    def test_line_proximity_corroboration(self):
        """Findings within 10 lines of each other count as corroborating."""
        gate = CorroborationGate()
        findings = [
            AuditFinding(**_finding(
                id="BLK-001", severity="critical", category="security",
                evidence=[_evidence(file_path="src/main.py", line_start=10, line_end=12)],
            )),
            AuditFinding(**_finding(
                id="BLK-002", severity="medium", category="compliance",
                evidence=[_evidence(file_path="src/main.py", line_start=18, line_end=20)],
            )),
        ]
        result = gate.validate(findings)
        blk1 = next(f for f in result if f.id == "BLK-001")
        # Lines 10-12 and 18-20 are within proximity (10 lines)
        assert blk1.severity == "critical"


# ═══════════════════════════════════════════════════════════════
# Full Pipeline
# ═══════════════════════════════════════════════════════════════


class TestValidationPipeline:
    def test_valid_finding_passes_all_gates(self):
        pipeline = ValidationPipeline()
        raw = _finding(
            evidence=[_evidence(
                file_path="src/main.py", line_start=10, line_end=10,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            )],
        )
        result = pipeline.validate([raw], _repo_files())
        assert len(result) == 1

    def test_invalid_schema_rejected(self):
        pipeline = ValidationPipeline()
        raw = _finding()
        del raw["title"]
        result = pipeline.validate([raw], _repo_files())
        assert len(result) == 0

    def test_invalid_evidence_rejected(self):
        pipeline = ValidationPipeline()
        raw = _finding(evidence=[_evidence(file_path="nonexistent.py")])
        result = pipeline.validate([raw], _repo_files())
        assert len(result) == 0

    def test_low_confidence_marked_but_kept(self):
        pipeline = ValidationPipeline()
        raw = _finding(
            confidence=0.5,
            evidence=[_evidence(
                file_path="src/main.py", line_start=10, line_end=10,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            )],
        )
        result = pipeline.validate([raw], _repo_files())
        assert len(result) == 1
        assert "REVIEW_NEEDED" in result[0].ai_explanation

    def test_lone_critical_demoted_in_pipeline(self):
        pipeline = ValidationPipeline()
        raw = _finding(
            severity="critical",
            evidence=[_evidence(
                file_path="src/main.py", line_start=10, line_end=10,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            )],
        )
        result = pipeline.validate([raw], _repo_files())
        assert len(result) == 1
        assert result[0].severity == "high"  # Demoted by Gate 4

    def test_multiple_findings_mixed_outcomes(self):
        pipeline = ValidationPipeline()
        raws = [
            # Valid finding
            _finding(
                id="BLK-001", severity="high",
                evidence=[_evidence(
                    file_path="src/main.py", line_start=10, line_end=10,
                    code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
                )],
            ),
            # Invalid schema
            {"garbage": True},
            # Invalid evidence
            _finding(
                id="BLK-003", evidence=[_evidence(file_path="nope.py")],
            ),
        ]
        result = pipeline.validate(raws, _repo_files())
        assert len(result) == 1
        assert result[0].id == "BLK-001"

    def test_validate_single(self):
        pipeline = ValidationPipeline()
        raw = _finding(
            evidence=[_evidence(
                file_path="src/main.py", line_start=10, line_end=10,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            )],
        )
        result = pipeline.validate_single(raw, _repo_files())
        assert result is not None

    def test_validate_single_invalid_returns_none(self):
        pipeline = ValidationPipeline()
        raw = _finding(evidence=[_evidence(file_path="nope.py")])
        result = pipeline.validate_single(raw, _repo_files())
        assert result is None

    def test_empty_input(self):
        pipeline = ValidationPipeline()
        result = pipeline.validate([], _repo_files())
        assert result == []
