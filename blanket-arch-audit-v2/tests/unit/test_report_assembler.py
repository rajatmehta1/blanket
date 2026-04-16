"""Tests for ReportAssembler + ComplianceMatrixBuilder + InfraFindingBuilder + RemediationPlanner."""

from __future__ import annotations

import pytest

from blanketaudit2.models.finding import AuditFinding, ComplianceRef, Evidence
from blanketaudit2.models.report import InfraFinding
from blanketaudit2.models.scoring import HealthScore
from blanketaudit2.scoring.compliance_matrix_builder import ComplianceMatrixBuilder
from blanketaudit2.scoring.infra_finding_builder import InfraFindingBuilder
from blanketaudit2.scoring.remediation_planner import RemediationPlanner
from blanketaudit2.scoring.report_assembler import ReportAssembler


# ── Helpers ──────────────────────────────────────────────────


def _finding(
    id: str = "BLK-001",
    severity: str = "high",
    category: str = "security",
    confidence: float = 0.9,
    title: str = "SQL Injection",
    file_path: str = "src/main.py",
    compliance_refs: list | None = None,
    effort_hours: float = 2.0,
    remediation: str = "Use parameterized queries.",
) -> AuditFinding:
    return AuditFinding(
        id=id, policy_id="SEC-001", title=title,
        description=f"Finding: {title}", severity=severity,
        category=category, confidence=confidence, source="static",
        evidence=[Evidence(
            file_path=file_path, repo_name="api",
            line_start=10, line_end=12,
            code_snippet="code here", tool="semgrep",
        )],
        compliance_refs=compliance_refs or [],
        ai_explanation="Explanation.", fix_code="fix()",
        remediation=remediation, effort_hours=effort_hours,
        dollar_impact="$10,000",
    )


def _ref(fw: str, clause: str, title: str = "Control"):
    return ComplianceRef(framework=fw, clause=clause, title=title)


# ═══════════════════════════════════════════════════════════════
# ComplianceMatrixBuilder
# ═══════════════════════════════════════════════════════════════


class TestComplianceMatrixBuilder:
    def test_builds_matrix_for_framework(self):
        builder = ComplianceMatrixBuilder()
        findings = [
            _finding(compliance_refs=[_ref("HIPAA", "§164.312(a)(1)", "Access Control")]),
            _finding(id="BLK-002", compliance_refs=[_ref("HIPAA", "§164.312(e)(1)", "Transmission")]),
        ]
        matrices = builder.build(findings, ["HIPAA"])
        assert len(matrices) == 1
        assert matrices[0].framework == "HIPAA"
        assert len(matrices[0].sections) == 2

    def test_status_fail_on_critical(self):
        builder = ComplianceMatrixBuilder()
        findings = [
            _finding(severity="critical", compliance_refs=[_ref("HIPAA", "§164.312(a)(1)")]),
        ]
        matrices = builder.build(findings, ["HIPAA"])
        assert matrices[0].sections[0].status == "fail"

    def test_status_pass_on_no_findings(self):
        builder = ComplianceMatrixBuilder()
        matrices = builder.build([], ["HIPAA"])
        assert len(matrices) == 1
        assert len(matrices[0].sections) == 0  # No controls to report

    def test_status_review_needed_on_low_confidence(self):
        builder = ComplianceMatrixBuilder()
        findings = [
            _finding(confidence=0.5, compliance_refs=[_ref("SOC2", "CC6.1")]),
        ]
        matrices = builder.build(findings, ["SOC2"])
        assert matrices[0].sections[0].status == "review_needed"

    def test_status_partial_on_medium(self):
        builder = ComplianceMatrixBuilder()
        findings = [
            _finding(severity="medium", compliance_refs=[_ref("HIPAA", "§164.312(a)(1)")]),
        ]
        matrices = builder.build(findings, ["HIPAA"])
        assert matrices[0].sections[0].status == "partial"

    def test_multiple_frameworks(self):
        builder = ComplianceMatrixBuilder()
        findings = [
            _finding(compliance_refs=[
                _ref("HIPAA", "§164.312(a)(1)"),
                _ref("SOC2", "CC6.1"),
            ]),
        ]
        matrices = builder.build(findings, ["HIPAA", "SOC2"])
        assert len(matrices) == 2
        fw_names = {m.framework for m in matrices}
        assert fw_names == {"HIPAA", "SOC2"}

    def test_finding_count_correct(self):
        builder = ComplianceMatrixBuilder()
        findings = [
            _finding(id="BLK-001", compliance_refs=[_ref("HIPAA", "§164.312(a)(1)")]),
            _finding(id="BLK-002", severity="medium",
                     compliance_refs=[_ref("HIPAA", "§164.312(a)(1)")]),
        ]
        matrices = builder.build(findings, ["HIPAA"])
        assert matrices[0].sections[0].finding_count == 2


# ═══════════════════════════════════════════════════════════════
# InfraFindingBuilder
# ═══════════════════════════════════════════════════════════════


class TestInfraFindingBuilder:
    def test_extracts_infra_by_category(self):
        builder = InfraFindingBuilder()
        findings = [
            _finding(category="infrastructure", title="Docker runs as root"),
            _finding(id="BLK-002", category="security", title="SQL Injection"),
        ]
        infra, code = builder.extract(findings)
        assert len(infra) == 1
        assert len(code) == 1
        assert infra[0].title == "Docker runs as root"
        assert isinstance(infra[0], InfraFinding)

    def test_extracts_infra_by_policy_id(self):
        builder = InfraFindingBuilder()
        findings = [
            _finding(category="quality", title="Unpinned base image"),
        ]
        # Override policy_id to infra prefix
        findings[0] = findings[0].model_copy(update={"policy_id": "QUAL-011"})
        infra, code = builder.extract(findings)
        assert len(infra) == 1

    def test_extracts_infra_by_keyword(self):
        builder = InfraFindingBuilder()
        findings = [
            _finding(title="Docker container missing healthcheck"),
            _finding(id="BLK-002", title="K8s pod without resource limits"),
        ]
        infra, code = builder.extract(findings)
        assert len(infra) == 2

    def test_code_findings_preserved(self):
        builder = InfraFindingBuilder()
        findings = [_finding(title="SQL Injection")]
        infra, code = builder.extract(findings)
        assert len(infra) == 0
        assert len(code) == 1

    def test_empty_findings(self):
        builder = InfraFindingBuilder()
        infra, code = builder.extract([])
        assert infra == []
        assert code == []

    def test_infra_card_has_required_fields(self):
        builder = InfraFindingBuilder()
        findings = [_finding(category="infrastructure", title="Root container")]
        infra, _ = builder.extract(findings)
        card = infra[0]
        assert card.severity in ("critical", "high", "medium", "low")
        assert card.title
        assert card.file
        assert card.detail


# ═══════════════════════════════════════════════════════════════
# RemediationPlanner
# ═══════════════════════════════════════════════════════════════


class TestRemediationPlanner:
    def test_phases_created(self):
        planner = RemediationPlanner()
        findings = [
            _finding(severity="critical"),
            _finding(id="BLK-002", severity="high"),
            _finding(id="BLK-003", severity="medium"),
        ]
        health = HealthScore(
            overall=40, grade="D", categories=[],
            severity_counts={"critical": 1, "high": 1, "medium": 1, "low": 0},
        )
        phases = planner.plan(findings, health)
        # Critical + top 5 high → Phase 1, remaining → Phase 2
        assert len(phases) >= 2
        assert "URGENT" in phases[0].title

    def test_critical_only_one_phase(self):
        planner = RemediationPlanner()
        findings = [_finding(severity="critical")]
        health = HealthScore(overall=20, grade="F", categories=[],
                             severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0})
        phases = planner.plan(findings, health)
        assert len(phases) == 1
        assert phases[0].items[0].finding_id == "BLK-001"
        assert "+25" in phases[0].items[0].score_impact

    def test_score_target_progression(self):
        planner = RemediationPlanner()
        findings = [
            _finding(severity="critical"),
            _finding(id="BLK-002", severity="high"),
        ]
        health = HealthScore(overall=30, grade="D", categories=[],
                             severity_counts={"critical": 1, "high": 1, "medium": 0, "low": 0})
        phases = planner.plan(findings, health)
        # Phase 1 should show score improvement
        assert "30 →" in phases[0].score_target

    def test_no_findings_no_phases(self):
        planner = RemediationPlanner()
        health = HealthScore(overall=100, grade="A", categories=[],
                             severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0})
        phases = planner.plan([], health)
        assert len(phases) == 0

    def test_effort_hours_summed(self):
        planner = RemediationPlanner()
        findings = [
            _finding(severity="critical", effort_hours=5.0),
            _finding(id="BLK-002", severity="critical", effort_hours=3.0),
        ]
        health = HealthScore(overall=20, grade="F", categories=[],
                             severity_counts={"critical": 2, "high": 0, "medium": 0, "low": 0})
        phases = planner.plan(findings, health)
        assert "8 hours" in phases[0].total_effort


# ═══════════════════════════════════════════════════════════════
# ReportAssembler
# ═══════════════════════════════════════════════════════════════


class TestReportAssembler:
    @pytest.mark.asyncio
    async def test_assembles_complete_report(self):
        assembler = ReportAssembler()
        state = {
            "project_name": "MedPay",
            "project_tagline": "Patient Payment Platform",
            "domain": "healthcare",
            "frameworks": ["HIPAA"],
            "scan_id": "scan-001",
            "repo_paths": [{"repo_name": "api", "local_path": "/tmp/api"}],
            "files": [
                {"path": "main.py", "language": "python", "loc": 200},
                {"path": "utils.py", "language": "python", "loc": 100},
            ],
            "validated_findings": [
                _finding(
                    severity="critical", title="SQL Injection",
                    compliance_refs=[_ref("HIPAA", "§164.312(a)(1)", "Access")],
                ).model_dump(),
                _finding(
                    id="BLK-002", severity="high", title="Hardcoded Password",
                ).model_dump(),
            ],
            "analysis_contexts": [{"methods": [{"name": "a"}, {"name": "b"}], "classes": []}],
        }

        report = await assembler.assemble(state)

        # Verify all top-level fields
        assert report["project_name"] == "MedPay"
        assert report["domain"] == "healthcare"
        assert report["total_files"] == 2
        assert report["total_methods"] == 2
        assert "health_score" in report
        assert "executive_summary" in report
        assert "findings" in report
        assert "compliance_matrix" in report
        assert "remediation_phases" in report
        assert "scan_manifest" in report
        assert report["active_frameworks"] == ["HIPAA"]

    @pytest.mark.asyncio
    async def test_findings_sorted_by_severity(self):
        assembler = ReportAssembler()
        state = {
            "project_name": "Test",
            "domain": "general",
            "frameworks": [],
            "repo_paths": [],
            "files": [],
            "validated_findings": [
                _finding(id="BLK-001", severity="low", title="Low").model_dump(),
                _finding(id="BLK-002", severity="critical", title="Critical").model_dump(),
                _finding(id="BLK-003", severity="medium", title="Medium").model_dump(),
                _finding(id="BLK-004", severity="high", title="High").model_dump(),
            ],
            "analysis_contexts": [],
        }

        report = await assembler.assemble(state)
        severities = [f["severity"] for f in report["findings"]]
        assert severities == ["critical", "high", "medium", "low"]

    @pytest.mark.asyncio
    async def test_infra_findings_extracted(self):
        assembler = ReportAssembler()
        state = {
            "project_name": "Test",
            "domain": "general",
            "frameworks": [],
            "repo_paths": [],
            "files": [],
            "validated_findings": [
                _finding(title="SQL Injection").model_dump(),
                _finding(
                    id="BLK-002", category="infrastructure",
                    title="Docker runs as root",
                ).model_dump(),
            ],
            "analysis_contexts": [],
        }

        report = await assembler.assemble(state)
        assert len(report["infra_findings"]) == 1
        assert report["infra_findings"][0]["title"] == "Docker runs as root"
        # Code findings should not include the infra one
        assert all(f["title"] != "Docker runs as root" for f in report["findings"])

    @pytest.mark.asyncio
    async def test_compliance_matrix_populated(self):
        assembler = ReportAssembler()
        state = {
            "project_name": "Test",
            "domain": "healthcare",
            "frameworks": ["HIPAA", "SOC2"],
            "repo_paths": [],
            "files": [],
            "validated_findings": [
                _finding(
                    compliance_refs=[
                        _ref("HIPAA", "§164.312(a)(1)", "Access Control"),
                        _ref("SOC2", "CC6.1", "Logical Access"),
                    ],
                ).model_dump(),
            ],
            "analysis_contexts": [],
        }

        report = await assembler.assemble(state)
        assert len(report["compliance_matrix"]) == 2
        fw_names = {m["framework"] for m in report["compliance_matrix"]}
        assert "HIPAA" in fw_names
        assert "SOC2" in fw_names

    @pytest.mark.asyncio
    async def test_empty_findings(self):
        assembler = ReportAssembler()
        state = {
            "project_name": "Clean",
            "domain": "general",
            "frameworks": [],
            "repo_paths": [],
            "files": [],
            "validated_findings": [],
            "analysis_contexts": [],
        }

        report = await assembler.assemble(state)
        assert report["health_score"]["overall"] == 100
        assert report["health_score"]["grade"] == "A"
        assert report["findings"] == []
        assert report["remediation_phases"] == []

    @pytest.mark.asyncio
    async def test_format_lines(self):
        assert ReportAssembler._format_lines(500) == "500"
        assert ReportAssembler._format_lines(5000) == "5k"
        assert ReportAssembler._format_lines(62000) == "62k"
        assert ReportAssembler._format_lines(1_500_000) == "1.5M"
