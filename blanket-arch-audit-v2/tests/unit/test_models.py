"""Tests for Pydantic v2 data models -- validation, rejection of malformed data."""
from __future__ import annotations

import pytest
from datetime import datetime
from pydantic import ValidationError

from blanketaudit.models.finding import (
    AuditFinding,
    ArchitectureFindings,
    BlastRadius,
    CallChainStep,
    ComplianceFindings,
    ComplianceRef,
    Evidence,
    QualityFindings,
    SecurityFindings,
)
from blanketaudit.models.scoring import CategoryScore, HealthScore
from blanketaudit.models.manifest import ScanManifest
from blanketaudit.models.compliance import ComplianceControlStatus, ComplianceMatrix
from blanketaudit.models.callgraph import (
    CallGraphSummary,
    CrossRepoEdge,
    DeadCodeSummary,
    EntryPointSummary,
)
from blanketaudit.models.roadmap import RemediationPhase, RemediationTask
from blanketaudit.models.report import AuditReport, ExecutiveSummary, InfraFinding
from blanketaudit.ingestion.models import (
    AnalysisContext,
    CallInfo,
    ClassInfo,
    EntryPointInfo,
    FileMetadata,
    FileType,
    ImportInfo,
    MethodInfo,
    ProjectInfo,
    RepoInfo,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_evidence(**overrides) -> dict:
    base = dict(
        file_path="src/main.py",
        repo_name="my-repo",
        line_start=10,
        line_end=15,
        code_snippet="x = 1",
        tool="semgrep",
    )
    base.update(overrides)
    return base


def _make_compliance_ref(**overrides) -> dict:
    base = dict(framework="HIPAA", clause="164.312(a)(1)", title="Access Control")
    base.update(overrides)
    return base


def _make_audit_finding(**overrides) -> dict:
    base = dict(
        id="BLK-001",
        policy_id="SEC-001",
        title="SQL Injection",
        description="User input is interpolated directly into SQL.",
        severity="critical",
        category="security",
        confidence=0.95,
        source="corroborated",
        evidence=[_make_evidence()],
        compliance_refs=[_make_compliance_ref()],
        ai_explanation="This is a serious SQL injection vulnerability.",
        fix_code="cursor.execute(query, params)",
        remediation="Use parameterized queries.",
        effort_hours=2.0,
        dollar_impact="$50,000 - $1,900,000",
    )
    base.update(overrides)
    return base


def _make_scan_manifest(**overrides) -> dict:
    base = dict(
        scan_id="scan-001",
        timestamp=datetime(2026, 3, 23, 12, 0, 0),
        policy_versions={"SEC": "1.0"},
        prompt_versions={"security": "1.0"},
        model_ids={"security": "claude-sonnet-4-20250514"},
        tool_versions={"semgrep": "1.60.0"},
        repo_commits={"my-repo": "abc123"},
        config_hash="a" * 64,
    )
    base.update(overrides)
    return base


# ===========================================================================
# Evidence
# ===========================================================================

class TestEvidence:
    def test_valid_evidence(self):
        ev = Evidence(**_make_evidence())
        assert ev.file_path == "src/main.py"
        assert ev.line_start == 10
        assert ev.line_end == 15

    def test_line_start_must_be_positive(self):
        with pytest.raises(ValidationError, match="line_start must be >= 1"):
            Evidence(**_make_evidence(line_start=0))

    def test_line_start_negative_rejected(self):
        with pytest.raises(ValidationError, match="line_start must be >= 1"):
            Evidence(**_make_evidence(line_start=-5))

    def test_line_end_must_be_gte_line_start(self):
        with pytest.raises(ValidationError, match="line_end must be >= line_start"):
            Evidence(**_make_evidence(line_start=20, line_end=10))

    def test_line_end_equal_to_line_start_valid(self):
        ev = Evidence(**_make_evidence(line_start=5, line_end=5))
        assert ev.line_start == ev.line_end == 5

    def test_missing_required_field_rejected(self):
        data = _make_evidence()
        del data["file_path"]
        with pytest.raises(ValidationError):
            Evidence(**data)


# ===========================================================================
# ComplianceRef
# ===========================================================================

class TestComplianceRef:
    def test_valid_ref(self):
        for fw in ("HIPAA", "SOC2", "PCI-DSS", "GDPR", "SOX", "ISO27001", "NIST"):
            ref = ComplianceRef(**_make_compliance_ref(framework=fw))
            assert ref.framework == fw

    def test_unknown_framework_rejected(self):
        with pytest.raises(ValidationError, match="Unknown framework"):
            ComplianceRef(**_make_compliance_ref(framework="UNKNOWN"))

    def test_case_variations_accepted(self):
        # The validator does case-insensitive comparison
        ref = ComplianceRef(**_make_compliance_ref(framework="hipaa"))
        assert ref.framework == "hipaa"

    def test_another_case_variation(self):
        ref = ComplianceRef(**_make_compliance_ref(framework="Soc2"))
        assert ref.framework == "Soc2"

    def test_empty_framework_rejected(self):
        with pytest.raises(ValidationError, match="Unknown framework"):
            ComplianceRef(**_make_compliance_ref(framework=""))


# ===========================================================================
# BlastRadius
# ===========================================================================

class TestBlastRadius:
    def test_valid_blast_radius(self):
        br = BlastRadius(
            entry_points=5,
            repos_affected=2,
            daily_calls="~2,400",
            affected_users="All patients",
        )
        assert br.entry_points == 5
        assert br.repos_affected == 2

    def test_missing_field_rejected(self):
        with pytest.raises(ValidationError):
            BlastRadius(entry_points=5)

    def test_negative_entry_points_rejected(self):
        with pytest.raises(ValidationError, match="non-negative"):
            BlastRadius(
                entry_points=-1, repos_affected=2,
                daily_calls="~100", affected_users="All",
            )

    def test_negative_repos_affected_rejected(self):
        with pytest.raises(ValidationError, match="non-negative"):
            BlastRadius(
                entry_points=1, repos_affected=-1,
                daily_calls="~100", affected_users="All",
            )

    def test_zero_values_accepted(self):
        br = BlastRadius(
            entry_points=0, repos_affected=0,
            daily_calls="0", affected_users="None",
        )
        assert br.entry_points == 0
        assert br.repos_affected == 0

    def test_serialization_roundtrip(self):
        br = BlastRadius(
            entry_points=5, repos_affected=2,
            daily_calls="~2,400", affected_users="All patients",
        )
        data = br.model_dump()
        restored = BlastRadius(**data)
        assert br == restored


# ===========================================================================
# CallChainStep
# ===========================================================================

class TestCallChainStep:
    def test_valid_step_types(self):
        for st in ("entry", "method", "cross_repo", "taint", "sink", "external", "propagation"):
            step = CallChainStep(method="doStuff()", step_type=st, repo="my-repo")
            assert step.step_type == st

    def test_invalid_step_type_rejected(self):
        with pytest.raises(ValidationError):
            CallChainStep(method="doStuff()", step_type="unknown", repo="my-repo")


# ===========================================================================
# AuditFinding
# ===========================================================================

class TestAuditFinding:
    def test_valid_finding(self):
        f = AuditFinding(**_make_audit_finding())
        assert f.id == "BLK-001"
        assert f.severity == "critical"
        assert f.confidence == 0.95
        assert len(f.evidence) == 1
        assert len(f.compliance_refs) == 1
        assert f.blast_radius is None
        assert f.call_chain == []

    def test_confidence_too_high(self):
        with pytest.raises(ValidationError, match="confidence must be between"):
            AuditFinding(**_make_audit_finding(confidence=1.5))

    def test_confidence_negative(self):
        with pytest.raises(ValidationError, match="confidence must be between"):
            AuditFinding(**_make_audit_finding(confidence=-0.1))

    def test_confidence_boundary_zero(self):
        f = AuditFinding(**_make_audit_finding(confidence=0.0))
        assert f.confidence == 0.0

    def test_confidence_boundary_one(self):
        f = AuditFinding(**_make_audit_finding(confidence=1.0))
        assert f.confidence == 1.0

    def test_invalid_severity(self):
        with pytest.raises(ValidationError):
            AuditFinding(**_make_audit_finding(severity="catastrophic"))

    def test_valid_severities(self):
        for sev in ("critical", "high", "medium", "low"):
            f = AuditFinding(**_make_audit_finding(severity=sev))
            assert f.severity == sev

    def test_invalid_category(self):
        with pytest.raises(ValidationError):
            AuditFinding(**_make_audit_finding(category="unknown"))

    def test_valid_categories(self):
        for cat in ("security", "compliance", "architecture", "quality",
                     "performance", "reliability", "infrastructure"):
            f = AuditFinding(**_make_audit_finding(category=cat))
            assert f.category == cat

    def test_invalid_source(self):
        with pytest.raises(ValidationError):
            AuditFinding(**_make_audit_finding(source="manual"))

    def test_id_pattern_validation_valid(self):
        f = AuditFinding(**_make_audit_finding(id="BLK-001"))
        assert f.id == "BLK-001"

    def test_id_pattern_validation_multi_digit(self):
        f = AuditFinding(**_make_audit_finding(id="BLK-99999"))
        assert f.id == "BLK-99999"

    def test_id_pattern_validation_invalid(self):
        with pytest.raises(ValidationError, match="BLK-<digits>"):
            AuditFinding(**_make_audit_finding(id="INVALID"))

    def test_id_pattern_no_prefix(self):
        with pytest.raises(ValidationError, match="BLK-<digits>"):
            AuditFinding(**_make_audit_finding(id="001"))

    def test_id_pattern_wrong_prefix(self):
        with pytest.raises(ValidationError, match="BLK-<digits>"):
            AuditFinding(**_make_audit_finding(id="SEC-001"))

    def test_serialization_roundtrip(self):
        original = AuditFinding(**_make_audit_finding())
        data = original.model_dump()
        restored = AuditFinding(**data)
        assert original == restored

    def test_finding_with_blast_radius(self):
        br = dict(
            entry_points=3,
            repos_affected=2,
            daily_calls="~1,000",
            affected_users="All users",
        )
        f = AuditFinding(**_make_audit_finding(blast_radius=br))
        assert f.blast_radius is not None
        assert f.blast_radius.entry_points == 3

    def test_finding_with_call_chain(self):
        chain = [
            dict(method="POST /api/patients", step_type="entry", repo="api"),
            dict(method="PatientService.search()", step_type="method", repo="api"),
            dict(method="db.execute()", step_type="sink", repo="api"),
        ]
        f = AuditFinding(**_make_audit_finding(call_chain=chain))
        assert len(f.call_chain) == 3
        assert f.call_chain[0].step_type == "entry"
        assert f.call_chain[2].step_type == "sink"

    def test_json_roundtrip(self):
        original = AuditFinding(**_make_audit_finding())
        json_str = original.model_dump_json()
        restored = AuditFinding.model_validate_json(json_str)
        assert original == restored


# ===========================================================================
# HealthScore
# ===========================================================================

class TestHealthScore:
    def test_valid_score(self):
        hs = HealthScore(
            overall=72,
            grade="B",
            categories=[
                CategoryScore(name="Security", score=60, finding_count=5),
                CategoryScore(name="Quality", score=85, finding_count=2),
            ],
            severity_counts={"critical": 1, "high": 3, "medium": 5, "low": 10},
        )
        assert hs.overall == 72
        assert hs.grade == "B"
        assert len(hs.categories) == 2

    def test_grade_must_be_valid_letter(self):
        with pytest.raises(ValidationError, match="Invalid grade"):
            HealthScore(
                overall=50, grade="X",
                categories=[], severity_counts={},
            )

    def test_valid_grades(self):
        for g in ("A", "B", "C", "D", "F"):
            hs = HealthScore(
                overall=50, grade=g, categories=[], severity_counts={},
            )
            assert hs.grade == g

    def test_overall_must_be_0_to_100_too_high(self):
        with pytest.raises(ValidationError, match="overall score must be 0-100"):
            HealthScore(
                overall=101, grade="A", categories=[], severity_counts={},
            )

    def test_overall_must_be_0_to_100_negative(self):
        with pytest.raises(ValidationError, match="overall score must be 0-100"):
            HealthScore(
                overall=-1, grade="F", categories=[], severity_counts={},
            )

    def test_overall_boundary_zero(self):
        hs = HealthScore(overall=0, grade="F", categories=[], severity_counts={})
        assert hs.overall == 0

    def test_overall_boundary_100(self):
        hs = HealthScore(overall=100, grade="A", categories=[], severity_counts={})
        assert hs.overall == 100


# ===========================================================================
# CategoryScore
# ===========================================================================

class TestCategoryScore:
    def test_valid_category_score(self):
        cs = CategoryScore(name="Security", score=75, finding_count=12)
        assert cs.name == "Security"
        assert cs.score == 75
        assert cs.finding_count == 12

    def test_missing_field_rejected(self):
        with pytest.raises(ValidationError):
            CategoryScore(name="Security")

    def test_score_too_high_rejected(self):
        with pytest.raises(ValidationError, match="score must be 0-100"):
            CategoryScore(name="Security", score=101, finding_count=0)

    def test_score_negative_rejected(self):
        with pytest.raises(ValidationError, match="score must be 0-100"):
            CategoryScore(name="Security", score=-1, finding_count=0)

    def test_score_boundary_zero(self):
        cs = CategoryScore(name="Security", score=0, finding_count=0)
        assert cs.score == 0

    def test_score_boundary_100(self):
        cs = CategoryScore(name="Security", score=100, finding_count=0)
        assert cs.score == 100

    def test_negative_finding_count_rejected(self):
        with pytest.raises(ValidationError, match="finding_count must be non-negative"):
            CategoryScore(name="Security", score=50, finding_count=-1)


# ===========================================================================
# ScanManifest
# ===========================================================================

class TestScanManifest:
    def test_valid_manifest(self):
        sm = ScanManifest(**_make_scan_manifest())
        assert sm.scan_id == "scan-001"
        assert sm.config_hash == "a" * 64

    def test_config_hash_must_be_64_chars(self):
        with pytest.raises(ValidationError, match="64-char SHA-256"):
            ScanManifest(**_make_scan_manifest(config_hash="abc"))

    def test_config_hash_wrong_length_63(self):
        with pytest.raises(ValidationError, match="64-char SHA-256"):
            ScanManifest(**_make_scan_manifest(config_hash="a" * 63))

    def test_config_hash_wrong_length_65(self):
        with pytest.raises(ValidationError, match="64-char SHA-256"):
            ScanManifest(**_make_scan_manifest(config_hash="a" * 65))

    def test_empty_config_hash_allowed(self):
        sm = ScanManifest(**_make_scan_manifest(config_hash=""))
        assert sm.config_hash == ""

    def test_timestamp_parsing(self):
        sm = ScanManifest(**_make_scan_manifest(timestamp="2026-03-23T12:00:00"))
        assert sm.timestamp == datetime(2026, 3, 23, 12, 0, 0)

    def test_serialization_roundtrip(self):
        original = ScanManifest(**_make_scan_manifest())
        data = original.model_dump()
        restored = ScanManifest(**data)
        assert original == restored


# ===========================================================================
# ComplianceControlStatus / ComplianceMatrix
# ===========================================================================

class TestComplianceControlStatus:
    def test_valid_control_status(self):
        cs = ComplianceControlStatus(
            control_id="HIPAA-164.312-a-1",
            framework="HIPAA",
            clause="164.312(a)(1)",
            title="Access Control",
            status="fail",
            finding_count=3,
            detail="Missing encryption at rest.",
        )
        assert cs.status == "fail"

    def test_valid_statuses(self):
        for s in ("pass", "partial", "fail", "gap", "not_applicable", "review_needed"):
            cs = ComplianceControlStatus(
                control_id="C1", framework="SOC2", clause="CC6.1",
                title="T", status=s, finding_count=0, detail="",
            )
            assert cs.status == s

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            ComplianceControlStatus(
                control_id="C1", framework="SOC2", clause="CC6.1",
                title="T", status="unknown", finding_count=0, detail="",
            )

    def test_negative_finding_count_rejected(self):
        with pytest.raises(ValidationError, match="finding_count must be non-negative"):
            ComplianceControlStatus(
                control_id="C1", framework="SOC2", clause="CC6.1",
                title="T", status="pass", finding_count=-1, detail="",
            )


class TestComplianceMatrix:
    def test_valid_matrix(self):
        cm = ComplianceMatrix(
            framework="HIPAA",
            sections=[
                ComplianceControlStatus(
                    control_id="H1", framework="HIPAA", clause="164.312(a)(1)",
                    title="Access", status="pass", finding_count=0, detail="OK",
                ),
            ],
        )
        assert cm.framework == "HIPAA"
        assert len(cm.sections) == 1

    def test_empty_sections_allowed(self):
        cm = ComplianceMatrix(framework="SOC2", sections=[])
        assert cm.sections == []


# ===========================================================================
# Per-agent output schemas
# ===========================================================================

class TestAgentOutputSchemas:
    def _finding(self, **kw) -> dict:
        return _make_audit_finding(**kw)

    def test_security_findings(self):
        sf = SecurityFindings(
            findings=[AuditFinding(**self._finding(category="security"))],
            scan_tool_versions={"semgrep": "1.60.0", "gitleaks": "8.18.0"},
        )
        assert len(sf.findings) == 1
        assert sf.scan_tool_versions["semgrep"] == "1.60.0"

    def test_security_findings_empty(self):
        sf = SecurityFindings(findings=[])
        assert sf.findings == []
        assert sf.scan_tool_versions == {}

    def test_compliance_findings(self):
        cf = ComplianceFindings(
            findings=[AuditFinding(**self._finding(category="compliance"))],
            control_statuses=[
                ComplianceControlStatus(
                    control_id="H1", framework="HIPAA", clause="164.312(a)(1)",
                    title="Access", status="fail", finding_count=1, detail="Issue",
                ),
            ],
        )
        assert len(cf.findings) == 1
        assert len(cf.control_statuses) == 1

    def test_architecture_findings(self):
        af = ArchitectureFindings(
            findings=[AuditFinding(**self._finding(category="architecture"))],
            layer_map={"src/api/routes.py": "presentation", "src/db/repo.py": "data"},
        )
        assert len(af.findings) == 1
        assert af.layer_map["src/api/routes.py"] == "presentation"

    def test_quality_findings(self):
        qf = QualityFindings(
            findings=[AuditFinding(**self._finding(category="quality"))],
            complexity_stats={"avg_cyclomatic": 8, "max_cyclomatic": 42},
        )
        assert len(qf.findings) == 1
        assert qf.complexity_stats["max_cyclomatic"] == 42


# ===========================================================================
# Ingestion models
# ===========================================================================

class TestIngestionModels:
    def test_file_metadata(self):
        fm = FileMetadata(
            path="src/main.py",
            repo_name="my-repo",
            language="python",
            loc=150,
            file_type=FileType.SOURCE,
            content_sha256="abcdef1234567890" * 4,
            size_bytes=4096,
        )
        assert fm.path == "src/main.py"
        assert fm.file_type == FileType.SOURCE
        assert fm.loc == 150

    def test_file_metadata_defaults(self):
        fm = FileMetadata(path="a.py", repo_name="r", language="python")
        assert fm.loc == 0
        assert fm.file_type == FileType.SOURCE
        assert fm.content_sha256 == ""
        assert fm.size_bytes == 0

    def test_file_type_enum_values(self):
        for ft in FileType:
            assert isinstance(ft.value, str)
        assert FileType.IAC.value == "iac"
        assert FileType.CICD.value == "cicd"

    def test_analysis_context(self):
        ctx = AnalysisContext(
            repo_name="my-repo",
            root_path="/tmp/repos/my-repo",
            total_loc=5000,
            total_methods=120,
            total_classes=30,
        )
        assert ctx.repo_name == "my-repo"
        assert ctx.files == []
        assert ctx.methods == []

    def test_analysis_context_with_nested_data(self):
        fm = FileMetadata(path="a.py", repo_name="r", language="python")
        mi = MethodInfo(
            name="foo", qualified_name="mod.foo",
            file_path="a.py", repo_name="r",
            line_start=1, line_end=10,
        )
        ctx = AnalysisContext(
            repo_name="r", root_path="/tmp",
            files=[fm], methods=[mi],
        )
        assert len(ctx.files) == 1
        assert len(ctx.methods) == 1

    def test_class_info(self):
        ci = ClassInfo(
            name="PatientService",
            file_path="src/service.py",
            repo_name="api",
            line_start=10,
            line_end=80,
            methods=["search", "create", "update"],
            bases=["BaseService"],
            decorators=["@injectable"],
            loc=70,
        )
        assert ci.name == "PatientService"
        assert len(ci.methods) == 3
        assert ci.bases == ["BaseService"]

    def test_class_info_defaults(self):
        ci = ClassInfo(
            name="C", file_path="f.py", repo_name="r",
            line_start=1, line_end=5,
        )
        assert ci.methods == []
        assert ci.bases == []
        assert ci.decorators == []
        assert ci.loc == 0

    def test_method_info(self):
        mi = MethodInfo(
            name="search_patients",
            qualified_name="PatientService.search_patients",
            file_path="src/service.py",
            repo_name="api",
            line_start=15,
            line_end=40,
            parameters=["query", "limit"],
            return_type="list[Patient]",
            decorators=["@cache"],
            is_entry_point=False,
            loc=25,
            complexity=6,
        )
        assert mi.name == "search_patients"
        assert mi.complexity == 6
        assert mi.is_entry_point is False

    def test_method_info_defaults(self):
        mi = MethodInfo(
            name="f", qualified_name="f",
            file_path="a.py", repo_name="r",
            line_start=1, line_end=2,
        )
        assert mi.parameters == []
        assert mi.return_type == ""
        assert mi.is_entry_point is False
        assert mi.complexity == 0

    def test_call_info(self):
        ci = CallInfo(
            caller="Service.do_work",
            callee="Repository.save",
            file_path="src/service.py",
            line_number=42,
            call_type="method",
        )
        assert ci.caller == "Service.do_work"
        assert ci.call_type == "method"

    def test_call_info_valid_types(self):
        for ct in ("direct", "method", "constructor", "http", "async"):
            ci = CallInfo(
                caller="a", callee="b", file_path="f.py",
                line_number=1, call_type=ct,
            )
            assert ci.call_type == ct

    def test_call_info_invalid_type(self):
        with pytest.raises(ValidationError):
            CallInfo(
                caller="a", callee="b", file_path="f.py",
                line_number=1, call_type="rpc",
            )

    def test_call_info_default_type(self):
        ci = CallInfo(caller="a", callee="b", file_path="f.py", line_number=1)
        assert ci.call_type == "direct"

    def test_entry_point_info(self):
        ep = EntryPointInfo(
            method_name="create_patient",
            file_path="src/routes.py",
            repo_name="api",
            http_method="POST",
            route="/api/patients",
            framework="fastapi",
            line_number=25,
        )
        assert ep.http_method == "POST"
        assert ep.route == "/api/patients"
        assert ep.framework == "fastapi"

    def test_entry_point_info_defaults(self):
        ep = EntryPointInfo(
            method_name="handler", file_path="f.py", repo_name="r",
        )
        assert ep.http_method == ""
        assert ep.route == ""
        assert ep.framework == ""
        assert ep.line_number == 0

    def test_import_info(self):
        ii = ImportInfo(
            source_file="src/service.py",
            imported_module="src.repository",
            imported_names=["PatientRepo", "ClaimRepo"],
            line_number=3,
            is_relative=True,
        )
        assert ii.imported_module == "src.repository"
        assert len(ii.imported_names) == 2
        assert ii.is_relative is True

    def test_import_info_defaults(self):
        ii = ImportInfo(source_file="a.py", imported_module="os")
        assert ii.imported_names == []
        assert ii.line_number == 0
        assert ii.is_relative is False

    def test_repo_info(self):
        ri = RepoInfo(
            name="patient-api",
            url="https://github.com/org/patient-api",
            branch="main",
            commit_sha="abc123def456",
            language="python",
            file_count=85,
            total_lines=12000,
        )
        assert ri.name == "patient-api"
        assert ri.file_count == 85

    def test_repo_info_defaults(self):
        ri = RepoInfo(name="r")
        assert ri.url == ""
        assert ri.branch == "main"
        assert ri.commit_sha == ""
        assert ri.file_count == 0

    def test_project_info(self):
        pi = ProjectInfo(
            name="MedPay",
            tagline="Patient Insurance Payment Platform",
            domain="Healthcare",
            repos=[RepoInfo(name="api"), RepoInfo(name="engine")],
        )
        assert pi.name == "MedPay"
        assert len(pi.repos) == 2

    def test_project_info_defaults(self):
        pi = ProjectInfo(name="P")
        assert pi.tagline == ""
        assert pi.domain == "general"
        assert pi.repos == []


# ===========================================================================
# CallGraph models
# ===========================================================================

class TestEntryPointSummary:
    def test_valid(self):
        ep = EntryPointSummary(route="/api/users", repo="api", depth=3, cross_repo=True)
        assert ep.depth == 3
        assert ep.cross_repo is True

    def test_negative_depth_rejected(self):
        with pytest.raises(ValidationError, match="non-negative"):
            EntryPointSummary(route="/api", repo="api", depth=-1, cross_repo=False)

    def test_zero_depth_accepted(self):
        ep = EntryPointSummary(route="/", repo="r", depth=0, cross_repo=False)
        assert ep.depth == 0


class TestDeadCodeSummary:
    def test_valid(self):
        dc = DeadCodeSummary(count=15, total_lines=300, top_files=["a.py", "b.py"])
        assert dc.count == 15

    def test_negative_count_rejected(self):
        with pytest.raises(ValidationError, match="non-negative"):
            DeadCodeSummary(count=-1, total_lines=0, top_files=[])

    def test_negative_total_lines_rejected(self):
        with pytest.raises(ValidationError, match="non-negative"):
            DeadCodeSummary(count=0, total_lines=-10, top_files=[])


class TestCrossRepoEdge:
    def test_valid(self):
        edge = CrossRepoEdge(
            from_method="api::ClaimService.submit()",
            to_method="engine::PaymentController.charge()",
            via="POST /api/payments/charge",
        )
        assert "api" in edge.from_method
        assert "engine" in edge.to_method


class TestCallGraphSummary:
    def test_valid_summary(self):
        cgs = CallGraphSummary(
            entry_points=[EntryPointSummary(route="/api", repo="r", depth=2, cross_repo=False)],
            cross_repo_edges=[],
            circular_dependencies=["A -> B -> A"],
            dead_methods=DeadCodeSummary(count=5, total_lines=100, top_files=["dead.py"]),
            single_points_of_failure=["CriticalService.process()"],
        )
        assert len(cgs.entry_points) == 1
        assert cgs.dead_methods.count == 5

    def test_empty_summary(self):
        cgs = CallGraphSummary(
            entry_points=[],
            cross_repo_edges=[],
            circular_dependencies=[],
            dead_methods=DeadCodeSummary(count=0, total_lines=0, top_files=[]),
            single_points_of_failure=[],
        )
        assert cgs.entry_points == []


# ===========================================================================
# Remediation models
# ===========================================================================

class TestRemediationModels:
    def test_remediation_task(self):
        task = RemediationTask(
            task="Fix SQL injection", effort="3h",
            finding_id="BLK-001", score_impact="+4",
        )
        assert task.score_impact == "+4"

    def test_remediation_phase(self):
        phase = RemediationPhase(
            title="URGENT — Days 1-14",
            date_range="Days 1-14",
            items=[RemediationTask(
                task="Fix SQLi", effort="3h",
                finding_id="BLK-001", score_impact="+4",
            )],
            total_effort="20 hours",
            score_target="31 → 52 (+21 points)",
        )
        assert len(phase.items) == 1
        assert "31" in phase.score_target


# ===========================================================================
# InfraFinding + ExecutiveSummary
# ===========================================================================

class TestInfraFinding:
    def test_valid(self):
        f = InfraFinding(
            severity="high", title="Container runs as root",
            file="Dockerfile", detail="USER not set", fix="Add USER appuser",
        )
        assert f.severity == "high"

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            InfraFinding(
                severity="catastrophic", title="T",
                file="f", detail="d", fix="f",
            )


class TestExecutiveSummary:
    def test_valid(self):
        es = ExecutiveSummary(
            paragraphs=["Overall assessment.", "Key risks."],
            immediate_actions=["Fix BLK-001", "Rotate secrets"],
        )
        assert len(es.paragraphs) == 2
        assert len(es.immediate_actions) == 2


# ===========================================================================
# AuditReport (top-level, full integration)
# ===========================================================================

class TestAuditReport:
    def _make_report(self, **overrides) -> dict:
        base = dict(
            project_name="MedPay",
            project_tagline="Patient Insurance Payment Platform",
            domain="Healthcare",
            repos=[{"name": "api", "lang": "python", "files": 85, "lines": 12000}],
            scan_date="March 21, 2026",
            scan_duration="12 min 34 sec",
            total_files=847,
            total_lines="62k",
            total_methods=1245,
            cross_repo_edge_count=23,
            entry_point_count=47,
            max_call_depth=8,
            health_score=dict(
                overall=31, grade="F",
                categories=[dict(name="Security", score=25, finding_count=7)],
                severity_counts={"critical": 7, "high": 19, "medium": 28, "low": 31},
            ),
            executive_summary=dict(
                paragraphs=["P1", "P2"],
                immediate_actions=["Fix BLK-001"],
            ),
            findings=[_make_audit_finding()],
            infra_findings=[dict(
                severity="high", title="Root container",
                file="Dockerfile", detail="d", fix="f",
            )],
            compliance_matrix=[dict(framework="HIPAA", sections=[])],
            call_graph_summary=dict(
                entry_points=[], cross_repo_edges=[],
                circular_dependencies=[],
                dead_methods=dict(count=0, total_lines=0, top_files=[]),
                single_points_of_failure=[],
            ),
            remediation_phases=[dict(
                title="Phase 1", date_range="Days 1-14",
                items=[], total_effort="20h", score_target="31→52",
            )],
            scan_manifest=_make_scan_manifest(),
            llm_provider="anthropic",
            llm_model="claude-sonnet-4-20250514",
            active_frameworks=["HIPAA", "SOC2"],
        )
        base.update(overrides)
        return base

    def test_valid_report(self):
        report = AuditReport(**self._make_report())
        assert report.project_name == "MedPay"
        assert report.health_score.grade == "F"
        assert len(report.findings) == 1
        assert report.llm_provider == "anthropic"

    def test_report_serialization_roundtrip(self):
        original = AuditReport(**self._make_report())
        json_str = original.model_dump_json()
        restored = AuditReport.model_validate_json(json_str)
        assert original.project_name == restored.project_name
        assert original.health_score.overall == restored.health_score.overall
        assert len(original.findings) == len(restored.findings)

    def test_report_all_fields_present(self):
        """Verify every CLAUDE.md field exists on the model."""
        report = AuditReport(**self._make_report())
        # Cover page data
        assert hasattr(report, "project_name")
        assert hasattr(report, "project_tagline")
        assert hasattr(report, "domain")
        assert hasattr(report, "repos")
        assert hasattr(report, "scan_date")
        assert hasattr(report, "scan_duration")
        assert hasattr(report, "total_files")
        assert hasattr(report, "total_lines")
        assert hasattr(report, "total_methods")
        assert hasattr(report, "cross_repo_edge_count")
        assert hasattr(report, "entry_point_count")
        assert hasattr(report, "max_call_depth")
        # Scores + summary
        assert hasattr(report, "health_score")
        assert hasattr(report, "executive_summary")
        # Findings
        assert hasattr(report, "findings")
        assert hasattr(report, "infra_findings")
        # Compliance + call graph
        assert hasattr(report, "compliance_matrix")
        assert hasattr(report, "call_graph_summary")
        # Roadmap + metadata
        assert hasattr(report, "remediation_phases")
        assert hasattr(report, "scan_manifest")
        assert hasattr(report, "llm_provider")
        assert hasattr(report, "llm_model")
        assert hasattr(report, "active_frameworks")

    def test_report_missing_required_field_rejected(self):
        data = self._make_report()
        del data["project_name"]
        with pytest.raises(ValidationError):
            AuditReport(**data)
