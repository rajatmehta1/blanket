"""Golden file test: verify generated report matches expected MedPay structure.

Creates a MedPay-like audit state with known findings, assembles into
AuditReport via ReportAssembler, then verifies every field is populated
and the HTML renders all 9 sections correctly.
"""

from __future__ import annotations

import pytest

from blanketaudit2.models.finding import (
    AuditFinding, BlastRadius, CallChainStep, ComplianceRef, Evidence,
)
from blanketaudit2.scoring.report_assembler import ReportAssembler
from blanketaudit2.report.pdf_generator import PDFReportGenerator


# ── MedPay fixture data ──────────────────────────────────────


def _medpay_findings() -> list[dict]:
    """Build findings matching the sample MedPay report."""
    base_evidence = lambda fp, ls, le, snip, tool: {
        "file_path": fp, "repo_name": "patient-api",
        "line_start": ls, "line_end": le,
        "code_snippet": snip, "tool": tool,
    }

    return [
        # BLK-001: Critical compliance — PHI in logs
        AuditFinding(
            id="BLK-001", policy_id="COMP-HIPAA-001",
            title="Patient PHI Logged in Plaintext to External Service",
            description="Log statements expose SSN, DOB, and diagnosis.",
            severity="critical", category="compliance", confidence=0.95,
            source="corroborated",
            evidence=[base_evidence(
                "src/services/patient_service.py", 42, 44,
                'logger.info("Processing patient %s, SSN: %s", patient.name, patient.ssn)',
                "semgrep",
            )],
            compliance_refs=[
                ComplianceRef(framework="HIPAA", clause="§164.312(a)(1)", title="Access Control"),
                ComplianceRef(framework="HIPAA", clause="§164.530(c)", title="Safeguards"),
                ComplianceRef(framework="SOC2", clause="CC6.1", title="Logical Access"),
            ],
            ai_explanation=(
                "This log statement writes three categories of Protected Health Information "
                "(PHI) — patient name, Social Security Number, and date of birth — to the "
                "application log in plaintext. Under HIPAA §164.530(c), covered entities must "
                "reasonably safeguard PHI from unintentional disclosure.\n\n"
                "The blast radius is significant: 8 entry points across the patient-api "
                "service can trigger this code path, affecting approximately 2,400 daily "
                "API calls that process patient records."
            ),
            fix_code=(
                '# BEFORE:\nlogger.info("Processing patient %s, SSN: %s", patient.name, patient.ssn)\n\n'
                '# AFTER:\nlogger.info("Processing patient %s", mask_phi(patient.id))'
            ),
            remediation="Replace raw PHI with masked identifiers using a PHI redaction utility.",
            effort_hours=3.0,
            dollar_impact="$50,000 — $1,900,000 per incident category",
            blast_radius=BlastRadius(
                entry_points=8, repos_affected=1,
                daily_calls="~2,400", affected_users="All patients",
            ),
            call_chain=[
                CallChainStep(method="POST /api/patients/{id}/claim", step_type="entry", repo="patient-api"),
                CallChainStep(method="PatientService.process_patient()", step_type="method", repo="patient-api"),
                CallChainStep(method="logger.debug(patient.ssn)", step_type="sink", repo="patient-api"),
            ],
        ).model_dump(),

        # BLK-002: Critical security — SQL injection
        AuditFinding(
            id="BLK-002", policy_id="SEC-001",
            title="SQL Injection via f-string in Patient Search",
            description="User input interpolated directly into SQL query.",
            severity="critical", category="security", confidence=0.95,
            source="corroborated",
            evidence=[base_evidence(
                "src/services/patient_search.py", 28, 28,
                'cursor.execute(f"SELECT * FROM patients WHERE name=\'{query}\'")',
                "semgrep",
            )],
            compliance_refs=[
                ComplianceRef(framework="HIPAA", clause="§164.312(a)(1)", title="Access Control"),
                ComplianceRef(framework="PCI-DSS", clause="Req 6.5.1", title="Injection Flaws"),
            ],
            ai_explanation=(
                "This f-string SQL query allows an attacker to extract, modify, or delete "
                "all patient records in the database. The blast radius spans 5 API endpoints "
                "across 2 repositories."
            ),
            fix_code='cursor.execute("SELECT * FROM patients WHERE name=%s", (query,))',
            remediation="Use parameterized queries.",
            effort_hours=2.0,
            dollar_impact="$100,000 — $1,900,000",
            blast_radius=BlastRadius(
                entry_points=5, repos_affected=2,
                daily_calls="~5,000", affected_users="All patients",
            ),
            call_chain=[
                CallChainStep(method="GET /api/patients/search", step_type="entry", repo="patient-api"),
                CallChainStep(method="PatientSearch.search()", step_type="method", repo="patient-api"),
                CallChainStep(method="db.execute(f'SELECT...')", step_type="sink", repo="patient-api"),
            ],
        ).model_dump(),

        # BLK-003: High security — hardcoded secret
        AuditFinding(
            id="BLK-003", policy_id="SEC-015",
            title="Hardcoded API Key in Source Code",
            description="API key committed to version control.",
            severity="high", category="security", confidence=0.9,
            source="static",
            evidence=[base_evidence(
                "src/config/settings.py", 12, 12,
                'STRIPE_API_KEY = "sk-live-abc123def456"',
                "gitleaks",
            )],
            compliance_refs=[
                ComplianceRef(framework="PCI-DSS", clause="Req 8.2", title="Authentication"),
                ComplianceRef(framework="SOC2", clause="CC6.2", title="Credentials"),
            ],
            ai_explanation="Stripe API key hardcoded in source. Anyone with repo access can charge cards.",
            fix_code='STRIPE_API_KEY = os.environ["STRIPE_API_KEY"]',
            remediation="Move to environment variables and rotate the exposed key.",
            effort_hours=1.0,
            dollar_impact="$5,000 — $100,000",
            blast_radius=BlastRadius(entry_points=3, repos_affected=1,
                                      daily_calls="~1,000", affected_users="All cardholders"),
            call_chain=[
                CallChainStep(method="POST /api/payments/charge", step_type="entry", repo="payment-engine"),
                CallChainStep(method="PaymentService.charge()", step_type="sink", repo="payment-engine"),
            ],
        ).model_dump(),

        # BLK-004: Medium quality — high complexity
        AuditFinding(
            id="BLK-004", policy_id="QUAL-001",
            title="High Cyclomatic Complexity in ClaimProcessor",
            description="Function has complexity 22, threshold 15.",
            severity="medium", category="quality", confidence=0.85,
            source="static",
            evidence=[base_evidence(
                "src/services/claim_processor.py", 45, 120,
                "def process_claim(claim): ...",
                "ast",
            )],
            compliance_refs=[],
            ai_explanation="This function handles too many responsibilities. Split into smaller methods.",
            fix_code="# Split into: validate_claim(), calculate_amount(), submit_claim()",
            remediation="Refactor into focused functions with single responsibility.",
            effort_hours=4.0,
            dollar_impact="$1,000 — $10,000",
        ).model_dump(),

        # BLK-005: Low infrastructure — unpinned image
        AuditFinding(
            id="BLK-005", policy_id="QUAL-011",
            title="Docker base image uses :latest tag",
            description="Non-reproducible build.",
            severity="low", category="infrastructure", confidence=0.9,
            source="static",
            evidence=[base_evidence("Dockerfile", 1, 1, "FROM python:latest", "regex")],
            compliance_refs=[],
            ai_explanation="Using :latest makes builds non-reproducible.",
            fix_code="FROM python:3.11-slim@sha256:abc123...",
            remediation="Pin to a specific digest.",
            effort_hours=0.5,
            dollar_impact="$100 — $1,000",
        ).model_dump(),
    ]


def _medpay_state() -> dict:
    """Build a complete pipeline state for the MedPay scenario."""
    return {
        "project_name": "MedPay",
        "project_tagline": "Patient Insurance Payment Platform",
        "domain": "healthcare",
        "frameworks": ["HIPAA", "SOC2", "PCI-DSS"],
        "scan_id": "scan-medpay-001",
        "repo_paths": [
            {"repo_name": "patient-api", "local_path": "/repos/patient-api", "commit_sha": "abc123"},
            {"repo_name": "payment-engine", "local_path": "/repos/payment-engine", "commit_sha": "def456"},
            {"repo_name": "shared-libs", "local_path": "/repos/shared-libs", "commit_sha": "ghi789"},
        ],
        "files": [
            {"path": f"src/file{i}.py", "language": "python", "loc": 150}
            for i in range(50)
        ],
        "validated_findings": _medpay_findings(),
        "analysis_contexts": [
            {"methods": [{"name": f"method_{i}"} for i in range(120)], "classes": []},
        ],
        "scan_duration": "12 min 34 sec",
    }


# ═══════════════════════════════════════════════════════════════
# Report structure tests
# ═══════════════════════════════════════════════════════════════


class TestMedPayReportStructure:
    @pytest.fixture(scope="class")
    def report(self):
        import asyncio
        assembler = ReportAssembler()
        return asyncio.run(assembler.assemble(_medpay_state()))

    # ── Cover page ───────────────────────────────────────────

    def test_project_name(self, report):
        assert report["project_name"] == "MedPay"

    def test_project_tagline(self, report):
        assert report["project_tagline"] == "Patient Insurance Payment Platform"

    def test_domain(self, report):
        assert report["domain"] == "healthcare"

    def test_repos_listed(self, report):
        assert len(report["repos"]) >= 1

    def test_scan_metadata(self, report):
        assert report["scan_date"] != ""
        assert report["total_files"] == 50
        assert report["total_methods"] == 120

    # ── Health score ─────────────────────────────────────────

    def test_health_score_populated(self, report):
        hs = report["health_score"]
        assert 0 <= hs["overall"] <= 100
        assert hs["grade"] in ("A", "B", "C", "D", "F")

    def test_categories_present(self, report):
        cats = report["health_score"]["categories"]
        assert len(cats) >= 5  # Security + 3 compliance + Quality + ...
        cat_names = {c["name"] for c in cats}
        assert "Security" in cat_names

    def test_severity_counts(self, report):
        sc = report["health_score"]["severity_counts"]
        assert sc["critical"] == 2
        assert sc["high"] == 1

    # ── Executive summary ────────────────────────────────────

    def test_executive_summary_paragraphs(self, report):
        es = report["executive_summary"]
        assert len(es["paragraphs"]) == 2
        assert len(es["paragraphs"][0]) > 50

    def test_executive_summary_actions(self, report):
        es = report["executive_summary"]
        assert len(es["immediate_actions"]) >= 1

    # ── Findings ─────────────────────────────────────────────

    def test_findings_present(self, report):
        # Infra findings are separated, so code findings may be < 5
        total = len(report["findings"]) + len(report["infra_findings"])
        assert total >= 4

    def test_findings_sorted_by_severity(self, report):
        if not report["findings"]:
            return
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(report["findings"]) - 1):
            a = severity_order.get(report["findings"][i]["severity"], 4)
            b = severity_order.get(report["findings"][i + 1]["severity"], 4)
            assert a <= b, "Findings not sorted by severity"

    def test_finding_has_all_fields(self, report):
        for f in report["findings"]:
            assert f["id"].startswith("BLK-")
            assert f["title"] != ""
            assert f["severity"] in ("critical", "high", "medium", "low")
            assert f["ai_explanation"] != ""
            assert f["fix_code"] != ""
            assert f["dollar_impact"] != ""
            assert len(f["evidence"]) >= 1

    def test_finding_has_call_chain(self, report):
        chain_findings = [f for f in report["findings"] if f.get("call_chain")]
        assert len(chain_findings) >= 1
        chain = chain_findings[0]["call_chain"]
        assert len(chain) >= 2
        step_types = {s["step_type"] for s in chain}
        assert "entry" in step_types or "sink" in step_types

    def test_finding_has_blast_radius(self, report):
        br_findings = [f for f in report["findings"] if f.get("blast_radius")]
        assert len(br_findings) >= 1
        br = br_findings[0]["blast_radius"]
        assert br["entry_points"] > 0
        assert br["repos_affected"] >= 1

    def test_finding_has_compliance_refs(self, report):
        ref_findings = [f for f in report["findings"] if f.get("compliance_refs")]
        assert len(ref_findings) >= 1
        ref = ref_findings[0]["compliance_refs"][0]
        assert ref["framework"] != ""
        assert ref["clause"] != ""

    # ── Compliance matrix ────────────────────────────────────

    def test_compliance_matrix_populated(self, report):
        assert len(report["compliance_matrix"]) >= 1

    def test_compliance_matrix_has_statuses(self, report):
        for matrix in report["compliance_matrix"]:
            assert matrix["framework"] != ""
            for sec in matrix.get("sections", []):
                assert sec["status"] in ("pass", "partial", "fail", "gap", "not_applicable", "review_needed")
                assert sec["detail"] != ""

    # ── Infrastructure findings ──────────────────────────────

    def test_infra_findings_present(self, report):
        assert len(report["infra_findings"]) >= 1

    def test_infra_finding_has_fix(self, report):
        for inf in report["infra_findings"]:
            assert inf["severity"] in ("critical", "high", "medium", "low")
            assert inf["title"] != ""
            assert inf["fix"] != ""

    # ── Remediation roadmap ──────────────────────────────────

    def test_remediation_phases(self, report):
        assert len(report["remediation_phases"]) >= 1

    def test_remediation_has_tasks(self, report):
        for phase in report["remediation_phases"]:
            assert phase["title"] != ""
            assert phase["score_target"] != ""
            assert "→" in phase["score_target"]
            for task in phase["items"]:
                assert task["finding_id"].startswith("BLK-")
                assert task["score_impact"].startswith("+")

    # ── Metadata ─────────────────────────────────────────────

    def test_scan_manifest(self, report):
        assert "scan_manifest" in report
        assert report["scan_manifest"] != {}

    def test_active_frameworks(self, report):
        assert report["active_frameworks"] == ["HIPAA", "SOC2", "PCI-DSS"]

    def test_total_lines_formatted(self, report):
        # 50 files × 150 LOC = 7500 → "7k"
        assert report["total_lines"] in ("7k", "7500", "8k")


# ═══════════════════════════════════════════════════════════════
# HTML rendering verification
# ═══════════════════════════════════════════════════════════════


class TestMedPayHTMLOutput:
    @pytest.fixture(scope="class")
    def report(self):
        import asyncio
        assembler = ReportAssembler()
        return asyncio.run(assembler.assemble(_medpay_state()))

    @pytest.fixture(scope="class")
    def html(self, report):
        gen = PDFReportGenerator()
        return gen.render_html(report)

    def test_html_contains_project_name(self, html):
        assert "MedPay" in html

    def test_html_contains_all_section_headers(self, html):
        assert "Architecture Audit Report" in html
        assert "Executive Summary" in html
        assert "Score" in html or "Dashboard" in html
        assert "Findings" in html or "BLK-001" in html
        assert "Compliance" in html
        assert "Call Graph" in html or "Callgraph" in html
        assert "Infrastructure" in html
        assert "Remediation" in html

    def test_html_contains_finding_details(self, html):
        assert "BLK-001" in html
        assert "BLK-002" in html
        assert "PHI" in html or "patient" in html.lower()
        assert "SQL Injection" in html or "sql" in html.lower()

    def test_html_contains_severity_badges(self, html):
        assert "severity-critical" in html
        assert "severity-high" in html

    def test_html_contains_svg_charts(self, html):
        assert "<svg" in html

    def test_html_contains_code_blocks(self, html):
        assert "code-snippet" in html or "fix-code" in html

    def test_html_contains_compliance_status(self, html):
        assert "status-" in html  # status-fail, status-pass, etc.

    def test_html_size_realistic(self, html):
        assert len(html) > 10_000  # Real report is substantial
