"""Tests for PDF/HTML report generation — SVG charts, syntax highlighting, templates, generators."""

from __future__ import annotations

from pathlib import Path

import pytest

from blanketaudit2.report.svg_charts import SVGChartRenderer
from blanketaudit2.report.syntax_highlighter import SyntaxHighlighter
from blanketaudit2.report.pdf_generator import PDFReportGenerator
from blanketaudit2.report.html_generator import HTMLGenerator


# ── Mock AuditReport dict ────────────────────────────────────


def _mock_report() -> dict:
    """Build a realistic AuditReport dict with all required fields."""
    return {
        "project_name": "MedPay",
        "project_tagline": "Patient Insurance Payment Platform",
        "domain": "Healthcare",
        "repos": [
            {"name": "patient-api", "lang": "python", "files": 85, "lines": 12000},
            {"name": "payment-engine", "lang": "java", "files": 62, "lines": 9400},
        ],
        "scan_date": "March 21, 2026",
        "scan_duration": "12 min 34 sec",
        "total_files": 847,
        "total_lines": "62k",
        "total_methods": 1245,
        "cross_repo_edge_count": 23,
        "entry_point_count": 47,
        "max_call_depth": 8,
        "health_score": {
            "overall": 31,
            "grade": "F",
            "categories": [
                {"name": "Security", "score": 20, "finding_count": 7},
                {"name": "HIPAA Compliance", "score": 45, "finding_count": 5},
                {"name": "SOC2 Compliance", "score": 60, "finding_count": 3},
                {"name": "Code Quality", "score": 72, "finding_count": 4},
                {"name": "Performance", "score": 85, "finding_count": 1},
                {"name": "Reliability", "score": 90, "finding_count": 0},
                {"name": "Infrastructure", "score": 55, "finding_count": 3},
            ],
            "severity_counts": {"critical": 7, "high": 19, "medium": 28, "low": 31},
        },
        "executive_summary": {
            "paragraphs": [
                "The MedPay platform scored 31/100 (Grade F), with 7 critical findings "
                "requiring immediate attention. The most severe issues are SQL injection "
                "vulnerabilities in the patient search API.",
                "Key risk areas include Security (20/100) and HIPAA Compliance (45/100). "
                "The payment-engine service has 3 cross-repo dependencies that amplify "
                "the blast radius of authentication vulnerabilities.",
            ],
            "immediate_actions": [
                "Fix BLK-001: SQL Injection in patient search (critical)",
                "Fix BLK-003: PHI logged in plaintext (critical)",
                "Rotate all hardcoded credentials found by Gitleaks",
                "Enable TLS for internal service communication",
            ],
        },
        "findings": [
            {
                "id": "BLK-001",
                "policy_id": "SEC-001",
                "title": "SQL Injection via f-string in Patient Search",
                "description": "User input interpolated into SQL query.",
                "severity": "critical",
                "category": "security",
                "confidence": 0.95,
                "source": "corroborated",
                "evidence": [{
                    "file_path": "src/services/patient_search.py",
                    "repo_name": "patient-api",
                    "line_start": 42,
                    "line_end": 42,
                    "code_snippet": 'cursor.execute(f"SELECT * FROM patients WHERE name=\'{query}\'")',
                    "tool": "semgrep",
                }],
                "compliance_refs": [
                    {"framework": "HIPAA", "clause": "§164.312(a)(1)", "title": "Access Control"},
                    {"framework": "PCI-DSS", "clause": "Req 6.5.1", "title": "Injection Flaws"},
                ],
                "ai_explanation": "This SQL injection allows an attacker to extract all patient records.",
                "fix_code": 'cursor.execute("SELECT * FROM patients WHERE name=%s", (query,))',
                "remediation": "Use parameterized queries.",
                "effort_hours": 2.0,
                "dollar_impact": "$50,000 — $1,900,000",
                "blast_radius": {
                    "entry_points": 5,
                    "repos_affected": 2,
                    "daily_calls": "~2,400",
                    "affected_users": "All patients",
                },
                "call_chain": [
                    {"method": "POST /api/patients/search", "step_type": "entry", "repo": "patient-api"},
                    {"method": "PatientService.search()", "step_type": "method", "repo": "patient-api"},
                    {"method": "db.execute()", "step_type": "sink", "repo": "patient-api"},
                ],
            },
        ],
        "infra_findings": [
            {
                "severity": "high",
                "title": "Docker container runs as root",
                "file": "Dockerfile",
                "detail": "No USER directive — container runs as root by default.",
                "fix": "Add USER appuser after installing dependencies.",
            },
        ],
        "compliance_matrix": [
            {
                "framework": "HIPAA",
                "sections": [
                    {
                        "control_id": "HIPAA-164.312-a-1",
                        "framework": "HIPAA",
                        "clause": "§164.312(a)(1)",
                        "title": "Access Control",
                        "status": "fail",
                        "finding_count": 3,
                        "detail": "3 findings: 2 critical, 1 high.",
                    },
                    {
                        "control_id": "HIPAA-164.312-e-1",
                        "framework": "HIPAA",
                        "clause": "§164.312(e)(1)",
                        "title": "Transmission Security",
                        "status": "partial",
                        "finding_count": 1,
                        "detail": "1 finding: 1 medium.",
                    },
                ],
            },
        ],
        "call_graph_summary": {
            "entry_points": [
                {"route": "POST /api/patients/search", "repo": "patient-api", "depth": 4, "cross_repo": False},
                {"route": "POST /api/payments/charge", "repo": "payment-engine", "depth": 6, "cross_repo": True},
            ],
            "cross_repo_edges": [
                {"from_method": "patient-api::ClaimService.submit()", "to_method": "payment-engine::PaymentController.charge()", "via": "POST /api/payments/charge"},
            ],
            "circular_dependencies": ["patient-api::models → patient-api::services → patient-api::models"],
            "dead_methods": {"count": 15, "total_lines": 342, "top_files": ["patient-api/src/legacy.py"]},
            "single_points_of_failure": ["patient-api::AuthMiddleware.verify()"],
        },
        "remediation_phases": [
            {
                "title": "URGENT — Days 1-14",
                "date_range": "Days 1-14",
                "items": [
                    {"task": "Fix SQL injection in patient search", "effort": "2h", "finding_id": "BLK-001", "score_impact": "+4"},
                    {"task": "Mask PHI in all log statements", "effort": "3h", "finding_id": "BLK-003", "score_impact": "+3"},
                ],
                "total_effort": "20 hours",
                "score_target": "31 → 52 (+21 points)",
            },
        ],
        "scan_manifest": {
            "scan_id": "scan-abc123",
            "timestamp": "2026-03-21T10:00:00Z",
            "policy_versions": {},
            "prompt_versions": {},
            "model_ids": {"compliance": "claude-opus-4-20250514"},
            "tool_versions": {"semgrep": "1.60.0"},
            "repo_commits": {"patient-api": "abc123"},
            "config_hash": "a" * 64,
        },
        "llm_provider": "anthropic",
        "llm_model": "claude-sonnet-4-20250514",
        "active_frameworks": ["HIPAA", "SOC2"],
    }


# ═══════════════════════════════════════════════════════════════
# SVG Charts
# ═══════════════════════════════════════════════════════════════


class TestSVGChartRenderer:
    def test_score_gauge_contains_svg(self):
        svg = SVGChartRenderer()
        result = svg.score_gauge(75, 200)
        assert "<svg" in result
        assert "75" in result
        assert "Grade" in result

    def test_score_gauge_colors_by_grade(self):
        svg = SVGChartRenderer()
        a_gauge = svg.score_gauge(90)
        f_gauge = svg.score_gauge(20)
        assert "#34d399" in a_gauge  # Green for A
        assert "#ef4444" in f_gauge  # Red for F

    def test_category_bars_contains_svg(self):
        svg = SVGChartRenderer()
        cats = [
            {"name": "Security", "score": 20, "finding_count": 7},
            {"name": "Quality", "score": 85, "finding_count": 2},
        ]
        result = svg.category_bars(cats)
        assert "<svg" in result
        assert "Security" in result
        assert "Quality" in result

    def test_severity_badges(self):
        svg = SVGChartRenderer()
        result = svg.severity_badges({"critical": 3, "high": 5, "medium": 10, "low": 2})
        assert "<svg" in result
        assert "3 critical" in result
        assert "5 high" in result

    def test_severity_badges_skips_zero(self):
        svg = SVGChartRenderer()
        result = svg.severity_badges({"critical": 0, "high": 2, "medium": 0, "low": 0})
        assert "critical" not in result
        assert "2 high" in result

    def test_gauge_with_label(self):
        svg = SVGChartRenderer()
        result = svg.score_gauge(50, 150, label="Overall")
        assert "Overall" in result


# ═══════════════════════════════════════════════════════════════
# Syntax Highlighter
# ═══════════════════════════════════════════════════════════════


class TestSyntaxHighlighter:
    def test_highlight_returns_html(self):
        hl = SyntaxHighlighter()
        result = hl.highlight('print("hello")', "python")
        assert "<pre" in result
        assert "code-snippet" in result

    def test_highlight_empty_code(self):
        hl = SyntaxHighlighter()
        assert hl.highlight("") == ""

    def test_highlight_fix_returns_html(self):
        hl = SyntaxHighlighter()
        result = hl.highlight_fix('cursor.execute(q, params)', "python")
        assert "<pre" in result
        assert "fix-code" in result

    def test_highlight_fix_empty(self):
        hl = SyntaxHighlighter()
        assert hl.highlight_fix("") == ""

    def test_escapes_html(self):
        hl = SyntaxHighlighter()
        result = hl.highlight('<script>alert("xss")</script>')
        assert "<script>" not in result  # Should be escaped

    # ── Multi-language tests ─────────────────────────────────

    def test_highlight_python(self):
        hl = SyntaxHighlighter()
        code = '''
def search_patients(query: str) -> list:
    cursor.execute(f"SELECT * FROM patients WHERE name='{query}'")
    return cursor.fetchall()
'''
        result = hl.highlight(code, "python")
        assert "<pre" in result
        assert "code-snippet" in result
        # Should have inline styles from Pygments
        assert "style=" in result or "color:" in result

    def test_highlight_java(self):
        hl = SyntaxHighlighter()
        code = '''
@GetMapping("/users/{id}")
public User getUser(@PathVariable Long id) {
    return userService.findById(id);
}
'''
        result = hl.highlight(code, "java")
        assert "<pre" in result

    def test_highlight_typescript(self):
        hl = SyntaxHighlighter()
        code = '''
app.get('/api/users/:id', async (req: Request, res: Response) => {
    const user = await db.findUser(req.params.id);
    res.json(user);
});
'''
        result = hl.highlight(code, "typescript")
        assert "<pre" in result

    def test_highlight_sql(self):
        hl = SyntaxHighlighter()
        code = "SELECT * FROM patients WHERE ssn = '123-45-6789'"
        result = hl.highlight(code, "sql")
        assert "<pre" in result

    def test_highlight_auto_detect(self):
        hl = SyntaxHighlighter()
        code = 'import os\nprint(os.getcwd())'
        result = hl.highlight(code)  # No language specified
        assert "<pre" in result

    def test_highlight_unknown_language_fallback(self):
        hl = SyntaxHighlighter()
        result = hl.highlight("some code", "nonexistent_language_xyz")
        assert "<pre" in result  # Should not crash

    def test_inline_styles_present(self):
        hl = SyntaxHighlighter()
        result = hl.highlight('x = 1', "python")
        assert "style=" in result  # prestyles should be in the pre tag

    # ── highlight_finding ────────────────────────────────────

    def test_highlight_finding_with_model(self):
        from blanketaudit2.models.finding import AuditFinding, Evidence
        finding = AuditFinding(
            id="BLK-001", policy_id="SEC-001",
            title="SQLi", description="d", severity="critical",
            category="security", confidence=0.9, source="static",
            evidence=[Evidence(
                file_path="src/db.py", repo_name="api",
                line_start=10, line_end=12,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
                tool="semgrep",
            )],
            compliance_refs=[], ai_explanation="", remediation="",
            fix_code='cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))',
            effort_hours=2.0, dollar_impact="",
        )
        hl = SyntaxHighlighter()
        code_html, fix_html = hl.highlight_finding(finding)
        assert "code-snippet" in code_html
        assert "fix-code" in fix_html

    def test_highlight_finding_with_dict(self):
        hl = SyntaxHighlighter()
        finding = {
            "evidence": [{"file_path": "main.py", "code_snippet": "print('hi')"}],
            "fix_code": "print('hello')",
        }
        code_html, fix_html = hl.highlight_finding(finding)
        assert "<pre" in code_html
        assert "<pre" in fix_html

    def test_highlight_finding_no_fix(self):
        hl = SyntaxHighlighter()
        finding = {
            "evidence": [{"file_path": "app.ts", "code_snippet": "fetch(url)"}],
            "fix_code": "",
        }
        code_html, fix_html = hl.highlight_finding(finding)
        assert "<pre" in code_html
        assert fix_html == ""

    def test_highlight_finding_no_evidence(self):
        hl = SyntaxHighlighter()
        finding = {"evidence": [], "fix_code": ""}
        code_html, fix_html = hl.highlight_finding(finding)
        assert code_html == ""
        assert fix_html == ""


# ═══════════════════════════════════════════════════════════════
# SVG XML validity
# ═══════════════════════════════════════════════════════════════


class TestSVGXMLValidity:
    """Verify all SVG output parses as valid XML."""

    def _parse_svg(self, svg_str: str) -> None:
        import xml.etree.ElementTree as ET
        ET.fromstring(svg_str)

    def test_score_gauge_valid_xml(self):
        svg = SVGChartRenderer()
        for score in (0, 25, 50, 75, 100):
            self._parse_svg(svg.score_gauge(score))

    def test_score_gauge_with_label_valid_xml(self):
        svg = SVGChartRenderer()
        self._parse_svg(svg.score_gauge(42, 150, "Overall"))

    def test_category_bars_valid_xml(self):
        svg = SVGChartRenderer()
        cats = [
            {"name": "Security", "score": 20, "finding_count": 7},
            {"name": "HIPAA Compliance", "score": 45, "finding_count": 5},
            {"name": "Code Quality", "score": 85, "finding_count": 2},
        ]
        self._parse_svg(svg.category_bars(cats))

    def test_severity_badges_valid_xml(self):
        svg = SVGChartRenderer()
        self._parse_svg(svg.severity_badges({"critical": 3, "high": 5, "medium": 10, "low": 2}))

    def test_severity_badges_single_valid_xml(self):
        svg = SVGChartRenderer()
        self._parse_svg(svg.severity_badges({"critical": 1, "high": 0, "medium": 0, "low": 0}))

    def test_gauge_boundary_scores(self):
        svg = SVGChartRenderer()
        for score in (0, 1, 29, 30, 49, 50, 69, 70, 84, 85, 99, 100):
            result = svg.score_gauge(score)
            self._parse_svg(result)
            assert str(score) in result

    def test_empty_categories_valid_xml(self):
        svg = SVGChartRenderer()
        self._parse_svg(svg.category_bars([]))


# ═══════════════════════════════════════════════════════════════
# HTML rendering (no WeasyPrint needed)
# ═══════════════════════════════════════════════════════════════


class TestHTMLRendering:
    def test_render_html_produces_valid_html(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert "<!DOCTYPE html>" in html
        assert "MedPay" in html
        assert "</html>" in html

    def test_html_contains_all_sections(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        # Cover page
        assert "Architecture Audit Report" in html
        assert "MedPay" in html
        # Executive summary
        assert "31/100" in html
        # Score dashboard
        assert "Security" in html
        # Findings
        assert "BLK-001" in html
        assert "SQL Injection" in html
        # Compliance matrix
        assert "§164.312(a)(1)" in html
        # Call graph
        assert "POST /api/patients/search" in html
        # Infrastructure
        assert "Docker" in html
        # Remediation
        assert "URGENT" in html
        assert "Days 1-14" in html

    def test_html_contains_severity_badges(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert "severity-critical" in html

    def test_html_contains_code_snippets(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert "code-snippet" in html or "SELECT" in html

    def test_html_contains_fix_code(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert "fix-code" in html or "parameterized" in html.lower()

    def test_html_contains_svg_charts(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert "<svg" in html  # Score gauge at minimum

    def test_html_contains_compliance_status(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert "status-fail" in html or "fail" in html.lower()

    def test_html_over_minimum_size(self):
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert len(html) > 5000  # Realistic report is at least 5KB

    def test_html_generator_to_file(self, tmp_path):
        gen = HTMLGenerator()
        path = gen.generate_to_file(_mock_report(), tmp_path / "report.html")
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "MedPay" in content
        assert len(content) > 5000


# ═══════════════════════════════════════════════════════════════
# Interactive HTML report
# ═══════════════════════════════════════════════════════════════


class TestInteractiveHTML:
    def test_has_javascript(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert "<script>" in html
        assert "addEventListener" in html

    def test_has_search_bar(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert "finding-search" in html
        assert "search-bar" in html

    def test_has_filter_buttons(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert "filter-btn" in html
        assert "data-severity" in html

    def test_has_navigation_bar(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert "nav-bar" in html
        assert "#findings" in html
        assert "#compliance" in html

    def test_findings_have_data_severity(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert 'data-severity="critical"' in html

    def test_findings_have_collapse_header(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert "finding-header" in html
        assert "finding-body" in html
        assert "toggle-icon" in html

    def test_tables_are_sortable(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert 'class="sortable"' in html

    def test_has_screen_css(self):
        gen = HTMLGenerator()
        html = gen.generate(_mock_report())
        assert 'media="screen"' in html
        assert "max-width: 900px" in html

    def test_interactive_to_file(self, tmp_path):
        gen = HTMLGenerator()
        path = gen.generate_to_file(_mock_report(), tmp_path / "interactive.html")
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "<script>" in content
        assert "MedPay" in content

    def test_larger_than_static(self):
        """Interactive HTML should be larger than static due to JS/CSS."""
        static_gen = PDFReportGenerator()
        interactive_gen = HTMLGenerator()
        static = static_gen.render_html(_mock_report())
        interactive = interactive_gen.generate(_mock_report())
        assert len(interactive) > len(static)


class TestHTMLWithEmptyReport:
    def test_empty_findings(self):
        report = _mock_report()
        report["findings"] = []
        report["infra_findings"] = []
        report["compliance_matrix"] = []
        report["remediation_phases"] = []
        gen = PDFReportGenerator()
        html = gen.render_html(report)
        assert "<!DOCTYPE html>" in html
        assert "MedPay" in html


# ═══════════════════════════════════════════════════════════════
# PDF generation (requires WeasyPrint)
# ═══════════════════════════════════════════════════════════════


class TestPDFGeneration:
    @staticmethod
    def _weasyprint_available() -> bool:
        try:
            import weasyprint
            weasyprint.HTML(string="<p>test</p>").write_pdf()
            return True
        except Exception:
            return False

    def test_pdf_generation(self, tmp_path):
        """Generate PDF from mock report — verify it's valid and >50KB."""
        if not self._weasyprint_available():
            pytest.skip("WeasyPrint not available (missing system libs)")

        gen = PDFReportGenerator()
        pdf_bytes = gen.generate(_mock_report())
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes[:5] == b"%PDF-"
        assert len(pdf_bytes) > 50_000

    def test_pdf_to_file(self, tmp_path):
        if not self._weasyprint_available():
            pytest.skip("WeasyPrint not available (missing system libs)")

        gen = PDFReportGenerator()
        path = gen.generate_to_file(_mock_report(), tmp_path / "report.pdf")
        assert path.exists()
        assert path.stat().st_size > 50_000

    def test_render_html_always_works(self):
        """render_html works even without WeasyPrint system libs."""
        gen = PDFReportGenerator()
        html = gen.render_html(_mock_report())
        assert len(html) > 1000
        assert "MedPay" in html
