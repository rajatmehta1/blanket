"""Tests for JSON and SARIF exporters."""

from __future__ import annotations

import json

import pytest

from blanketaudit2.report.json_exporter import JSONExporter
from blanketaudit2.report.sarif_exporter import SARIFExporter


# ── Mock report ──────────────────────────────────────────────


def _mock_report() -> dict:
    return {
        "project_name": "MedPay",
        "scan_date": "March 21, 2026",
        "health_score": {
            "overall": 31,
            "grade": "F",
            "categories": [
                {"name": "Security", "score": 20, "finding_count": 3},
                {"name": "HIPAA Compliance", "score": 75, "finding_count": 1},
            ],
            "severity_counts": {"critical": 2, "high": 3, "medium": 5, "low": 4},
        },
        "findings": [
            {
                "id": "BLK-001",
                "policy_id": "SEC-001",
                "title": "SQL Injection via f-string",
                "description": "User input interpolated into SQL.",
                "severity": "critical",
                "category": "security",
                "confidence": 0.95,
                "source": "corroborated",
                "evidence": [{
                    "file_path": "src/db.py",
                    "repo_name": "api",
                    "line_start": 42,
                    "line_end": 42,
                    "code_snippet": 'f"SELECT * FROM patients WHERE id={uid}"',
                    "tool": "semgrep",
                }],
                "compliance_refs": [
                    {"framework": "HIPAA", "clause": "§164.312(a)(1)", "title": "Access Control"},
                    {"framework": "PCI-DSS", "clause": "Req 6.5.1", "title": "Injection"},
                ],
                "ai_explanation": "Confirmed SQL injection vulnerability.",
                "fix_code": 'cursor.execute("SELECT * FROM patients WHERE id=%s", (uid,))',
                "remediation": "Use parameterized queries.",
                "effort_hours": 2.0,
                "dollar_impact": "$50,000 — $1,900,000",
                "call_chain": [
                    {"method": "POST /api/patients/search", "step_type": "entry", "repo": "api"},
                    {"method": "PatientService.search()", "step_type": "method", "repo": "api"},
                    {"method": "db.execute()", "step_type": "sink", "repo": "api"},
                ],
            },
            {
                "id": "BLK-002",
                "policy_id": "SEC-014",
                "title": "Hardcoded Password",
                "description": "Password in source code.",
                "severity": "high",
                "category": "security",
                "confidence": 0.9,
                "source": "static",
                "evidence": [{
                    "file_path": "src/config.py",
                    "repo_name": "api",
                    "line_start": 5,
                    "line_end": 5,
                    "code_snippet": 'password = "SuperSecret123"',
                    "tool": "gitleaks",
                }],
                "compliance_refs": [],
                "ai_explanation": "",
                "fix_code": "",
                "remediation": "Use environment variables.",
                "effort_hours": 1.0,
                "dollar_impact": "$5,000 — $50,000",
                "call_chain": [],
            },
        ],
        "infra_findings": [
            {
                "severity": "high",
                "title": "Docker runs as root",
                "file": "Dockerfile",
                "detail": "No USER directive.",
                "fix": "Add USER appuser.",
            },
        ],
        "compliance_matrix": [],
        "remediation_phases": [
            {
                "title": "URGENT",
                "date_range": "Days 1-14",
                "items": [
                    {"task": "Fix SQLi", "effort": "2h", "finding_id": "BLK-001", "score_impact": "+4"},
                    {"task": "Rotate creds", "effort": "3h", "finding_id": "BLK-002", "score_impact": "+2"},
                ],
                "total_effort": "5 hours",
                "score_target": "31 → 45",
            },
        ],
        "active_frameworks": ["HIPAA", "SOC2"],
        "scan_manifest": {"scan_id": "scan-abc123"},
        "llm_provider": "anthropic",
        "llm_model": "claude-sonnet-4-20250514",
    }


# ═══════════════════════════════════════════════════════════════
# JSON Exporter
# ═══════════════════════════════════════════════════════════════


class TestJSONExporter:
    def test_export_to_file(self, tmp_path):
        exporter = JSONExporter()
        path = exporter.export(_mock_report(), tmp_path / "report.json")
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["project_name"] == "MedPay"
        assert len(data["findings"]) == 2

    def test_to_json_string(self):
        exporter = JSONExporter()
        result = exporter.to_json(_mock_report())
        data = json.loads(result)
        assert data["project_name"] == "MedPay"

    def test_full_report_roundtrip(self):
        report = _mock_report()
        exporter = JSONExporter()
        result = json.loads(exporter.to_json(report))
        assert result["health_score"]["overall"] == 31
        assert result["health_score"]["grade"] == "F"
        assert len(result["findings"]) == 2

    def test_export_summary(self, tmp_path):
        exporter = JSONExporter()
        path = exporter.export_summary(_mock_report(), tmp_path / "summary.json")
        assert path.exists()
        summary = json.loads(path.read_text(encoding="utf-8"))
        assert summary["tool"] == "blanketaudit2"
        assert summary["project"] == "MedPay"

    def test_summary_gate_fails_on_critical(self):
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(_mock_report()))
        assert summary["gate"]["passed"] is False
        assert "Critical" in summary["gate"]["reason"]

    def test_summary_gate_passes_when_clean(self):
        report = _mock_report()
        report["findings"] = []
        report["health_score"]["overall"] = 100
        report["health_score"]["grade"] = "A"
        report["health_score"]["severity_counts"] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(report))
        assert summary["gate"]["passed"] is True

    def test_summary_severity_counts(self):
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(_mock_report()))
        assert summary["severity_counts"]["critical"] == 2
        assert summary["severity_counts"]["high"] == 3

    def test_summary_critical_ids(self):
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(_mock_report()))
        assert "BLK-001" in summary["critical_finding_ids"]

    def test_summary_categories(self):
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(_mock_report()))
        cat_names = [c["name"] for c in summary["categories"]]
        assert "Security" in cat_names

    def test_summary_remediation_effort(self):
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(_mock_report()))
        assert summary["remediation_effort_hours"] == 5.0

    def test_summary_frameworks(self):
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(_mock_report()))
        assert summary["frameworks"] == ["HIPAA", "SOC2"]

    def test_summary_finding_count_includes_infra(self):
        exporter = JSONExporter()
        summary = json.loads(exporter.to_summary_json(_mock_report()))
        assert summary["finding_count"] == 3  # 2 findings + 1 infra


# ═══════════════════════════════════════════════════════════════
# SARIF Exporter
# ═══════════════════════════════════════════════════════════════


class TestSARIFExporter:
    def test_export_to_file(self, tmp_path):
        exporter = SARIFExporter()
        path = exporter.export(_mock_report(), tmp_path / "report.sarif")
        assert path.exists()
        sarif = json.loads(path.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"

    def test_sarif_structure(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        assert "$schema" in sarif
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert run["tool"]["driver"]["name"] == "BlanketAudit"

    def test_rules_created(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "SEC-001" in rule_ids
        assert "SEC-014" in rule_ids

    def test_results_created(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        results = sarif["runs"][0]["results"]
        # 2 findings + 1 infra finding
        assert len(results) == 3

    def test_result_has_location(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/db.py"
        assert loc["region"]["startLine"] == 42

    def test_result_has_code_snippet(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        result = sarif["runs"][0]["results"][0]
        snippet = result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        assert "SELECT" in snippet

    def test_severity_mapping(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        results = sarif["runs"][0]["results"]
        critical_result = next(r for r in results if r["ruleId"] == "SEC-001")
        assert critical_result["level"] == "error"

    def test_call_chain_as_code_flow(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        result = sarif["runs"][0]["results"][0]
        assert "codeFlows" in result
        flow = result["codeFlows"][0]["threadFlows"][0]["locations"]
        assert len(flow) == 3
        assert "entry" in flow[0]["location"]["message"]["text"]
        assert "sink" in flow[2]["location"]["message"]["text"]

    def test_compliance_refs_as_related(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        result = sarif["runs"][0]["results"][0]
        assert "relatedLocations" in result
        related_text = [r["message"]["text"] for r in result["relatedLocations"]]
        assert any("HIPAA" in t for t in related_text)
        assert any("PCI-DSS" in t for t in related_text)

    def test_infra_findings_included(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        results = sarif["runs"][0]["results"]
        infra_results = [r for r in results if "INFRA" in r.get("ruleId", "")]
        assert len(infra_results) == 1
        assert infra_results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "Dockerfile"

    def test_to_json_string(self):
        exporter = SARIFExporter()
        result = exporter.to_json(_mock_report())
        sarif = json.loads(result)
        assert sarif["version"] == "2.1.0"

    def test_rule_has_compliance_tags(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sqli_rule = next(r for r in rules if r["id"] == "SEC-001")
        tags = sqli_rule["properties"]["tags"]
        assert "HIPAA" in tags
        assert "PCI-DSS" in tags

    def test_empty_report(self):
        report = _mock_report()
        report["findings"] = []
        report["infra_findings"] = []
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(report)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_rank_field(self):
        exporter = SARIFExporter()
        sarif = exporter.to_sarif(_mock_report())
        critical = sarif["runs"][0]["results"][0]
        assert critical["rank"] == 9.0
        high = sarif["runs"][0]["results"][1]
        assert high["rank"] == 7.0
