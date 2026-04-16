"""Machine-readable JSON export for CI/CD dashboards.

Exports the full AuditReport as structured JSON, plus a simplified
summary format suitable for CI/CD pipeline consumption (pass/fail
gate, badge data, trend tracking).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class JSONExporter:
    """Export audit report as JSON — full and summary formats."""

    def export(self, report: dict, output_path: str | Path) -> Path:
        """Write the full report as formatted JSON."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("json_export.full", path=str(output_path))
        return output_path

    def export_summary(self, report: dict, output_path: str | Path) -> Path:
        """Write a CI/CD-friendly summary JSON.

        Contains only the data needed for pipeline gates, badges,
        and trend dashboards — no code snippets or AI explanations.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        summary = self._build_summary(report)
        output_path.write_text(
            json.dumps(summary, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("json_export.summary", path=str(output_path))
        return output_path

    def to_json(self, report: dict) -> str:
        """Return the full report as a JSON string."""
        return json.dumps(report, indent=2, default=str, ensure_ascii=False)

    def to_summary_json(self, report: dict) -> str:
        """Return the CI/CD summary as a JSON string."""
        return json.dumps(self._build_summary(report), indent=2, default=str)

    @staticmethod
    def _build_summary(report: dict) -> dict:
        """Build the simplified CI/CD summary."""
        hs = report.get("health_score", {})
        findings = report.get("findings", [])
        severity_counts = hs.get("severity_counts", {})

        # CI/CD pass/fail gate
        overall = hs.get("overall", 0)
        grade = hs.get("grade", "F")
        gate_passed = overall >= 50 and severity_counts.get("critical", 0) == 0

        # Finding IDs by severity (for quick reference)
        critical_ids = [f.get("id", "") for f in findings if f.get("severity") == "critical"]
        high_ids = [f.get("id", "") for f in findings if f.get("severity") == "high"]

        return {
            "schema_version": "1.0",
            "tool": "blanketaudit2",
            "project": report.get("project_name", ""),
            "scan_id": report.get("scan_manifest", {}).get("scan_id", ""),
            "scan_date": report.get("scan_date", ""),
            "gate": {
                "passed": gate_passed,
                "score": overall,
                "grade": grade,
                "threshold": 50,
                "reason": "Passed" if gate_passed else (
                    f"Critical findings: {len(critical_ids)}" if critical_ids
                    else f"Score {overall} below threshold 50"
                ),
            },
            "severity_counts": severity_counts,
            "finding_count": len(findings) + len(report.get("infra_findings", [])),
            "critical_finding_ids": critical_ids,
            "high_finding_ids": high_ids[:10],
            "categories": [
                {"name": c.get("name", ""), "score": c.get("score", 0)}
                for c in hs.get("categories", [])
            ],
            "frameworks": report.get("active_frameworks", []),
            "remediation_effort_hours": sum(
                float(t.get("effort", "0").rstrip("h") or 0)
                for phase in report.get("remediation_phases", [])
                for t in phase.get("items", [])
            ),
        }
