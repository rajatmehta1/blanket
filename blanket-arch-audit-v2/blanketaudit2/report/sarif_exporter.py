"""SARIF v2.1.0 export for IDE and GitHub Code Scanning integration.

Produces a SARIF log that can be:
- Uploaded to GitHub via ``gh api`` or ``actions/upload-sarif``
- Opened in VS Code with the SARIF Viewer extension
- Consumed by any SARIF-compatible tool

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

_SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SEVERITY_TO_SARIF_RANK: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
}


class SARIFExporter:
    """Export audit findings as SARIF v2.1.0."""

    def export(self, report: dict, output_path: str | Path) -> Path:
        """Write SARIF log to a file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        sarif = self.to_sarif(report)
        output_path.write_text(
            json.dumps(sarif, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("sarif_export.done", path=str(output_path))
        return output_path

    def to_sarif(self, report: dict) -> dict:
        """Convert an AuditReport dict to a SARIF log object."""
        findings = report.get("findings", [])
        infra = report.get("infra_findings", [])

        rules = self._build_rules(findings)
        results = self._build_results(findings)

        # Add infra findings as results too
        for inf in infra:
            rule_id = f"INFRA-{inf.get('title', 'unknown')[:30].replace(' ', '-')}"
            if rule_id not in {r["id"] for r in rules}:
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": inf.get("title", "")},
                    "defaultConfiguration": {
                        "level": _SEVERITY_TO_SARIF_LEVEL.get(inf.get("severity", "medium"), "warning"),
                    },
                })
            results.append({
                "ruleId": rule_id,
                "level": _SEVERITY_TO_SARIF_LEVEL.get(inf.get("severity", "medium"), "warning"),
                "message": {"text": inf.get("detail", inf.get("title", ""))},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": inf.get("file", "")},
                        "region": {"startLine": 1},
                    },
                }],
            })

        sarif = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "BlanketAudit",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/blanketaudit",
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": report.get("scan_date", ""),
                }],
            }],
        }

        return sarif

    def to_json(self, report: dict) -> str:
        """Return the SARIF log as a JSON string."""
        return json.dumps(self.to_sarif(report), indent=2, ensure_ascii=False)

    # ── Internals ────────────────────────────────────────────

    @staticmethod
    def _build_rules(findings: list[dict]) -> list[dict]:
        """Build SARIF rule definitions from findings."""
        seen: set[str] = set()
        rules: list[dict] = []

        for f in findings:
            policy_id = f.get("policy_id", f.get("id", ""))
            if policy_id in seen:
                continue
            seen.add(policy_id)

            severity = f.get("severity", "medium")
            properties: dict[str, Any] = {
                "tags": [f.get("category", "security")],
            }
            # Add compliance framework tags
            for ref in f.get("compliance_refs", []):
                fw = ref.get("framework", "")
                if fw:
                    properties["tags"].append(fw)

            rules.append({
                "id": policy_id,
                "shortDescription": {"text": f.get("title", "")[:200]},
                "fullDescription": {"text": f.get("description", "")[:1000]},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
                },
                "properties": properties,
                "helpUri": "",
            })

        return rules

    @staticmethod
    def _build_results(findings: list[dict]) -> list[dict]:
        """Build SARIF result entries from findings."""
        results: list[dict] = []

        for f in findings:
            policy_id = f.get("policy_id", f.get("id", ""))
            severity = f.get("severity", "medium")

            # Build locations from evidence
            locations: list[dict] = []
            for ev in f.get("evidence", []):
                loc: dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": ev.get("file_path", ""),
                        },
                        "region": {
                            "startLine": ev.get("line_start", 1),
                            "endLine": ev.get("line_end", ev.get("line_start", 1)),
                            "snippet": {"text": ev.get("code_snippet", "")[:500]},
                        },
                    },
                }
                locations.append(loc)

            # Build message with AI explanation
            message_parts = [f.get("title", "")]
            if f.get("ai_explanation"):
                message_parts.append(f["ai_explanation"][:500])
            if f.get("remediation"):
                message_parts.append(f"Remediation: {f['remediation'][:300]}")

            # Build code flows from call chain
            code_flows: list[dict] = []
            call_chain = f.get("call_chain", [])
            if call_chain:
                thread_flows = []
                for step in call_chain:
                    thread_flows.append({
                        "location": {
                            "message": {"text": f"{step.get('step_type', '')}: {step.get('method', '')}"},
                        },
                    })
                code_flows.append({"threadFlows": [{"locations": thread_flows}]})

            # Build fixes from fix_code
            fixes: list[dict] = []
            if f.get("fix_code"):
                fixes.append({
                    "description": {"text": f.get("remediation", "Apply fix")[:200]},
                })

            result: dict[str, Any] = {
                "ruleId": policy_id,
                "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
                "message": {"text": "\n\n".join(message_parts)},
                "locations": locations or [{"physicalLocation": {"artifactLocation": {"uri": ""}, "region": {"startLine": 1}}}],
                "rank": _SEVERITY_TO_SARIF_RANK.get(severity, 1.0),
            }

            if code_flows:
                result["codeFlows"] = code_flows
            if fixes:
                result["fixes"] = fixes

            # Compliance references as related locations
            related: list[dict] = []
            for ref in f.get("compliance_refs", []):
                related.append({
                    "message": {"text": f"{ref.get('framework', '')} {ref.get('clause', '')}: {ref.get('title', '')}"},
                })
            if related:
                result["relatedLocations"] = related

            results.append(result)

        return results
