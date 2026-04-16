"""Deduplication, root-cause grouping, and cross-framework compliance mapping.

Design doc Tier 5 + CTO review fix:
  Level 1: Exact dedup — same file+line+category = one finding (keep highest confidence)
  Level 2: Root-cause grouping — same policy_id+title = one representative finding
           with an affected_locations[] array and affected_count.
           This turns "743x High Cyclomatic Complexity" into "1 finding, 743 locations".

One finding can map to multiple compliance controls across frameworks.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog

from blanketaudit.models.finding import AuditFinding, ComplianceRef, Evidence

logger = structlog.get_logger()

# Known cross-framework mappings: if a finding matches one control,
# it likely also applies to related controls in other frameworks.
_CROSS_FRAMEWORK_MAP: dict[str, list[dict]] = {
    # Encryption at rest / in transit
    "encrypt": [
        {"framework": "HIPAA", "clause": "§164.312(a)(2)(iv)", "title": "Encryption and Decryption"},
        {"framework": "HIPAA", "clause": "§164.312(e)(1)", "title": "Transmission Security"},
        {"framework": "SOC2", "clause": "CC6.7", "title": "Data Transmission Security"},
        {"framework": "PCI-DSS", "clause": "Req 4.1", "title": "Encrypt Transmission"},
        {"framework": "GDPR", "clause": "Art. 32", "title": "Security of Processing"},
    ],
    # Access control
    "access_control": [
        {"framework": "HIPAA", "clause": "§164.312(a)(1)", "title": "Access Control"},
        {"framework": "SOC2", "clause": "CC6.1", "title": "Logical Access Controls"},
        {"framework": "PCI-DSS", "clause": "Req 7.1", "title": "Access Control Systems"},
        {"framework": "GDPR", "clause": "Art. 32", "title": "Security of Processing"},
    ],
    # Audit logging
    "audit_log": [
        {"framework": "HIPAA", "clause": "§164.312(b)", "title": "Audit Controls"},
        {"framework": "SOC2", "clause": "CC7.1", "title": "Monitoring"},
        {"framework": "PCI-DSS", "clause": "Req 10.1", "title": "Audit Trails"},
    ],
    # Injection / input validation
    "injection": [
        {"framework": "PCI-DSS", "clause": "Req 6.5.1", "title": "Injection Flaws"},
        {"framework": "SOC2", "clause": "CC6.1", "title": "Logical Access Controls"},
    ],
    # Secrets / credentials
    "secrets": [
        {"framework": "PCI-DSS", "clause": "Req 8.2", "title": "Authentication Methods"},
        {"framework": "SOC2", "clause": "CC6.2", "title": "Credential Management"},
        {"framework": "HIPAA", "clause": "§164.312(d)", "title": "Person or Entity Authentication"},
    ],
}

# Keywords in finding titles that trigger cross-framework mapping
_KEYWORD_TO_TOPIC: dict[str, str] = {
    "encrypt": "encrypt", "tls": "encrypt", "ssl": "encrypt", "https": "encrypt",
    "access control": "access_control", "auth": "access_control", "rbac": "access_control",
    "permission": "access_control", "missing auth": "access_control",
    "audit": "audit_log", "logging": "audit_log", "log": "audit_log",
    "injection": "injection", "sqli": "injection", "xss": "injection",
    "secret": "secrets", "password": "secrets", "credential": "secrets",
    "api key": "secrets", "hardcoded": "secrets",
}

# Finding titles that should be grouped at the repo/module level (one per root cause)
# rather than per-location. These are high-volume static findings.
_GROUPABLE_POLICY_IDS = {
    "QUAL-001",   # High Cyclomatic Complexity
    "QUAL-002",   # Dead Functions
    "QUAL-007",   # Oversized Source Files
    "QUAL-008",   # Missing Docstrings
    "QUAL-018",   # Long Functions
    "ARCH-001",   # Circular Import Dependencies
    "ARCH-002",   # God Class Anti-Pattern
    "ARCH-006",   # Monolith Anti-Pattern
    "ARCH-007",   # Dead Code Module
    "ARCH-015",   # Missing API Versioning
    "QUAL-006",   # Copy-Paste Code
    "QUAL-009",   # Stale TODOs
    "QUAL-016",   # Missing Logging
    "QUAL-017",   # Magic Numbers
}


def _dedup_key(finding: AuditFinding) -> str:
    """Build a dedup key from file + line range + category."""
    if not finding.evidence:
        return f"{finding.id}::no_evidence"
    ev = finding.evidence[0]
    return f"{ev.file_path}::{ev.line_start}-{ev.line_end}::{finding.category}"


def _group_key(finding: AuditFinding) -> str:
    """Build a group key for root-cause grouping: policy_id + category.

    Findings with the same policy trigger are collapsed into one
    representative finding with affected_locations[].
    """
    return f"{finding.policy_id}::{finding.category}"


class FindingMerger:
    """Deduplicate findings and apply cross-framework compliance mapping.

    Two-level dedup:
      Level 1: Exact dedup — same file + line + category = one finding
      Level 2: Root-cause grouping — same policy_id + category = one representative
               with affected_locations[] (only for known high-volume policy IDs)
    """

    def __init__(self, active_frameworks: list[str] | None = None) -> None:
        self._active_frameworks = set(
            fw.upper() for fw in (active_frameworks or [])
        )

    def merge(self, findings: list[AuditFinding]) -> list[AuditFinding]:
        """Deduplicate, group, and enrich findings with cross-framework refs."""
        # Step 1: Exact dedup (same file+line+category)
        deduped = self._dedup(findings)
        logger.info("merger.deduped", input=len(findings), after_dedup=len(deduped))

        # Step 2: Root-cause grouping (collapse high-volume same-policy findings)
        grouped = self._group_by_root_cause(deduped)
        logger.info("merger.grouped", after_group=len(grouped))

        # Step 3: Cross-framework mapping
        if self._active_frameworks:
            grouped = [self._add_cross_framework_refs(f) for f in grouped]

        logger.info(
            "merger.done",
            input=len(findings),
            output=len(grouped),
            deduped=len(findings) - len(grouped),
        )
        return grouped

    def _dedup(self, findings: list[AuditFinding]) -> list[AuditFinding]:
        """Keep highest-confidence finding per dedup key."""
        groups: dict[str, list[AuditFinding]] = defaultdict(list)
        for f in findings:
            groups[_dedup_key(f)].append(f)

        result: list[AuditFinding] = []
        for key, group in groups.items():
            # Pick highest confidence; on tie, pick highest severity
            severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            best = max(
                group,
                key=lambda f: (f.confidence, -severity_rank.get(f.severity, 4)),
            )
            # Merge compliance refs from all duplicates
            all_refs = []
            seen_clauses: set[str] = set()
            for f in group:
                for ref in f.compliance_refs:
                    key_str = f"{ref.framework}::{ref.clause}"
                    if key_str not in seen_clauses:
                        seen_clauses.add(key_str)
                        all_refs.append(ref)

            if all_refs:
                best = best.model_copy(update={"compliance_refs": all_refs})

            result.append(best)

        return result

    def _group_by_root_cause(
        self,
        findings: list[AuditFinding],
    ) -> list[AuditFinding]:
        """Collapse same-policy findings into one representative with affected_locations[].

        Only groups findings whose policy_id is in _GROUPABLE_POLICY_IDS.
        Findings with AI enrichment are never collapsed (they have unique analysis).
        """
        ungroupable: list[AuditFinding] = []
        groups: dict[str, list[AuditFinding]] = defaultdict(list)

        for f in findings:
            # Don't group findings that already have AI enrichment
            has_ai = bool(f.ai_explanation and f.ai_explanation.strip())
            if f.policy_id in _GROUPABLE_POLICY_IDS and not has_ai:
                groups[_group_key(f)].append(f)
            else:
                ungroupable.append(f)

        grouped: list[AuditFinding] = []
        for key, group in groups.items():
            if len(group) == 1:
                grouped.append(group[0])
                continue

            # Pick the worst-severity finding as representative
            severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            group.sort(key=lambda f: (severity_rank.get(f.severity, 4), -f.confidence))
            representative = group[0]

            # Collect all evidence locations
            all_locations: list[Evidence] = []
            seen_locations: set[str] = set()
            for f in group:
                for ev in f.evidence:
                    loc_key = f"{ev.file_path}::{ev.line_start}"
                    if loc_key not in seen_locations:
                        seen_locations.add(loc_key)
                        all_locations.append(ev)

            # Merge all compliance refs
            all_refs: list[ComplianceRef] = []
            seen_clauses: set[str] = set()
            for f in group:
                for ref in f.compliance_refs:
                    key_str = f"{ref.framework}::{ref.clause}"
                    if key_str not in seen_clauses:
                        seen_clauses.add(key_str)
                        all_refs.append(ref)

            # Update the representative with grouped data
            # Rewrite title to show count: "High Cyclomatic Complexity (743 locations)"
            base_title = representative.title
            # Strip any existing function-specific detail for a cleaner group title
            policy_name = _POLICY_DISPLAY_NAMES.get(
                representative.policy_id,
                representative.title.split(":")[0].strip(),
            )
            group_title = f"{policy_name} ({len(group)} locations)"

            # Build a summary description
            file_set = {ev.file_path for ev in all_locations}
            top_files = sorted(file_set)[:5]
            file_summary = ", ".join(top_files)
            if len(file_set) > 5:
                file_summary += f", ... and {len(file_set) - 5} more files"

            group_desc = (
                f"{len(group)} instances of {policy_name} detected across "
                f"{len(file_set)} files: {file_summary}."
            )

            # Sum effort hours
            total_effort = sum(f.effort_hours for f in group) or len(group) * 0.5

            representative = representative.model_copy(update={
                "title": group_title,
                "description": group_desc,
                "affected_locations": all_locations,
                "affected_count": len(group),
                "compliance_refs": all_refs if all_refs else representative.compliance_refs,
                "effort_hours": total_effort,
            })
            grouped.append(representative)

        return ungroupable + grouped

    def _add_cross_framework_refs(self, finding: AuditFinding) -> AuditFinding:
        """Add compliance refs from other frameworks based on keywords."""
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        combined = f"{title_lower} {desc_lower}"

        new_refs: list[ComplianceRef] = list(finding.compliance_refs)
        existing = {f"{r.framework}::{r.clause}" for r in new_refs}

        for keyword, topic in _KEYWORD_TO_TOPIC.items():
            if keyword not in combined:
                continue
            mappings = _CROSS_FRAMEWORK_MAP.get(topic, [])
            for m in mappings:
                fw = m["framework"]
                if fw not in self._active_frameworks:
                    continue
                key = f"{fw}::{m['clause']}"
                if key not in existing:
                    try:
                        new_refs.append(ComplianceRef(
                            framework=fw, clause=m["clause"], title=m["title"],
                        ))
                        existing.add(key)
                    except Exception:
                        pass

        if len(new_refs) > len(finding.compliance_refs):
            return finding.model_copy(update={"compliance_refs": new_refs})
        return finding


# Display names for policy IDs (used in grouped finding titles)
_POLICY_DISPLAY_NAMES: dict[str, str] = {
    "QUAL-001": "High Cyclomatic Complexity",
    "QUAL-002": "Dead Functions",
    "QUAL-007": "Oversized Source Files",
    "QUAL-008": "Missing Docstrings on Public API",
    "QUAL-018": "Long Functions",
    "ARCH-001": "Circular Import Dependencies",
    "ARCH-002": "God Class Anti-Pattern",
    "ARCH-006": "Monolith Anti-Pattern",
    "ARCH-007": "Dead Code Module",
    "ARCH-015": "Missing API Versioning",
    "QUAL-006": "Copy-Paste Code",
    "QUAL-009": "Stale TODOs",
    "QUAL-016": "Missing Logging",
    "QUAL-017": "Magic Numbers",
}
