"""Deduplication and cross-framework compliance mapping.

Design doc Tier 5: same file+line+category = one finding (keep highest
confidence).  One finding can map to multiple compliance controls across
frameworks.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog

from blanketaudit.models.finding import AuditFinding, ComplianceRef

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


def _dedup_key(finding: AuditFinding) -> str:
    """Build a dedup key from file + line range + category."""
    if not finding.evidence:
        return f"{finding.id}::no_evidence"
    ev = finding.evidence[0]
    return f"{ev.file_path}::{ev.line_start}-{ev.line_end}::{finding.category}"


class FindingMerger:
    """Deduplicate findings and apply cross-framework compliance mapping.

    Dedup rule: same file + line range + category = one finding,
    keep the one with the highest confidence.
    """

    def __init__(self, active_frameworks: list[str] | None = None) -> None:
        self._active_frameworks = set(
            fw.upper() for fw in (active_frameworks or [])
        )

    def merge(self, findings: list[AuditFinding]) -> list[AuditFinding]:
        """Deduplicate and enrich findings with cross-framework refs."""
        # Step 1: Dedup
        deduped = self._dedup(findings)

        # Step 2: Cross-framework mapping
        if self._active_frameworks:
            deduped = [self._add_cross_framework_refs(f) for f in deduped]

        logger.info(
            "merger.done",
            input=len(findings),
            output=len(deduped),
            deduped=len(findings) - len(deduped),
        )
        return deduped

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
