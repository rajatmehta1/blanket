"""Policy conflict resolution: Security > Compliance > Architecture > Quality.

Design doc §4.6: when two policies produce conflicting recommendations for
the same code location, use a fixed priority hierarchy plus explicit
``conflicts_with`` / ``supersedes`` metadata.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog

from blanketaudit.models.finding import AuditFinding
from blanketaudit.policies.schema import Policy

logger = structlog.get_logger()

# Category priority: lower index = higher priority.
PRIORITY_ORDER = ["security", "compliance", "architecture", "quality"]

# Severity priority (for same-category conflicts).
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _location_key(finding: AuditFinding) -> str:
    """Build a location key for grouping findings that cover the same code."""
    if not finding.evidence:
        return f"{finding.id}::no_evidence"
    ev = finding.evidence[0]
    return f"{ev.file_path}::{ev.line_start}-{ev.line_end}"


class ConflictResolver:
    """Resolve conflicting policy recommendations.

    Resolution rules:
    1. **Explicit supersedes**: if policy A declares ``supersedes: [B]``,
       finding from A wins over finding from B at the same location.
    2. **Category hierarchy**: Security > Compliance > Architecture > Quality.
    3. **Same category**: higher severity wins.
    4. **Otherwise**: both findings are kept with a ``CONFLICT`` flag
       for human review.
    """

    def __init__(self, policies: dict[str, Policy] | None = None) -> None:
        self._policies = policies or {}

    def resolve(self, findings: list[AuditFinding]) -> list[AuditFinding]:
        """Resolve conflicts across all findings.

        Returns a deduplicated list with conflicts resolved.
        """
        if len(findings) <= 1:
            return list(findings)

        # Group findings by code location
        groups: dict[str, list[AuditFinding]] = defaultdict(list)
        for f in findings:
            groups[_location_key(f)].append(f)

        resolved: list[AuditFinding] = []
        conflict_count = 0

        for location, group in groups.items():
            if len(group) == 1:
                resolved.append(group[0])
                continue

            winner = self._resolve_group(group)
            if winner is not None:
                resolved.append(winner)
                conflict_count += 1
            else:
                # No clear winner — keep all with conflict flag
                for f in group:
                    flagged = f.model_copy(update={
                        "ai_explanation": f"[CONFLICT — multiple policies at this location]\n\n{f.ai_explanation}",
                    })
                    resolved.append(flagged)
                conflict_count += 1

        if conflict_count:
            logger.info(
                "conflict_resolver.resolved",
                total_findings=len(findings),
                conflicts=conflict_count,
                output=len(resolved),
            )

        return resolved

    def _resolve_group(self, group: list[AuditFinding]) -> AuditFinding | None:
        """Resolve a group of findings at the same location.

        Returns the winning finding, or *None* if no clear winner
        (both kept with conflict flag).
        """
        # 1. Check explicit supersedes
        for f in group:
            policy = self._policies.get(f.policy_id)
            if policy and policy.supersedes:
                others_superseded = all(
                    other.policy_id in policy.supersedes
                    for other in group
                    if other.id != f.id
                )
                if others_superseded:
                    return f

        # 2. Category hierarchy
        categories = {f.category for f in group}
        if len(categories) > 1:
            # Different categories — highest priority wins
            best_category = min(
                categories,
                key=lambda c: PRIORITY_ORDER.index(c) if c in PRIORITY_ORDER else 99,
            )
            category_winners = [f for f in group if f.category == best_category]
            if len(category_winners) == 1:
                return category_winners[0]
            # Multiple from same top category — fall through to severity
            group = category_winners

        # 3. Same category — highest severity wins
        severities = {f.severity for f in group}
        if len(severities) > 1:
            best_severity = min(
                severities,
                key=lambda s: _SEVERITY_RANK.get(s, 99),
            )
            severity_winners = [f for f in group if f.severity == best_severity]
            if len(severity_winners) == 1:
                return severity_winners[0]
            # Multiple with same severity — pick first (stable)
            return severity_winners[0]

        # 4. Everything identical — no clear winner
        if len(group) <= 1:
            return group[0] if group else None
        return None
