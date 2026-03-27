"""3-phase remediation roadmap with simulated per-task score impact.

Phase 1 (Days 1-14): all critical + top high findings
Phase 2 (Days 15-45): remaining high + important medium
Phase 3 (Days 46-90): remaining medium + low + tech debt

Each task's score_impact is computed by simulating: "if this finding
were removed, what would the new composite score be?"
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit.models.finding import AuditFinding
from blanketaudit.models.roadmap import RemediationPhase, RemediationTask
from blanketaudit.models.scoring import HealthScore

logger = structlog.get_logger()


class RemediationPlanner:
    """Build a 3-phase remediation roadmap with simulated score impacts."""

    def __init__(self, scorer: Any = None) -> None:
        """
        Parameters
        ----------
        scorer:
            A ``RiskScorer`` instance.  If provided, used for
            per-task score impact simulation.
        """
        self._scorer = scorer

    def plan(
        self,
        findings: list[AuditFinding],
        health_score: HealthScore,
    ) -> list[RemediationPhase]:
        """Build the 3-phase remediation roadmap."""
        if not findings:
            return []

        # Sort by composite priority: severity × blast_radius × compliance_weight
        sorted_findings = sorted(findings, key=_priority_key, reverse=True)

        # Partition into phases by severity tier
        critical = [f for f in sorted_findings if f.severity == "critical"]
        high = [f for f in sorted_findings if f.severity == "high"]
        medium = [f for f in sorted_findings if f.severity == "medium"]
        low = [f for f in sorted_findings if f.severity == "low"]

        # Phase 1 (URGENT): all critical + top 5 high (by priority)
        phase1 = critical + high[:5]
        # Phase 2 (SHORT-TERM): remaining high + top 10 medium
        phase2 = high[5:] + medium[:10]
        # Phase 3 (MEDIUM-TERM): remaining medium + all low (tech debt)
        phase3 = medium[10:] + low

        current_score = health_score.overall
        phases: list[RemediationPhase] = []
        resolved_ids: set[str] = set()

        if phase1:
            tasks, effort, new_score = self._build_phase_tasks(
                phase1, findings, current_score, resolved_ids,
            )
            impact = new_score - current_score
            phases.append(RemediationPhase(
                title="URGENT — Days 1-14",
                date_range="Days 1-14",
                items=tasks,
                total_effort=f"{effort:.0f} hours",
                score_target=f"{current_score} → {new_score} (+{impact} points)",
            ))
            current_score = new_score
            resolved_ids.update(f.id for f in phase1)

        if phase2:
            tasks, effort, new_score = self._build_phase_tasks(
                phase2, findings, current_score, resolved_ids,
            )
            impact = new_score - current_score
            phases.append(RemediationPhase(
                title="SHORT-TERM — Days 15-45",
                date_range="Days 15-45",
                items=tasks,
                total_effort=f"{effort:.0f} hours",
                score_target=f"{current_score} → {new_score} (+{impact} points)",
            ))
            current_score = new_score
            resolved_ids.update(f.id for f in phase2)

        if phase3:
            tasks, effort, new_score = self._build_phase_tasks(
                phase3, findings, current_score, resolved_ids,
            )
            impact = new_score - current_score
            phases.append(RemediationPhase(
                title="MEDIUM-TERM — Days 46-90",
                date_range="Days 46-90",
                items=tasks,
                total_effort=f"{effort:.0f} hours",
                score_target=f"{current_score} → {new_score} (+{impact} points)",
            ))

        logger.info(
            "remediation.planned",
            phases=len(phases),
            total_tasks=sum(len(p.items) for p in phases),
        )
        return phases

    def _build_phase_tasks(
        self,
        phase_findings: list[AuditFinding],
        all_findings: list[AuditFinding],
        current_score: int,
        already_resolved: set[str],
    ) -> tuple[list[RemediationTask], float, int]:
        """Build tasks for one phase with simulated score impacts.

        Returns (tasks, total_effort, projected_score_after_phase).
        """
        tasks: list[RemediationTask] = []
        total_effort = 0.0

        # Compute per-task impact via simulation
        simulated_resolved = set(already_resolved)

        for f in phase_findings:
            impact = self._simulate_impact(f, all_findings, simulated_resolved)
            simulated_resolved.add(f.id)

            effort = f.effort_hours if f.effort_hours > 0 else 2.0
            task_desc = f.remediation if f.remediation else f"Fix: {f.title}"

            tasks.append(RemediationTask(
                task=task_desc[:200],
                effort=f"{effort:.0f}h",
                finding_id=f.id,
                score_impact=f"+{impact}",
            ))
            total_effort += effort

        # Compute final score after all phase findings resolved
        all_phase_ids = {f.id for f in phase_findings}
        final_excluded = already_resolved | all_phase_ids
        new_score = self._compute_score_without(all_findings, final_excluded)
        new_score = min(100, new_score)

        return tasks, total_effort, new_score

    def _simulate_impact(
        self,
        finding: AuditFinding,
        all_findings: list[AuditFinding],
        already_excluded: set[str],
    ) -> int:
        """Simulate: if this finding were fixed, how much does the score improve?"""
        if self._scorer is not None:
            try:
                score_before = self._scorer.score_without(all_findings, already_excluded)
                score_after = self._scorer.score_without(
                    all_findings, already_excluded | {finding.id}
                )
                return max(0, score_after - score_before)
            except Exception:
                pass

        # Fallback: use severity-based estimate
        return _SEVERITY_IMPACT.get(finding.severity, 1)

    def _compute_score_without(
        self,
        all_findings: list[AuditFinding],
        exclude_ids: set[str],
    ) -> int:
        """Compute score excluding resolved findings."""
        if self._scorer is not None:
            try:
                return self._scorer.score_without(all_findings, exclude_ids)
            except Exception:
                pass

        # Fallback: simple penalty-based calculation
        remaining = [f for f in all_findings if f.id not in exclude_ids]
        penalty = sum(_SEVERITY_IMPACT.get(f.severity, 1) for f in remaining)
        return max(0, min(100, 100 - penalty))


# Fallback severity → score impact estimate
_SEVERITY_IMPACT: dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
}

# Severity weight for composite priority
_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 100,
    "high": 50,
    "medium": 15,
    "low": 5,
}

# Compliance weight multiplier — findings with compliance refs get boosted
_COMPLIANCE_MULTIPLIER = 1.5


def _priority_key(finding: AuditFinding) -> float:
    """Compute composite priority: severity × blast_radius × compliance_weight.

    Higher value = higher priority = should be fixed first.
    """
    severity_w = _SEVERITY_WEIGHT.get(finding.severity, 5)

    # Blast radius factor: entry_points count (default 1 if not set)
    blast = 1
    if finding.blast_radius is not None:
        blast = max(1, finding.blast_radius.entry_points)

    # Compliance weight: boost findings with compliance refs
    compliance_w = 1.0
    if finding.compliance_refs:
        compliance_w = _COMPLIANCE_MULTIPLIER

    return severity_w * blast * compliance_w
