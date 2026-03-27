"""Finding Aggregator — orchestrates the full Tier 5 pipeline.

Combines: dedup → cross-framework mapping → 4 hallucination gates →
risk scoring → executive summary generation.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from blanketaudit.llm.guardrails import INJECTION_DEFENSE_PREFIX
from blanketaudit.llm.resilience import safe_llm_call
from blanketaudit.models.finding import AuditFinding
from blanketaudit.models.scoring import HealthScore
from blanketaudit.scoring.finding_merger import FindingMerger
from blanketaudit.scoring.risk_scorer import RiskScorer
from blanketaudit.validation.pipeline import ValidationPipeline

logger = structlog.get_logger()


class FindingAggregator:
    """Orchestrate the full Tier 5 pipeline.

    1. Deduplicate findings (same file+line+category)
    2. Apply cross-framework compliance mapping
    3. Run 4 hallucination gates
    4. Score and grade
    5. Generate executive summary

    Usage::

        aggregator = FindingAggregator(active_frameworks=["HIPAA", "SOC2"])
        result = await aggregator.aggregate(raw_findings, repo_files)
    """

    def __init__(
        self,
        active_frameworks: list[str] | None = None,
        llm: Any | None = None,
    ) -> None:
        self._frameworks = active_frameworks or []
        self._llm = llm
        self._merger = FindingMerger(active_frameworks=self._frameworks)
        self._validator = ValidationPipeline()
        self._scorer = RiskScorer(active_frameworks=self._frameworks)

    async def aggregate(
        self,
        raw_findings: list[dict],
        repo_files: dict[str, str],
    ) -> AggregationResult:
        """Run the full Tier 5 pipeline.

        Parameters
        ----------
        raw_findings:
            Raw finding dicts from all agents (static + AI).
        repo_files:
            ``{file_path: content}`` for evidence verification.

        Returns
        -------
        AggregationResult with validated findings, health score, and summary.
        """
        logger.info("aggregator.start", raw_count=len(raw_findings))

        # Step 1-2: Validate through 4 hallucination gates
        # (includes schema validation which parses dicts into AuditFinding)
        validated = self._validator.validate(raw_findings, repo_files)
        logger.info("aggregator.validated", count=len(validated))

        # Step 3: Dedup + cross-framework mapping
        merged = self._merger.merge(validated)
        logger.info("aggregator.merged", count=len(merged))

        # Step 4: Risk scoring
        health_score = self._scorer.score(merged)

        # Step 5: Executive summary
        summary = await self._generate_summary(merged, health_score)

        result = AggregationResult(
            findings=merged,
            health_score=health_score,
            executive_summary=summary,
            raw_count=len(raw_findings),
            validated_count=len(validated),
            merged_count=len(merged),
        )

        logger.info(
            "aggregator.done",
            raw=result.raw_count,
            validated=result.validated_count,
            merged=result.merged_count,
            score=health_score.overall,
            grade=health_score.grade,
        )
        return result

    async def _generate_summary(
        self,
        findings: list[AuditFinding],
        health_score: HealthScore,
    ) -> dict:
        """Generate executive summary — LLM if available, template fallback."""
        if self._llm is not None:
            try:
                return await self._generate_summary_llm(findings, health_score)
            except Exception as exc:
                logger.warning("aggregator.llm_summary_failed", error=str(exc)[:200])

        return self._generate_summary_template(findings, health_score)

    async def _generate_summary_llm(
        self,
        findings: list[AuditFinding],
        health_score: HealthScore,
    ) -> dict:
        """Generate executive summary using LLM."""
        from langchain_core.messages import HumanMessage, SystemMessage

        severity_counts = health_score.severity_counts
        critical_titles = [
            f"- {f.id}: {f.title}" for f in findings
            if f.severity == "critical"
        ][:5]

        system_prompt = (
            f"{INJECTION_DEFENSE_PREFIX}\n\n"
            "Generate an executive summary as JSON:\n"
            '{"paragraphs": ["paragraph1", "paragraph2"], '
            '"immediate_actions": ["action1", "action2", ...]}\n'
            "Write for a CTO. Use specific numbers. 2 paragraphs. 3-5 actions."
        )

        user_prompt = (
            f"Health score: {health_score.overall}/100 (Grade: {health_score.grade})\n"
            f"Severity: {severity_counts}\n"
            f"Total findings: {len(findings)}\n"
            f"Critical findings:\n{''.join(critical_titles) or 'None'}\n"
            f"Frameworks: {', '.join(self._frameworks) or 'None'}\n"
        )

        response = await safe_llm_call(
            self._llm,
            [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)],
            agent_name="executive_summary",
        )

        try:
            data = json.loads(response.content)
            return {
                "paragraphs": data.get("paragraphs", [])[:2],
                "immediate_actions": data.get("immediate_actions", [])[:5],
            }
        except json.JSONDecodeError:
            # Use response as a single paragraph
            return {
                "paragraphs": [response.content[:1000]],
                "immediate_actions": [],
            }

    @staticmethod
    def _generate_summary_template(
        findings: list[AuditFinding],
        health_score: HealthScore,
    ) -> dict:
        """Generate executive summary from template (no LLM needed)."""
        sc = health_score.severity_counts
        total = len(findings)

        para1 = (
            f"The architecture audit scored {health_score.overall}/100 "
            f"(Grade {health_score.grade}), identifying {total} findings "
            f"across the codebase. Of these, {sc.get('critical', 0)} are critical "
            f"severity, {sc.get('high', 0)} are high, {sc.get('medium', 0)} are medium, "
            f"and {sc.get('low', 0)} are low."
        )

        # Build paragraph 2 based on findings
        categories = {}
        for f in findings:
            categories[f.category] = categories.get(f.category, 0) + 1
        top_cats = sorted(categories.items(), key=lambda x: -x[1])[:3]

        if top_cats:
            areas = ", ".join(f"{cat} ({n} findings)" for cat, n in top_cats)
            para2 = f"The primary risk areas are: {areas}."
        else:
            para2 = "No significant risk areas were identified."

        # Actions
        actions: list[str] = []
        critical_findings = [f for f in findings if f.severity == "critical"]
        for cf in critical_findings[:3]:
            actions.append(f"Fix {cf.id}: {cf.title}")
        if not actions:
            high_findings = [f for f in findings if f.severity == "high"]
            for hf in high_findings[:3]:
                actions.append(f"Address {hf.id}: {hf.title}")
        if not actions:
            actions.append("Continue monitoring — no critical or high findings detected.")

        return {
            "paragraphs": [para1, para2],
            "immediate_actions": actions,
        }


class AggregationResult:
    """Result of the Tier 5 aggregation pipeline."""

    def __init__(
        self,
        findings: list[AuditFinding],
        health_score: HealthScore,
        executive_summary: dict,
        raw_count: int = 0,
        validated_count: int = 0,
        merged_count: int = 0,
    ) -> None:
        self.findings = findings
        self.health_score = health_score
        self.executive_summary = executive_summary
        self.raw_count = raw_count
        self.validated_count = validated_count
        self.merged_count = merged_count


# ═══════════════════════════════════════════════════════════════
# ReportAssembler — builds the final AuditReport
# ═══════════════════════════════════════════════════════════════


class ReportAssembler:
    """Transform pipeline state into the complete AuditReport model.

    Bridges Tier 5 (scoring) → Tier 6 (report generation).
    Every field in AuditReport is populated here.
    """

    def __init__(self, llm: Any = None) -> None:
        self._llm = llm

    async def assemble(self, state: dict) -> dict:
        """Build a complete AuditReport dict from pipeline state.

        Parameters
        ----------
        state:
            The full AuditState dict from the pipeline.

        Returns
        -------
        A dict matching the AuditReport model schema.
        """
        from datetime import datetime

        from blanketaudit.models.callgraph import (
            CallGraphSummary, DeadCodeSummary, EntryPointSummary,
        )
        from blanketaudit.models.manifest import ScanManifest
        from blanketaudit.models.report import ExecutiveSummary
        from blanketaudit.scoring.compliance_matrix_builder import ComplianceMatrixBuilder
        from blanketaudit.scoring.infra_finding_builder import InfraFindingBuilder
        from blanketaudit.scoring.remediation_planner import RemediationPlanner

        frameworks = state.get("frameworks", state.get("active_frameworks", []))

        # 1. Get validated + merged findings
        findings = self._get_findings(state)

        # 2. Sort findings: critical → high → medium → low
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 4), f.title))

        # 3. Separate infra findings
        infra_builder = InfraFindingBuilder()
        infra_findings, code_findings = infra_builder.extract(findings)

        # 4. Build compliance matrix
        matrix_builder = ComplianceMatrixBuilder()
        compliance_matrix = matrix_builder.build(findings, frameworks)

        # 5. Score
        scorer = RiskScorer(active_frameworks=frameworks)
        health_score = scorer.score(findings)

        # 6. Build remediation roadmap
        planner = RemediationPlanner()
        remediation_phases = planner.plan(findings, health_score)

        # 7. Generate executive summary
        aggregator = FindingAggregator(active_frameworks=frameworks, llm=self._llm)
        summary_dict = await aggregator._generate_summary(findings, health_score)
        executive_summary = ExecutiveSummary(
            paragraphs=summary_dict.get("paragraphs", []),
            immediate_actions=summary_dict.get("immediate_actions", []),
        )

        # 8. Call graph summary (from state or empty)
        call_graph_summary = self._build_call_graph_summary(state)

        # 9. Scan manifest
        scan_manifest = self._build_manifest(state)

        # 10. Compute aggregate metrics
        files = state.get("files", [])
        total_loc = sum(f.get("loc", 0) for f in files) if files else 0
        total_methods = self._count_methods(state)

        # 11. Assemble the report
        report = {
            "project_name": state.get("project_name", "Unknown"),
            "project_tagline": state.get("project_tagline", ""),
            "domain": state.get("domain", "general"),
            "repos": self._build_repo_list(state),
            "scan_date": datetime.now().strftime("%B %d, %Y"),
            "scan_duration": state.get("scan_duration", ""),
            "total_files": len(files),
            "total_lines": self._format_lines(total_loc),
            "total_methods": total_methods,
            "cross_repo_edge_count": len(call_graph_summary.get("cross_repo_edges", [])) if isinstance(call_graph_summary, dict) else len(call_graph_summary.cross_repo_edges),
            "entry_point_count": len(call_graph_summary.get("entry_points", [])) if isinstance(call_graph_summary, dict) else len(call_graph_summary.entry_points),
            "max_call_depth": self._max_depth(call_graph_summary),
            "health_score": health_score.model_dump(),
            "executive_summary": executive_summary.model_dump(),
            "findings": [f.model_dump() for f in code_findings],
            "infra_findings": [f.model_dump() for f in infra_findings],
            "compliance_matrix": [m.model_dump() for m in compliance_matrix],
            "call_graph_summary": call_graph_summary.model_dump() if hasattr(call_graph_summary, "model_dump") else call_graph_summary,
            "remediation_phases": [p.model_dump() for p in remediation_phases],
            "scan_manifest": scan_manifest,
            "llm_provider": state.get("llm_provider", state.get("config", {}).get("llm", {}).get("provider", "none")),
            "llm_model": state.get("llm_model", ""),
            "active_frameworks": frameworks,
        }

        logger.info(
            "report_assembler.done",
            findings=len(code_findings),
            infra=len(infra_findings),
            score=health_score.overall,
        )
        return report

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _get_findings(state: dict) -> list[AuditFinding]:
        """Extract findings from state, handling both dicts and models."""
        raw = state.get("validated_findings", state.get("findings", []))
        findings: list[AuditFinding] = []
        for f in raw:
            if isinstance(f, AuditFinding):
                findings.append(f)
            elif isinstance(f, dict):
                try:
                    findings.append(AuditFinding.model_validate(f))
                except Exception:
                    pass
        return findings

    @staticmethod
    def _build_repo_list(state: dict) -> list[dict]:
        """Build repo summary list for the cover page."""
        repos = []
        for rp in state.get("repo_paths", []):
            repos.append({
                "name": rp.get("repo_name", ""),
                "lang": "",
                "files": 0,
                "lines": 0,
            })
        return repos or [{"name": state.get("project_name", ""), "lang": "", "files": 0, "lines": 0}]

    @staticmethod
    def _build_call_graph_summary(state: dict) -> Any:
        """Build or retrieve call graph summary."""
        if "call_graph_summary" in state:
            return state["call_graph_summary"]

        from blanketaudit.models.callgraph import CallGraphSummary, DeadCodeSummary
        return CallGraphSummary(
            entry_points=[],
            cross_repo_edges=[],
            circular_dependencies=[],
            dead_methods=DeadCodeSummary(count=0, total_lines=0, top_files=[]),
            single_points_of_failure=[],
        )

    @staticmethod
    def _build_manifest(state: dict) -> dict:
        """Build or retrieve scan manifest."""
        if "scan_manifest" in state and state["scan_manifest"]:
            m = state["scan_manifest"]
            return m if isinstance(m, dict) else m.model_dump() if hasattr(m, "model_dump") else {}

        from datetime import datetime, timezone
        return {
            "scan_id": state.get("scan_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_versions": {},
            "prompt_versions": {},
            "model_ids": {},
            "tool_versions": {},
            "repo_commits": {},
            "config_hash": "",
        }

    @staticmethod
    def _count_methods(state: dict) -> int:
        total = 0
        for ctx in state.get("analysis_contexts", []):
            methods = ctx.get("methods", []) if isinstance(ctx, dict) else getattr(ctx, "methods", [])
            total += len(methods)
        return total

    @staticmethod
    def _format_lines(loc: int) -> str:
        if loc >= 1_000_000:
            return f"{loc / 1_000_000:.1f}M"
        if loc >= 1000:
            return f"{loc // 1000}k"
        return str(loc)

    @staticmethod
    def _max_depth(cgs: Any) -> int:
        if isinstance(cgs, dict):
            entries = cgs.get("entry_points", [])
            return max((e.get("depth", 0) for e in entries), default=0)
        if hasattr(cgs, "entry_points"):
            return max((e.depth for e in cgs.entry_points), default=0)
        return 0
