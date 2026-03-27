"""LangGraph StateGraph: the 7-tier audit pipeline.

Design doc §2.1 Tier 3:
  ingest → triage → estimate_cost → [budget check] →
  static_analysis → [parallel agents] →
  validate → score → report → manifest

Each node is an async function that reads and writes AuditState.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal

import structlog

from blanketaudit.config import get_settings
from blanketaudit.metrics import set_scan_context, timed_span
from blanketaudit.orchestrator.state import AuditState

logger = structlog.get_logger()

# Sentinel for pipeline end
END = "__end__"


class AuditPipeline:
    """Build and run the full audit StateGraph.

    Usage::

        pipeline = AuditPipeline()
        graph = pipeline.build()
        result = await pipeline.run({
            "project_name": "MedPay",
            "repo_sources": [{"url": "github.com/org/api"}],
            ...
        })
    """

    def __init__(self) -> None:
        self._graph: Any = None

    # ═══════════════════════════════════════════════════════════
    # Graph construction
    # ═══════════════════════════════════════════════════════════

    def build(self) -> Any:
        """Build and compile the LangGraph StateGraph.

        Returns the compiled graph, or a SimplePipeline fallback if
        langgraph is not installed.
        """
        try:
            from langgraph.graph import StateGraph

            graph = StateGraph(AuditState)

            # ── Tier 1-2: Ingestion ──────────────────────────
            graph.add_node("ingest_repos", self.ingest_node)

            # ── Tier 3: Triage + cost ────────────────────────
            graph.add_node("triage_files", self.triage_node)
            graph.add_node("estimate_cost", self.estimate_node)

            # ── Tier 3.5: Static analysis ────────────────────
            graph.add_node("run_static_analysis", self.static_node)

            # ── Tier 4: AI agents ────────────────────────────
            graph.add_node("security_agent", self.security_node)
            graph.add_node("compliance_agent", self.compliance_node)
            graph.add_node("architecture_agent", self.architecture_node)
            graph.add_node("quality_agent", self.quality_node)

            # ── Tier 5: Aggregation ──────────────────────────
            graph.add_node("validate_findings", self.validate_node)
            graph.add_node("score_and_prioritize", self.score_node)

            # ── Tier 6: Report ───────────────────────────────
            graph.add_node("generate_report", self.report_node)
            graph.add_node("record_manifest", self.manifest_node)

            # ── Edges ────────────────────────────────────────
            graph.set_entry_point("ingest_repos")
            graph.add_edge("ingest_repos", "triage_files")
            graph.add_edge("triage_files", "estimate_cost")

            # Budget check: abort if over budget or dry-run
            graph.add_conditional_edges(
                "estimate_cost",
                self._check_budget,
                {
                    "proceed": "run_static_analysis",
                    "abort": "record_manifest",
                },
            )

            graph.add_edge("run_static_analysis", "security_agent")
            graph.add_edge("security_agent", "compliance_agent")
            graph.add_edge("compliance_agent", "architecture_agent")
            graph.add_edge("architecture_agent", "quality_agent")
            graph.add_edge("quality_agent", "validate_findings")
            graph.add_edge("validate_findings", "score_and_prioritize")
            graph.add_edge("score_and_prioritize", "generate_report")
            graph.add_edge("generate_report", "record_manifest")
            graph.set_finish_point("record_manifest")

            self._graph = graph.compile()
            return self._graph

        except ImportError:
            logger.warning(
                "pipeline.langgraph_not_installed",
                msg="Falling back to SimplePipeline",
            )
            self._graph = SimplePipeline(self)
            return self._graph

    async def run(self, initial_state: dict) -> dict:
        """Execute the pipeline with the given initial state."""
        scan_id = initial_state.get("scan_id", f"scan-{uuid.uuid4().hex[:12]}")
        initial_state.setdefault("scan_id", scan_id)
        initial_state.setdefault("status", "running")
        initial_state.setdefault("errors", [])
        initial_state.setdefault("dry_run", False)

        set_scan_context(scan_id=scan_id)
        logger.info("pipeline.starting", scan_id=scan_id)

        start = time.perf_counter()
        try:
            if hasattr(self._graph, "ainvoke"):
                result = await self._graph.ainvoke(initial_state)
            else:
                result = await self._graph.run(initial_state)

            elapsed = time.perf_counter() - start
            result["status"] = result.get("status", "completed")
            logger.info(
                "pipeline.completed",
                scan_id=scan_id,
                duration_s=round(elapsed, 1),
                status=result["status"],
            )
            return result
        except Exception as exc:
            elapsed = time.perf_counter() - start
            logger.error(
                "pipeline.failed",
                scan_id=scan_id,
                error=str(exc)[:300],
                duration_s=round(elapsed, 1),
            )
            initial_state["status"] = "failed"
            initial_state["errors"] = initial_state.get("errors", []) + [str(exc)]
            return initial_state

    # ═══════════════════════════════════════════════════════════
    # Pipeline nodes
    # ═══════════════════════════════════════════════════════════

    async def ingest_node(self, state: AuditState) -> dict:
        """Tier 1-2: Clone repos, index files, parse ASTs, build dep graph."""
        set_scan_context(step="ingest")
        logger.info("node.ingest.start")

        try:
            from blanketaudit.ingestion.file_indexer import FileIndexer
            from pathlib import Path

            files: list[dict] = []
            repo_paths: list[dict] = []

            for source in state.get("repo_sources", []):
                local_path = source.get("local_path", source.get("url", ""))
                repo_name = source.get("name", Path(local_path).name)

                indexer = FileIndexer()
                indexed = indexer.index_project(Path(local_path), repo_name)
                files.extend([f.model_dump() for f in indexed])
                repo_paths.append({
                    "repo_name": repo_name,
                    "local_path": str(local_path),
                    "commit_sha": source.get("commit_sha", ""),
                })

            logger.info("node.ingest.done", files=len(files))
            return {"files": files, "repo_paths": repo_paths}
        except Exception as exc:
            logger.error("node.ingest.failed", error=str(exc)[:200])
            return {"errors": [f"Ingestion failed: {exc}"], "files": []}

    async def triage_node(self, state: AuditState) -> dict:
        """Tier 3: Score files and assign to tiers."""
        set_scan_context(step="triage")
        logger.info("node.triage.start")

        try:
            from blanketaudit.ingestion.models import FileMetadata
            from blanketaudit.triage.file_scorer import FileScorer
            from blanketaudit.triage.tier_assigner import TierAssigner
            from blanketaudit.triage.batch_assembler import BatchAssembler

            files = [FileMetadata.model_validate(f) for f in state.get("files", [])]

            scorer = FileScorer()
            scores = scorer.score_all(files)

            assigner = TierAssigner()
            tiers = assigner.assign(files, scores)

            assembler = BatchAssembler()
            batches = assembler.assemble(files, tiers)

            logger.info(
                "node.triage.done",
                tier1=sum(1 for t in tiers.values() if t == 1),
                tier2=sum(1 for t in tiers.values() if t == 2),
                tier3=sum(1 for t in tiers.values() if t == 3),
                batches=len(batches),
            )
            return {
                "file_scores": scores,
                "file_tiers": tiers,
                "batches": [[f.model_dump() for f in batch] for batch in batches],
            }
        except Exception as exc:
            logger.error("node.triage.failed", error=str(exc)[:200])
            return {"errors": [f"Triage failed: {exc}"], "file_scores": {}, "file_tiers": {}}

    async def estimate_node(self, state: AuditState) -> dict:
        """Tier 3: Project cost. If --dry-run, pipeline stops here."""
        set_scan_context(step="estimate")
        logger.info("node.estimate.start")

        try:
            from blanketaudit.ingestion.models import FileMetadata
            from blanketaudit.orchestrator.cost_estimator import CostEstimator

            files = [FileMetadata.model_validate(f) for f in state.get("files", [])]
            tiers = state.get("file_tiers", {})

            estimator = CostEstimator()
            estimate = estimator.estimate(files, tiers)

            logger.info(
                "node.estimate.done",
                usd=estimate.total_estimated_usd,
                tokens=estimate.total_estimated_tokens,
                within_budget=estimate.recommendation,
            )
            return {"cost_estimate": estimate.model_dump()}
        except Exception as exc:
            logger.error("node.estimate.failed", error=str(exc)[:200])
            return {"errors": [f"Cost estimation failed: {exc}"], "cost_estimate": {}}

    async def static_node(self, state: AuditState) -> dict:
        """Tier 3.5: Run static analysis tools (Semgrep, Gitleaks, OSV)."""
        set_scan_context(step="static_scan")
        logger.info("node.static.start")

        findings: list[dict] = []
        errors: list[str] = []

        for repo in state.get("repo_paths", []):
            path = repo.get("local_path", "")
            if not path:
                continue

            try:
                from blanketaudit.agents.tools.semgrep_tool import run_semgrep
                semgrep_results = await run_semgrep(path)
                findings.extend(semgrep_results)
            except Exception as exc:
                errors.append(f"Semgrep failed: {exc}")

            try:
                from blanketaudit.agents.tools.gitleaks_tool import run_gitleaks
                gitleaks_results = await run_gitleaks(path)
                findings.extend(gitleaks_results)
            except Exception as exc:
                errors.append(f"Gitleaks failed: {exc}")

            try:
                from blanketaudit.agents.tools.osv_tool import run_osv_scan
                osv_results = await run_osv_scan(path)
                findings.extend(osv_results)
            except Exception as exc:
                errors.append(f"OSV failed: {exc}")

        logger.info("node.static.done", findings=len(findings))
        return {"static_findings": findings, "errors": errors}

    async def security_node(self, state: AuditState) -> dict:
        """Tier 4: Security agent — AI analysis on static candidates."""
        return await self._run_agent("security", state)

    async def compliance_node(self, state: AuditState) -> dict:
        """Tier 4: Compliance agent."""
        return await self._run_agent("compliance", state)

    async def architecture_node(self, state: AuditState) -> dict:
        """Tier 4: Architecture agent."""
        return await self._run_agent("architecture", state)

    async def quality_node(self, state: AuditState) -> dict:
        """Tier 4: Quality agent."""
        return await self._run_agent("quality", state)

    async def validate_node(self, state: AuditState) -> dict:
        """Tier 5: Run 4 hallucination gates on all findings."""
        set_scan_context(step="validation")
        logger.info("node.validate.start")

        try:
            from blanketaudit.validation.pipeline import ValidationPipeline

            # Combine static + agent findings
            all_raw = (
                state.get("static_findings", []) +
                state.get("agent_findings", [])
            )

            # Build repo_files map for evidence verification
            repo_files = self._build_repo_files(state)

            pipeline = ValidationPipeline()
            validated = pipeline.validate(all_raw, repo_files)

            logger.info("node.validate.done", input=len(all_raw), validated=len(validated))
            return {
                "validated_findings": [f.model_dump() for f in validated],
            }
        except Exception as exc:
            logger.error("node.validate.failed", error=str(exc)[:200])
            # Graceful degradation: pass findings through without validation
            return {
                "validated_findings": state.get("static_findings", []) + state.get("agent_findings", []),
                "errors": [f"Validation failed: {exc}"],
            }

    async def score_node(self, state: AuditState) -> dict:
        """Tier 5: Score findings, build compliance matrix, remediation plan."""
        set_scan_context(step="merge")
        logger.info("node.score.start")

        validated = state.get("validated_findings", [])

        # Compute severity counts for health score
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in validated:
            sev = f.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Simple scoring: 100 - weighted penalties
        score = max(0, 100 - (
            severity_counts["critical"] * 25 +
            severity_counts["high"] * 10 +
            severity_counts["medium"] * 3 +
            severity_counts["low"] * 1
        ))
        grade = (
            "A" if score >= 85 else
            "B" if score >= 70 else
            "C" if score >= 50 else
            "D" if score >= 30 else "F"
        )

        health_score = {
            "overall": score,
            "grade": grade,
            "categories": [],
            "severity_counts": severity_counts,
        }

        logger.info("node.score.done", score=score, grade=grade)
        return {
            "health_score": health_score,
            "compliance_matrix": [],
            "remediation_phases": [],
        }

    async def report_node(self, state: AuditState) -> dict:
        """Tier 6: Generate the full audit report via ReportAssembler.

        Populates ALL AuditReport fields: cover page data, health score,
        executive summary, sorted findings, infra findings, compliance matrix,
        call graph summary, remediation roadmap, scan manifest.
        """
        set_scan_context(step="report")
        logger.info("node.report.start")

        try:
            from blanketaudit.scoring.report_assembler import ReportAssembler

            assembler = ReportAssembler()
            report = await assembler.assemble(state)

            logger.info("node.report.done", fields=len(report))
            return {"report": report, "status": "completed"}

        except Exception as exc:
            logger.error("node.report.failed", error=str(exc)[:200])
            # Fallback: minimal report so pipeline doesn't crash
            report = {
                "project_name": state.get("project_name", ""),
                "scan_id": state.get("scan_id", ""),
                "domain": state.get("domain", "general"),
                "health_score": state.get("health_score", {}),
                "findings": state.get("validated_findings", []),
                "compliance_matrix": [],
                "remediation_phases": [],
                "cost_estimate": state.get("cost_estimate", {}),
            }
            return {"report": report, "status": "completed", "errors": [f"Report assembly failed: {exc}"]}

    async def manifest_node(self, state: AuditState) -> dict:
        """Record the scan manifest for reproducibility."""
        set_scan_context(step="manifest")

        repo_commits = {}
        for rp in state.get("repo_paths", []):
            repo_commits[rp.get("repo_name", "")] = rp.get("commit_sha", "")

        manifest = {
            "scan_id": state.get("scan_id", ""),
            "repo_commits": repo_commits,
            "cost_estimate": state.get("cost_estimate", {}),
            "status": state.get("status", "completed"),
        }

        logger.info("node.manifest.done", scan_id=manifest["scan_id"])
        return {"scan_manifest": manifest}

    # ═══════════════════════════════════════════════════════════
    # Conditional routing
    # ═══════════════════════════════════════════════════════════

    def _check_budget(self, state: AuditState) -> Literal["proceed", "abort"]:
        """Route: proceed with scan or abort (over budget / dry-run)."""
        if state.get("dry_run"):
            logger.info("pipeline.dry_run_stop")
            return "abort"

        estimate = state.get("cost_estimate", {})
        within = estimate.get("within_budget", True)
        if not within:
            settings = get_settings()
            if settings.cost.abort_on_budget:
                logger.warning("pipeline.over_budget")
                return "abort"

        return "proceed"

    # ═══════════════════════════════════════════════════════════
    # Agent helpers
    # ═══════════════════════════════════════════════════════════

    async def _run_agent(self, agent_name: str, state: AuditState) -> dict:
        """Run one analysis agent with graceful degradation."""
        set_scan_context(agent=agent_name, step="ai_analysis")
        logger.info(f"node.agent.{agent_name}.start")

        settings = get_settings()
        agents_cfg = getattr(settings.agents, agent_name, None)
        if agents_cfg and not agents_cfg.enabled:
            logger.info(f"node.agent.{agent_name}.disabled")
            return {"agent_findings": []}

        try:
            from blanketaudit.llm.provider import get_llm_for_agent

            llm = get_llm_for_agent(agent_name)
            if llm is None:
                logger.info(f"node.agent.{agent_name}.no_llm")
                return {"agent_findings": []}

            # In the full implementation, each agent would:
            # 1. Get its static findings
            # 2. Run AI analysis on them
            # 3. Return enriched findings
            # For now, return empty (agents are built in later prompts)
            return {"agent_findings": []}

        except Exception as exc:
            logger.error(
                f"node.agent.{agent_name}.failed",
                error=str(exc)[:200],
            )
            return {
                "agent_findings": [],
                "errors": [f"Agent {agent_name} failed: {exc}"],
            }

    @staticmethod
    def _build_repo_files(state: AuditState) -> dict[str, str]:
        """Build a {file_path: content} map for evidence verification.

        In a real scan this reads from the cloned repos.  For now
        returns an empty dict (evidence gate will skip verification).
        """
        return {}


# ═══════════════════════════════════════════════════════════════
# Fallback: SimplePipeline (no LangGraph dependency)
# ═══════════════════════════════════════════════════════════════


class SimplePipeline:
    """Sequential pipeline fallback when langgraph is not installed.

    Runs nodes in order without the StateGraph framework.
    """

    def __init__(self, pipeline: AuditPipeline) -> None:
        self._pipeline = pipeline

    async def run(self, state: dict) -> dict:
        """Run all nodes sequentially."""
        p = self._pipeline

        nodes = [
            ("ingest_repos", p.ingest_node),
            ("triage_files", p.triage_node),
            ("estimate_cost", p.estimate_node),
        ]

        for name, node in nodes:
            result = await node(state)
            state = {**state, **result}

        # Budget check
        route = p._check_budget(state)
        if route == "abort":
            result = await p.manifest_node(state)
            state = {**state, **result}
            state["status"] = "aborted" if state.get("dry_run") else "over_budget"
            return state

        # Static analysis
        result = await p.static_node(state)
        state = {**state, **{k: (state.get(k, []) + v) if isinstance(v, list) and k in ("errors", "static_findings") else v for k, v in result.items()}}

        # Agents (sequential)
        for agent_node in [p.security_node, p.compliance_node, p.architecture_node, p.quality_node]:
            result = await agent_node(state)
            for k, v in result.items():
                if k in ("agent_findings", "errors") and isinstance(v, list):
                    state[k] = state.get(k, []) + v
                else:
                    state[k] = v

        # Validate + Score + Report + Manifest
        for node in [p.validate_node, p.score_node, p.report_node, p.manifest_node]:
            result = await node(state)
            state = {**state, **result}

        return state
