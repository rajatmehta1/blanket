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

        # Convert raw tool dicts → AuditFinding-compatible dicts
        raw_count = len(findings)
        converted = self._convert_static_to_findings(findings, state)

        logger.info("node.static.done", findings=len(converted), raw_tool_findings=raw_count)
        return {"static_findings": converted, "static_raw_count": raw_count, "errors": errors}

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
            static = state.get("static_findings", [])
            agent = state.get("agent_findings", [])
            all_raw = static + agent

            logger.info(
                "node.validate.input_summary",
                static_count=len(static),
                agent_count=len(agent),
                total=len(all_raw),
                sample_keys=list(all_raw[0].keys()) if all_raw else [],
            )

            # Build repo_files map for evidence verification
            repo_files = self._build_repo_files(state)
            logger.info("node.validate.repo_files", file_count=len(repo_files))

            pipeline = ValidationPipeline()

            # Separate static-only findings from AI findings.
            # Static tools (semgrep, gitleaks, osv) don't hallucinate —
            # Gate 2 (evidence path verification) was designed for AI output.
            # Run static findings through Gate 1 (schema) only,
            # run AI findings through all 4 gates.
            static_only = [f for f in all_raw if f.get("source") == "static"]
            ai_findings = [f for f in all_raw if f.get("source") != "static"]

            # Validate AI findings through all 4 gates
            validated_ai = pipeline.validate(ai_findings, repo_files) if ai_findings else []

            # Validate static findings through Gate 1 (schema) only
            from blanketaudit.validation.gate_schema import SchemaGate
            schema_gate = SchemaGate()
            validated_static: list = []
            for raw in static_only:
                finding = schema_gate.validate(raw)
                if finding is not None:
                    validated_static.append(finding)
                else:
                    logger.warning("node.validate.static_schema_fail", finding_id=raw.get("id", "?"))

            all_validated = validated_static + validated_ai

            logger.info(
                "node.validate.done",
                input=len(all_raw),
                validated=len(all_validated),
                static_passed=len(validated_static),
                ai_passed=len(validated_ai),
            )
            return {
                "validated_findings": [f.model_dump() for f in all_validated],
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
        static_raw_count = state.get("static_raw_count", 0)

        # Detect incomplete scan: tools produced findings but validation rejected all
        scan_incomplete = (
            len(validated) == 0
            and static_raw_count > 0
        )
        if scan_incomplete:
            logger.warning(
                "score.incomplete_scan",
                msg="Static tools found findings but all were rejected by validation gates",
                raw_count=static_raw_count,
                validated_count=0,
            )

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
    # Static finding conversion
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def _convert_static_to_findings(
        raw_findings: list[dict], state: AuditState
    ) -> list[dict]:
        """Convert raw tool output dicts into AuditFinding-compatible dicts.

        Raw tools (semgrep, gitleaks, osv) return minimal dicts.  The
        validation pipeline expects dicts that can parse into AuditFinding.
        This bridge fills in required fields with sensible defaults.
        """
        from pathlib import Path as _Path

        converted: list[dict] = []
        repo_name = ""
        repo_local_path = ""
        repos = state.get("repo_paths", [])
        if repos:
            repo_name = repos[0].get("repo_name", repos[0].get("name", "unknown"))
            repo_local_path = repos[0].get("local_path", "")

        # Build set of known relative file paths for normalization
        known_files = {f.get("path", "") for f in state.get("files", []) if f.get("path")}

        def _normalize_evidence_path(raw_path: str) -> str:
            """Normalize tool-reported file paths to match indexed file paths.

            Tools like gitleaks may report paths relative to the git root
            (e.g., 'blanket-arch-audit-v2/tests/foo.py') but the indexer
            stores paths relative to the scan target (e.g., 'tests/foo.py').
            """
            p = raw_path.replace("\\", "/")
            # Already matches an indexed file
            if p in known_files:
                return p
            # Try stripping directory prefixes one level at a time
            parts = p.split("/")
            for i in range(1, len(parts)):
                candidate = "/".join(parts[i:])
                if candidate in known_files:
                    return candidate
            return p  # Return as-is if no match found

        # Map tool-specific rule patterns to policy prefixes
        _TOOL_CATEGORY: dict[str, str] = {
            "semgrep": "security",
            "gitleaks": "security",
            "osv": "security",
        }
        _TOOL_POLICY_PREFIX: dict[str, str] = {
            "semgrep": "SEC",
            "gitleaks": "SEC",
            "osv": "SEC",
        }
        _TOOL_SEVERITY_DEFAULT: dict[str, str] = {
            "semgrep": "medium",
            "gitleaks": "high",
            "osv": "medium",
        }

        for idx, raw in enumerate(raw_findings, start=1):
            tool = raw.get("tool", "unknown")
            severity = raw.get("severity", _TOOL_SEVERITY_DEFAULT.get(tool, "medium"))
            # Normalise severity values from tools
            severity_map = {
                "error": "high",
                "warning": "medium",
                "info": "low",
                "note": "low",
            }
            severity = severity_map.get(severity, severity)
            if severity not in ("critical", "high", "medium", "low"):
                severity = "medium"

            category = _TOOL_CATEGORY.get(tool, "security")
            policy_prefix = _TOOL_POLICY_PREFIX.get(tool, "SEC")

            # Build title from tool-specific fields
            rule_id = raw.get("rule_id", "")
            message = raw.get("message", raw.get("description", ""))
            if tool == "gitleaks":
                title = f"Secret Detected: {raw.get('description', rule_id)}"
                description = f"Blanket identified a potential secret ({rule_id}) in the source code."
                remediation = "Remove the secret from source code and rotate the credential immediately."
                fix_code = "# Remove hardcoded secret and use environment variables instead"
            elif tool == "osv":
                pkg = raw.get("package_name", "")
                ver = raw.get("package_version", "")
                vuln_id = raw.get("vuln_id", rule_id)
                fixed = raw.get("fixed_version", "")
                title = f"Vulnerable Dependency: {pkg}@{ver} ({vuln_id})"
                description = message or f"Blanket identified a known vulnerability ({vuln_id}) in {pkg}@{ver}."
                remediation = f"Upgrade {pkg} to {fixed}." if fixed else f"Check for a patched version of {pkg}."
                fix_code = f"# Upgrade: {pkg} >= {fixed}" if fixed else f"# Check for updates to {pkg}"
            else:
                title = message[:120] if message else f"Static finding: {rule_id}"
                description = message or f"Blanket identified a code pattern violation ({rule_id})."
                remediation = "Review and fix the flagged code pattern."
                fix_code = ""

            finding_dict = {
                "id": f"BLK-{idx:03d}",
                "policy_id": f"{policy_prefix}-{idx:03d}",
                "title": title,
                "description": description,
                "severity": severity,
                "category": category,
                "confidence": 0.85 if tool in ("semgrep", "gitleaks") else 0.7,
                "source": "static",
                "evidence": [
                    {
                        "file_path": _normalize_evidence_path(raw.get("file_path", "unknown")),
                        "repo_name": repo_name,
                        "line_start": raw.get("line_start", 1),
                        "line_end": raw.get("line_end", raw.get("line_start", 1)),
                        "code_snippet": raw.get("code_snippet", ""),
                        "tool": tool,
                    }
                ],
                "compliance_refs": [],
                # "ai_explanation": f"Static analysis tool '{tool}' flagged this issue. {description}",
                "ai_explanation": f"{description}",
                "fix_code": fix_code,
                "remediation": remediation,
                "effort_hours": 1.0,
                "dollar_impact": "",
            }
            converted.append(finding_dict)

        return converted

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

            # Instantiate the actual agent class
            agent_cls = self._get_agent_class(agent_name)
            agent = agent_cls(llm=llm)

            # Run the agent (static → AI → validate)
            findings = await agent.execute(state)

            logger.info(
                f"node.agent.{agent_name}.done",
                findings=len(findings),
            )

            # Convert AuditFinding objects to dicts for state
            return {
                "agent_findings": [
                    f.model_dump() if hasattr(f, "model_dump") else f
                    for f in findings
                ],
            }

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
    def _get_agent_class(agent_name: str):
        """Import and return the agent class for the given name."""
        if agent_name == "security":
            from blanketaudit.agents.security_agent import SecurityAgent
            return SecurityAgent
        elif agent_name == "compliance":
            from blanketaudit.agents.compliance_agent import ComplianceAgent
            return ComplianceAgent
        elif agent_name == "architecture":
            from blanketaudit.agents.architecture_agent import ArchitectureAgent
            return ArchitectureAgent
        elif agent_name == "quality":
            from blanketaudit.agents.quality_agent import QualityAgent
            return QualityAgent
        else:
            raise ValueError(f"Unknown agent: {agent_name}")

    @staticmethod
    def _build_repo_files(state: AuditState) -> dict[str, str]:
        """Build a {relative_file_path: content} map for evidence verification.

        Reads files from the scanned repos so Gate 2 can verify evidence.
        Also reads from the git root to cover files found by tools like
        gitleaks that scan across git history.
        """
        from pathlib import Path
        import subprocess

        repo_files: dict[str, str] = {}

        for repo in state.get("repo_paths", []):
            local_path = repo.get("local_path", "")
            if not local_path:
                continue
            repo_root = Path(local_path).resolve()

            # 1. Index files from the scan target (indexed paths)
            for file_meta in state.get("files", []):
                rel = file_meta.get("path", "")
                if not rel:
                    continue
                full = repo_root / rel
                if full.is_file():
                    try:
                        repo_files[rel] = full.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue

            # 2. Also find the git root — tools like gitleaks report
            #    paths relative to the git root, not the scan target
            try:
                result = subprocess.run(
                    ["git", "rev-parse", "--show-toplevel"],
                    capture_output=True, text=True, cwd=str(repo_root),
                    timeout=5,
                )
                if result.returncode == 0:
                    git_root = Path(result.stdout.strip()).resolve()
                    # For evidence paths relative to git root, also index them
                    for file_meta in state.get("files", []):
                        rel = file_meta.get("path", "")
                        if not rel:
                            continue
                        # Compute path relative to git root
                        full = repo_root / rel
                        if full.is_file():
                            try:
                                git_rel = str(full.relative_to(git_root)).replace("\\", "/")
                                if git_rel not in repo_files:
                                    repo_files[git_rel] = full.read_text(encoding="utf-8", errors="replace")
                            except (ValueError, OSError):
                                continue
            except (subprocess.SubprocessError, OSError):
                pass

        # 3. For any evidence file_paths from static findings that are
        #    not in repo_files, try to resolve them from the git root
        static_findings = state.get("static_findings", [])
        for finding in static_findings:
            for ev in finding.get("evidence", []):
                fp = ev.get("file_path", "")
                if fp and fp not in repo_files:
                    # Try resolving from git root
                    for repo in state.get("repo_paths", []):
                        local_path = repo.get("local_path", "")
                        if not local_path:
                            continue
                        try:
                            result = subprocess.run(
                                ["git", "rev-parse", "--show-toplevel"],
                                capture_output=True, text=True,
                                cwd=str(Path(local_path).resolve()),
                                timeout=5,
                            )
                            if result.returncode == 0:
                                git_root = Path(result.stdout.strip()).resolve()
                                candidate = git_root / fp
                                if candidate.is_file():
                                    repo_files[fp] = candidate.read_text(
                                        encoding="utf-8", errors="replace"
                                    )
                                    break
                        except (subprocess.SubprocessError, OSError):
                            continue

        return repo_files


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
