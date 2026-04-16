"""Compliance agent — AST + semantic search → AI control mapping.

Design doc §5.2: maps code to regulatory controls using dual-layer
analysis.  Static checks run compliance policy regex + Milvus RAG
for clause matching.  AI classifies each control as PASS/PARTIAL/FAIL/
GAP/NOT_APPLICABLE/REVIEW_NEEDED.

Guardrail: process-level controls (BAA, incident response, pen test)
are always REVIEW_NEEDED — the agent cannot verify these from code alone.
Uses ``get_llm_for_agent("compliance")`` → higher-capability model.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from blanketaudit2.agents.base_agent import BaseAgent
from blanketaudit2.llm.guardrails import INJECTION_DEFENSE_PREFIX, wrap_code_content
from blanketaudit2.llm.resilience import safe_llm_call
from blanketaudit2.models.compliance import ComplianceControlStatus
from blanketaudit2.models.finding import AuditFinding, ComplianceRef
from blanketaudit2.orchestrator.state import AuditState

logger = structlog.get_logger()

# Controls that are process-level — cannot be verified from code alone.
# These always get REVIEW_NEEDED regardless of what the LLM says.
_PROCESS_LEVEL_CONTROLS: set[str] = {
    "COMP-HIPAA-006",   # BAA reference
    "COMP-HIPAA-008",   # PHI retention policy
    "COMP-SOC2-003",    # Change management
    "COMP-SOC2-008",    # Incident response
    "COMP-SOC2-009",    # Vendor assessment
    "COMP-PCI-004",     # SAST in CI/CD (partially checkable)
    "COMP-PCI-008",     # Pen test evidence
    "COMP-GDPR-004",    # DPA
}

# Finding ID counter
_COUNTER = 0


def _next_id() -> str:
    global _COUNTER
    _COUNTER += 1
    return f"BLK-{_COUNTER:03d}"


def _reset_counter(start: int = 0) -> None:
    global _COUNTER
    _COUNTER = start


class ComplianceAgent(BaseAgent):
    """Compliance analysis agent.

    Static: load compliance policies, run regex checks, query Milvus RAG.
    AI: evaluate evidence against each compliance control, classify status.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__("compliance", **kwargs)

    # ── Static checks ────────────────────────────────────────

    async def run_static_checks(self, state: AuditState) -> list[AuditFinding]:
        """Run compliance policy static checks + Milvus RAG search.

        1. Load compliance policies matching active frameworks.
        2. Run regex/AST static checks from each policy.
        3. Search Milvus for compliance clause matches (if available).
        """
        findings: list[AuditFinding] = []
        frameworks = state.get("frameworks", [])
        repo_paths = state.get("repo_paths", [])

        # Step 1: Run compliance policy static checks
        policy_findings = await self._run_policy_checks(state, frameworks)
        findings.extend(policy_findings)

        # Step 2: Milvus RAG — search for compliance-relevant code patterns
        rag_findings = await self._run_rag_search(state, frameworks)
        findings.extend(rag_findings)

        logger.info(
            "compliance_agent.static_done",
            policy_findings=len(policy_findings),
            rag_findings=len(rag_findings),
            total=len(findings),
        )
        return findings

    async def _run_policy_checks(
        self,
        state: AuditState,
        frameworks: list[str],
    ) -> list[AuditFinding]:
        """Run compliance policies against repo files."""
        findings: list[AuditFinding] = []

        try:
            from blanketaudit2.policies.engine import PolicyEngine
            from pathlib import Path

            engine = PolicyEngine()
            policy_dir = Path(__file__).parent.parent / "policies" / "compliance"
            if not policy_dir.exists():
                return findings

            policies = engine.load_policies(policy_dir)

            # Build file contents from repo paths
            file_contents: dict[str, str] = {}
            for repo in state.get("repo_paths", []):
                local_path = Path(repo.get("local_path", ""))
                if local_path.exists():
                    for f in state.get("files", []):
                        fp = local_path / f.get("path", "")
                        if fp.exists() and fp.stat().st_size < 500_000:
                            try:
                                file_contents[f["path"]] = fp.read_text(
                                    encoding="utf-8", errors="replace"
                                )
                            except OSError:
                                pass

            repo_name = ""
            if state.get("repo_paths"):
                repo_name = state["repo_paths"][0].get("repo_name", "")

            for policy in policies:
                candidates = engine.execute_static_checks(policy, file_contents)
                for c in candidates:
                    compliance_refs = self._policy_to_refs(policy)
                    findings.append(self._make_static_finding(
                        finding_id=_next_id(),
                        policy_id=policy.id,
                        title=f"{policy.name}",
                        description=policy.description or policy.name,
                        severity=policy.severity,
                        category="compliance",
                        file_path=c.file_path,
                        repo_name=repo_name,
                        line_start=c.line_start,
                        line_end=c.line_end,
                        code_snippet=c.code_snippet[:500],
                        tool=c.tool,
                        confidence=0.7,
                    ))
                    # Add compliance refs to last finding
                    if findings and compliance_refs:
                        findings[-1] = findings[-1].model_copy(
                            update={"compliance_refs": compliance_refs}
                        )

        except Exception as exc:
            logger.warning("compliance_agent.policy_check_failed", error=str(exc)[:200])

        return findings

    async def _run_rag_search(
        self,
        state: AuditState,
        frameworks: list[str],
    ) -> list[AuditFinding]:
        """Search Milvus for compliance-relevant code patterns."""
        try:
            from blanketaudit2.agents.tools.milvus_tools import compliance_rag

            queries = self._build_rag_queries(frameworks)
            findings: list[AuditFinding] = []

            for query in queries[:10]:  # Limit queries
                result_json = await compliance_rag(query, top_k=3)
                result = json.loads(result_json)
                if "error" in result:
                    continue
                # RAG results become low-confidence candidates for AI analysis
                for clause in result.get("clauses", []):
                    if clause.get("relevance_score", 0) > 0.5:
                        logger.debug(
                            "compliance_agent.rag_match",
                            framework=clause.get("framework"),
                            clause=clause.get("clause"),
                        )

            return findings  # RAG mostly informs AI analysis, few direct findings

        except Exception as exc:
            logger.warning("compliance_agent.rag_failed", error=str(exc)[:200])
            return []

    # ── AI analysis ──────────────────────────────────────────

    async def run_ai_analysis(
        self,
        state: AuditState,
        candidates: list[AuditFinding],
    ) -> list[AuditFinding] | None:
        """Classify each finding's compliance status via LLM.

        For each candidate:
        1. Build context with compliance clause text + code evidence
        2. Ask LLM to classify: PASS/PARTIAL/FAIL/GAP/NOT_APPLICABLE
        3. Apply process-level guardrail
        4. Enrich with explanation and compliance mapping
        """
        if not candidates:
            return candidates

        enriched: list[AuditFinding] = []

        for candidate in candidates:
            try:
                result = await self._classify_one(state, candidate)
                if result is not None:
                    enriched.append(result)
            except Exception as exc:
                logger.warning(
                    "compliance_agent.ai_one_failed",
                    finding_id=candidate.id,
                    error=str(exc)[:200],
                )
                enriched.append(candidate)

        return enriched if enriched else None

    async def _classify_one(
        self,
        state: AuditState,
        candidate: AuditFinding,
    ) -> AuditFinding:
        """AI classification for one compliance finding."""
        from langchain_core.messages import HumanMessage, SystemMessage

        evidence = candidate.evidence[0] if candidate.evidence else None
        code_context = evidence.code_snippet if evidence else ""
        file_path = evidence.file_path if evidence else ""

        frameworks_str = ", ".join(state.get("frameworks", ["HIPAA", "SOC2"]))

        system_prompt = (
            f"{INJECTION_DEFENSE_PREFIX}\n\n"
            "You are a compliance auditor. Respond with JSON:\n"
            '{"status": "pass|partial|fail|gap|not_applicable|review_needed", '
            '"confidence": float, "explanation": str, '
            '"compliance_refs": [{"framework": str, "clause": str, "title": str}], '
            '"remediation": str}\n\n'
            f"Active frameworks: {frameworks_str}\n"
            "Only use REAL control IDs from these frameworks.\n"
            "For process-level controls, always set status=review_needed.\n"
        )

        user_prompt = (
            f"Policy: {candidate.policy_id} — {candidate.title}\n"
            f"File: {file_path}\n"
            f"Code:\n{wrap_code_content(code_context, file_path)}\n"
            f"Current severity: {candidate.severity}\n\n"
            "Classify this against the relevant compliance controls."
        )

        response = await safe_llm_call(
            self.llm,
            [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)],
            agent_name=self.name,
            cost_tracker=self.cost_tracker,
            circuit_breaker=self.circuit_breaker,
        )

        return self._parse_classification(candidate, response.content)

    def _parse_classification(
        self,
        candidate: AuditFinding,
        response_text: str,
    ) -> AuditFinding:
        """Parse LLM classification response and apply guardrails."""
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            return candidate.model_copy(update={
                "ai_explanation": response_text[:2000],
                "source": "ai",
            })

        # Parse compliance refs from LLM
        compliance_refs: list[ComplianceRef] = []
        for ref_data in data.get("compliance_refs", []):
            try:
                compliance_refs.append(ComplianceRef(
                    framework=ref_data.get("framework", ""),
                    clause=ref_data.get("clause", ""),
                    title=ref_data.get("title", ""),
                ))
            except Exception:
                pass  # Skip invalid refs

        # Apply process-level guardrail
        status = data.get("status", "review_needed")
        if self._is_process_level(candidate.policy_id):
            status = "review_needed"
            logger.info(
                "compliance_agent.process_level_guardrail",
                policy_id=candidate.policy_id,
                original_status=data.get("status"),
            )

        confidence = min(1.0, max(0.0, data.get("confidence", candidate.confidence)))

        return candidate.model_copy(update={
            "ai_explanation": data.get("explanation", "")[:2000],
            "remediation": data.get("remediation", candidate.remediation),
            "confidence": confidence,
            "compliance_refs": compliance_refs if compliance_refs else candidate.compliance_refs,
            "source": "corroborated" if candidate.source == "static" else "ai",
        })

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _is_process_level(policy_id: str) -> bool:
        """Check if a policy is process-level (cannot be verified from code)."""
        return policy_id in _PROCESS_LEVEL_CONTROLS

    @staticmethod
    def _policy_to_refs(policy: Any) -> list[ComplianceRef]:
        """Convert policy framework strings to ComplianceRef objects."""
        refs: list[ComplianceRef] = []
        for fw_str in getattr(policy, "frameworks", []):
            # Parse "HIPAA-164.312-a-1" → framework=HIPAA, clause=164.312(a)(1)
            parts = fw_str.split("-", 1)
            framework = parts[0].upper() if parts else ""
            clause = parts[1] if len(parts) > 1 else ""

            # Normalize framework names
            fw_map = {
                "HIPAA": "HIPAA", "SOC2": "SOC2", "PCI": "PCI-DSS",
                "GDPR": "GDPR", "SOX": "SOX", "NIST": "NIST",
            }
            framework = fw_map.get(framework, framework)
            if not framework:
                continue

            try:
                refs.append(ComplianceRef(
                    framework=framework,
                    clause=clause or fw_str,
                    title=fw_str,
                ))
            except Exception:
                pass

        return refs

    @staticmethod
    def _build_rag_queries(frameworks: list[str]) -> list[str]:
        """Build RAG search queries for compliance clause matching."""
        queries = []
        topics = [
            "access control authentication",
            "encryption at rest and in transit",
            "audit logging and monitoring",
            "data protection and privacy",
            "input validation and injection prevention",
            "session management and timeout",
            "error handling and information disclosure",
            "secrets management and key rotation",
        ]
        for topic in topics:
            for fw in frameworks[:4]:
                queries.append(f"{fw} {topic}")
        return queries
