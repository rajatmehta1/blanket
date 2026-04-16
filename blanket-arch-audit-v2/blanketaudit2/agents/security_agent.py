"""Security agent — Semgrep + Gitleaks + OSV → AI reasoning.

Design doc §5.1: the security agent runs three static tools, then
uses the LLM to filter false positives and enrich true findings
with blast radius, fix code, and compliance references.

Guardrail: severity > medium requires evidence from 2+ signals.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from blanketaudit2.agents.base_agent import BaseAgent
from blanketaudit2.llm.guardrails import INJECTION_DEFENSE_PREFIX, wrap_code_content
from blanketaudit2.llm.resilience import safe_llm_call
from blanketaudit2.models.finding import AuditFinding
from blanketaudit2.orchestrator.state import AuditState

logger = structlog.get_logger()

# Semgrep rules for security
_SECURITY_CONFIGS = ["auto"]

# Finding ID counter (per agent run)
_COUNTER = 0


def _next_id() -> str:
    global _COUNTER
    _COUNTER += 1
    return f"BLK-{_COUNTER:03d}"


def _reset_counter(start: int = 0) -> None:
    global _COUNTER
    _COUNTER = start


class SecurityAgent(BaseAgent):
    """Security analysis agent.

    Static checks: Semgrep SAST + Gitleaks secrets + OSV CVEs.
    AI analysis: contextual reasoning on each candidate.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__("security", **kwargs)

    # ── Static checks ────────────────────────────────────────

    async def run_static_checks(self, state: AuditState) -> list[AuditFinding]:
        """Run Semgrep, Gitleaks, and OSV-scanner.

        Converts raw tool output into AuditFinding objects.
        """
        findings: list[AuditFinding] = []
        repo_paths = state.get("repo_paths", [])

        for repo in repo_paths:
            local_path = repo.get("local_path", "")
            repo_name = repo.get("repo_name", "")
            if not local_path:
                continue

            # Semgrep SAST
            semgrep_findings = await self._run_semgrep(local_path, repo_name)
            findings.extend(semgrep_findings)

            # Gitleaks secret detection
            gitleaks_findings = await self._run_gitleaks(local_path, repo_name)
            findings.extend(gitleaks_findings)

            # OSV CVE scanning
            osv_findings = await self._run_osv(local_path, repo_name)
            findings.extend(osv_findings)

        logger.info(
            "security_agent.static_done",
            semgrep=sum(1 for f in findings if any(
                e.tool == "semgrep" for e in f.evidence
            )),
            gitleaks=sum(1 for f in findings if any(
                e.tool == "gitleaks" for e in f.evidence
            )),
            osv=sum(1 for f in findings if any(
                e.tool == "osv" for e in f.evidence
            )),
            total=len(findings),
        )
        return findings

    async def _run_semgrep(self, repo_path: str, repo_name: str) -> list[AuditFinding]:
        try:
            from blanketaudit2.agents.tools.semgrep_tool import run_semgrep
            raw = await run_semgrep(repo_path, configs=_SECURITY_CONFIGS)
            return [self._tool_result_to_finding(r, repo_name) for r in raw]
        except Exception as exc:
            logger.warning("security_agent.semgrep_failed", error=str(exc)[:200])
            return []

    async def _run_gitleaks(self, repo_path: str, repo_name: str) -> list[AuditFinding]:
        try:
            from blanketaudit2.agents.tools.gitleaks_tool import run_gitleaks
            raw = await run_gitleaks(repo_path)
            return [self._tool_result_to_finding(r, repo_name) for r in raw]
        except Exception as exc:
            logger.warning("security_agent.gitleaks_failed", error=str(exc)[:200])
            return []

    async def _run_osv(self, repo_path: str, repo_name: str) -> list[AuditFinding]:
        try:
            from blanketaudit2.agents.tools.osv_tool import run_osv_scan
            raw = await run_osv_scan(repo_path)
            return [self._tool_result_to_finding(r, repo_name) for r in raw]
        except Exception as exc:
            logger.warning("security_agent.osv_failed", error=str(exc)[:200])
            return []

    def _tool_result_to_finding(self, raw: dict, repo_name: str) -> AuditFinding:
        """Convert a raw tool result dict into an AuditFinding."""
        tool = raw.get("tool", "unknown")
        severity = raw.get("severity", "medium")
        # Map tool severity to our severity levels
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"

        return self._make_static_finding(
            finding_id=_next_id(),
            policy_id=raw.get("rule_id", raw.get("vuln_id", f"SEC-{tool}")),
            title=raw.get("message", raw.get("description", f"Finding from {tool}"))[:200],
            description=raw.get("message", "")[:500],
            severity=severity,
            category="security",
            file_path=raw.get("file_path", ""),
            repo_name=repo_name,
            line_start=raw.get("line_start", 1),
            line_end=raw.get("line_end", 1),
            code_snippet=raw.get("code_snippet", "")[:500],
            tool=tool,
            confidence=0.7 if tool in ("semgrep", "osv") else 0.8,
        )

    # ── AI analysis ──────────────────────────────────────────

    async def run_ai_analysis(
        self,
        state: AuditState,
        candidates: list[AuditFinding],
    ) -> list[AuditFinding] | None:
        """Enrich candidates with AI reasoning.

        For each candidate:
        1. Build code context (surrounding lines + call graph)
        2. Ask LLM: true positive or false positive?
        3. If true positive: enrich with explanation, fix, compliance refs
        4. Apply guardrail: severity > medium needs 2+ signals

        Returns enriched findings, or None to keep originals on failure.
        """
        if not candidates:
            return candidates

        enriched: list[AuditFinding] = []

        for candidate in candidates:
            try:
                result = await self._analyze_one(state, candidate)
                if result is not None:
                    enriched.append(result)
            except Exception as exc:
                logger.warning(
                    "security_agent.ai_one_failed",
                    finding_id=candidate.id,
                    error=str(exc)[:200],
                )
                # Keep original on failure
                enriched.append(candidate)

        return enriched if enriched else None

    async def _analyze_one(
        self,
        state: AuditState,
        candidate: AuditFinding,
    ) -> AuditFinding | None:
        """AI analysis for a single candidate finding."""
        from langchain_core.messages import HumanMessage, SystemMessage

        # Build context
        evidence = candidate.evidence[0] if candidate.evidence else None
        code_context = evidence.code_snippet if evidence else ""
        file_path = evidence.file_path if evidence else ""

        system_prompt = (
            f"{INJECTION_DEFENSE_PREFIX}\n\n"
            "You are a security engineer reviewing a static analysis finding.\n"
            "Respond with JSON: {\"is_true_positive\": bool, \"confidence\": float, "
            "\"explanation\": str, \"fix_code\": str, \"severity\": str}\n"
            "If false positive, set is_true_positive=false.\n"
        )

        user_prompt = (
            f"Finding: {candidate.title}\n"
            f"Tool: {evidence.tool if evidence else 'unknown'}\n"
            f"File: {file_path}\n"
            f"Code:\n{wrap_code_content(code_context, file_path)}\n"
            f"Severity (from tool): {candidate.severity}\n\n"
            "Is this a true positive? Provide analysis."
        )

        response = await safe_llm_call(
            self.llm,
            [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)],
            agent_name=self.name,
            cost_tracker=self.cost_tracker,
            circuit_breaker=self.circuit_breaker,
        )

        # Parse response
        return self._parse_ai_response(candidate, response.content)

    def _parse_ai_response(
        self,
        candidate: AuditFinding,
        response_text: str,
    ) -> AuditFinding | None:
        """Parse the LLM response and enrich the finding."""
        try:
            # Try JSON parse
            data = json.loads(response_text)
        except json.JSONDecodeError:
            # Not JSON — use as explanation text
            return candidate.model_copy(update={
                "ai_explanation": response_text[:2000],
                "source": "ai",
            })

        is_tp = data.get("is_true_positive", True)
        if not is_tp:
            # LLM says false positive — drop it
            logger.info(
                "security_agent.false_positive",
                finding_id=candidate.id,
            )
            return None

        # Enrich the finding
        ai_severity = data.get("severity", candidate.severity)
        if ai_severity not in ("critical", "high", "medium", "low"):
            ai_severity = candidate.severity

        # Guardrail: severity > medium needs 2+ signals
        final_severity = self._apply_severity_guardrail(
            candidate.severity, ai_severity, candidate.source,
        )

        return candidate.model_copy(update={
            "ai_explanation": (data.get("ai_explanation") or data.get("explanation") or "")[:2000],
            "fix_code": data.get("fix_code", candidate.fix_code),
            "confidence": min(1.0, max(0.0, data.get("confidence", candidate.confidence))),
            "severity": final_severity,
            "source": "corroborated" if candidate.source == "static" else "ai",
        })

    @staticmethod
    def _apply_severity_guardrail(
        static_severity: str,
        ai_severity: str,
        source: str,
    ) -> str:
        """Guardrail §5.1: severity > medium requires 2+ signals.

        If only one signal (static OR AI, not both) suggests high/critical,
        cap at medium.
        """
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # Both agree on high+ → keep it
        if severity_rank.get(static_severity, 3) <= 1 and severity_rank.get(ai_severity, 3) <= 1:
            # Pick the higher severity
            return static_severity if severity_rank[static_severity] <= severity_rank[ai_severity] else ai_severity

        # Only one says high+ → cap at the lower of the two, but at least medium
        if severity_rank.get(ai_severity, 3) <= 1 and severity_rank.get(static_severity, 3) > 1:
            return "medium"
        if severity_rank.get(static_severity, 3) <= 1 and severity_rank.get(ai_severity, 3) > 1:
            return "medium"

        # Both medium or lower — use the higher
        if severity_rank.get(static_severity, 3) <= severity_rank.get(ai_severity, 3):
            return static_severity
        return ai_severity
