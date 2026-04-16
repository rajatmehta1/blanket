"""Common agent execution pattern — static → AI → validate.

Design doc §5: ALL agents follow this template method.
1. Run deterministic tools FIRST (static_checks from policies)
2. Feed candidates into LLM for contextual reasoning
3. Validate output through OutputValidator (correction cycle)
4. Return list[AuditFinding]
5. If LLM unavailable: return static-only findings (no crash)
"""

from __future__ import annotations

import abc
import time
from typing import Any

import structlog

from blanketaudit.exceptions import BudgetExceededError, CircuitOpenError
from blanketaudit.llm.cost_tracker import CostTracker, TokenBudget
from blanketaudit.llm.provider import get_llm_for_agent
from blanketaudit.llm.resilience import CircuitBreaker
from blanketaudit.metrics import record_llm_call, set_scan_context
from blanketaudit.models.finding import AuditFinding
from blanketaudit.orchestrator.state import AuditState

logger = structlog.get_logger()


class BaseAgent(abc.ABC):
    """Base class for all analysis agents.

    Subclasses override ``run_static_checks`` and ``run_ai_analysis``.
    The ``execute`` method implements the template:
    static → (optional AI) → return findings.
    """

    def __init__(
        self,
        agent_name: str,
        *,
        llm: Any | None = None,
        cost_tracker: CostTracker | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self.name = agent_name
        self._llm = llm  # Lazy-loaded if None
        self.cost_tracker = cost_tracker
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self._budget: TokenBudget | None = None

    @property
    def llm(self) -> Any:
        """Lazy-load the LLM on first access."""
        if self._llm is None:
            self._llm = get_llm_for_agent(self.name)
        return self._llm

    def set_budget(self, budget: TokenBudget) -> None:
        self._budget = budget

    # ── Template method ──────────────────────────────────────

    async def execute(self, state: AuditState) -> list[AuditFinding]:
        """Run the full agent pipeline: static → AI → return.

        Never raises — errors are logged and static results returned.
        """
        set_scan_context(agent=self.name)
        start = time.perf_counter()

        logger.info(f"agent.{self.name}.start")

        # Step 1: Static checks (always run, even without LLM)
        try:
            candidates = await self.run_static_checks(state)
        except Exception as exc:
            logger.error(
                f"agent.{self.name}.static_failed",
                error=str(exc)[:200],
            )
            candidates = []

        logger.info(
            f"agent.{self.name}.static_done",
            candidates=len(candidates),
        )

        # Step 2: AI reasoning (if LLM available and budget allows)
        # PRIORITY: Sort candidates so critical/high are enriched first.
        # If budget runs out, low-severity findings degrade gracefully to static-only.
        if self._should_run_ai():
            candidates = self._prioritize_for_ai(candidates)
            try:
                enriched = await self.run_ai_analysis(state, candidates)
                if enriched is not None:
                    candidates = enriched
                    logger.info(
                        f"agent.{self.name}.ai_done",
                        findings=len(candidates),
                    )
            except CircuitOpenError as exc:
                logger.warning(
                    f"agent.{self.name}.circuit_open",
                    error=str(exc)[:100],
                )
            except BudgetExceededError as exc:
                logger.warning(
                    f"agent.{self.name}.budget_exceeded",
                    error=str(exc)[:100],
                )
            except Exception as exc:
                logger.warning(
                    f"agent.{self.name}.ai_fallback",
                    error=str(exc)[:200],
                )
                # Fall through — return static-only candidates

        elapsed = time.perf_counter() - start
        logger.info(
            f"agent.{self.name}.complete",
            findings=len(candidates),
            duration_ms=round(elapsed * 1000, 1),
        )
        return candidates

    def _should_run_ai(self) -> bool:
        """Check if AI analysis should run."""
        if self.llm is None:
            return False
        if self._budget and self._budget.is_exhausted:
            logger.info(f"agent.{self.name}.budget_exhausted")
            return False
        if self._budget and self._budget.should_demote:
            logger.info(f"agent.{self.name}.budget_demoting")
            return False
        return True

    @staticmethod
    def _prioritize_for_ai(candidates: list[AuditFinding]) -> list[AuditFinding]:
        """Sort candidates so critical/high findings are enriched first.

        When the token budget is limited, this ensures the most severe
        findings get AI explanations before budget exhaustion.
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            candidates,
            key=lambda f: (
                severity_order.get(f.severity, 4),
                -f.confidence,
            ),
        )

    # ── Abstract methods (override in subclass) ──────────────

    @abc.abstractmethod
    async def run_static_checks(self, state: AuditState) -> list[AuditFinding]:
        """Run deterministic tools. Returns candidate findings."""
        ...

    @abc.abstractmethod
    async def run_ai_analysis(
        self,
        state: AuditState,
        candidates: list[AuditFinding],
    ) -> list[AuditFinding] | None:
        """LLM reasoning on candidates. Returns enriched findings.

        May return None to keep the original candidates.
        """
        ...

    # ── Helpers for subclasses ───────────────────────────────

    def _make_static_finding(
        self,
        *,
        finding_id: str,
        policy_id: str,
        title: str,
        description: str,
        severity: str,
        category: str,
        file_path: str,
        repo_name: str,
        line_start: int,
        line_end: int,
        code_snippet: str,
        tool: str,
        confidence: float = 0.8,
    ) -> AuditFinding:
        """Create a finding from static analysis results."""
        return AuditFinding(
            id=finding_id,
            policy_id=policy_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            confidence=confidence,
            source="static",
            evidence=[{
                "file_path": file_path,
                "repo_name": repo_name,
                "line_start": line_start,
                "line_end": line_end,
                "code_snippet": code_snippet,
                "tool": tool,
            }],
            compliance_refs=[],
            ai_explanation="",
            fix_code="",
            remediation="",
            effort_hours=0.0,
            dollar_impact="",
        )

    @staticmethod
    def _findings_to_dicts(findings: list[AuditFinding]) -> list[dict]:
        return [f.model_dump() for f in findings]
