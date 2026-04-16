"""Code quality agent — complexity + dead code + coverage → AI assessment.

Design doc §5.4: analyse code quality metrics and use AI to estimate
tech debt hours and refactoring priority.

Guardrails:
- Don't flag test files for complexity
- Don't flag generated code (protobuf, codegen, migrations)
- Configurable complexity thresholds per language
"""

from __future__ import annotations

import json
import re
from typing import Any

import structlog

from blanketaudit2.agents.base_agent import BaseAgent
from blanketaudit2.llm.guardrails import INJECTION_DEFENSE_PREFIX, wrap_code_content
from blanketaudit2.llm.resilience import safe_llm_call
from blanketaudit2.models.finding import AuditFinding
from blanketaudit2.orchestrator.state import AuditState

logger = structlog.get_logger()

# ── Complexity thresholds per language ───────────────────────

DEFAULT_COMPLEXITY_THRESHOLDS: dict[str, int] = {
    "python": 15,
    "java": 15,
    "typescript": 15,
    "javascript": 15,
    "go": 20,       # Go tends to have more explicit error handling branches
    "rust": 20,
    "csharp": 15,
}

DEFAULT_LOC_THRESHOLD = 50  # Functions >50 LOC flagged

# ── Generated / test file patterns ───────────────────────────

_GENERATED_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"_pb2\.py$", r"_pb2_grpc\.py$", r"\.generated\.",
        r"codegen", r"auto.?gen", r"migration", r"alembic/versions",
        r"\.min\.(js|css)$", r"\.d\.ts$", r"vendor/", r"node_modules/",
    )
]

_TEST_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"test_", r"_test\.", r"\.test\.", r"\.spec\.",
        r"tests[/\\]", r"__tests__[/\\]", r"Test\.java$",
        r"conftest\.py$", r"fixtures?[/\\]",
    )
]

# Finding ID counter
_COUNTER = 0


def _next_id() -> str:
    global _COUNTER
    _COUNTER += 1
    return f"BLK-{_COUNTER:03d}"


def _reset_counter(start: int = 0) -> None:
    global _COUNTER
    _COUNTER = start


def _is_generated(path: str) -> bool:
    return any(p.search(path) for p in _GENERATED_PATTERNS)


def _is_test_file(path: str) -> bool:
    return any(p.search(path) for p in _TEST_PATTERNS)


def _get_threshold(language: str, thresholds: dict[str, int] | None = None) -> int:
    t = thresholds or DEFAULT_COMPLEXITY_THRESHOLDS
    return t.get(language, 15)


class QualityAgent(BaseAgent):
    """Code quality analysis agent.

    Static: complexity per function, dead code detection, coverage parsing,
    silent exceptions, long functions, quality policy checks.
    AI: tech debt estimation, refactoring priority, maintainability assessment.
    """

    def __init__(
        self,
        complexity_thresholds: dict[str, int] | None = None,
        loc_threshold: int = DEFAULT_LOC_THRESHOLD,
        **kwargs: Any,
    ) -> None:
        super().__init__("quality", **kwargs)
        self._complexity_thresholds = complexity_thresholds or DEFAULT_COMPLEXITY_THRESHOLDS
        self._loc_threshold = loc_threshold

    # ── Static checks ────────────────────────────────────────

    async def run_static_checks(self, state: AuditState) -> list[AuditFinding]:
        """Run quality static analysis.

        1. Flag high-complexity functions
        2. Flag long functions (>50 LOC)
        3. Detect silent exception handling
        4. Parse coverage reports (if available)
        5. Run quality policy YAML checks
        """
        findings: list[AuditFinding] = []
        repo_name = ""
        if state.get("repo_paths"):
            repo_name = state["repo_paths"][0].get("repo_name", "")

        # From analysis contexts: complexity + long functions
        findings.extend(self._check_complexity(state, repo_name))
        findings.extend(self._check_long_functions(state, repo_name))

        # Coverage report analysis
        findings.extend(await self._check_coverage(state, repo_name))

        # Quality policy checks
        findings.extend(await self._run_policy_checks(state))

        logger.info("quality_agent.static_done", findings=len(findings))
        return findings

    def _check_complexity(self, state: AuditState, repo_name: str) -> list[AuditFinding]:
        """Flag functions with cyclomatic complexity above threshold."""
        findings: list[AuditFinding] = []

        for ctx in state.get("analysis_contexts", []):
            methods = ctx.get("methods", []) if isinstance(ctx, dict) else getattr(ctx, "methods", [])

            for m in methods:
                fp = m.get("file_path", "") if isinstance(m, dict) else getattr(m, "file_path", "")
                complexity = m.get("complexity", 0) if isinstance(m, dict) else getattr(m, "complexity", 0)
                name = m.get("qualified_name", "") if isinstance(m, dict) else getattr(m, "qualified_name", "")
                lang = self._infer_language(fp)
                threshold = _get_threshold(lang, self._complexity_thresholds)

                if _is_generated(fp) or _is_test_file(fp):
                    continue

                if complexity > threshold:
                    line_start = m.get("line_start", 1) if isinstance(m, dict) else getattr(m, "line_start", 1)
                    line_end = m.get("line_end", 1) if isinstance(m, dict) else getattr(m, "line_end", 1)

                    findings.append(self._make_static_finding(
                        finding_id=_next_id(),
                        policy_id="QUAL-001",
                        title=f"High complexity: {name} (complexity={complexity}, threshold={threshold})",
                        description=(
                            f"Function {name} has cyclomatic complexity {complexity}, "
                            f"exceeding the threshold of {threshold} for {lang or 'default'}. "
                            f"Consider splitting into smaller functions."
                        ),
                        severity="medium",
                        category="quality",
                        file_path=fp,
                        repo_name=repo_name,
                        line_start=line_start,
                        line_end=line_end,
                        code_snippet=f"{name}: complexity={complexity}",
                        tool="ast",
                        confidence=0.9,
                    ))

        return findings

    def _check_long_functions(self, state: AuditState, repo_name: str) -> list[AuditFinding]:
        """Flag functions exceeding the LOC threshold."""
        findings: list[AuditFinding] = []

        for ctx in state.get("analysis_contexts", []):
            methods = ctx.get("methods", []) if isinstance(ctx, dict) else getattr(ctx, "methods", [])

            for m in methods:
                fp = m.get("file_path", "") if isinstance(m, dict) else getattr(m, "file_path", "")
                loc = m.get("loc", 0) if isinstance(m, dict) else getattr(m, "loc", 0)
                name = m.get("qualified_name", "") if isinstance(m, dict) else getattr(m, "qualified_name", "")

                if _is_generated(fp) or _is_test_file(fp):
                    continue

                if loc > self._loc_threshold:
                    line_start = m.get("line_start", 1) if isinstance(m, dict) else getattr(m, "line_start", 1)
                    line_end = m.get("line_end", 1) if isinstance(m, dict) else getattr(m, "line_end", 1)

                    findings.append(self._make_static_finding(
                        finding_id=_next_id(),
                        policy_id="QUAL-018",
                        title=f"Long function: {name} ({loc} LOC)",
                        description=(
                            f"Function {name} is {loc} lines long, exceeding the "
                            f"{self._loc_threshold}-line threshold. Long functions are "
                            f"harder to understand, test, and maintain."
                        ),
                        severity="medium",
                        category="quality",
                        file_path=fp,
                        repo_name=repo_name,
                        line_start=line_start,
                        line_end=line_end,
                        code_snippet=f"{name}: {loc} LOC",
                        tool="ast",
                        confidence=0.85,
                    ))

        return findings

    async def _check_coverage(self, state: AuditState, repo_name: str) -> list[AuditFinding]:
        """Parse coverage reports and flag low-coverage files."""
        findings: list[AuditFinding] = []

        for repo in state.get("repo_paths", []):
            local_path = repo.get("local_path", "")
            if not local_path:
                continue

            try:
                from blanketaudit2.agents.tools.coverage_tool import parse_coverage_report
                result_json = parse_coverage_report(local_path)
                result = json.loads(result_json)

                if "error" in result:
                    continue

                overall = result.get("overall_percent", 100)
                if overall < 50:
                    findings.append(self._make_static_finding(
                        finding_id=_next_id(),
                        policy_id="QUAL-003",
                        title=f"Low test coverage: {overall:.0f}%",
                        description=(
                            f"Overall test coverage is {overall:.0f}%, below the "
                            f"recommended 50% minimum. Critical paths may be untested."
                        ),
                        severity="medium",
                        category="quality",
                        file_path="coverage.xml",
                        repo_name=repo_name,
                        line_start=1, line_end=1,
                        code_snippet=f"Overall coverage: {overall:.0f}%",
                        tool="coverage",
                        confidence=0.95,
                    ))

            except Exception as exc:
                logger.debug("quality_agent.coverage_skipped", error=str(exc)[:100])

        return findings

    async def _run_policy_checks(self, state: AuditState) -> list[AuditFinding]:
        """Run quality policy YAML checks."""
        findings: list[AuditFinding] = []
        try:
            from blanketaudit2.policies.engine import PolicyEngine
            from pathlib import Path

            engine = PolicyEngine()
            policy_dir = Path(__file__).parent.parent / "policies" / "quality"
            if not policy_dir.exists():
                return findings

            policies = engine.load_policies(policy_dir)
            file_contents = self._load_file_contents(state)
            repo_name = ""
            if state.get("repo_paths"):
                repo_name = state["repo_paths"][0].get("repo_name", "")

            for policy in policies:
                candidates = engine.execute_static_checks(policy, file_contents)
                for c in candidates:
                    if _is_generated(c.file_path):
                        continue
                    findings.append(self._make_static_finding(
                        finding_id=_next_id(),
                        policy_id=policy.id,
                        title=policy.name,
                        description=policy.description or policy.name,
                        severity=policy.severity,
                        category="quality",
                        file_path=c.file_path,
                        repo_name=repo_name,
                        line_start=c.line_start,
                        line_end=c.line_end,
                        code_snippet=c.code_snippet[:500],
                        tool=c.tool,
                        confidence=0.7,
                    ))
        except Exception as exc:
            logger.warning("quality_agent.policy_failed", error=str(exc)[:200])

        return findings

    # ── AI analysis ──────────────────────────────────────────

    async def run_ai_analysis(
        self,
        state: AuditState,
        candidates: list[AuditFinding],
    ) -> list[AuditFinding] | None:
        """AI assessment: tech debt hours, refactoring priority."""
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
                    "quality_agent.ai_one_failed",
                    finding_id=candidate.id,
                    error=str(exc)[:200],
                )
                enriched.append(candidate)

        return enriched if enriched else None

    async def _analyze_one(
        self,
        state: AuditState,
        candidate: AuditFinding,
    ) -> AuditFinding:
        """AI analysis for one quality finding."""
        from langchain_core.messages import HumanMessage, SystemMessage

        evidence = candidate.evidence[0] if candidate.evidence else None
        code_context = evidence.code_snippet if evidence else ""
        file_path = evidence.file_path if evidence else ""

        system_prompt = (
            f"{INJECTION_DEFENSE_PREFIX}\n\n"
            "You are a code reviewer assessing quality and maintainability.\n"
            "Respond with JSON: {\"is_real_issue\": bool, \"confidence\": float, "
            "\"explanation\": str, \"fix_code\": str, \"effort_hours\": float, "
            "\"priority\": \"high|medium|low\"}\n"
            "Consider: is this a real maintainability concern or acceptable?\n"
            "Don't flag test code or generated code.\n"
        )

        user_prompt = (
            f"Quality finding: {candidate.title}\n"
            f"Policy: {candidate.policy_id}\n"
            f"File: {file_path}\n"
            f"Code:\n{wrap_code_content(code_context, file_path)}\n"
            "Assess the quality impact and suggest improvements."
        )

        response = await safe_llm_call(
            self.llm,
            [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)],
            agent_name=self.name,
            cost_tracker=self.cost_tracker,
            circuit_breaker=self.circuit_breaker,
        )

        return self._parse_ai_response(candidate, response.content)

    def _parse_ai_response(
        self,
        candidate: AuditFinding,
        response_text: str,
    ) -> AuditFinding | None:
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            return candidate.model_copy(update={
                "ai_explanation": response_text[:2000],
                "source": "ai",
            })

        if not data.get("is_real_issue", True):
            logger.info("quality_agent.false_positive", finding_id=candidate.id)
            return None

        return candidate.model_copy(update={
            "ai_explanation": data.get("explanation", "")[:2000],
            "fix_code": data.get("fix_code", candidate.fix_code),
            "effort_hours": data.get("effort_hours", candidate.effort_hours),
            "confidence": min(1.0, max(0.0, data.get("confidence", candidate.confidence))),
            "source": "corroborated" if candidate.source == "static" else "ai",
        })

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _infer_language(file_path: str) -> str:
        ext_map = {
            ".py": "python", ".java": "java", ".ts": "typescript",
            ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
            ".go": "go", ".rs": "rust", ".cs": "csharp",
        }
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        return ""

    @staticmethod
    def _load_file_contents(state: AuditState) -> dict[str, str]:
        from pathlib import Path
        contents: dict[str, str] = {}
        for repo in state.get("repo_paths", []):
            local_path = Path(repo.get("local_path", ""))
            if not local_path.exists():
                continue
            for f in state.get("files", []):
                fp = local_path / f.get("path", "")
                if fp.exists() and fp.stat().st_size < 500_000:
                    try:
                        contents[f["path"]] = fp.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        pass
        return contents
