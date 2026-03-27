"""Tests for BaseAgent pattern and SecurityAgent.

Uses mock LLM and tool outputs — no real API calls.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit.agents.base_agent import BaseAgent
from blanketaudit.agents.security_agent import SecurityAgent, _reset_counter
from blanketaudit.config import Settings, get_settings
from blanketaudit.exceptions import BudgetExceededError, CircuitOpenError
from blanketaudit.llm.cost_tracker import TokenBudget
from blanketaudit.llm.resilience import CircuitBreaker
from blanketaudit.models.finding import AuditFinding


# ── Helpers ──────────────────────────────────────────────────


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(llm={"provider": "none"})


def _mock_llm(response_text: str = '{"is_true_positive": true, "confidence": 0.9, "explanation": "Confirmed SQL injection.", "fix_code": "use params", "severity": "critical"}'):
    """Create a mock LLM that returns the given JSON."""
    mock = AsyncMock()
    resp = MagicMock()
    resp.content = response_text
    resp.usage_metadata = {"input_tokens": 500, "output_tokens": 200}
    mock.ainvoke = AsyncMock(return_value=resp)
    mock.model_name = "test-model"
    mock.model = "test-model"
    mock.provider = "test"
    return mock


def _sample_state(repo_path: str = "/tmp/repo") -> dict:
    return {
        "repo_paths": [{"repo_name": "api", "local_path": repo_path}],
        "files": [],
        "file_tiers": {},
    }


def _semgrep_result() -> dict:
    return {
        "tool": "semgrep",
        "rule_id": "python.lang.security.audit.formatted-sql-query",
        "file_path": "src/db.py",
        "line_start": 15,
        "line_end": 15,
        "message": "SQL injection via f-string",
        "severity": "high",
        "code_snippet": 'f"SELECT * FROM users WHERE id={uid}"',
    }


def _gitleaks_result() -> dict:
    return {
        "tool": "gitleaks",
        "rule_id": "generic-api-key",
        "file_path": "config.py",
        "line_start": 5,
        "line_end": 5,
        "message": "Secret detected: API key",
        "severity": "high",
        "code_snippet": 'API_KEY = "sk-1234"',
    }


def _osv_result() -> dict:
    return {
        "tool": "osv",
        "vuln_id": "GHSA-abcd-1234",
        "file_path": "requirements.txt",
        "line_start": 1,
        "line_end": 1,
        "message": "XSS in flask debugger",
        "severity": "high",
        "code_snippet": "flask@2.0.0",
    }


# ═══════════════════════════════════════════════════════════════
# BaseAgent — template method pattern
# ═══════════════════════════════════════════════════════════════


class ConcreteAgent(BaseAgent):
    """Test implementation of BaseAgent."""

    def __init__(self, static_results=None, ai_results=None, ai_error=None, **kwargs):
        super().__init__("test", **kwargs)
        self._static = static_results or []
        self._ai = ai_results
        self._ai_error = ai_error

    async def run_static_checks(self, state):
        return self._static

    async def run_ai_analysis(self, state, candidates):
        if self._ai_error:
            raise self._ai_error
        return self._ai


class TestBaseAgent:
    @pytest.mark.asyncio
    async def test_static_only_when_no_llm(self):
        findings = [MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(static_results=findings, llm=None)
        result = await agent.execute({})
        assert result == findings

    @pytest.mark.asyncio
    async def test_ai_enriches_candidates(self):
        static = [MagicMock(spec=AuditFinding)]
        enriched = [MagicMock(spec=AuditFinding), MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(static_results=static, ai_results=enriched, llm=_mock_llm())
        result = await agent.execute({})
        assert result == enriched

    @pytest.mark.asyncio
    async def test_ai_failure_falls_back_to_static(self):
        static = [MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(
            static_results=static,
            ai_error=RuntimeError("LLM down"),
            llm=_mock_llm(),
        )
        result = await agent.execute({})
        assert result == static

    @pytest.mark.asyncio
    async def test_circuit_open_falls_back(self):
        static = [MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(
            static_results=static,
            ai_error=CircuitOpenError("open"),
            llm=_mock_llm(),
        )
        result = await agent.execute({})
        assert result == static

    @pytest.mark.asyncio
    async def test_budget_exceeded_falls_back(self):
        static = [MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(
            static_results=static,
            ai_error=BudgetExceededError("over"),
            llm=_mock_llm(),
        )
        result = await agent.execute({})
        assert result == static

    @pytest.mark.asyncio
    async def test_skips_ai_when_budget_exhausted(self):
        static = [MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(
            static_results=static,
            ai_results=[],  # Should NOT be called
            llm=_mock_llm(),
        )
        budget = TokenBudget(agent_name="test", max_tokens=100)
        budget.consume(200, 0)  # Exhaust it
        agent.set_budget(budget)
        result = await agent.execute({})
        assert result == static

    @pytest.mark.asyncio
    async def test_skips_ai_when_budget_should_demote(self):
        static = [MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(
            static_results=static,
            ai_results=[],
            llm=_mock_llm(),
        )
        budget = TokenBudget(agent_name="test", max_tokens=100)
        budget.consume(85, 0)  # 85% → should_demote
        agent.set_budget(budget)
        result = await agent.execute({})
        assert result == static

    @pytest.mark.asyncio
    async def test_static_failure_returns_empty(self):
        class FailAgent(BaseAgent):
            async def run_static_checks(self, state):
                raise RuntimeError("parse error")
            async def run_ai_analysis(self, state, candidates):
                return candidates
        agent = FailAgent("fail", llm=None)
        result = await agent.execute({})
        assert result == []

    @pytest.mark.asyncio
    async def test_ai_returns_none_keeps_static(self):
        static = [MagicMock(spec=AuditFinding)]
        agent = ConcreteAgent(
            static_results=static,
            ai_results=None,  # None means "keep originals"
            llm=_mock_llm(),
        )
        result = await agent.execute({})
        assert result == static


# ═══════════════════════════════════════════════════════════════
# SecurityAgent — static checks
# ═══════════════════════════════════════════════════════════════


class TestSecurityAgentStatic:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_runs_all_three_tools(self):
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = SecurityAgent(llm=None)

        with patch("blanketaudit.agents.tools.semgrep_tool.run_semgrep",
                    return_value=[_semgrep_result()]), \
             patch("blanketaudit.agents.tools.gitleaks_tool.run_gitleaks",
                    return_value=[_gitleaks_result()]), \
             patch("blanketaudit.agents.tools.osv_tool.run_osv_scan",
                    return_value=[_osv_result()]):
            findings = await agent.run_static_checks(_sample_state())

        assert len(findings) == 3
        tools = {f.evidence[0].tool for f in findings}
        assert tools == {"semgrep", "gitleaks", "osv"}

    @pytest.mark.asyncio
    async def test_tool_failure_does_not_crash(self):
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = SecurityAgent(llm=None)

        with patch("blanketaudit.agents.tools.semgrep_tool.run_semgrep",
                    side_effect=RuntimeError("semgrep broken")), \
             patch("blanketaudit.agents.tools.gitleaks_tool.run_gitleaks",
                    return_value=[_gitleaks_result()]), \
             patch("blanketaudit.agents.tools.osv_tool.run_osv_scan",
                    return_value=[]):
            findings = await agent.run_static_checks(_sample_state())

        assert len(findings) == 1  # Only gitleaks succeeded

    @pytest.mark.asyncio
    async def test_no_repos_returns_empty(self):
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = SecurityAgent(llm=None)
        findings = await agent.run_static_checks({"repo_paths": []})
        assert findings == []

    @pytest.mark.asyncio
    async def test_finding_has_correct_structure(self):
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = SecurityAgent(llm=None)

        with patch("blanketaudit.agents.tools.semgrep_tool.run_semgrep",
                    return_value=[_semgrep_result()]), \
             patch("blanketaudit.agents.tools.gitleaks_tool.run_gitleaks", return_value=[]), \
             patch("blanketaudit.agents.tools.osv_tool.run_osv_scan", return_value=[]):
            findings = await agent.run_static_checks(_sample_state())

        f = findings[0]
        assert f.id.startswith("BLK-")
        assert f.category == "security"
        assert f.source == "static"
        assert len(f.evidence) == 1
        assert f.evidence[0].tool == "semgrep"


# ═══════════════════════════════════════════════════════════════
# SecurityAgent — AI analysis
# ═══════════════════════════════════════════════════════════════


class TestSecurityAgentAI:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    def _make_candidate(self) -> AuditFinding:
        return AuditFinding(
            id="BLK-001", policy_id="SEC-001",
            title="SQL Injection", description="f-string SQL",
            severity="high", category="security",
            confidence=0.7, source="static",
            evidence=[{
                "file_path": "db.py", "repo_name": "api",
                "line_start": 10, "line_end": 10,
                "code_snippet": 'f"SELECT * FROM users WHERE id={uid}"',
                "tool": "semgrep",
            }],
            compliance_refs=[],
            ai_explanation="", fix_code="", remediation="",
            effort_hours=0, dollar_impact="",
        )

    @pytest.mark.asyncio
    async def test_ai_enriches_true_positive(self):
        llm = _mock_llm(json.dumps({
            "is_true_positive": True,
            "confidence": 0.95,
            "explanation": "Confirmed SQL injection via f-string.",
            "fix_code": "cursor.execute(query, (uid,))",
            "severity": "critical",
        }))
        cb = CircuitBreaker(failure_threshold=5)

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = SecurityAgent(llm=llm, circuit_breaker=cb)

        candidate = self._make_candidate()
        result = await agent.run_ai_analysis({}, [candidate])

        assert result is not None
        assert len(result) == 1
        assert result[0].ai_explanation == "Confirmed SQL injection via f-string."
        assert result[0].source == "corroborated"

    @pytest.mark.asyncio
    async def test_ai_filters_false_positive(self):
        llm = _mock_llm(json.dumps({
            "is_true_positive": False,
            "confidence": 0.3,
            "explanation": "This is test code.",
            "fix_code": "",
            "severity": "low",
        }))
        cb = CircuitBreaker(failure_threshold=5)

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = SecurityAgent(llm=llm, circuit_breaker=cb)

        candidate = self._make_candidate()
        result = await agent.run_ai_analysis({}, [candidate])

        # run_ai_analysis returns None when all filtered → base_agent keeps static
        # OR returns an empty list. Either way, no findings pass through.
        assert result is None or len(result) == 0

    @pytest.mark.asyncio
    async def test_empty_candidates_returns_empty(self):
        agent = SecurityAgent(llm=_mock_llm())
        result = await agent.run_ai_analysis({}, [])
        assert result == []


# ═══════════════════════════════════════════════════════════════
# SecurityAgent — severity guardrail
# ═══════════════════════════════════════════════════════════════


class TestSeverityGuardrail:
    def test_both_agree_critical(self):
        result = SecurityAgent._apply_severity_guardrail("critical", "critical", "static")
        assert result == "critical"

    def test_both_agree_high(self):
        result = SecurityAgent._apply_severity_guardrail("high", "high", "static")
        assert result == "high"

    def test_static_high_ai_critical_keeps_critical(self):
        result = SecurityAgent._apply_severity_guardrail("high", "critical", "static")
        assert result == "critical"

    def test_only_ai_says_critical_capped_medium(self):
        result = SecurityAgent._apply_severity_guardrail("medium", "critical", "static")
        assert result == "medium"

    def test_only_static_says_high_capped_medium(self):
        result = SecurityAgent._apply_severity_guardrail("high", "low", "static")
        assert result == "medium"

    def test_both_medium_stays_medium(self):
        result = SecurityAgent._apply_severity_guardrail("medium", "medium", "static")
        assert result == "medium"

    def test_both_low_stays_low(self):
        result = SecurityAgent._apply_severity_guardrail("low", "low", "static")
        assert result == "low"

    def test_medium_and_low(self):
        result = SecurityAgent._apply_severity_guardrail("medium", "low", "static")
        assert result == "medium"


# ═══════════════════════════════════════════════════════════════
# SecurityAgent — full execute (end to end)
# ═══════════════════════════════════════════════════════════════


class TestSecurityAgentExecute:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_execute_static_only(self):
        """No LLM → static-only findings returned."""
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = SecurityAgent(llm=None)

        with patch("blanketaudit.agents.tools.semgrep_tool.run_semgrep",
                    return_value=[_semgrep_result()]), \
             patch("blanketaudit.agents.tools.gitleaks_tool.run_gitleaks", return_value=[]), \
             patch("blanketaudit.agents.tools.osv_tool.run_osv_scan", return_value=[]):
            result = await agent.execute(_sample_state())

        assert len(result) == 1
        assert result[0].source == "static"

    @pytest.mark.asyncio
    async def test_execute_with_ai(self):
        """With LLM → findings enriched by AI."""
        llm = _mock_llm(json.dumps({
            "is_true_positive": True,
            "confidence": 0.9,
            "explanation": "Real SQLi.",
            "fix_code": "params",
            "severity": "high",
        }))
        cb = CircuitBreaker(failure_threshold=5)

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = SecurityAgent(llm=llm, circuit_breaker=cb)

        with patch("blanketaudit.agents.tools.semgrep_tool.run_semgrep",
                    return_value=[_semgrep_result()]), \
             patch("blanketaudit.agents.tools.gitleaks_tool.run_gitleaks", return_value=[]), \
             patch("blanketaudit.agents.tools.osv_tool.run_osv_scan", return_value=[]):
            result = await agent.execute(_sample_state())

        assert len(result) == 1
        assert result[0].ai_explanation == "Real SQLi."
