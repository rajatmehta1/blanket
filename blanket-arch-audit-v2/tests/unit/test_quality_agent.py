"""Tests for QualityAgent — complexity, long functions, coverage, guardrails."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit2.agents.quality_agent import (
    DEFAULT_COMPLEXITY_THRESHOLDS,
    QualityAgent,
    _is_generated,
    _is_test_file,
    _get_threshold,
    _reset_counter,
)
from blanketaudit2.config import Settings, get_settings
from blanketaudit2.llm.resilience import CircuitBreaker
from blanketaudit2.models.finding import AuditFinding, Evidence


# ── Helpers ──────────────────────────────────────────────────


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(llm={"provider": "none"})


def _mock_llm(response: str = "{}"):
    mock = AsyncMock()
    resp = MagicMock()
    resp.content = response
    resp.usage_metadata = {"input_tokens": 500, "output_tokens": 200}
    mock.ainvoke = AsyncMock(return_value=resp)
    mock.model_name = "test"
    mock.model = "test"
    mock.provider = "test"
    return mock


def _method(
    name: str = "process",
    file_path: str = "src/service.py",
    complexity: int = 5,
    loc: int = 20,
    line_start: int = 1,
    line_end: int = 20,
) -> dict:
    return {
        "name": name,
        "qualified_name": name,
        "file_path": file_path,
        "repo_name": "api",
        "line_start": line_start,
        "line_end": line_end,
        "complexity": complexity,
        "loc": loc,
        "parameters": [],
        "return_type": "",
        "decorators": [],
        "is_entry_point": False,
    }


def _state_with_methods(methods: list[dict]) -> dict:
    return {
        "repo_paths": [{"repo_name": "api", "local_path": "/tmp"}],
        "files": [],
        "analysis_contexts": [{"methods": methods, "classes": [], "imports": []}],
    }


def _candidate(
    policy_id: str = "QUAL-001",
    title: str = "High complexity",
) -> AuditFinding:
    return AuditFinding(
        id="BLK-001", policy_id=policy_id,
        title=title, description="Quality finding",
        severity="medium", category="quality",
        confidence=0.8, source="static",
        evidence=[Evidence(
            file_path="src/service.py", repo_name="api",
            line_start=1, line_end=50,
            code_snippet="def process(): ...", tool="ast",
        )],
        compliance_refs=[], ai_explanation="", fix_code="",
        remediation="", effort_hours=0, dollar_impact="",
    )


# ═══════════════════════════════════════════════════════════════
# Guardrails
# ═══════════════════════════════════════════════════════════════


class TestGuardrails:
    def test_test_file_detected_prefix(self):
        assert _is_test_file("test_service.py")

    def test_test_file_detected_suffix(self):
        assert _is_test_file("service_test.py")

    def test_test_file_js_spec(self):
        assert _is_test_file("component.spec.ts")

    def test_test_file_js_test(self):
        assert _is_test_file("utils.test.js")

    def test_test_file_directory(self):
        assert _is_test_file("tests/unit/test_auth.py")

    def test_test_file_java(self):
        assert _is_test_file("UserServiceTest.java")

    def test_test_file_conftest(self):
        assert _is_test_file("conftest.py")

    def test_normal_file_not_test(self):
        assert not _is_test_file("src/service.py")

    def test_generated_detected(self):
        assert _is_generated("proto/user_pb2.py")

    def test_migration_detected(self):
        assert _is_generated("alembic/versions/001.py")

    def test_normal_not_generated(self):
        assert not _is_generated("src/models.py")


class TestThresholds:
    def test_python_default(self):
        assert _get_threshold("python") == 15

    def test_go_higher_default(self):
        assert _get_threshold("go") == 20

    def test_custom_threshold(self):
        assert _get_threshold("python", {"python": 10}) == 10

    def test_unknown_language_default(self):
        assert _get_threshold("cobol") == 15


# ═══════════════════════════════════════════════════════════════
# Complexity checks
# ═══════════════════════════════════════════════════════════════


class TestComplexityChecks:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_flags_high_complexity(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([
            _method("complex_func", "src/service.py", complexity=20),
        ])
        findings = agent._check_complexity(state, "api")
        assert len(findings) == 1
        assert "complexity=20" in findings[0].title
        assert findings[0].policy_id == "QUAL-001"

    @pytest.mark.asyncio
    async def test_skips_below_threshold(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([
            _method("simple_func", "src/util.py", complexity=5),
        ])
        findings = agent._check_complexity(state, "api")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_skips_test_files(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([
            _method("test_complex", "tests/test_service.py", complexity=25),
        ])
        findings = agent._check_complexity(state, "api")
        assert len(findings) == 0  # Test files skipped

    @pytest.mark.asyncio
    async def test_skips_generated_code(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([
            _method("gen_func", "proto/user_pb2.py", complexity=50),
        ])
        findings = agent._check_complexity(state, "api")
        assert len(findings) == 0  # Generated code skipped

    @pytest.mark.asyncio
    async def test_custom_threshold(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(complexity_thresholds={"python": 10}, llm=None)

        state = _state_with_methods([
            _method("medium_func", "src/service.py", complexity=12),
        ])
        findings = agent._check_complexity(state, "api")
        assert len(findings) == 1  # 12 > custom threshold 10

    @pytest.mark.asyncio
    async def test_go_higher_threshold(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([
            _method("go_func", "cmd/main.go", complexity=18),
        ])
        findings = agent._check_complexity(state, "api")
        assert len(findings) == 0  # 18 < Go threshold 20


# ═══════════════════════════════════════════════════════════════
# Long function checks
# ═══════════════════════════════════════════════════════════════


class TestLongFunctionChecks:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_flags_long_function(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([
            _method("huge_func", "src/service.py", loc=80),
        ])
        findings = agent._check_long_functions(state, "api")
        assert len(findings) == 1
        assert "80 LOC" in findings[0].title

    @pytest.mark.asyncio
    async def test_skips_short_function(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([_method("short", "src/util.py", loc=10)])
        findings = agent._check_long_functions(state, "api")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_skips_test_file_long_function(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([_method("test_big", "tests/test_main.py", loc=100)])
        findings = agent._check_long_functions(state, "api")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_custom_loc_threshold(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(loc_threshold=30, llm=None)

        state = _state_with_methods([_method("medium", "src/app.py", loc=40)])
        findings = agent._check_long_functions(state, "api")
        assert len(findings) == 1


# ═══════════════════════════════════════════════════════════════
# AI analysis
# ═══════════════════════════════════════════════════════════════


class TestQualityAI:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_enriches_real_issue(self):
        llm = _mock_llm(json.dumps({
            "is_real_issue": True,
            "confidence": 0.9,
            "explanation": "This function handles too many responsibilities.",
            "fix_code": "Split into process_input() and process_output()",
            "effort_hours": 3.0,
            "priority": "medium",
        }))
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = QualityAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis({}, [_candidate()])
        assert result is not None
        assert len(result) == 1
        assert result[0].effort_hours == 3.0
        assert result[0].source == "corroborated"

    @pytest.mark.asyncio
    async def test_filters_false_positive(self):
        llm = _mock_llm(json.dumps({
            "is_real_issue": False,
            "explanation": "This complexity is inherent to the algorithm.",
        }))
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = QualityAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis({}, [_candidate()])
        assert result is None or len(result) == 0

    @pytest.mark.asyncio
    async def test_invalid_json_keeps_candidate(self):
        llm = _mock_llm("Free text quality assessment.")
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = QualityAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis({}, [_candidate()])
        assert result is not None
        assert "Free text" in result[0].ai_explanation

    @pytest.mark.asyncio
    async def test_empty_candidates(self):
        agent = QualityAgent(llm=_mock_llm())
        result = await agent.run_ai_analysis({}, [])
        assert result == []


# ═══════════════════════════════════════════════════════════════
# Full execute
# ═══════════════════════════════════════════════════════════════


class TestQualityAgentExecute:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_execute_static_only(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        state = _state_with_methods([
            _method("complex_func", "src/service.py", complexity=20, loc=80),
        ])

        result = await agent.execute(state)
        assert isinstance(result, list)
        assert len(result) >= 2  # Complexity + long function
        for f in result:
            assert f.category == "quality"

    @pytest.mark.asyncio
    async def test_execute_empty_state(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = QualityAgent(llm=None)

        result = await agent.execute({
            "repo_paths": [], "files": [], "analysis_contexts": [],
        })
        assert isinstance(result, list)
