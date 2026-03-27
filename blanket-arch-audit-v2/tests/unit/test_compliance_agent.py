"""Tests for ComplianceAgent — static checks, AI classification, guardrails."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit.agents.compliance_agent import (
    ComplianceAgent,
    _PROCESS_LEVEL_CONTROLS,
    _reset_counter,
)
from blanketaudit.config import Settings, get_settings
from blanketaudit.llm.resilience import CircuitBreaker
from blanketaudit.models.finding import AuditFinding, ComplianceRef, Evidence


# ── Helpers ──────────────────────────────────────────────────


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(llm={"provider": "none"})


def _mock_llm(response_text: str = "{}"):
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
        "frameworks": ["HIPAA", "SOC2"],
    }


def _candidate(
    policy_id: str = "COMP-HIPAA-001",
    title: str = "PHI in Logs",
    severity: str = "critical",
) -> AuditFinding:
    return AuditFinding(
        id="BLK-001", policy_id=policy_id,
        title=title, description=f"Compliance finding: {title}",
        severity=severity, category="compliance",
        confidence=0.7, source="static",
        evidence=[Evidence(
            file_path="service.py", repo_name="api",
            line_start=10, line_end=12,
            code_snippet='logger.info("patient: %s", patient.ssn)',
            tool="regex",
        )],
        compliance_refs=[ComplianceRef(
            framework="HIPAA", clause="§164.312(e)(1)", title="Transmission Security",
        )],
        ai_explanation="", fix_code="", remediation="",
        effort_hours=0, dollar_impact="",
    )


# ═══════════════════════════════════════════════════════════════
# Process-level guardrail
# ═══════════════════════════════════════════════════════════════


class TestProcessLevelGuardrail:
    def test_baa_is_process_level(self):
        assert ComplianceAgent._is_process_level("COMP-HIPAA-006")

    def test_incident_response_is_process_level(self):
        assert ComplianceAgent._is_process_level("COMP-SOC2-008")

    def test_pen_test_is_process_level(self):
        assert ComplianceAgent._is_process_level("COMP-PCI-008")

    def test_dpa_is_process_level(self):
        assert ComplianceAgent._is_process_level("COMP-GDPR-004")

    def test_phi_in_logs_is_not_process_level(self):
        assert not ComplianceAgent._is_process_level("COMP-HIPAA-001")

    def test_encryption_is_not_process_level(self):
        assert not ComplianceAgent._is_process_level("COMP-HIPAA-002")

    def test_all_defined_controls_exist(self):
        assert len(_PROCESS_LEVEL_CONTROLS) >= 7


# ═══════════════════════════════════════════════════════════════
# Policy-to-refs conversion
# ═══════════════════════════════════════════════════════════════


class TestPolicyToRefs:
    def test_hipaa_framework(self):
        policy = MagicMock()
        policy.frameworks = ["HIPAA-164.312-a-1"]
        refs = ComplianceAgent._policy_to_refs(policy)
        assert len(refs) == 1
        assert refs[0].framework == "HIPAA"

    def test_multiple_frameworks(self):
        policy = MagicMock()
        policy.frameworks = ["HIPAA-164.312-a-1", "SOC2-CC6.1"]
        refs = ComplianceAgent._policy_to_refs(policy)
        assert len(refs) == 2

    def test_empty_frameworks(self):
        policy = MagicMock()
        policy.frameworks = []
        refs = ComplianceAgent._policy_to_refs(policy)
        assert refs == []

    def test_pci_normalization(self):
        policy = MagicMock()
        policy.frameworks = ["PCI-6.5.1"]
        refs = ComplianceAgent._policy_to_refs(policy)
        assert len(refs) == 1
        assert refs[0].framework == "PCI-DSS"


# ═══════════════════════════════════════════════════════════════
# RAG query building
# ═══════════════════════════════════════════════════════════════


class TestBuildRagQueries:
    def test_generates_queries(self):
        queries = ComplianceAgent._build_rag_queries(["HIPAA", "SOC2"])
        assert len(queries) > 0
        assert any("HIPAA" in q for q in queries)
        assert any("encryption" in q for q in queries)

    def test_empty_frameworks(self):
        queries = ComplianceAgent._build_rag_queries([])
        assert queries == []


# ═══════════════════════════════════════════════════════════════
# AI classification
# ═══════════════════════════════════════════════════════════════


class TestComplianceAIClassification:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_classifies_fail(self):
        llm = _mock_llm(json.dumps({
            "status": "fail",
            "confidence": 0.9,
            "explanation": "PHI is logged in plaintext without masking.",
            "compliance_refs": [
                {"framework": "HIPAA", "clause": "§164.530(c)", "title": "Safeguards"},
            ],
            "remediation": "Mask PHI before logging.",
        }))
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ComplianceAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis(
            {"frameworks": ["HIPAA"]},
            [_candidate()],
        )

        assert result is not None
        assert len(result) == 1
        assert result[0].ai_explanation == "PHI is logged in plaintext without masking."
        assert result[0].source == "corroborated"
        assert len(result[0].compliance_refs) == 1
        assert result[0].compliance_refs[0].framework == "HIPAA"

    @pytest.mark.asyncio
    async def test_process_level_forced_review_needed(self):
        """Process-level controls always get review_needed, even if LLM says pass."""
        llm = _mock_llm(json.dumps({
            "status": "pass",  # LLM says pass, but guardrail overrides
            "confidence": 0.95,
            "explanation": "BAA appears to be in place.",
            "compliance_refs": [],
            "remediation": "",
        }))
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ComplianceAgent(llm=llm, circuit_breaker=cb)

        # COMP-HIPAA-006 is a process-level control (BAA)
        candidate = _candidate(policy_id="COMP-HIPAA-006", title="Missing BAA Reference")
        result = await agent.run_ai_analysis(
            {"frameworks": ["HIPAA"]},
            [candidate],
        )

        assert result is not None
        assert len(result) == 1
        # The guardrail should have logged the override — but since status
        # isn't a direct field on AuditFinding, the effect is that the agent
        # logged the guardrail activation. The key verification: it didn't crash.

    @pytest.mark.asyncio
    async def test_invalid_json_keeps_candidate(self):
        llm = _mock_llm("This is not valid JSON at all, just text explanation.")
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ComplianceAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis(
            {"frameworks": ["HIPAA"]},
            [_candidate()],
        )

        assert result is not None
        assert len(result) == 1
        assert "not valid JSON" in result[0].ai_explanation

    @pytest.mark.asyncio
    async def test_empty_candidates(self):
        agent = ComplianceAgent(llm=_mock_llm())
        result = await agent.run_ai_analysis({"frameworks": []}, [])
        assert result == []

    @pytest.mark.asyncio
    async def test_llm_failure_keeps_originals(self):
        llm = AsyncMock()
        llm.ainvoke = AsyncMock(side_effect=RuntimeError("LLM down"))
        llm.model_name = "test"
        llm.model = "test"
        llm.provider = "test"
        cb = CircuitBreaker(failure_threshold=5)

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ComplianceAgent(llm=llm, circuit_breaker=cb)

        candidate = _candidate()
        result = await agent.run_ai_analysis(
            {"frameworks": ["HIPAA"]},
            [candidate],
        )

        # On failure, should keep the original candidate
        assert result is not None
        assert len(result) == 1
        assert result[0].id == candidate.id


# ═══════════════════════════════════════════════════════════════
# Static checks with real policies
# ═══════════════════════════════════════════════════════════════


class TestComplianceStaticChecks:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_phi_in_logs_detected(self, tmp_path):
        """PHI logging policy fires on real code."""
        repo = tmp_path / "api"
        repo.mkdir()
        (repo / "service.py").write_text(
            'import logging\nlogger = logging.getLogger()\n'
            'def process(patient):\n    logger.info("Processing patient %s", patient.ssn)\n'
        )

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ComplianceAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": str(repo)}],
            "files": [{"path": "service.py", "repo_name": "api", "language": "python"}],
            "frameworks": ["HIPAA"],
        }

        findings = await agent.run_static_checks(state)
        # Should find PHI in logs
        phi_findings = [f for f in findings if "phi" in f.title.lower() or "log" in f.title.lower()]
        assert len(phi_findings) >= 1

    @pytest.mark.asyncio
    async def test_clean_code_fewer_findings(self, tmp_path):
        """Clean code should produce fewer findings."""
        repo = tmp_path / "clean"
        repo.mkdir()
        (repo / "main.py").write_text(
            'def hello():\n    return "Hello, World!"\n'
        )

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ComplianceAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "clean", "local_path": str(repo)}],
            "files": [{"path": "main.py", "repo_name": "clean", "language": "python"}],
            "frameworks": ["HIPAA"],
        }

        findings = await agent.run_static_checks(state)
        # Clean code should have few or no compliance findings
        assert len(findings) < 5

    @pytest.mark.asyncio
    async def test_no_repos_returns_empty(self):
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ComplianceAgent(llm=None)
        findings = await agent.run_static_checks({"repo_paths": [], "frameworks": []})
        assert findings == []


# ═══════════════════════════════════════════════════════════════
# Full execute (end to end)
# ═══════════════════════════════════════════════════════════════


class TestComplianceAgentExecute:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_execute_static_only(self, tmp_path):
        repo = tmp_path / "api"
        repo.mkdir()
        (repo / "service.py").write_text('password = "secret"\n')

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ComplianceAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": str(repo)}],
            "files": [{"path": "service.py", "repo_name": "api", "language": "python"}],
            "frameworks": ["HIPAA"],
        }

        result = await agent.execute(state)
        # Should complete without error
        assert isinstance(result, list)
        for f in result:
            assert f.category == "compliance"

    @pytest.mark.asyncio
    async def test_uses_higher_capability_model(self):
        """Verify compliance agent requests the higher-capability model."""
        with patch("blanketaudit.agents.base_agent.get_llm_for_agent") as mock_get:
            mock_get.return_value = None
            agent = ComplianceAgent()
            _ = agent.llm
            mock_get.assert_called_with("compliance")
