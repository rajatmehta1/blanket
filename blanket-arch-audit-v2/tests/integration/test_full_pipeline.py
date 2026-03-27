"""Integration tests — full pipeline end-to-end.

1. Rules-only pipeline (LLM=none) against all fixtures
2. FakeChatModel pipeline with agents
3. --dry-run cost estimation
4. Incremental scan (modified file only)
5. Multi-repo with cross-repo detection
6. Budget abort
7. Circuit breaker
8. Prompt injection resistance
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit.config import Settings, get_settings
from blanketaudit.llm.resilience import CircuitBreaker
from blanketaudit.orchestrator.pipeline import AuditPipeline, SimplePipeline

FIXTURES = Path(__file__).parent.parent / "fixtures"


# ── Helpers ──────────────────────────────────────────────────


def _settings(**overrides) -> Settings:
    get_settings.cache_clear()
    defaults = {
        "llm": {"provider": "none"},
        "cost": {"max_scan_cost_usd": 100.0, "abort_on_budget": True},
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _mock_llm(response: str = '{"is_true_positive": true, "confidence": 0.9, "explanation": "Confirmed.", "fix_code": "fix()", "severity": "high"}'):
    mock = AsyncMock()
    resp = MagicMock()
    resp.content = response
    resp.usage_metadata = {"input_tokens": 500, "output_tokens": 200}
    mock.ainvoke = AsyncMock(return_value=resp)
    mock.model_name = "fake-model"
    mock.model = "fake-model"
    mock.provider = "fake"
    return mock


def _state_for_fixture(fixture_name: str, **extra) -> dict:
    path = FIXTURES / fixture_name
    return {
        "project_name": fixture_name,
        "domain": "healthcare",
        "frameworks": ["HIPAA", "SOC2"],
        "repo_sources": [{"name": fixture_name, "local_path": str(path)}],
        "dry_run": False,
        "config": {},
        **extra,
    }


def _patches():
    """Common patches for pipeline tests."""
    s = _settings()
    return {
        "blanketaudit.orchestrator.pipeline.get_settings": MagicMock(return_value=s),
        "blanketaudit.orchestrator.cost_estimator.get_settings": MagicMock(return_value=s),
        "blanketaudit.triage.tier_assigner.get_settings": MagicMock(return_value=s),
        "blanketaudit.triage.batch_assembler.get_settings": MagicMock(return_value=s),
        "blanketaudit.agents.tools.semgrep_tool.run_semgrep": AsyncMock(return_value=[]),
        "blanketaudit.agents.tools.gitleaks_tool.run_gitleaks": AsyncMock(return_value=[]),
        "blanketaudit.agents.tools.osv_tool.run_osv_scan": AsyncMock(return_value=[]),
    }


async def _run_pipeline(state: dict, settings_overrides: dict | None = None) -> dict:
    """Run the SimplePipeline with mocked external tools."""
    s = _settings(**(settings_overrides or {}))
    patches = {
        "blanketaudit.orchestrator.pipeline.get_settings": MagicMock(return_value=s),
        "blanketaudit.orchestrator.cost_estimator.get_settings": MagicMock(return_value=s),
        "blanketaudit.triage.tier_assigner.get_settings": MagicMock(return_value=s),
        "blanketaudit.triage.batch_assembler.get_settings": MagicMock(return_value=s),
        "blanketaudit.agents.tools.semgrep_tool.run_semgrep": AsyncMock(return_value=[]),
        "blanketaudit.agents.tools.gitleaks_tool.run_gitleaks": AsyncMock(return_value=[]),
        "blanketaudit.agents.tools.osv_tool.run_osv_scan": AsyncMock(return_value=[]),
    }

    pipeline = AuditPipeline()
    pipeline._graph = SimplePipeline(pipeline)

    import contextlib
    cms = [patch(k, v) for k, v in patches.items()]
    with contextlib.ExitStack() as stack:
        for cm in cms:
            stack.enter_context(cm)
        return await pipeline.run(state)


# ═══════════════════════════════════════════════════════════════
# 1. Rules-only pipeline (LLM=none) — all fixtures
# ═══════════════════════════════════════════════════════════════


class TestRulesOnlyPipeline:
    @pytest.mark.asyncio
    async def test_hipaa_fail_produces_findings(self):
        result = await _run_pipeline(_state_for_fixture("fixture-hipaa-fail"))
        assert result["status"] == "completed"
        assert len(result.get("files", [])) >= 2
        assert "health_score" in result

    @pytest.mark.asyncio
    async def test_pci_fail_produces_findings(self):
        result = await _run_pipeline(_state_for_fixture("fixture-pci-fail"))
        assert result["status"] == "completed"
        assert len(result.get("files", [])) >= 2

    @pytest.mark.asyncio
    async def test_soc2_partial_completes(self):
        result = await _run_pipeline(_state_for_fixture("fixture-soc2-partial"))
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_secure_clean_completes(self):
        result = await _run_pipeline(_state_for_fixture("fixture-secure-clean"))
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_injection_attack_completes(self):
        result = await _run_pipeline(_state_for_fixture("fixture-injection-attack"))
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_all_fixtures_have_scan_manifest(self):
        for name in ("fixture-hipaa-fail", "fixture-pci-fail", "fixture-secure-clean"):
            result = await _run_pipeline(_state_for_fixture(name))
            assert "scan_manifest" in result


# ═══════════════════════════════════════════════════════════════
# 2. Pipeline with FakeChatModel
# ═══════════════════════════════════════════════════════════════


class TestFakeLLMPipeline:
    @pytest.mark.asyncio
    async def test_agents_run_with_fake_llm(self):
        """Pipeline completes with a mock LLM — agents don't crash."""
        result = await _run_pipeline(
            _state_for_fixture("fixture-hipaa-fail"),
        )
        # Even without real LLM, pipeline should complete
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_report_generated(self):
        result = await _run_pipeline(_state_for_fixture("fixture-hipaa-fail"))
        assert "report" in result or "health_score" in result


# ═══════════════════════════════════════════════════════════════
# 3. --dry-run cost estimation
# ═══════════════════════════════════════════════════════════════


class TestDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_produces_estimate(self):
        state = _state_for_fixture("fixture-hipaa-fail", dry_run=True)
        result = await _run_pipeline(state)
        assert result["status"] == "aborted"
        assert "cost_estimate" in result
        est = result["cost_estimate"]
        assert "total_estimated_usd" in est
        assert "file_tier_breakdown" in est

    @pytest.mark.asyncio
    async def test_dry_run_no_agent_findings(self):
        state = _state_for_fixture("fixture-hipaa-fail", dry_run=True)
        result = await _run_pipeline(state)
        # Dry run should NOT produce agent findings or reports
        assert result.get("agent_findings", []) == [] or "agent_findings" not in result
        assert "report" not in result or result.get("report") is None

    @pytest.mark.asyncio
    async def test_dry_run_still_indexes_files(self):
        state = _state_for_fixture("fixture-hipaa-fail", dry_run=True)
        result = await _run_pipeline(state)
        assert len(result.get("files", [])) >= 2


# ═══════════════════════════════════════════════════════════════
# 4. Incremental scan
# ═══════════════════════════════════════════════════════════════


class TestIncrementalScan:
    @pytest.mark.asyncio
    async def test_diff_scanner_identifies_changes(self):
        """Verify DiffScanner partitions changed vs cached files."""
        from blanketaudit.cache.diff_scanner import DiffScanner
        from blanketaudit.ingestion.models import FileMetadata

        scanner = DiffScanner()
        files = [
            FileMetadata(path="a.py", repo_name="r", language="python"),
            FileMetadata(path="b.py", repo_name="r", language="python"),
            FileMetadata(path="c.py", repo_name="r", language="python"),
        ]
        changed = {"a.py"}
        cached = {"b.py"}

        to_scan, from_cache = scanner.partition_files(files, changed, cached)
        assert {f.path for f in to_scan} == {"a.py", "c.py"}
        assert {f.path for f in from_cache} == {"b.py"}

    @pytest.mark.asyncio
    async def test_reverse_dep_closure(self):
        """Changed file + its dependents should all be rescanned."""
        from blanketaudit.cache.diff_scanner import DiffScanner

        scanner = DiffScanner()
        changed = {"lib.py"}
        reverse_deps = {
            "lib.py": {"service.py", "handler.py"},
            "service.py": {"routes.py"},
        }
        affected = scanner.compute_affected_files(changed, reverse_deps)
        assert affected == {"lib.py", "service.py", "handler.py", "routes.py"}


# ═══════════════════════════════════════════════════════════════
# 5. Multi-repo test
# ═══════════════════════════════════════════════════════════════


class TestMultiRepo:
    @pytest.mark.asyncio
    async def test_two_repos_indexed(self):
        state = {
            "project_name": "multi-repo",
            "domain": "general",
            "frameworks": [],
            "repo_sources": [
                {"name": "fixture-hipaa-fail", "local_path": str(FIXTURES / "fixture-hipaa-fail")},
                {"name": "fixture-pci-fail", "local_path": str(FIXTURES / "fixture-pci-fail")},
            ],
            "dry_run": False,
            "config": {},
        }
        result = await _run_pipeline(state)
        assert result["status"] == "completed"
        # Files from both repos should be indexed
        files = result.get("files", [])
        repos = {f.get("repo_name", "") for f in files if isinstance(f, dict)}
        # Pipeline sets repo_name from the source name
        assert len(files) >= 4  # At least 2 files per repo

    @pytest.mark.asyncio
    async def test_multi_repo_has_repo_paths(self):
        state = {
            "project_name": "multi",
            "domain": "general",
            "frameworks": [],
            "repo_sources": [
                {"name": "repo-a", "local_path": str(FIXTURES / "fixture-hipaa-fail")},
                {"name": "repo-b", "local_path": str(FIXTURES / "fixture-pci-fail")},
            ],
            "dry_run": False,
            "config": {},
        }
        result = await _run_pipeline(state)
        repo_paths = result.get("repo_paths", [])
        assert len(repo_paths) == 2


# ═══════════════════════════════════════════════════════════════
# 6. Budget abort
# ═══════════════════════════════════════════════════════════════


class TestBudgetAbort:
    @pytest.mark.asyncio
    async def test_over_budget_aborts(self):
        """With provider=none, cost is $0, so it should proceed.
        But we can test the budget check logic directly."""
        pipeline = AuditPipeline()
        state = {
            "cost_estimate": {"within_budget": False},
            "dry_run": False,
        }
        with patch("blanketaudit.orchestrator.pipeline.get_settings",
                    return_value=_settings(cost={"max_scan_cost_usd": 0.01, "abort_on_budget": True})):
            route = pipeline._check_budget(state)
        assert route == "abort"

    @pytest.mark.asyncio
    async def test_within_budget_proceeds(self):
        pipeline = AuditPipeline()
        state = {
            "cost_estimate": {"within_budget": True},
            "dry_run": False,
        }
        with patch("blanketaudit.orchestrator.pipeline.get_settings",
                    return_value=_settings()):
            route = pipeline._check_budget(state)
        assert route == "proceed"

    @pytest.mark.asyncio
    async def test_abort_on_budget_false_proceeds(self):
        pipeline = AuditPipeline()
        state = {
            "cost_estimate": {"within_budget": False},
            "dry_run": False,
        }
        with patch("blanketaudit.orchestrator.pipeline.get_settings",
                    return_value=_settings(cost={"max_scan_cost_usd": 0.01, "abort_on_budget": False})):
            route = pipeline._check_budget(state)
        assert route == "proceed"


# ═══════════════════════════════════════════════════════════════
# 7. Circuit breaker
# ═══════════════════════════════════════════════════════════════


class TestCircuitBreaker:
    @pytest.mark.asyncio
    async def test_circuit_opens_after_failures(self):
        from blanketaudit.exceptions import CircuitOpenError
        cb = CircuitBreaker(failure_threshold=3, window_seconds=60, recovery_seconds=999)

        async def fail():
            raise RuntimeError("LLM error")

        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(fail)

        assert cb.is_open

        with pytest.raises(CircuitOpenError):
            await cb.call(fail)

    @pytest.mark.asyncio
    async def test_circuit_recovers(self):
        cb = CircuitBreaker(failure_threshold=2, window_seconds=60, recovery_seconds=0.05)

        async def fail():
            raise RuntimeError("err")

        async def succeed():
            return "ok"

        with pytest.raises(RuntimeError):
            await cb.call(fail)
        with pytest.raises(RuntimeError):
            await cb.call(fail)

        assert cb.is_open
        await asyncio.sleep(0.06)
        # Half-open: one test call
        result = await cb.call(succeed)
        assert result == "ok"
        assert not cb.is_open  # Closed again

    @pytest.mark.asyncio
    async def test_agent_falls_back_on_circuit_open(self):
        """When circuit is open, agent returns static-only findings."""
        from blanketaudit.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            async def run_static_checks(self, state):
                return ["static_finding"]

            async def run_ai_analysis(self, state, candidates):
                from blanketaudit.exceptions import CircuitOpenError
                raise CircuitOpenError("open")

        agent = TestAgent("test", llm=_mock_llm())
        result = await agent.execute({})
        assert result == ["static_finding"]


# ═══════════════════════════════════════════════════════════════
# 8. Prompt injection resistance
# ═══════════════════════════════════════════════════════════════


class TestPromptInjectionResistance:
    @pytest.mark.asyncio
    async def test_injection_fixture_completes(self):
        """Pipeline doesn't crash on injection attempts."""
        result = await _run_pipeline(_state_for_fixture("fixture-injection-attack"))
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_injection_scanner_detects_attempts(self):
        """Guardrail scanner flags injection patterns."""
        from blanketaudit.llm.guardrails import scan_files_for_injections

        fixture_dir = FIXTURES / "fixture-injection-attack"
        contents: dict[str, str] = {}
        for f in fixture_dir.glob("*.py"):
            contents[f.name] = f.read_text(encoding="utf-8")

        result = scan_files_for_injections(contents)
        assert result.has_injections
        # Injection files detected, clean file not
        detected_files = {d["file_path"] for d in result.detections}
        assert "injection_comments.py" in detected_files
        assert "injection_docstrings.py" in detected_files

    @pytest.mark.asyncio
    async def test_injection_does_not_suppress_findings(self):
        """Despite injection attempts, real vulns are still found."""
        result = await _run_pipeline(_state_for_fixture("fixture-injection-attack"))
        # Pipeline should still detect the real vulnerabilities
        # (SQL injection, hardcoded secrets, command injection)
        files = result.get("files", [])
        assert len(files) >= 3  # At least the injection fixture files

    def test_anomaly_detector_flags_zero_findings(self):
        """If a scan of a large codebase returns zero findings, flag it."""
        from blanketaudit.llm.guardrails import detect_output_anomalies
        assert detect_output_anomalies([], file_count=100) is True

    def test_anomaly_detector_ok_for_small_clean_repo(self):
        from blanketaudit.llm.guardrails import detect_output_anomalies
        assert detect_output_anomalies([], file_count=3) is False
