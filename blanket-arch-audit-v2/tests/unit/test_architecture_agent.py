"""Tests for ArchitectureAgent — cycles, layers, God classes, guardrails."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit2.agents.architecture_agent import (
    ArchitectureAgent,
    _is_generated,
    _is_monorepo_cross_package,
    _reset_counter,
    infer_layer,
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


def _candidate(
    policy_id: str = "ARCH-001",
    title: str = "Circular dependency",
    file_path: str = "src/service.py",
) -> AuditFinding:
    return AuditFinding(
        id="BLK-001", policy_id=policy_id,
        title=title, description="Architecture finding",
        severity="high", category="architecture",
        confidence=0.8, source="static",
        evidence=[Evidence(
            file_path=file_path, repo_name="api",
            line_start=1, line_end=10,
            code_snippet="from routes import handler", tool="dep_graph",
        )],
        compliance_refs=[], ai_explanation="", fix_code="",
        remediation="", effort_hours=0, dollar_impact="",
    )


# ═══════════════════════════════════════════════════════════════
# Layer inference
# ═══════════════════════════════════════════════════════════════


class TestInferLayer:
    def test_routes_is_presentation(self):
        assert infer_layer("src/routes/users.py") == "presentation"

    def test_controllers_is_presentation(self):
        assert infer_layer("app/controllers/UserController.java") == "presentation"

    def test_handlers_is_presentation(self):
        assert infer_layer("src/handlers/auth.py") == "presentation"

    def test_services_is_business(self):
        assert infer_layer("src/services/payment.py") == "business"

    def test_repositories_is_data(self):
        assert infer_layer("src/repositories/user_repo.py") == "data"

    def test_db_is_data(self):
        assert infer_layer("src/db/models.py") == "data"

    def test_config_is_infrastructure(self):
        assert infer_layer("src/config/settings.py") == "infrastructure"

    def test_utils_is_infrastructure(self):
        assert infer_layer("src/utils/helpers.py") == "infrastructure"

    def test_unknown_path(self):
        assert infer_layer("main.py") == "unknown"


# ═══════════════════════════════════════════════════════════════
# Guardrails
# ═══════════════════════════════════════════════════════════════


class TestGeneratedCodeGuardrail:
    def test_protobuf_is_generated(self):
        assert _is_generated("proto/user_pb2.py")

    def test_grpc_is_generated(self):
        assert _is_generated("proto/user_pb2_grpc.py")

    def test_codegen_is_generated(self):
        assert _is_generated("generated/codegen/models.py")

    def test_migration_is_generated(self):
        assert _is_generated("alembic/versions/001_init.py")

    def test_minified_is_generated(self):
        assert _is_generated("dist/app.min.js")

    def test_vendor_is_generated(self):
        assert _is_generated("vendor/lib/something.go")

    def test_normal_source_not_generated(self):
        assert not _is_generated("src/service.py")

    def test_dts_is_generated(self):
        assert _is_generated("types/api.d.ts")


class TestMonorepoGuardrail:
    def test_cross_package_detected(self):
        assert _is_monorepo_cross_package(
            "packages/api/src/service.py",
            "packages/shared/src/utils.py",
        )

    def test_cross_service_detected(self):
        assert _is_monorepo_cross_package(
            "services/auth/handler.py",
            "services/payment/client.py",
        )

    def test_same_dir_not_cross_package(self):
        assert not _is_monorepo_cross_package(
            "src/service.py",
            "src/utils.py",
        )

    def test_libs_detected(self):
        assert _is_monorepo_cross_package(
            "libs/crypto/encrypt.py",
            "libs/auth/token.py",
        )


# ═══════════════════════════════════════════════════════════════
# Static checks
# ═══════════════════════════════════════════════════════════════


class TestArchitectureStaticChecks:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_detects_circular_deps(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": "/tmp"}],
            "files": [
                {"path": "a.py", "language": "python"},
                {"path": "b.py", "language": "python"},
            ],
            "analysis_contexts": [{
                "imports": [
                    {"source_file": "a.py", "imported_module": "b"},
                    {"source_file": "b.py", "imported_module": "a"},
                ],
                "classes": [],
            }],
        }

        findings = await agent.run_static_checks(state)
        cycle_findings = [f for f in findings if f.policy_id == "ARCH-001"]
        assert len(cycle_findings) >= 1
        assert "circular" in cycle_findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_detects_layer_violation(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": "/tmp"}],
            "files": [
                {"path": "db/repo.py", "language": "python"},
                {"path": "routes/api.py", "language": "python"},
            ],
            "analysis_contexts": [{
                "imports": [
                    {"source_file": "db/repo.py", "imported_module": "routes.api"},
                ],
                "classes": [],
            }],
        }

        findings = await agent.run_static_checks(state)
        violation_findings = [f for f in findings if f.policy_id == "ARCH-003"]
        assert len(violation_findings) >= 1
        assert "layer violation" in violation_findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_skips_generated_code_in_cycles(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": "/tmp"}],
            "files": [
                {"path": "proto/user_pb2.py"},
                {"path": "proto/service_pb2.py"},
            ],
            "analysis_contexts": [{
                "imports": [
                    {"source_file": "proto/user_pb2.py", "imported_module": "proto.service_pb2"},
                    {"source_file": "proto/service_pb2.py", "imported_module": "proto.user_pb2"},
                ],
                "classes": [],
            }],
        }

        findings = await agent.run_static_checks(state)
        cycle_findings = [f for f in findings if f.policy_id == "ARCH-001"]
        assert len(cycle_findings) == 0  # Generated code skipped

    @pytest.mark.asyncio
    async def test_skips_monorepo_cross_package_violations(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "mono", "local_path": "/tmp"}],
            "files": [
                {"path": "packages/db/repo.py"},
                {"path": "packages/api/routes.py"},
            ],
            "analysis_contexts": [{
                "imports": [
                    {"source_file": "packages/db/repo.py",
                     "imported_module": "packages.api.routes"},
                ],
                "classes": [],
            }],
        }

        findings = await agent.run_static_checks(state)
        violations = [f for f in findings if f.policy_id == "ARCH-003"]
        assert len(violations) == 0  # Monorepo cross-package is OK

    @pytest.mark.asyncio
    async def test_detects_god_class(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": "/tmp"}],
            "files": [{"path": "src/mega.py"}],
            "analysis_contexts": [{
                "imports": [],
                "classes": [{
                    "name": "MegaClass",
                    "file_path": "src/mega.py",
                    "methods": [f"method_{i}" for i in range(25)],
                    "loc": 800,
                    "line_start": 1,
                    "line_end": 800,
                }],
            }],
        }

        findings = await agent.run_static_checks(state)
        god_findings = [f for f in findings if f.policy_id == "ARCH-002"]
        assert len(god_findings) == 1
        assert "God class" in god_findings[0].title
        assert "25 methods" in god_findings[0].title

    @pytest.mark.asyncio
    async def test_skips_generated_god_class(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": "/tmp"}],
            "files": [],
            "analysis_contexts": [{
                "imports": [],
                "classes": [{
                    "name": "GeneratedProto",
                    "file_path": "proto/user_pb2.py",  # Generated!
                    "methods": [f"m{i}" for i in range(30)],
                    "loc": 1000,
                    "line_start": 1, "line_end": 1000,
                }],
            }],
        }

        findings = await agent.run_static_checks(state)
        god_findings = [f for f in findings if f.policy_id == "ARCH-002"]
        assert len(god_findings) == 0  # Generated code skipped

    @pytest.mark.asyncio
    async def test_empty_state(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)
        findings = await agent.run_static_checks({
            "repo_paths": [], "files": [], "analysis_contexts": [],
        })
        assert isinstance(findings, list)


# ═══════════════════════════════════════════════════════════════
# AI analysis
# ═══════════════════════════════════════════════════════════════


class TestArchitectureAI:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_enriches_real_issue(self):
        llm = _mock_llm(json.dumps({
            "is_real_issue": True,
            "confidence": 0.9,
            "explanation": "Circular dependency creates tight coupling.",
            "fix_suggestion": "Extract shared interface.",
            "effort_hours": 4.0,
        }))
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ArchitectureAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis({}, [_candidate()])
        assert result is not None
        assert len(result) == 1
        assert result[0].ai_explanation == "Circular dependency creates tight coupling."
        assert result[0].effort_hours == 4.0
        assert result[0].source == "corroborated"

    @pytest.mark.asyncio
    async def test_filters_false_positive(self):
        llm = _mock_llm(json.dumps({
            "is_real_issue": False,
            "confidence": 0.3,
            "explanation": "Intentional design decision.",
            "fix_suggestion": "",
            "effort_hours": 0,
        }))
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ArchitectureAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis({}, [_candidate()])
        assert result is None or len(result) == 0

    @pytest.mark.asyncio
    async def test_invalid_json_keeps_candidate(self):
        llm = _mock_llm("Free-form architecture analysis text.")
        cb = CircuitBreaker(failure_threshold=5)
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ArchitectureAgent(llm=llm, circuit_breaker=cb)

        result = await agent.run_ai_analysis({}, [_candidate()])
        assert result is not None
        assert len(result) == 1
        assert "Free-form" in result[0].ai_explanation

    @pytest.mark.asyncio
    async def test_empty_candidates(self):
        agent = ArchitectureAgent(llm=_mock_llm())
        result = await agent.run_ai_analysis({}, [])
        assert result == []


# ═══════════════════════════════════════════════════════════════
# Full execute
# ═══════════════════════════════════════════════════════════════


class TestArchitectureAgentExecute:
    @pytest.fixture(autouse=True)
    def reset(self):
        _reset_counter(0)

    @pytest.mark.asyncio
    async def test_execute_static_only(self):
        with patch("blanketaudit2.agents.base_agent.get_llm_for_agent", return_value=None):
            agent = ArchitectureAgent(llm=None)

        state = {
            "repo_paths": [{"repo_name": "api", "local_path": "/tmp"}],
            "files": [],
            "analysis_contexts": [{
                "imports": [
                    {"source_file": "a.py", "imported_module": "b"},
                    {"source_file": "b.py", "imported_module": "a"},
                ],
                "classes": [],
            }],
        }

        result = await agent.execute(state)
        assert isinstance(result, list)
        for f in result:
            assert f.category == "architecture"
