"""Final hardening verification — all 10 design doc requirements enforced.

These tests verify structural invariants across the entire codebase,
not just individual module behavior.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

import pytest

SRC = Path(__file__).parent.parent.parent / "blanketaudit"


def _python_files(root: Path = SRC) -> list[Path]:
    return sorted(f for f in root.rglob("*.py") if "__pycache__" not in str(f))


# ═══════════════════════════════════════════════════════════════
# 1. LLM ISOLATION: no direct provider imports outside llm/
# ═══════════════════════════════════════════════════════════════


class TestLLMIsolation:
    FORBIDDEN_IMPORTS = [
        "from anthropic", "import anthropic",
        "from openai", "import openai",
        "from langchain_anthropic", "from langchain_openai",
        "from langchain_groq", "from langchain_google_genai",
        "from langchain_community.chat_models", "from langchain_community.embeddings",
    ]

    def test_no_direct_provider_imports(self):
        """No file outside blanketaudit/llm/ imports provider SDKs directly."""
        violations = []
        llm_dir = SRC / "llm"
        for f in _python_files():
            if llm_dir in f.parents or f.parent == llm_dir:
                continue  # OK inside llm/
            content = f.read_text(encoding="utf-8", errors="replace")
            for forbidden in self.FORBIDDEN_IMPORTS:
                if forbidden in content:
                    violations.append(f"{f.relative_to(SRC)}:{forbidden}")
        assert not violations, f"Direct provider imports found:\n" + "\n".join(violations)


# ═══════════════════════════════════════════════════════════════
# 2. HALLUCINATION GATES: pipeline uses ValidationPipeline
# ═══════════════════════════════════════════════════════════════


class TestHallucinationGates:
    def test_pipeline_validates_findings(self):
        """The orchestrator pipeline calls ValidationPipeline."""
        pipeline_src = (SRC / "orchestrator" / "pipeline.py").read_text(encoding="utf-8")
        assert "ValidationPipeline" in pipeline_src

    def test_report_assembler_validates(self):
        """ReportAssembler runs validation before scoring."""
        assembler_src = (SRC / "scoring" / "report_assembler.py").read_text(encoding="utf-8")
        assert "ValidationPipeline" in assembler_src

    def test_four_gates_in_pipeline(self):
        """ValidationPipeline imports all 4 gates."""
        vp_src = (SRC / "validation" / "pipeline.py").read_text(encoding="utf-8")
        assert "SchemaGate" in vp_src
        assert "EvidenceGate" in vp_src
        assert "ConfidenceGate" in vp_src
        assert "CorroborationGate" in vp_src


# ═══════════════════════════════════════════════════════════════
# 3. COST TRACKING: all LLM calls go through safe_llm_call
# ═══════════════════════════════════════════════════════════════


class TestCostTracking:
    def test_agents_use_safe_llm_call(self):
        """All agents use safe_llm_call, not direct llm.ainvoke."""
        agents_dir = SRC / "agents"
        for f in _python_files(agents_dir):
            if f.name in ("__init__.py", "base_agent.py"):
                continue
            if f.parent.name == "tools":
                continue
            content = f.read_text(encoding="utf-8", errors="replace")
            if "ainvoke" in content:
                assert "safe_llm_call" in content, \
                    f"{f.name} uses ainvoke without safe_llm_call"

    def test_safe_llm_call_has_cost_tracker(self):
        """safe_llm_call accepts cost_tracker parameter."""
        resilience_src = (SRC / "llm" / "resilience.py").read_text(encoding="utf-8")
        assert "cost_tracker" in resilience_src


# ═══════════════════════════════════════════════════════════════
# 4. CIRCUIT BREAKER: all agents have circuit breaker
# ═══════════════════════════════════════════════════════════════


class TestCircuitBreakerUsage:
    def test_base_agent_has_circuit_breaker(self):
        src = (SRC / "agents" / "base_agent.py").read_text(encoding="utf-8")
        assert "CircuitBreaker" in src
        assert "self.circuit_breaker" in src

    def test_all_agents_pass_circuit_breaker(self):
        """Every agent's safe_llm_call includes circuit_breaker."""
        for name in ("security_agent", "compliance_agent", "architecture_agent", "quality_agent"):
            src = (SRC / "agents" / f"{name}.py").read_text(encoding="utf-8")
            assert "circuit_breaker=self.circuit_breaker" in src, \
                f"{name} doesn't pass circuit_breaker to safe_llm_call"


# ═══════════════════════════════════════════════════════════════
# 5. EVIDENCE VERIFICATION: Gate 2 always runs
# ═══════════════════════════════════════════════════════════════


class TestEvidenceVerification:
    def test_evidence_gate_in_pipeline(self):
        src = (SRC / "validation" / "pipeline.py").read_text(encoding="utf-8")
        assert "evidence_gate.validate" in src

    def test_evidence_gate_checks_file_exists(self):
        src = (SRC / "validation" / "gate_evidence.py").read_text(encoding="utf-8")
        assert "file_path" in src
        assert "line_end" in src
        assert "fuzzy" in src.lower() or "fuzz" in src.lower()


# ═══════════════════════════════════════════════════════════════
# 6. PROMPT INJECTION: all prompts have defense
# ═══════════════════════════════════════════════════════════════


class TestPromptInjectionDefense:
    def test_all_system_prompts_have_defense(self):
        prompts_dir = SRC / "llm" / "prompts"
        for f in _python_files(prompts_dir):
            if f.name == "__init__.py":
                continue
            content = f.read_text(encoding="utf-8", errors="replace")
            if "SYSTEM_PROMPT" in content:
                assert "{injection_defense}" in content, \
                    f"{f.name} system prompt missing {{injection_defense}}"

    def test_agents_use_injection_prefix(self):
        """Agent AI analysis methods include INJECTION_DEFENSE_PREFIX."""
        for name in ("security_agent", "compliance_agent", "architecture_agent", "quality_agent"):
            src = (SRC / "agents" / f"{name}.py").read_text(encoding="utf-8")
            assert "INJECTION_DEFENSE_PREFIX" in src, \
                f"{name} doesn't use INJECTION_DEFENSE_PREFIX"


# ═══════════════════════════════════════════════════════════════
# 7. CLEANUP: atexit handler
# ═══════════════════════════════════════════════════════════════


class TestCleanup:
    def test_atexit_registered(self):
        src = (SRC / "llm" / "guardrails.py").read_text(encoding="utf-8")
        assert "atexit.register" in src

    def test_register_cleanup_exists(self):
        from blanketaudit.llm.guardrails import register_cleanup, clear_cleanup_dirs
        clear_cleanup_dirs()
        register_cleanup("/tmp/test")
        from blanketaudit.llm.guardrails import get_registered_cleanup_dirs
        assert len(get_registered_cleanup_dirs()) == 1
        clear_cleanup_dirs()


# ═══════════════════════════════════════════════════════════════
# 8. LOGGING: structured logging with context
# ═══════════════════════════════════════════════════════════════


class TestLogging:
    def test_pipeline_sets_scan_context(self):
        src = (SRC / "orchestrator" / "pipeline.py").read_text(encoding="utf-8")
        assert "set_scan_context" in src
        assert "scan_id" in src

    def test_agents_set_context(self):
        src = (SRC / "agents" / "base_agent.py").read_text(encoding="utf-8")
        assert "set_scan_context" in src

    def test_metrics_module_has_context_vars(self):
        src = (SRC / "metrics.py").read_text(encoding="utf-8")
        assert "_scan_id" in src
        assert "_agent_name" in src


# ═══════════════════════════════════════════════════════════════
# 9. SCAN MANIFEST: every scan records manifest
# ═══════════════════════════════════════════════════════════════


class TestScanManifest:
    def test_pipeline_has_manifest_node(self):
        src = (SRC / "orchestrator" / "pipeline.py").read_text(encoding="utf-8")
        assert "manifest_node" in src
        assert "record_manifest" in src

    def test_manifest_model_has_all_fields(self):
        from blanketaudit.models.manifest import ScanManifest
        fields = ScanManifest.model_fields
        required = {"scan_id", "timestamp", "policy_versions", "prompt_versions",
                     "model_ids", "tool_versions", "repo_commits", "config_hash"}
        assert required.issubset(set(fields.keys()))


# ═══════════════════════════════════════════════════════════════
# 10. GRACEFUL DEGRADATION: everything works without external deps
# ═══════════════════════════════════════════════════════════════


class TestGracefulDegradation:
    @pytest.mark.asyncio
    async def test_graph_store_falls_back(self):
        from unittest.mock import patch
        from blanketaudit.config import get_settings
        get_settings.cache_clear()
        s = Settings(llm={"provider": "none"}, neo4j_password="")
        with patch("blanketaudit.storage.get_settings", return_value=s):
            from blanketaudit.storage import get_graph_store
            from blanketaudit.storage.memory_fallback import InMemoryGraph
            store = await get_graph_store()
            assert isinstance(store, InMemoryGraph)

    @pytest.mark.asyncio
    async def test_scan_store_falls_back(self):
        from unittest.mock import patch
        from blanketaudit.storage.memory_fallback import InMemoryScanStore
        with patch("blanketaudit.storage.sqlite_store.SQLiteStore.connect",
                    side_effect=Exception("no sqlite")):
            from blanketaudit.storage import get_scan_store
            store = await get_scan_store()
            assert isinstance(store, InMemoryScanStore)

    def test_llm_none_returns_none(self):
        from unittest.mock import patch
        from blanketaudit.config import get_settings, Settings
        get_settings.cache_clear()
        s = Settings(llm={"provider": "none"})
        with patch("blanketaudit.llm.provider.get_settings", return_value=s):
            from blanketaudit.llm.provider import get_llm
            assert get_llm() is None

    def test_embeddings_none_returns_none(self):
        from unittest.mock import patch
        from blanketaudit.config import get_settings, Settings
        get_settings.cache_clear()
        s = Settings(embedding={"provider": "none"}, llm={"provider": "none"})
        with patch("blanketaudit.llm.embeddings.get_settings", return_value=s):
            from blanketaudit.llm.embeddings import get_embeddings
            assert get_embeddings() is None

    @pytest.mark.asyncio
    async def test_full_pipeline_no_external_deps(self):
        """Pipeline completes with all external services disabled."""
        from blanketaudit.orchestrator.pipeline import AuditPipeline, SimplePipeline
        from unittest.mock import patch, AsyncMock, MagicMock
        from blanketaudit.config import Settings

        s = Settings(llm={"provider": "none"}, embedding={"provider": "none"}, neo4j_password="")
        pipeline = AuditPipeline()
        pipeline._graph = SimplePipeline(pipeline)

        state = {
            "project_name": "degradation-test",
            "domain": "general",
            "frameworks": [],
            "repo_sources": [{"name": "fixture-secure-clean",
                              "local_path": str(Path(__file__).parent.parent / "fixtures" / "fixture-secure-clean")}],
            "dry_run": False,
            "config": {},
        }

        patches = {
            "blanketaudit.orchestrator.pipeline.get_settings": MagicMock(return_value=s),
            "blanketaudit.orchestrator.cost_estimator.get_settings": MagicMock(return_value=s),
            "blanketaudit.triage.tier_assigner.get_settings": MagicMock(return_value=s),
            "blanketaudit.triage.batch_assembler.get_settings": MagicMock(return_value=s),
            "blanketaudit.agents.tools.semgrep_tool.run_semgrep": AsyncMock(return_value=[]),
            "blanketaudit.agents.tools.gitleaks_tool.run_gitleaks": AsyncMock(return_value=[]),
            "blanketaudit.agents.tools.osv_tool.run_osv_scan": AsyncMock(return_value=[]),
        }

        import contextlib
        cms = [patch(k, v) for k, v in patches.items()]
        with contextlib.ExitStack() as stack:
            for cm in cms:
                stack.enter_context(cm)
            result = await pipeline.run(state)

        assert result["status"] == "completed"
        assert "health_score" in result


# Import needed for the degradation test
from blanketaudit.config import Settings
