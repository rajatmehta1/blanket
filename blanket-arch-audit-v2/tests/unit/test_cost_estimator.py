"""Tests for blanketaudit2.orchestrator.cost_estimator."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from blanketaudit2.config import Settings, get_settings
from blanketaudit2.ingestion.models import FileMetadata, FileType
from blanketaudit2.orchestrator.cost_estimator import (
    CostEstimate,
    CostEstimator,
    _estimate_file_input_tokens,
    format_estimate_table,
)


# ── Helpers ──────────────────────────────────────────────────


def _settings(**overrides) -> Settings:
    get_settings.cache_clear()
    defaults = {
        "llm": {"provider": "anthropic", "model": "", "compliance_model": ""},
        "cost": {"max_scan_cost_usd": 15.0},
        "agents": {
            "security": {"enabled": True},
            "compliance": {"enabled": True},
            "architecture": {"enabled": True},
            "quality": {"enabled": True},
        },
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _file(
    path: str = "src/main.py",
    loc: int = 200,
    size_bytes: int = 8000,
    file_type: FileType = FileType.SOURCE,
) -> FileMetadata:
    return FileMetadata(
        path=path, repo_name="api", language="python",
        loc=loc, file_type=file_type, size_bytes=size_bytes,
    )


# ── Token estimation heuristic ───────────────────────────────


class TestEstimateFileInputTokens:
    def test_from_size_bytes(self):
        f = _file(size_bytes=4000, loc=0)
        tokens = _estimate_file_input_tokens(f)
        # 4000 / 4 + 500 overhead = 1500
        assert tokens == 1500

    def test_from_loc_fallback(self):
        f = _file(size_bytes=0, loc=100)
        tokens = _estimate_file_input_tokens(f)
        # 100 * 40 / 4 + 500 = 1500
        assert tokens == 1500

    def test_minimum_for_empty_file(self):
        f = _file(size_bytes=0, loc=0)
        tokens = _estimate_file_input_tokens(f)
        # 200 + 500 = 700
        assert tokens == 700

    def test_larger_file_more_tokens(self):
        small = _estimate_file_input_tokens(_file(size_bytes=1000))
        large = _estimate_file_input_tokens(_file(size_bytes=20000))
        assert large > small


# ── CostEstimator ────────────────────────────────────────────


class TestCostEstimator:
    def _estimator(self, settings=None, cached=None):
        s = settings or _settings()
        with patch("blanketaudit2.orchestrator.cost_estimator.get_settings", return_value=s):
            return CostEstimator(
                max_scan_cost_usd=s.cost.max_scan_cost_usd,
                cached_file_paths=cached or set(),
            )

    def _run(self, estimator, files, tiers):
        with patch("blanketaudit2.orchestrator.cost_estimator.get_settings",
                    return_value=_settings()):
            return estimator.estimate(files, tiers)

    def test_basic_estimate(self):
        est = self._estimator()
        files = [_file(path=f"f{i}.py") for i in range(10)]
        tiers = {f"f{i}.py": 1 for i in range(10)}
        result = est.estimate(files, tiers)

        assert isinstance(result, CostEstimate)
        assert result.total_estimated_usd > 0
        assert result.total_estimated_tokens > 0
        assert result.file_tier_breakdown["tier1"] == 10
        assert result.total_files == 10
        assert len(result.per_agent) == 4  # All 4 agents

    def test_tier3_files_cost_zero(self):
        est = self._estimator()
        files = [_file(path=f"f{i}.py") for i in range(10)]
        tiers = {f"f{i}.py": 3 for i in range(10)}
        result = est.estimate(files, tiers)

        assert result.total_estimated_usd == 0.0
        assert result.total_estimated_tokens == 0

    def test_tier2_costs_less_than_tier1(self):
        est = self._estimator()
        files = [_file(path="a.py", size_bytes=10000)]
        tier1_result = est.estimate(files, {"a.py": 1})
        tier2_result = est.estimate(files, {"a.py": 2})

        assert tier1_result.total_estimated_usd > tier2_result.total_estimated_usd

    def test_cached_files_excluded(self):
        est = self._estimator(cached={"a.py", "b.py"})
        files = [_file(path="a.py"), _file(path="b.py"), _file(path="c.py")]
        tiers = {"a.py": 1, "b.py": 1, "c.py": 1}
        result = est.estimate(files, tiers)

        assert result.cached_files == 2
        # Only c.py contributes to cost
        est_uncached = self._estimator(cached=set())
        result_all = est_uncached.estimate(files, tiers)
        assert result.total_estimated_usd < result_all.total_estimated_usd

    def test_no_files_zero_cost(self):
        est = self._estimator()
        result = est.estimate([], {})
        assert result.total_estimated_usd == 0.0
        assert result.total_estimated_tokens == 0
        assert result.total_files == 0

    def test_model_routing_compliance_gets_higher_model(self):
        est = self._estimator()
        files = [_file()]
        result = est.estimate(files, {"src/main.py": 1})

        routing = result.model_routing
        assert "compliance" in routing
        assert "security" in routing
        # Compliance should get opus, security should get sonnet
        assert "opus" in routing["compliance"]
        assert "sonnet" in routing["security"]

    def test_model_routing_with_overrides(self):
        s = _settings(llm={
            "provider": "anthropic",
            "model": "",
            "compliance_model": "",
            "agent_model_overrides": {"security": "claude-haiku-4-5-20251001"},
        })
        est = self._estimator(settings=s)
        files = [_file()]
        with patch("blanketaudit2.orchestrator.cost_estimator.get_settings", return_value=s):
            result = est.estimate(files, {"src/main.py": 1})
        assert result.model_routing["security"] == "claude-haiku-4-5-20251001"

    def test_per_agent_breakdown(self):
        est = self._estimator()
        files = [_file(path=f"f{i}.py", size_bytes=5000) for i in range(5)]
        tiers = {f"f{i}.py": 1 for i in range(5)}
        result = est.estimate(files, tiers)

        assert len(result.per_agent) == 4
        total_from_agents = sum(a.estimated_usd for a in result.per_agent)
        assert abs(total_from_agents - result.total_estimated_usd) < 0.01

    def test_total_loc_computed(self):
        files = [_file(path="a.py", loc=100), _file(path="b.py", loc=200)]
        est = self._estimator()
        result = est.estimate(files, {"a.py": 1, "b.py": 2})
        assert result.total_loc == 300

    def test_mixed_tiers(self):
        est = self._estimator()
        files = [
            _file(path="a.py"),  # tier 1
            _file(path="b.py"),  # tier 2
            _file(path="c.py"),  # tier 3
        ]
        tiers = {"a.py": 1, "b.py": 2, "c.py": 3}
        result = est.estimate(files, tiers)
        assert result.file_tier_breakdown == {"tier1": 1, "tier2": 1, "tier3": 1}
        assert result.total_estimated_usd > 0  # tier1 + tier2 contribute


# ── Recommendations ──────────────────────────────────────────


class TestRecommendations:
    def _estimate_with_cost(self, total_usd, max_cost):
        s = _settings(
            llm={"provider": "anthropic", "model": ""},
            cost={"max_scan_cost_usd": max_cost},
        )
        with patch("blanketaudit2.orchestrator.cost_estimator.get_settings", return_value=s):
            est = CostEstimator(max_scan_cost_usd=max_cost)
            return est._make_recommendation(total_usd)

    def test_within_budget(self):
        rec = self._estimate_with_cost(5.0, 15.0)
        assert "Within budget" in rec or "within budget" in rec.lower()

    def test_well_within_budget(self):
        rec = self._estimate_with_cost(3.0, 15.0)
        assert "Well within budget" in rec

    def test_over_budget(self):
        rec = self._estimate_with_cost(20.0, 15.0)
        assert "Over budget" in rec

    def test_no_limit_set(self):
        rec = self._estimate_with_cost(50.0, 0.0)
        assert "no budget limit" in rec.lower()

    def test_no_llm_provider(self):
        s = _settings(llm={"provider": "none"})
        with patch("blanketaudit2.orchestrator.cost_estimator.get_settings", return_value=s):
            est = CostEstimator()
            rec = est._make_recommendation(0.0)
        assert "free" in rec.lower() or "static" in rec.lower()


# ── Disabled agents ──────────────────────────────────────────


class TestDisabledAgents:
    def test_disabled_agent_excluded(self):
        s = _settings(agents={
            "security": {"enabled": True},
            "compliance": {"enabled": False},
            "architecture": {"enabled": False},
            "quality": {"enabled": False},
        })
        with patch("blanketaudit2.orchestrator.cost_estimator.get_settings", return_value=s):
            est = CostEstimator(max_scan_cost_usd=15.0)
            files = [_file()]
            result = est.estimate(files, {"src/main.py": 1})
        assert len(result.per_agent) == 1
        assert result.per_agent[0].agent == "security"

    def test_all_agents_disabled_zero_cost(self):
        s = _settings(agents={
            "security": {"enabled": False},
            "compliance": {"enabled": False},
            "architecture": {"enabled": False},
            "quality": {"enabled": False},
        })
        with patch("blanketaudit2.orchestrator.cost_estimator.get_settings", return_value=s):
            est = CostEstimator(max_scan_cost_usd=15.0)
            result = est.estimate([_file()], {"src/main.py": 1})
        assert result.total_estimated_usd == 0.0
        assert result.per_agent == []


# ── Table formatter ──────────────────────────────────────────


class TestFormatEstimateTable:
    def test_produces_output(self):
        from blanketaudit2.orchestrator.cost_estimator import AgentCostEstimate
        estimate = CostEstimate(
            total_estimated_usd=8.50,
            per_agent=[
                AgentCostEstimate(agent="security", model="claude-sonnet-4-20250514",
                                   input_tokens=100000, output_tokens=50000, estimated_usd=2.10),
                AgentCostEstimate(agent="compliance", model="claude-opus-4-20250514",
                                   input_tokens=80000, output_tokens=40000, estimated_usd=6.40),
            ],
            total_estimated_tokens=270000,
            file_tier_breakdown={"tier1": 120, "tier2": 230, "tier3": 497},
            model_routing={"security": "claude-sonnet-4-20250514", "compliance": "claude-opus-4-20250514"},
            cached_files=42,
            total_files=847,
            total_loc=62000,
            recommendation="Within budget ($8.50 of $15.00)",
        )
        table = format_estimate_table(estimate)
        assert "BlanketAudit" in table
        assert "8.50" in table
        assert "Tier 1" in table
        assert "security" in table
        assert "compliance" in table
        assert "Within budget" in table
        assert "Cached" in table

    def test_no_cached_files_hides_line(self):
        from blanketaudit2.orchestrator.cost_estimator import AgentCostEstimate
        estimate = CostEstimate(
            total_estimated_usd=0.0,
            per_agent=[],
            total_estimated_tokens=0,
            file_tier_breakdown={"tier1": 0, "tier2": 0, "tier3": 10},
            model_routing={},
            cached_files=0,
            total_files=10,
            total_loc=500,
            recommendation="Free",
        )
        table = format_estimate_table(estimate)
        assert "Cached" not in table
