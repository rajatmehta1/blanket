"""Tests for blanketaudit2.llm.cost_tracker."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from blanketaudit2.config import Settings, get_settings
from blanketaudit2.exceptions import BudgetExceededError
from blanketaudit2.llm.cost_tracker import (
    PRICING,
    CallRecord,
    CostTracker,
    TokenBudget,
    _FALLBACK_PRICING,
    _get_pricing,
    count_tokens,
)


# ── Helpers ──────────────────────────────────────────────────


def _settings(**cost_overrides) -> Settings:
    get_settings.cache_clear()
    cost = {"max_scan_cost_usd": 15.0, "per_agent_token_budget": 500_000, **cost_overrides}
    return Settings(llm={"provider": "none"}, cost=cost)


# ── Pricing lookup ───────────────────────────────────────────


class TestPricing:
    def test_known_model(self):
        inp, out = _get_pricing("claude-sonnet-4-20250514")
        assert inp == 3.0
        assert out == 15.0

    def test_prefix_match(self):
        # A hypothetical variant should still match.
        inp, out = _get_pricing("gpt-4o-mini-2025-01-01")
        assert inp == 0.15
        assert out == 0.60

    def test_unknown_model_returns_fallback(self):
        assert _get_pricing("totally-unknown-model") == _FALLBACK_PRICING

    def test_local_model_is_free(self):
        inp, out = _get_pricing("llama3.1")
        assert inp == 0.0
        assert out == 0.0


# ── Token counting ───────────────────────────────────────────


class TestCountTokens:
    def test_returns_positive_int(self):
        n = count_tokens("Hello, world!")
        assert isinstance(n, int)
        assert n > 0

    def test_empty_string(self):
        # Empty string has minimal tokens.
        n = count_tokens("")
        assert n >= 0

    def test_longer_text_has_more_tokens(self):
        short = count_tokens("hi")
        long = count_tokens("This is a much longer sentence with many more words.")
        assert long > short

    def test_fallback_when_tiktoken_unavailable(self):
        with patch.dict("sys.modules", {"tiktoken": None}):
            # Clear the cached encodings so it tries to reimport.
            from blanketaudit2.llm import cost_tracker
            old = cost_tracker._encodings.copy()
            cost_tracker._encodings.clear()
            try:
                n = count_tokens("Hello, world!", model="nonexistent")
                # Heuristic: len("Hello, world!") // 4 = 3
                assert n >= 1
            finally:
                cost_tracker._encodings.update(old)


# ── TokenBudget ──────────────────────────────────────────────


class TestTokenBudget:
    def test_initial_state(self):
        b = TokenBudget(agent_name="security", max_tokens=100_000)
        assert b.used_tokens == 0
        assert b.remaining == 100_000
        assert b.percent_used == 0.0
        assert not b.should_demote
        assert not b.is_exhausted

    def test_consume_updates_counts(self):
        b = TokenBudget(agent_name="security", max_tokens=1000)
        ok = b.consume(input_tokens=300, output_tokens=200)
        assert ok is True
        assert b.used_tokens == 500
        assert b.used_input == 300
        assert b.used_output == 200
        assert b.remaining == 500

    def test_should_demote_at_80_percent(self):
        b = TokenBudget(agent_name="security", max_tokens=1000)
        b.consume(799, 0)
        assert not b.should_demote
        b.consume(1, 0)
        assert b.should_demote

    def test_is_exhausted_at_100_percent(self):
        b = TokenBudget(agent_name="security", max_tokens=1000)
        b.consume(500, 400)
        assert not b.is_exhausted
        ok = b.consume(0, 100)
        assert b.is_exhausted
        assert ok is False

    def test_consume_returns_false_when_exceeded(self):
        b = TokenBudget(agent_name="security", max_tokens=100)
        ok = b.consume(200, 0)
        assert ok is False

    def test_zero_budget(self):
        b = TokenBudget(agent_name="test", max_tokens=0)
        assert b.percent_used == 1.0
        assert b.is_exhausted
        assert b.should_demote


# ── CostTracker ──────────────────────────────────────────────


class TestCostTracker:
    def test_from_settings(self):
        with patch("blanketaudit2.llm.cost_tracker.get_settings") as mock_gs:
            mock_gs.return_value = _settings(max_scan_cost_usd=25.0)
            tracker = CostTracker.from_settings()
        assert tracker.max_scan_cost_usd == 25.0

    def test_create_agent_budget(self):
        with patch("blanketaudit2.llm.cost_tracker.get_settings") as mock_gs:
            mock_gs.return_value = _settings(per_agent_token_budget=200_000)
            tracker = CostTracker(max_scan_cost_usd=15.0)
            budget = tracker.create_agent_budget("security")
        assert budget.max_tokens == 200_000
        assert "security" in tracker.agent_budgets

    def test_create_agent_budget_custom_limit(self):
        with patch("blanketaudit2.llm.cost_tracker.get_settings") as mock_gs:
            mock_gs.return_value = _settings()
            tracker = CostTracker(max_scan_cost_usd=15.0)
            budget = tracker.create_agent_budget("compliance", max_tokens=1_000_000)
        assert budget.max_tokens == 1_000_000

    def test_record_call_updates_totals(self):
        tracker = CostTracker(max_scan_cost_usd=100.0)
        tracker.record_call("security", "gpt-4o-mini", input_tokens=1000, output_tokens=500)

        assert tracker.total_input_tokens == 1000
        assert tracker.total_output_tokens == 500
        assert tracker.total_tokens == 1500
        assert tracker.call_count == 1
        # gpt-4o-mini: (0.15 * 1000 + 0.60 * 500) / 1_000_000
        expected_cost = (0.15 * 1000 + 0.60 * 500) / 1_000_000
        assert abs(tracker.total_cost_usd - expected_cost) < 1e-9

    def test_record_call_updates_agent_budget(self):
        with patch("blanketaudit2.llm.cost_tracker.get_settings") as mock_gs:
            mock_gs.return_value = _settings()
            tracker = CostTracker(max_scan_cost_usd=100.0)
            tracker.create_agent_budget("security", max_tokens=10_000)

        tracker.record_call("security", "gpt-4o-mini", input_tokens=3000, output_tokens=2000)
        budget = tracker.agent_budgets["security"]
        assert budget.used_tokens == 5000
        assert budget.percent_used == 0.5

    def test_record_call_raises_on_budget_exceeded(self):
        tracker = CostTracker(max_scan_cost_usd=0.001, abort_on_budget=True)
        # A call with an expensive model will blow the tiny budget.
        with pytest.raises(BudgetExceededError, match="exceeds limit"):
            tracker.record_call(
                "compliance", "claude-opus-4-20250514",
                input_tokens=100_000, output_tokens=50_000,
            )

    def test_no_raise_when_abort_disabled(self):
        tracker = CostTracker(max_scan_cost_usd=0.001, abort_on_budget=False)
        # Should NOT raise even though budget is exceeded.
        tracker.record_call(
            "compliance", "claude-opus-4-20250514",
            input_tokens=100_000, output_tokens=50_000,
        )
        assert tracker.total_cost_usd > 0.001

    def test_no_raise_when_max_cost_is_zero(self):
        tracker = CostTracker(max_scan_cost_usd=0.0, abort_on_budget=True)
        # max=0 means unlimited.
        tracker.record_call("security", "gpt-4o", input_tokens=1_000_000, output_tokens=500_000)
        assert tracker.total_cost_usd > 0

    def test_agent_cost(self):
        tracker = CostTracker(max_scan_cost_usd=100.0)
        tracker.record_call("security", "gpt-4o-mini", input_tokens=1000, output_tokens=500)
        tracker.record_call("compliance", "gpt-4o", input_tokens=1000, output_tokens=500)
        tracker.record_call("security", "gpt-4o-mini", input_tokens=2000, output_tokens=1000)

        sec_cost = tracker.agent_cost("security")
        comp_cost = tracker.agent_cost("compliance")
        assert sec_cost > 0
        assert comp_cost > 0
        assert abs(sec_cost + comp_cost - tracker.total_cost_usd) < 1e-9

    def test_summary(self):
        with patch("blanketaudit2.llm.cost_tracker.get_settings") as mock_gs:
            mock_gs.return_value = _settings()
            tracker = CostTracker(max_scan_cost_usd=15.0)
            tracker.create_agent_budget("security", max_tokens=10_000)

        tracker.record_call("security", "gpt-4o-mini", input_tokens=5000, output_tokens=3000)
        s = tracker.summary()

        assert s["total_tokens"] == 8000
        assert s["call_count"] == 1
        assert s["max_scan_cost_usd"] == 15.0
        assert "security" in s["per_agent"]
        assert s["per_agent"]["security"]["used_tokens"] == 8000
        assert s["per_agent"]["security"]["should_demote"] is True  # 80% of 10k

    def test_multiple_calls_accumulate(self):
        tracker = CostTracker(max_scan_cost_usd=100.0)
        for _ in range(5):
            tracker.record_call("security", "gpt-4o-mini", input_tokens=100, output_tokens=50)
        assert tracker.call_count == 5
        assert tracker.total_input_tokens == 500
        assert tracker.total_output_tokens == 250


# ── Dry-run estimation ───────────────────────────────────────


class TestEstimateScanCost:
    def test_basic_estimation(self):
        tracker = CostTracker(max_scan_cost_usd=15.0)
        result = tracker.estimate_scan_cost(
            file_tiers={1: 100, 2: 200, 3: 500},
            model_routing={
                "security": "claude-sonnet-4-20250514",
                "compliance": "claude-opus-4-20250514",
            },
        )
        assert "estimated_cost_usd" in result
        assert "per_agent" in result
        assert "total_tokens" in result
        assert "tier_breakdown" in result
        assert "within_budget" in result
        assert result["estimated_cost_usd"] >= 0
        assert result["total_tokens"] > 0

    def test_tier3_only_is_free(self):
        tracker = CostTracker(max_scan_cost_usd=15.0)
        result = tracker.estimate_scan_cost(
            file_tiers={1: 0, 2: 0, 3: 500},
            model_routing={"security": "llama3.1"},
        )
        assert result["estimated_cost_usd"] == 0.0
        assert result["total_tokens"] == 0

    def test_within_budget_flag(self):
        tracker = CostTracker(max_scan_cost_usd=0.01)
        result = tracker.estimate_scan_cost(
            file_tiers={1: 1000, 2: 0, 3: 0},
            model_routing={"compliance": "claude-opus-4-20250514"},
        )
        assert result["within_budget"] is False

    def test_unlimited_budget(self):
        tracker = CostTracker(max_scan_cost_usd=0.0)
        result = tracker.estimate_scan_cost(
            file_tiers={1: 1000},
            model_routing={"security": "claude-opus-4-20250514"},
        )
        assert result["within_budget"] is True
