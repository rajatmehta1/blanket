"""Token counting, cost tracking, and budget enforcement.

Every LLM call in the system is recorded here.  The orchestrator checks
budgets before dispatching work and aborts if ``max_scan_cost_usd`` is
exceeded (design doc §9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from blanketaudit2.config import get_settings
from blanketaudit2.exceptions import BudgetExceededError

logger = structlog.get_logger()

# ── Pricing table ────────────────────────────────────────────
# Per 1 M tokens: (input_cost, output_cost).
# Local models (Ollama) are free.  Unknown models fall back to a
# conservative estimate so we never silently spend too much.

PRICING: dict[str, tuple[float, float]] = {
    # Anthropic
    "claude-opus-4-20250514": (15.0, 75.0),
    "claude-opus-4-6": (15.0, 75.0),
    "claude-sonnet-4-20250514": (3.0, 15.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (0.80, 4.0),
    # OpenAI
    "gpt-4o": (2.50, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.0, 30.0),
    # Google
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.0-flash": (0.10, 0.40),
    # Groq (hosted — very cheap)
    "llama-3.1-70b-versatile": (0.59, 0.79),
    "llama-3.1-8b-instant": (0.05, 0.08),
    # Local / free (Ollama)
    "llama3.1": (0.0, 0.0),
    "qwen2.5-coder:7b": (0.0, 0.0),
    "qwen2.5-coder": (0.0, 0.0),
    "nomic-embed-text": (0.0, 0.0),
}

# Conservative fallback for models not in the table.
_FALLBACK_PRICING: tuple[float, float] = (10.0, 30.0)


def _get_pricing(model: str) -> tuple[float, float]:
    """Return (input_cost, output_cost) per 1 M tokens for *model*."""
    if model in PRICING:
        return PRICING[model]
    # Try prefix matching — longest key first so "gpt-4o-mini-*" matches
    # "gpt-4o-mini" rather than "gpt-4o".
    for key in sorted(PRICING, key=len, reverse=True):
        if model.startswith(key):
            return PRICING[key]
    return _FALLBACK_PRICING


# ── Token counting ───────────────────────────────────────────

# tiktoken encoding singletons (lazy-loaded).
_encodings: dict[str, Any] = {}


def _get_encoding(model: str) -> Any:
    """Return a tiktoken encoding for *model*, with caching."""
    if model not in _encodings:
        try:
            import tiktoken
            try:
                _encodings[model] = tiktoken.encoding_for_model(model)
            except KeyError:
                # Model not in tiktoken's registry — use cl100k_base as a
                # reasonable approximation for modern models.
                _encodings[model] = tiktoken.get_encoding("cl100k_base")
        except ImportError:
            return None
    return _encodings[model]


def count_tokens(text: str, model: str = "cl100k_base") -> int:
    """Count tokens in *text* for *model*.

    Falls back to a ``len(text) / 4`` heuristic if tiktoken is unavailable.
    """
    enc = _get_encoding(model)
    if enc is not None:
        return len(enc.encode(text))
    # Rough heuristic: ~4 chars per token for English text.
    return max(1, len(text) // 4)


# ── Per-agent token budget ───────────────────────────────────


@dataclass
class TokenBudget:
    """Track token usage for a single agent with hard abort thresholds.

    At **80 %** usage the orchestrator should demote remaining files to
    Tier 3 (static-only).  At **100 %** all LLM calls for this agent stop.
    """

    agent_name: str
    max_tokens: int = 500_000
    used_input: int = 0
    used_output: int = 0

    # ── derived properties ───────────────────────────────────

    @property
    def used_tokens(self) -> int:
        return self.used_input + self.used_output

    @property
    def remaining(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    @property
    def percent_used(self) -> float:
        return self.used_tokens / self.max_tokens if self.max_tokens > 0 else 1.0

    @property
    def should_demote(self) -> bool:
        """At 80 %, remaining files should be demoted to Tier 3."""
        return self.percent_used >= 0.80

    @property
    def is_exhausted(self) -> bool:
        return self.used_tokens >= self.max_tokens

    # ── mutation ─────────────────────────────────────────────

    def consume(self, input_tokens: int, output_tokens: int) -> bool:
        """Record token consumption.  Return *False* if budget is now exceeded."""
        self.used_input += input_tokens
        self.used_output += output_tokens
        return not self.is_exhausted


# ── Scan-wide cost tracker ───────────────────────────────────


@dataclass
class CallRecord:
    """One logged LLM call."""

    agent_name: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float


@dataclass
class CostTracker:
    """Aggregate cost and token tracking for an entire scan.

    Used by:
    - ``estimate_cost`` node: dry-run projection
    - Every LLM call wrapper: real-time tracking
    - Orchestrator: abort if over ``max_scan_cost_usd``
    """

    max_scan_cost_usd: float = 0.0
    abort_on_budget: bool = True

    # Internal state
    agent_budgets: dict[str, TokenBudget] = field(default_factory=dict)
    calls: list[CallRecord] = field(default_factory=list)
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0

    # ── setup ────────────────────────────────────────────────

    @classmethod
    def from_settings(cls) -> CostTracker:
        """Create a tracker pre-configured from the global settings."""
        cfg = get_settings().cost
        return cls(
            max_scan_cost_usd=cfg.max_scan_cost_usd,
            abort_on_budget=cfg.abort_on_budget,
        )

    def create_agent_budget(
        self, agent_name: str, max_tokens: int | None = None
    ) -> TokenBudget:
        """Register a per-agent budget.  Returns the new budget object."""
        limit = max_tokens or get_settings().cost.per_agent_token_budget
        budget = TokenBudget(agent_name=agent_name, max_tokens=limit)
        self.agent_budgets[agent_name] = budget
        logger.info(
            "cost.agent_budget_created",
            agent=agent_name,
            max_tokens=limit,
        )
        return budget

    # ── recording ────────────────────────────────────────────

    def record_call(
        self,
        agent_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        """Record an LLM call, update totals, and enforce budgets.

        Raises ``BudgetExceededError`` if the scan-wide cost limit is
        breached and ``abort_on_budget`` is *True*.
        """
        inp_price, out_price = _get_pricing(model)
        cost = (input_tokens * inp_price + output_tokens * out_price) / 1_000_000

        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost_usd += cost

        record = CallRecord(
            agent_name=agent_name,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
        )
        self.calls.append(record)

        # Update per-agent budget
        budget = self.agent_budgets.get(agent_name)
        if budget is not None:
            budget.consume(input_tokens, output_tokens)

        logger.info(
            "cost.call_recorded",
            agent=agent_name,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=round(cost, 6),
            total_cost_usd=round(self.total_cost_usd, 4),
        )

        # Enforce scan-wide cost limit
        if (
            self.abort_on_budget
            and self.max_scan_cost_usd > 0
            and self.total_cost_usd > self.max_scan_cost_usd
        ):
            raise BudgetExceededError(
                f"Scan cost ${self.total_cost_usd:.2f} exceeds limit "
                f"${self.max_scan_cost_usd:.2f}",
                details={
                    "total_cost_usd": self.total_cost_usd,
                    "max_scan_cost_usd": self.max_scan_cost_usd,
                    "call_count": len(self.calls),
                },
            )

    # ── queries ──────────────────────────────────────────────

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    def agent_cost(self, agent_name: str) -> float:
        """Total cost for a specific agent."""
        return sum(c.cost_usd for c in self.calls if c.agent_name == agent_name)

    def summary(self) -> dict:
        """Return a human-readable summary dict."""
        per_agent: dict[str, dict] = {}
        for name, budget in self.agent_budgets.items():
            per_agent[name] = {
                "used_tokens": budget.used_tokens,
                "max_tokens": budget.max_tokens,
                "percent_used": round(budget.percent_used * 100, 1),
                "cost_usd": round(self.agent_cost(name), 4),
                "is_exhausted": budget.is_exhausted,
                "should_demote": budget.should_demote,
            }
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "max_scan_cost_usd": self.max_scan_cost_usd,
            "call_count": self.call_count,
            "per_agent": per_agent,
        }

    # ── dry-run estimation ───────────────────────────────────

    def estimate_scan_cost(
        self,
        file_tiers: dict[int, int],
        model_routing: dict[str, str],
    ) -> dict:
        """Project the cost of a scan without running it.

        Parameters
        ----------
        file_tiers:
            ``{1: 120, 2: 230, 3: 497}`` — file count per tier.
        model_routing:
            ``{"security": "claude-sonnet-4-20250514", "compliance": "claude-opus-4-20250514", ...}``

        Returns
        -------
        dict with estimated_cost_usd, per_agent breakdown, total_tokens,
        and tier_breakdown.
        """
        # Average tokens per file per tier (rough heuristics).
        AVG_INPUT_TOKENS = {1: 4_000, 2: 1_500, 3: 0}
        AVG_OUTPUT_TOKENS = {1: 2_000, 2: 500, 3: 0}

        agents = list(model_routing.keys())
        per_agent: dict[str, float] = {}
        total_tokens = 0

        for agent_name, model in model_routing.items():
            inp_price, out_price = _get_pricing(model)
            agent_input = 0
            agent_output = 0

            for tier, file_count in file_tiers.items():
                agent_input += file_count * AVG_INPUT_TOKENS.get(tier, 0)
                agent_output += file_count * AVG_OUTPUT_TOKENS.get(tier, 0)

            agent_cost = (
                agent_input * inp_price + agent_output * out_price
            ) / 1_000_000
            per_agent[agent_name] = round(agent_cost, 4)
            total_tokens += agent_input + agent_output

        estimated_total = sum(per_agent.values())

        return {
            "estimated_cost_usd": round(estimated_total, 2),
            "per_agent": per_agent,
            "total_tokens": total_tokens,
            "tier_breakdown": dict(file_tiers),
            "within_budget": (
                estimated_total <= self.max_scan_cost_usd
                if self.max_scan_cost_usd > 0
                else True
            ),
        }
