"""Dry-run cost projection — full scan simulation with zero LLM calls.

Design doc §9.1: ``blanketaudit scan --dry-run`` clones repos, indexes
files, runs triage, then projects cost based on tier assignments and
per-agent model routing.  The user sees a cost table and can approve or
abort before any LLM spend.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel

from blanketaudit.config import LLMProvider, get_settings
from blanketaudit.ingestion.models import FileMetadata, FileType
from blanketaudit.llm.cost_tracker import _get_pricing
from blanketaudit.llm.provider import (
    _DEFAULT_COMPLIANCE_MODELS,
    _DEFAULT_MODELS,
)

logger = structlog.get_logger()

# ── Token estimation heuristics ──────────────────────────────
# Average tokens per file by tier (input + output combined).
# These are deliberately conservative (over-estimates are safer).

# Chars per token approximation
_CHARS_PER_TOKEN = 4

# Overhead per file: system prompt fragment, format instructions, etc.
_PER_FILE_OVERHEAD_TOKENS = 500

# Output-to-input ratio: for every input token the LLM produces ~0.5 output
_OUTPUT_RATIO = 0.5

# Tier 2 files get lighter analysis (30% of Tier 1 tokens)
_TIER2_FACTOR = 0.30


def _estimate_file_input_tokens(file: FileMetadata) -> int:
    """Estimate the input tokens for analysing one file."""
    if file.size_bytes > 0:
        content_tokens = file.size_bytes // _CHARS_PER_TOKEN
    elif file.loc > 0:
        content_tokens = (file.loc * 40) // _CHARS_PER_TOKEN
    else:
        content_tokens = 200  # Minimum placeholder

    return content_tokens + _PER_FILE_OVERHEAD_TOKENS


# ── Cost estimate model ──────────────────────────────────────


class AgentCostEstimate(BaseModel):
    """Projected cost for a single agent."""
    agent: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_usd: float = 0.0


class CostEstimate(BaseModel):
    """Complete cost projection for a scan."""
    total_estimated_usd: float
    per_agent: list[AgentCostEstimate]
    total_estimated_tokens: int
    file_tier_breakdown: dict[str, int]  # {"tier1": N, "tier2": N, "tier3": N}
    model_routing: dict[str, str]        # {"security": "claude-sonnet-4-20250514", ...}
    cached_files: int = 0                # Files that would use incremental cache
    total_files: int = 0
    total_loc: int = 0
    recommendation: str = ""


# ── Estimator ────────────────────────────────────────────────


class CostEstimator:
    """Project token usage and dollar cost without making any LLM calls.

    Usage::

        estimator = CostEstimator()
        estimate = estimator.estimate(files, tiers)
        if estimate.total_estimated_usd > settings.cost.max_scan_cost_usd:
            print("Over budget!")
    """

    def __init__(
        self,
        max_scan_cost_usd: float | None = None,
        cached_file_paths: set[str] | None = None,
    ) -> None:
        settings = get_settings()
        self._max_cost = (
            max_scan_cost_usd
            if max_scan_cost_usd is not None
            else settings.cost.max_scan_cost_usd
        )
        self._cached = cached_file_paths or set()
        self._settings = settings

    # ── Public API ───────────────────────────────────────────

    def estimate(
        self,
        files: list[FileMetadata],
        tiers: dict[str, int],
        scores: dict[str, int] | None = None,
    ) -> CostEstimate:
        """Run the cost projection.

        Parameters
        ----------
        files:
            All indexed files.
        tiers:
            ``{file_path: tier_number}`` from TierAssigner.
        scores:
            Optional ``{file_path: score}`` for richer reporting.
        """
        # Tier breakdown
        tier_counts = {"tier1": 0, "tier2": 0, "tier3": 0}
        tier1_files: list[FileMetadata] = []
        tier2_files: list[FileMetadata] = []

        for f in files:
            tier = tiers.get(f.path, 3)
            if tier == 1:
                tier_counts["tier1"] += 1
                if f.path not in self._cached:
                    tier1_files.append(f)
            elif tier == 2:
                tier_counts["tier2"] += 1
                if f.path not in self._cached:
                    tier2_files.append(f)
            else:
                tier_counts["tier3"] += 1

        cached_count = sum(1 for f in files if f.path in self._cached)

        # Resolve model routing
        model_routing = self._resolve_model_routing()

        # Estimate per agent
        active_agents = self._get_active_agents()
        agent_estimates: list[AgentCostEstimate] = []

        for agent_name in active_agents:
            model = model_routing[agent_name]
            inp_price, out_price = _get_pricing(model)

            # Sum input tokens across Tier 1 + Tier 2 files
            agent_input = 0
            for f in tier1_files:
                agent_input += _estimate_file_input_tokens(f)
            for f in tier2_files:
                agent_input += int(_estimate_file_input_tokens(f) * _TIER2_FACTOR)

            agent_output = int(agent_input * _OUTPUT_RATIO)
            agent_cost = (
                agent_input * inp_price + agent_output * out_price
            ) / 1_000_000

            agent_estimates.append(AgentCostEstimate(
                agent=agent_name,
                model=model,
                input_tokens=agent_input,
                output_tokens=agent_output,
                estimated_usd=round(agent_cost, 4),
            ))

        total_tokens = sum(a.input_tokens + a.output_tokens for a in agent_estimates)
        total_usd = sum(a.estimated_usd for a in agent_estimates)

        # Recommendation
        recommendation = self._make_recommendation(total_usd)

        estimate = CostEstimate(
            total_estimated_usd=round(total_usd, 2),
            per_agent=agent_estimates,
            total_estimated_tokens=total_tokens,
            file_tier_breakdown=tier_counts,
            model_routing=model_routing,
            cached_files=cached_count,
            total_files=len(files),
            total_loc=sum(f.loc for f in files),
            recommendation=recommendation,
        )

        logger.info(
            "cost_estimate.complete",
            total_usd=estimate.total_estimated_usd,
            total_tokens=estimate.total_estimated_tokens,
            tier1=tier_counts["tier1"],
            tier2=tier_counts["tier2"],
            tier3=tier_counts["tier3"],
            cached=cached_count,
            recommendation=recommendation,
        )

        return estimate

    # ── Internals ────────────────────────────────────────────

    def _resolve_model_routing(self) -> dict[str, str]:
        """Determine which model each agent will use."""
        cfg = self._settings.llm
        provider = cfg.provider
        routing: dict[str, str] = {}

        for agent_name in self._get_active_agents():
            # 1. Per-agent override
            override = cfg.agent_model_overrides.get(agent_name)
            if override:
                routing[agent_name] = override
                continue

            # 2. Compliance gets a higher model
            if agent_name == "compliance":
                model = cfg.compliance_model or _DEFAULT_COMPLIANCE_MODELS.get(provider, "")
                if model:
                    routing[agent_name] = model
                    continue

            # 3. Standard model
            model = cfg.model
            if not model:
                model = _DEFAULT_MODELS.get(provider, "unknown")
            routing[agent_name] = model

        return routing

    def _get_active_agents(self) -> list[str]:
        """Return the list of enabled agent names."""
        agents_cfg = self._settings.agents
        active: list[str] = []
        if agents_cfg.security.enabled:
            active.append("security")
        if agents_cfg.compliance.enabled:
            active.append("compliance")
        if agents_cfg.architecture.enabled:
            active.append("architecture")
        if agents_cfg.quality.enabled:
            active.append("quality")
        return active

    def _make_recommendation(self, total_usd: float) -> str:
        """Generate a human-readable recommendation."""
        if self._settings.llm.provider is LLMProvider.NONE:
            return "No LLM provider configured — static-only analysis (free)"

        if self._max_cost <= 0:
            return f"Estimated ${total_usd:.2f} (no budget limit set)"

        if total_usd <= self._max_cost * 0.5:
            return f"Well within budget (${total_usd:.2f} of ${self._max_cost:.2f})"

        if total_usd <= self._max_cost:
            return f"Within budget (${total_usd:.2f} of ${self._max_cost:.2f})"

        return (
            f"Over budget — ${total_usd:.2f} exceeds ${self._max_cost:.2f}. "
            "Reduce with --paths filter or increase max_scan_cost_usd"
        )


# ── Rich table formatter (for CLI) ──────────────────────────


def format_estimate_table(estimate: CostEstimate) -> str:
    """Format the cost estimate as a Rich-compatible table string.

    Returns plain text suitable for ``console.print()`` or ``typer.echo()``.
    """
    lines: list[str] = []
    lines.append("")
    lines.append("╔══════════════════════════════════════════════════════╗")
    lines.append("║           BlanketAudit — Dry-Run Estimate           ║")
    lines.append("╠══════════════════════════════════════════════════════╣")
    lines.append(f"║  Total files:  {estimate.total_files:>6}   Total LOC:  {estimate.total_loc:>8}  ║")
    lines.append(f"║  Tier 1:       {estimate.file_tier_breakdown.get('tier1', 0):>6}   (full AI)              ║")
    lines.append(f"║  Tier 2:       {estimate.file_tier_breakdown.get('tier2', 0):>6}   (light AI)             ║")
    lines.append(f"║  Tier 3:       {estimate.file_tier_breakdown.get('tier3', 0):>6}   (static only)          ║")
    if estimate.cached_files:
        lines.append(f"║  Cached:       {estimate.cached_files:>6}   (skip — unchanged)     ║")
    lines.append("╠══════════════════════════════════════════════════════╣")
    lines.append("║  Agent            Model                     Cost    ║")
    lines.append("║  ─────            ─────                     ────    ║")
    for a in estimate.per_agent:
        model_short = a.model[:25].ljust(25)
        lines.append(f"║  {a.agent:<16} {model_short} ${a.estimated_usd:>6.2f}  ║")
    lines.append("╠══════════════════════════════════════════════════════╣")
    lines.append(f"║  TOTAL ESTIMATED:                        ${estimate.total_estimated_usd:>7.2f}  ║")
    lines.append(f"║  Total tokens:  {estimate.total_estimated_tokens:>10,}                     ║")
    lines.append("╠══════════════════════════════════════════════════════╣")
    lines.append(f"║  {estimate.recommendation:<52} ║")
    lines.append("╚══════════════════════════════════════════════════════╝")
    lines.append("")
    return "\n".join(lines)
