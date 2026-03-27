"""Financial risk estimation per finding.

Combines:
1. Compliance framework penalty data (HIPAA, PCI-DSS, GDPR, SOX)
2. Data breach cost data (Ponemon/IBM research)
3. Domain inference from blast radius
4. LLM reasoning for novel situations (optional)

All estimates are conservative ranges, not single numbers.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from blanketaudit.models.finding import AuditFinding, BlastRadius

logger = structlog.get_logger()

# ── Compliance framework penalty reference data ──────────────

PENALTY_DATA: dict[str, dict] = {
    "HIPAA": {
        "description": "HIPAA violation penalties",
        "min": 100,       # per violation minimum
        "max": 1_900_000, # per incident category maximum
        "text": "$100 — $1,900,000 per incident category",
    },
    "PCI-DSS": {
        "description": "PCI-DSS non-compliance fines",
        "min": 5_000,
        "max": 100_000,   # per month
        "text": "$5,000 — $100,000/month in fines",
    },
    "GDPR": {
        "description": "GDPR fine ceiling",
        "min": 10_000,
        "max": 20_000_000,
        "text": "Up to 4% of annual revenue or €20M",
    },
    "SOC2": {
        "description": "SOC2 non-compliance impacts",
        "min": 10_000,
        "max": 500_000,
        "text": "Lost customer trust, contract penalties",
    },
    "SOX": {
        "description": "SOX violation penalties",
        "min": 100_000,
        "max": 5_000_000,
        "text": "Criminal penalties for willful violations up to $5M",
    },
}

# Ponemon/IBM data breach cost per record by domain
_COST_PER_RECORD: dict[str, int] = {
    "healthcare": 400,    # Healthcare is highest
    "finance": 300,
    "technology": 200,
    "retail": 175,
    "general": 165,       # Global average
}

# Severity multipliers for financial impact
_SEVERITY_MULTIPLIER: dict[str, float] = {
    "critical": 1.0,
    "high": 0.5,
    "medium": 0.15,
    "low": 0.05,
}


class DollarImpactEstimator:
    """Estimate financial risk per finding."""

    def __init__(
        self,
        domain: str = "general",
        llm: Any = None,
    ) -> None:
        self._domain = domain
        self._llm = llm
        self._cost_per_record = _COST_PER_RECORD.get(domain, _COST_PER_RECORD["general"])

    async def estimate(self, finding: AuditFinding) -> str:
        """Return a human-readable dollar impact range string.

        Combines compliance penalties, breach cost estimates, and
        severity multipliers.
        """
        # Try LLM-assisted estimate first
        if self._llm is not None:
            try:
                return await self._estimate_with_llm(finding)
            except Exception as exc:
                logger.debug("dollar_impact.llm_failed", error=str(exc)[:100])

        # Rule-based estimation
        return self._estimate_rules(finding)

    def _estimate_rules(self, finding: AuditFinding) -> str:
        """Rule-based dollar impact estimation."""
        low = 0
        high = 0
        multiplier = _SEVERITY_MULTIPLIER.get(finding.severity, 0.1)

        # 1. Compliance framework penalties
        for ref in finding.compliance_refs:
            fw = ref.framework.upper()
            penalty = PENALTY_DATA.get(fw)
            if penalty:
                low += int(penalty["min"] * multiplier)
                high += int(penalty["max"] * multiplier)

        # 2. Data breach cost from blast radius
        if finding.blast_radius:
            breach_estimate = self._breach_cost(finding.blast_radius, multiplier)
            low += breach_estimate[0]
            high += breach_estimate[1]
        elif finding.severity in ("critical", "high"):
            # Default estimate without blast radius
            low += int(1_000 * multiplier)
            high += int(100_000 * multiplier)

        # 3. Minimum floor based on severity
        if low == 0 and high == 0:
            severity_floors = {
                "critical": (10_000, 500_000),
                "high": (5_000, 100_000),
                "medium": (1_000, 25_000),
                "low": (100, 5_000),
            }
            low, high = severity_floors.get(finding.severity, (100, 5_000))

        return self._format_range(low, high)

    def _breach_cost(
        self,
        blast_radius: BlastRadius,
        multiplier: float,
    ) -> tuple[int, int]:
        """Estimate breach cost from blast radius data."""
        # Infer record count from affected_users description
        records = self._infer_record_count(blast_radius.affected_users)
        cost = records * self._cost_per_record

        low = int(cost * 0.1 * multiplier)
        high = int(cost * multiplier)
        return (max(low, 1_000), max(high, 10_000))

    @staticmethod
    def _infer_record_count(affected_users: str) -> int:
        """Estimate number of affected records from user group description."""
        lower = affected_users.lower()
        if "all" in lower:
            return 10_000
        if "admin" in lower:
            return 50
        if "provider" in lower or "staff" in lower:
            return 500
        if "unknown" in lower:
            return 1_000
        return 1_000

    @staticmethod
    def _format_range(low: int, high: int) -> str:
        """Format as human-readable dollar range."""
        if low >= high:
            high = low * 10  # Ensure there's a range

        def fmt(n: int) -> str:
            if n >= 1_000_000:
                return f"${n / 1_000_000:.1f}M"
            if n >= 1_000:
                return f"${n:,.0f}"
            return f"${n}"

        return f"{fmt(low)} — {fmt(high)}"

    async def _estimate_with_llm(self, finding: AuditFinding) -> str:
        """Use LLM for more nuanced dollar impact estimation."""
        from langchain_core.messages import HumanMessage, SystemMessage

        from blanketaudit.llm.guardrails import INJECTION_DEFENSE_PREFIX
        from blanketaudit.llm.resilience import safe_llm_call

        frameworks = [ref.framework for ref in finding.compliance_refs]
        blast = ""
        if finding.blast_radius:
            blast = (
                f"Blast radius: {finding.blast_radius.entry_points} entry points, "
                f"{finding.blast_radius.repos_affected} repos, "
                f"affects {finding.blast_radius.affected_users}"
            )

        system_prompt = (
            f"{INJECTION_DEFENSE_PREFIX}\n\n"
            "Estimate the financial risk for this vulnerability.\n"
            "Respond with ONLY a dollar range string like: $10,000 — $500,000\n"
            f"Domain: {self._domain}. Consider: fines, breach costs, downtime.\n"
        )

        user_prompt = (
            f"Finding: {finding.title} ({finding.severity})\n"
            f"Frameworks: {', '.join(frameworks) or 'None'}\n"
            f"{blast}\n"
        )

        response = await safe_llm_call(
            self._llm,
            [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)],
            agent_name="dollar_impact",
        )

        text = response.content.strip()
        # Validate it looks like a dollar range
        if "$" in text and len(text) < 100:
            return text
        return self._estimate_rules(finding)
