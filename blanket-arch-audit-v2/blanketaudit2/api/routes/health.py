"""Health endpoint with provider status and circuit breaker info."""

from __future__ import annotations

from fastapi import APIRouter

from blanketaudit2 import __version__
from blanketaudit2.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    """Detailed health check showing provider config and system status."""
    settings = get_settings()
    llm_cfg = settings.llm
    emb_cfg = settings.embedding

    # Circuit breaker status
    cb_status = "unknown"
    try:
        from blanketaudit2.llm.resilience import get_circuit_breaker
        cb = get_circuit_breaker()
        cb_status = cb.state.value
    except Exception:
        cb_status = "not_initialized"

    return {
        "status": "ok",
        "version": __version__,
        "llm": {
            "provider": llm_cfg.provider.value,
            "model": llm_cfg.model or "(default)",
            "compliance_model": llm_cfg.compliance_model or "(default)",
            "agent_overrides": llm_cfg.agent_model_overrides,
        },
        "embeddings": {
            "provider": emb_cfg.provider.value,
            "model": emb_cfg.model or "(default)",
        },
        "circuit_breaker": cb_status,
        "cost": {
            "max_scan_cost_usd": settings.cost.max_scan_cost_usd,
            "per_agent_token_budget": settings.cost.per_agent_token_budget,
        },
        "active_frameworks": settings.active_frameworks,
        "domain": settings.domain,
    }
