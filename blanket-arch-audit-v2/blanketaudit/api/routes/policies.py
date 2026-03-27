"""Policy listing endpoint."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

router = APIRouter(tags=["policies"])


@router.get("/policies")
async def list_policies(category: str | None = None) -> list[dict]:
    """List all loaded audit policies, optionally filtered by category."""
    from blanketaudit.policies.engine import PolicyEngine

    engine = PolicyEngine()
    policy_dir = Path(__file__).parent.parent.parent / "policies"
    categories = {category} if category else None
    policies = engine.load_policies(policy_dir, categories=categories)

    return [
        {
            "id": p.id,
            "name": p.name,
            "category": p.category,
            "severity": p.severity,
            "description": p.description[:200] if p.description else "",
            "frameworks": p.frameworks,
            "has_static_checks": len(p.static_checks) > 0,
            "has_ai_analysis": p.ai_analysis is not None,
        }
        for p in sorted(policies, key=lambda x: (x.category, x.id))
    ]
