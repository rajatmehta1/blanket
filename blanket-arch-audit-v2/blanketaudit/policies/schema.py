"""Policy data models and YAML schema validation.

Design doc §4.1: each policy YAML has an ``id``, ``name``, ``category``,
``severity``, optional ``frameworks``, plus ``static_checks`` (deterministic)
and ``ai_analysis`` (LLM-based contextual reasoning).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ── Static check definitions ─────────────────────────────────


class ASTPatternCondition(BaseModel):
    """One condition inside an AST pattern check."""
    child_type: str = ""
    text_matches: str = ""
    has_child: str = ""


class ASTPattern(BaseModel):
    """An AST-based static check pattern."""
    node_type: str
    conditions: list[ASTPatternCondition] = []


class StaticCheck(BaseModel):
    """One static check within a policy."""
    tool: Literal["semgrep", "gitleaks", "osv", "ast", "regex"]
    rule: str = ""              # Semgrep rule path or ID
    pattern: ASTPattern | None = None  # For tool=="ast"
    regex: str = ""             # For tool=="regex"


# ── AI analysis definition ───────────────────────────────────


class AIAnalysis(BaseModel):
    """LLM-based analysis configuration for a policy."""
    prompt_template: str
    expected_output: str = "finding_assessment"
    min_confidence: float = 0.7


# ── Top-level Policy model ───────────────────────────────────


class Policy(BaseModel):
    """A single audit policy loaded from YAML.

    Each policy defines BOTH static checks (deterministic, no LLM)
    AND ai_analysis (LLM contextual reasoning).  Static always runs
    first; AI analyses the candidates.
    """
    id: str
    name: str
    category: Literal["security", "compliance", "architecture", "quality"]
    severity: Literal["critical", "high", "medium", "low"]
    description: str = ""
    frameworks: list[str] = []  # e.g., ["PCI-DSS-6.5.1", "HIPAA-164.312-a-1"]

    # Dual-layer checks
    static_checks: list[StaticCheck] = []
    ai_analysis: AIAnalysis | None = None

    # Remediation
    remediation_template: str = ""
    effort_hours: float = 0.0

    # Conflict metadata
    conflicts_with: list[str] = []  # Policy IDs this may conflict with
    supersedes: list[str] = []      # Policy IDs this explicitly overrides

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not v:
            raise ValueError("Policy id cannot be empty")
        return v


def validate_policy_dict(data: dict) -> Policy | None:
    """Parse and validate a raw dict into a Policy model.

    Returns *None* if validation fails.
    """
    try:
        return Policy.model_validate(data)
    except Exception:
        return None
