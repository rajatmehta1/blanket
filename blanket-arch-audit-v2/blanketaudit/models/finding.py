"""AuditFinding and related models — the atomic unit of the system."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

from blanketaudit.models.compliance import ComplianceControlStatus


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------

class BlastRadius(BaseModel):
    """How far a vulnerability reaches across the system."""

    entry_points: int
    repos_affected: int
    daily_calls: str
    affected_users: str

    @field_validator("entry_points", "repos_affected")
    @classmethod
    def validate_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Must be non-negative")
        return v


class CallChainStep(BaseModel):
    """One step in the call chain from entry point to vulnerability."""

    method: str
    step_type: Literal[
        "entry", "method", "cross_repo", "taint", "sink", "external", "propagation"
    ]
    repo: str


class ComplianceRef(BaseModel):
    """A specific compliance control violated by a finding."""

    framework: str
    clause: str
    title: str

    @field_validator("framework")
    @classmethod
    def validate_framework(cls, v: str) -> str:
        allowed = {"HIPAA", "SOC2", "PCI-DSS", "GDPR", "SOX", "ISO27001", "NIST"}
        if v.upper() not in {f.upper() for f in allowed}:
            raise ValueError(f"Unknown framework '{v}'. Allowed: {allowed}")
        return v


class Evidence(BaseModel):
    """Proof that a finding exists at a specific location in code."""

    file_path: str
    repo_name: str
    line_start: int
    line_end: int
    code_snippet: str
    tool: str

    @field_validator("line_start")
    @classmethod
    def validate_line_start(cls, v: int) -> int:
        if v < 1:
            raise ValueError("line_start must be >= 1")
        return v

    @model_validator(mode="after")
    def validate_line_range(self) -> Evidence:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


# ---------------------------------------------------------------------------
# Core finding model
# ---------------------------------------------------------------------------

class AuditFinding(BaseModel):
    """The atomic unit of the system — one issue found by any agent."""

    id: str
    policy_id: str
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low"]
    category: Literal[
        "security",
        "compliance",
        "architecture",
        "quality",
        "performance",
        "reliability",
        "infrastructure",
    ]
    confidence: float
    source: Literal["static", "ai", "corroborated"]

    # Evidence (Gate 2 verified)
    evidence: list[Evidence]

    # Compliance mapping (Gate 1 validated)
    compliance_refs: list[ComplianceRef]

    # AI-generated content
    ai_explanation: str
    fix_code: str
    remediation: str
    effort_hours: float
    dollar_impact: str

    # Call graph data
    blast_radius: BlastRadius | None = None
    call_chain: list[CallChainStep] = []

    # Grouping: when multiple findings share the same root cause (e.g., 743x
    # "High Cyclomatic Complexity"), they are collapsed into a single finding
    # with the worst-case instance as representative and all locations listed here.
    affected_locations: list[Evidence] = []
    affected_count: int = 1

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not re.match(r"^BLK-\d+$", v):
            raise ValueError(f"id must match pattern 'BLK-<digits>', got '{v}'")
        return v


# ---------------------------------------------------------------------------
# Per-agent output schemas
# ---------------------------------------------------------------------------

class SecurityFindings(BaseModel):
    """Output schema for the security agent."""

    findings: list[AuditFinding]
    scan_tool_versions: dict[str, str] = {}


class ComplianceFindings(BaseModel):
    """Output schema for the compliance agent."""

    findings: list[AuditFinding]
    control_statuses: list[ComplianceControlStatus] = []


class ArchitectureFindings(BaseModel):
    """Output schema for the architecture agent."""

    findings: list[AuditFinding]
    layer_map: dict[str, str] = {}  # file_path -> layer name


class QualityFindings(BaseModel):
    """Output schema for the quality agent."""

    findings: list[AuditFinding]
    complexity_stats: dict[str, int] = {}
