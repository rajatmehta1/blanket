"""Compliance matrix models."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, field_validator


class ComplianceControlStatus(BaseModel):
    """One control's status in the compliance matrix."""

    control_id: str
    framework: str
    clause: str
    title: str
    status: Literal["pass", "partial", "fail", "gap", "not_applicable", "review_needed"]
    finding_count: int
    detail: str

    @field_validator("finding_count")
    @classmethod
    def validate_finding_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("finding_count must be non-negative")
        return v


class ComplianceMatrix(BaseModel):
    """Grouped compliance status for one framework."""

    framework: str
    sections: list[ComplianceControlStatus]
