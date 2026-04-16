"""Score dashboard models."""
from __future__ import annotations

from pydantic import BaseModel, field_validator


class CategoryScore(BaseModel):
    """Score for one report category."""

    name: str
    score: int
    finding_count: int

    @field_validator("score")
    @classmethod
    def validate_score(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError("score must be 0-100")
        return v

    @field_validator("finding_count")
    @classmethod
    def validate_finding_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("finding_count must be non-negative")
        return v


class HealthScore(BaseModel):
    """Complete scoring for the report."""

    overall: int
    grade: str
    categories: list[CategoryScore]
    severity_counts: dict[str, int]

    @field_validator("grade")
    @classmethod
    def validate_grade(cls, v: str) -> str:
        if v not in ("A", "B", "C", "D", "F"):
            raise ValueError(f"Invalid grade '{v}'. Must be A/B/C/D/F")
        return v

    @field_validator("overall")
    @classmethod
    def validate_overall(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError("overall score must be 0-100")
        return v
