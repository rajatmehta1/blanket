"""Call graph summary models for the report."""
from __future__ import annotations

from pydantic import BaseModel, field_validator


class EntryPointSummary(BaseModel):
    """One entry point in the call graph summary."""

    route: str
    repo: str
    depth: int
    cross_repo: bool

    @field_validator("depth")
    @classmethod
    def validate_depth(cls, v: int) -> int:
        if v < 0:
            raise ValueError("depth must be non-negative")
        return v


class CrossRepoEdge(BaseModel):
    """One cross-repo HTTP call in the call graph."""

    from_method: str
    to_method: str
    via: str


class DeadCodeSummary(BaseModel):
    """Summary of unreachable methods."""

    count: int
    total_lines: int
    top_files: list[str]

    @field_validator("count", "total_lines")
    @classmethod
    def validate_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Must be non-negative")
        return v


class CallGraphSummary(BaseModel):
    """Complete call graph analysis for the report."""

    entry_points: list[EntryPointSummary]
    cross_repo_edges: list[CrossRepoEdge]
    circular_dependencies: list[str]
    dead_methods: DeadCodeSummary
    single_points_of_failure: list[str]
