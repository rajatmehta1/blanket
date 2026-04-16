"""Remediation roadmap models."""
from __future__ import annotations
from pydantic import BaseModel

class RemediationTask(BaseModel):
    task: str
    effort: str
    finding_id: str
    score_impact: str

class RemediationPhase(BaseModel):
    title: str
    date_range: str
    items: list[RemediationTask]
    total_effort: str
    score_target: str
