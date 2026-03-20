from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = None
    category: str = Field(
        "custom", pattern="^(security|quality|compliance|architecture|custom)$"
    )
    severity: str = Field("warning", pattern="^(error|warning|info)$")
    tags: list[str] = Field(default_factory=list)
    prompt_injection_text: str = Field(..., min_length=1)
    applies_to_languages: list[str] = Field(default_factory=list)
    applies_to_frameworks: list[str] = Field(default_factory=list)
    is_active: bool = True


class PolicyUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = None
    category: str | None = Field(
        None, pattern="^(security|quality|compliance|architecture|custom)$"
    )
    severity: str | None = Field(None, pattern="^(error|warning|info)$")
    tags: list[str] | None = None
    prompt_injection_text: str | None = Field(None, min_length=1)
    applies_to_languages: list[str] | None = None
    applies_to_frameworks: list[str] | None = None
    is_active: bool | None = None


class PolicyRead(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    slug: str
    description: str | None
    category: str
    severity: str
    tags: list[str]
    prompt_injection_text: str
    applies_to_languages: list[str]
    applies_to_frameworks: list[str]
    is_template: bool
    template_source: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
