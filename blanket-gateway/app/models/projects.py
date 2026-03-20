from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = None
    language: str | None = None
    framework: str | None = None
    is_active: bool = True


class ProjectUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = None
    language: str | None = None
    framework: str | None = None
    is_active: bool | None = None


class ProjectRead(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    slug: str
    description: str | None
    language: str | None
    framework: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
