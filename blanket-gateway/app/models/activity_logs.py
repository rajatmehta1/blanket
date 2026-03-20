from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class EnforcementLogRead(BaseModel):
    id: UUID
    org_id: UUID
    project_id: UUID | None
    api_key_id: UUID | None
    event_type: str
    source_tool: str | None
    language: str | None
    framework: str | None
    policies_applied: list[UUID]
    policies_count: int
    prompt_token_count: int | None
    enriched_token_count: int | None
    processing_ms: int | None
    created_at: datetime
