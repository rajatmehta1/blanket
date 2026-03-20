from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AssignmentCreate(BaseModel):
    policy_id: UUID
    is_enabled: bool = True


class AssignmentUpdate(BaseModel):
    is_enabled: bool


class AssignmentRead(BaseModel):
    project_id: UUID
    policy_id: UUID
    is_enabled: bool
    enabled_at: datetime
    enabled_by: UUID | None


class AssignmentDetailRead(BaseModel):
    project_id: UUID
    policy_id: UUID
    is_enabled: bool
    enabled_at: datetime
    enabled_by: UUID | None
    policy_name: str
    policy_category: str
    policy_severity: str
