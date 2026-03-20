from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import AuthContext, require_auth
from app.models.activity_logs import EnforcementLogRead
from app.models.common import ApiResponse, PaginationMeta
from app.services import activity_logs as svc

router = APIRouter(prefix="/api/v1/activity", tags=["activity"])


@router.get("", response_model=ApiResponse[list[EnforcementLogRead]])
async def list_activity(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    project_id: UUID | None = Query(None),
    event_type: str | None = Query(None),
    from_date: datetime | None = Query(None),
    to_date: datetime | None = Query(None),
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[list[EnforcementLogRead]]:
    rows, total = await svc.list_logs(
        auth.org_id, page, page_size, project_id, event_type, from_date, to_date
    )
    return ApiResponse(
        data=[EnforcementLogRead(**dict(r)) for r in rows],
        meta=PaginationMeta(page=page, page_size=page_size, total=total),
    )


@router.get("/{log_id}", response_model=ApiResponse[EnforcementLogRead])
async def get_activity(
    log_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[EnforcementLogRead]:
    row = await svc.get_log(auth.org_id, log_id)
    if not row:
        raise HTTPException(404, "Activity log not found")
    return ApiResponse(data=EnforcementLogRead(**dict(row)))
