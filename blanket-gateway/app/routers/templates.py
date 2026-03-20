from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import AuthContext, require_auth
from app.models.common import ApiResponse
from app.models.policies import PolicyRead
from app.services import templates as svc
from app.services.activity_logs import log_mutation
from app.services.templates import NotFoundError

router = APIRouter(prefix="/api/v1/templates", tags=["templates"])


@router.get("", response_model=ApiResponse[list[PolicyRead]])
async def list_templates(
    category: str | None = Query(None),
    severity: str | None = Query(None),
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[list[PolicyRead]]:
    rows = await svc.list_templates(category, severity)
    return ApiResponse(
        data=[PolicyRead(**dict(r)) for r in rows],
    )


@router.get("/{template_id}", response_model=ApiResponse[PolicyRead])
async def get_template(
    template_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[PolicyRead]:
    row = await svc.get_template(template_id)
    if not row:
        raise HTTPException(404, "Template not found")
    return ApiResponse(data=PolicyRead(**dict(row)))


@router.post(
    "/{template_id}/instantiate",
    response_model=ApiResponse[PolicyRead],
    status_code=201,
)
async def instantiate_template(
    template_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[PolicyRead]:
    try:
        row = await svc.instantiate_template(auth.org_id, template_id)
    except NotFoundError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))
    policy = PolicyRead(**dict(row))
    await log_mutation(
        auth.org_id, auth.api_key_id, "template.instantiate", policy_id=policy.id
    )
    return ApiResponse(data=policy)
