from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import AuthContext, require_auth
from app.models.common import ApiResponse, PaginationMeta
from app.models.policies import PolicyCreate, PolicyRead, PolicyUpdate
from app.services import policies as svc
from app.services.activity_logs import log_mutation

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


@router.get("", response_model=ApiResponse[list[PolicyRead]])
async def list_policies(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    category: str | None = Query(None),
    severity: str | None = Query(None),
    is_active: bool | None = Query(None),
    tag: str | None = Query(None),
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[list[PolicyRead]]:
    rows, total = await svc.list_policies(
        auth.org_id, page, page_size, sort_by, sort_order,
        category, severity, is_active, tag,
    )
    return ApiResponse(
        data=[PolicyRead(**dict(r)) for r in rows],
        meta=PaginationMeta(page=page, page_size=page_size, total=total),
    )


@router.get("/{policy_id}", response_model=ApiResponse[PolicyRead])
async def get_policy(
    policy_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[PolicyRead]:
    row = await svc.get_policy(auth.org_id, policy_id)
    if not row:
        raise HTTPException(404, "Policy not found")
    return ApiResponse(data=PolicyRead(**dict(row)))


@router.post("", response_model=ApiResponse[PolicyRead], status_code=201)
async def create_policy(
    body: PolicyCreate,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[PolicyRead]:
    try:
        row = await svc.create_policy(auth.org_id, body)
    except ValueError as e:
        raise HTTPException(409, str(e))
    policy = PolicyRead(**dict(row))
    await log_mutation(
        auth.org_id, auth.api_key_id, "policy.create", policy_id=policy.id
    )
    return ApiResponse(data=policy)


@router.patch("/{policy_id}", response_model=ApiResponse[PolicyRead])
async def update_policy(
    policy_id: UUID,
    body: PolicyUpdate,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[PolicyRead]:
    row = await svc.update_policy(auth.org_id, policy_id, body)
    if not row:
        raise HTTPException(404, "Policy not found")
    policy = PolicyRead(**dict(row))
    await log_mutation(
        auth.org_id, auth.api_key_id, "policy.update", policy_id=policy.id
    )
    return ApiResponse(data=policy)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> None:
    deleted = await svc.delete_policy(auth.org_id, policy_id)
    if not deleted:
        raise HTTPException(404, "Policy not found")
    await log_mutation(
        auth.org_id, auth.api_key_id, "policy.delete", policy_id=policy_id
    )
