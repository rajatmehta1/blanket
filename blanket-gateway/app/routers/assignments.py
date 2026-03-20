from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthContext, require_auth
from app.models.assignments import (
    AssignmentCreate,
    AssignmentDetailRead,
    AssignmentRead,
    AssignmentUpdate,
)
from app.models.common import ApiResponse
from app.services import assignments as svc
from app.services.activity_logs import log_mutation
from app.services.assignments import ConflictError, NotFoundError

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/policies", tags=["assignments"]
)


@router.get("", response_model=ApiResponse[list[AssignmentDetailRead]])
async def list_assignments(
    project_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[list[AssignmentDetailRead]]:
    rows = await svc.list_assignments(auth.org_id, project_id)
    return ApiResponse(
        data=[AssignmentDetailRead(**dict(r)) for r in rows],
    )


@router.post("", response_model=ApiResponse[AssignmentRead], status_code=201)
async def assign_policy(
    project_id: UUID,
    body: AssignmentCreate,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[AssignmentRead]:
    try:
        row = await svc.assign_policy(
            auth.org_id, project_id, body.policy_id, body.is_enabled
        )
    except NotFoundError as e:
        raise HTTPException(404, str(e))
    except ConflictError as e:
        raise HTTPException(409, str(e))
    assignment = AssignmentRead(**row)
    await log_mutation(
        auth.org_id,
        auth.api_key_id,
        "assignment.create",
        project_id=project_id,
        policy_id=body.policy_id,
    )
    return ApiResponse(data=assignment)


@router.patch("/{policy_id}", response_model=ApiResponse[AssignmentRead])
async def update_assignment(
    project_id: UUID,
    policy_id: UUID,
    body: AssignmentUpdate,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[AssignmentRead]:
    row = await svc.update_assignment(
        auth.org_id, project_id, policy_id, body.is_enabled
    )
    if not row:
        raise HTTPException(404, "Assignment not found")
    return ApiResponse(data=AssignmentRead(**dict(row)))


@router.delete("/{policy_id}", status_code=204)
async def remove_assignment(
    project_id: UUID,
    policy_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> None:
    removed = await svc.remove_assignment(auth.org_id, project_id, policy_id)
    if not removed:
        raise HTTPException(404, "Assignment not found")
    await log_mutation(
        auth.org_id,
        auth.api_key_id,
        "assignment.delete",
        project_id=project_id,
        policy_id=policy_id,
    )
