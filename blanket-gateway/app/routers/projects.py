from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import AuthContext, require_auth
from app.models.common import ApiResponse, PaginationMeta
from app.models.projects import ProjectCreate, ProjectRead, ProjectUpdate
from app.services import projects as svc
from app.services.activity_logs import log_mutation

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


@router.get("", response_model=ApiResponse[list[ProjectRead]])
async def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    is_active: bool | None = Query(None),
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[list[ProjectRead]]:
    rows, total = await svc.list_projects(
        auth.org_id, page, page_size, sort_by, sort_order, is_active
    )
    return ApiResponse(
        data=[ProjectRead(**dict(r)) for r in rows],
        meta=PaginationMeta(page=page, page_size=page_size, total=total),
    )


@router.get("/{project_id}", response_model=ApiResponse[ProjectRead])
async def get_project(
    project_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[ProjectRead]:
    row = await svc.get_project(auth.org_id, project_id)
    if not row:
        raise HTTPException(404, "Project not found")
    return ApiResponse(data=ProjectRead(**dict(row)))


@router.post("", response_model=ApiResponse[ProjectRead], status_code=201)
async def create_project(
    body: ProjectCreate,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[ProjectRead]:
    try:
        row = await svc.create_project(auth.org_id, body)
    except ValueError as e:
        raise HTTPException(409, str(e))
    project = ProjectRead(**dict(row))
    await log_mutation(
        auth.org_id, auth.api_key_id, "project.create", project_id=project.id
    )
    return ApiResponse(data=project)


@router.patch("/{project_id}", response_model=ApiResponse[ProjectRead])
async def update_project(
    project_id: UUID,
    body: ProjectUpdate,
    auth: AuthContext = Depends(require_auth),
) -> ApiResponse[ProjectRead]:
    row = await svc.update_project(auth.org_id, project_id, body)
    if not row:
        raise HTTPException(404, "Project not found")
    project = ProjectRead(**dict(row))
    await log_mutation(
        auth.org_id, auth.api_key_id, "project.update", project_id=project.id
    )
    return ApiResponse(data=project)


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: UUID,
    auth: AuthContext = Depends(require_auth),
) -> None:
    deleted = await svc.delete_project(auth.org_id, project_id)
    if not deleted:
        raise HTTPException(404, "Project not found")
    await log_mutation(
        auth.org_id, auth.api_key_id, "project.delete", project_id=project_id
    )
