from __future__ import annotations

from uuid import UUID

from app.database import execute, fetch_all, fetch_one
from app.models.projects import ProjectCreate, ProjectUpdate
from app.services._helpers import ensure_unique_slug, generate_slug

ALLOWED_SORT = {"created_at", "updated_at", "name", "slug"}


async def list_projects(
    org_id: UUID,
    page: int,
    page_size: int,
    sort_by: str,
    sort_order: str,
    is_active: bool | None = None,
) -> tuple[list, int]:
    if sort_by not in ALLOWED_SORT:
        sort_by = "created_at"
    order = "ASC" if sort_order == "asc" else "DESC"
    offset = (page - 1) * page_size

    conditions = ["org_id = $1"]
    params: list = [org_id]
    idx = 2

    if is_active is not None:
        conditions.append(f"is_active = ${idx}")
        params.append(is_active)
        idx += 1

    where = " AND ".join(conditions)

    count_row = await fetch_one(
        f"SELECT count(*) FROM projects WHERE {where}", *params
    )
    total = count_row["count"] if count_row else 0

    rows = await fetch_all(
        f"""SELECT * FROM projects WHERE {where}
            ORDER BY {sort_by} {order}
            LIMIT ${idx} OFFSET ${idx + 1}""",
        *params,
        page_size,
        offset,
    )
    return rows, total


async def get_project(org_id: UUID, project_id: UUID):
    return await fetch_one(
        "SELECT * FROM projects WHERE id = $1 AND org_id = $2",
        project_id,
        org_id,
    )


async def create_project(org_id: UUID, data: ProjectCreate):
    slug = generate_slug(data.name)
    slug = await ensure_unique_slug("projects", org_id, slug)

    return await fetch_one(
        """INSERT INTO projects (org_id, name, slug, description, language, framework, is_active)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING *""",
        org_id,
        data.name,
        slug,
        data.description,
        data.language,
        data.framework,
        data.is_active,
    )


async def update_project(org_id: UUID, project_id: UUID, data: ProjectUpdate):
    updates = data.model_dump(exclude_none=True)
    if not updates:
        return await get_project(org_id, project_id)

    if "name" in updates:
        slug = generate_slug(updates["name"])
        slug = await ensure_unique_slug("projects", org_id, slug, exclude_id=project_id)
        updates["slug"] = slug

    set_parts = []
    params: list = []
    idx = 1
    for key, val in updates.items():
        set_parts.append(f"{key} = ${idx}")
        params.append(val)
        idx += 1

    params.extend([project_id, org_id])
    return await fetch_one(
        f"""UPDATE projects SET {', '.join(set_parts)}
            WHERE id = ${idx} AND org_id = ${idx + 1}
            RETURNING *""",
        *params,
    )


async def delete_project(org_id: UUID, project_id: UUID) -> bool:
    result = await execute(
        "DELETE FROM projects WHERE id = $1 AND org_id = $2",
        project_id,
        org_id,
    )
    return result == "DELETE 1"
