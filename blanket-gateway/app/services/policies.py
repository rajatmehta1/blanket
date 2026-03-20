from __future__ import annotations

from uuid import UUID

from app.database import execute, fetch_all, fetch_one
from app.models.policies import PolicyCreate, PolicyUpdate
from app.services._helpers import ensure_unique_slug, generate_slug

ALLOWED_SORT = {"created_at", "updated_at", "name", "slug", "category", "severity"}


async def list_policies(
    org_id: UUID,
    page: int,
    page_size: int,
    sort_by: str,
    sort_order: str,
    category: str | None = None,
    severity: str | None = None,
    is_active: bool | None = None,
    tag: str | None = None,
) -> tuple[list, int]:
    if sort_by not in ALLOWED_SORT:
        sort_by = "created_at"
    order = "ASC" if sort_order == "asc" else "DESC"
    offset = (page - 1) * page_size

    conditions = ["org_id = $1", "is_template = false"]
    params: list = [org_id]
    idx = 2

    if category is not None:
        conditions.append(f"category = ${idx}::policy_category")
        params.append(category)
        idx += 1
    if severity is not None:
        conditions.append(f"severity = ${idx}::policy_severity")
        params.append(severity)
        idx += 1
    if is_active is not None:
        conditions.append(f"is_active = ${idx}")
        params.append(is_active)
        idx += 1
    if tag is not None:
        conditions.append(f"${idx} = ANY(tags)")
        params.append(tag)
        idx += 1

    where = " AND ".join(conditions)

    count_row = await fetch_one(
        f"SELECT count(*) FROM policies WHERE {where}", *params
    )
    total = count_row["count"] if count_row else 0

    rows = await fetch_all(
        f"""SELECT * FROM policies WHERE {where}
            ORDER BY {sort_by} {order}
            LIMIT ${idx} OFFSET ${idx + 1}""",
        *params,
        page_size,
        offset,
    )
    return rows, total


async def get_policy(org_id: UUID, policy_id: UUID):
    return await fetch_one(
        "SELECT * FROM policies WHERE id = $1 AND org_id = $2 AND is_template = false",
        policy_id,
        org_id,
    )


async def create_policy(org_id: UUID, data: PolicyCreate):
    slug = generate_slug(data.name)
    slug = await ensure_unique_slug("policies", org_id, slug)

    return await fetch_one(
        """INSERT INTO policies
           (org_id, name, slug, description, category, severity, tags,
            prompt_injection_text, applies_to_languages, applies_to_frameworks,
            is_template, template_source, is_active)
           VALUES ($1, $2, $3, $4, $5::policy_category, $6::policy_severity, $7,
                   $8, $9, $10, false, NULL, $11)
           RETURNING *""",
        org_id,
        data.name,
        slug,
        data.description,
        data.category,
        data.severity,
        data.tags,
        data.prompt_injection_text,
        data.applies_to_languages,
        data.applies_to_frameworks,
        data.is_active,
    )


async def update_policy(org_id: UUID, policy_id: UUID, data: PolicyUpdate):
    updates = data.model_dump(exclude_none=True)
    if not updates:
        return await get_policy(org_id, policy_id)

    if "name" in updates:
        slug = generate_slug(updates["name"])
        slug = await ensure_unique_slug("policies", org_id, slug, exclude_id=policy_id)
        updates["slug"] = slug

    set_parts = []
    params: list = []
    idx = 1
    for key, val in updates.items():
        if key == "category":
            set_parts.append(f"category = ${idx}::policy_category")
        elif key == "severity":
            set_parts.append(f"severity = ${idx}::policy_severity")
        else:
            set_parts.append(f"{key} = ${idx}")
        params.append(val)
        idx += 1

    params.extend([policy_id, org_id])
    return await fetch_one(
        f"""UPDATE policies SET {', '.join(set_parts)}
            WHERE id = ${idx} AND org_id = ${idx + 1} AND is_template = false
            RETURNING *""",
        *params,
    )


async def delete_policy(org_id: UUID, policy_id: UUID) -> bool:
    result = await execute(
        "DELETE FROM policies WHERE id = $1 AND org_id = $2 AND is_template = false",
        policy_id,
        org_id,
    )
    return result == "DELETE 1"
