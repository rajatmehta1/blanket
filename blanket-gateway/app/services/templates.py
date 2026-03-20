from __future__ import annotations

from uuid import UUID

from app.database import fetch_all, fetch_one
from app.services._helpers import ensure_unique_slug

SYSTEM_ORG_ID = UUID("00000000-0000-0000-0000-000000000001")


class NotFoundError(Exception):
    pass


async def list_templates(
    category: str | None = None,
    severity: str | None = None,
) -> list:
    conditions = ["org_id = $1", "is_template = true", "is_active = true"]
    params: list = [SYSTEM_ORG_ID]
    idx = 2

    if category is not None:
        conditions.append(f"category = ${idx}::policy_category")
        params.append(category)
        idx += 1
    if severity is not None:
        conditions.append(f"severity = ${idx}::policy_severity")
        params.append(severity)
        idx += 1

    where = " AND ".join(conditions)
    return await fetch_all(
        f"SELECT * FROM policies WHERE {where} ORDER BY category, name",
        *params,
    )


async def get_template(template_id: UUID):
    return await fetch_one(
        "SELECT * FROM policies WHERE id = $1 AND org_id = $2 AND is_template = true",
        template_id,
        SYSTEM_ORG_ID,
    )


async def instantiate_template(org_id: UUID, template_id: UUID):
    template = await get_template(template_id)
    if template is None:
        raise NotFoundError("Template not found")

    slug = template["slug"]
    slug = await ensure_unique_slug("policies", org_id, slug)

    return await fetch_one(
        """INSERT INTO policies
           (org_id, name, slug, description, category, severity, tags,
            prompt_injection_text, applies_to_languages, applies_to_frameworks,
            is_template, template_source, is_active)
           VALUES ($1, $2, $3, $4, $5::policy_category, $6::policy_severity, $7,
                   $8, $9, $10, false, $11, true)
           RETURNING *""",
        org_id,
        template["name"],
        slug,
        template["description"],
        template["category"],
        template["severity"],
        template["tags"],
        template["prompt_injection_text"],
        template["applies_to_languages"],
        template["applies_to_frameworks"],
        str(template["id"]),
    )
