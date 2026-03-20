from __future__ import annotations

from uuid import UUID

from slugify import slugify as _slugify

from app.database import fetch_one


def generate_slug(name: str) -> str:
    return _slugify(name, lowercase=True)


async def ensure_unique_slug(
    table: str,
    org_id: UUID,
    base_slug: str,
    exclude_id: UUID | None = None,
) -> str:
    for suffix in ("", "-2", "-3", "-4", "-5"):
        candidate = base_slug + suffix
        query = f"SELECT 1 FROM {table} WHERE org_id = $1 AND slug = $2"
        params: list = [org_id, candidate]
        if exclude_id is not None:
            query += " AND id != $3"
            params.append(exclude_id)
        exists = await fetch_one(query, *params)
        if exists is None:
            return candidate
    raise ValueError(f"Could not generate unique slug for '{base_slug}'")
