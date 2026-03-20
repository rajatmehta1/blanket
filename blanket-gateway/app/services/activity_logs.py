from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from app.database import execute, fetch_all, fetch_one

logger = logging.getLogger("blanket.services.activity")


async def log_mutation(
    org_id: UUID,
    api_key_id: UUID,
    action: str,
    project_id: UUID | None = None,
    policy_id: UUID | None = None,
) -> None:
    policies = [policy_id] if policy_id else []
    await execute(
        """
        INSERT INTO enforcement_log
            (org_id, project_id, api_key_id, event_type, source_tool,
             policies_applied, policies_count)
        VALUES ($1, $2, $3, 'api_mutation', $4, $5, $6)
        """,
        org_id,
        project_id,
        api_key_id,
        action,
        policies,
        len(policies),
    )


async def list_logs(
    org_id: UUID,
    page: int,
    page_size: int,
    project_id: UUID | None = None,
    event_type: str | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
) -> tuple[list, int]:
    conditions = ["org_id = $1"]
    params: list = [org_id]
    idx = 2

    if project_id is not None:
        conditions.append(f"project_id = ${idx}")
        params.append(project_id)
        idx += 1
    if event_type is not None:
        conditions.append(f"event_type = ${idx}")
        params.append(event_type)
        idx += 1
    if from_date is not None:
        conditions.append(f"created_at >= ${idx}")
        params.append(from_date)
        idx += 1
    if to_date is not None:
        conditions.append(f"created_at <= ${idx}")
        params.append(to_date)
        idx += 1

    where = " AND ".join(conditions)
    offset = (page - 1) * page_size

    count_row = await fetch_one(
        f"SELECT count(*) FROM enforcement_log WHERE {where}", *params
    )
    total = count_row["count"] if count_row else 0

    rows = await fetch_all(
        f"""SELECT * FROM enforcement_log WHERE {where}
            ORDER BY created_at DESC
            LIMIT ${idx} OFFSET ${idx + 1}""",
        *params,
        page_size,
        offset,
    )
    return rows, total


async def get_log(org_id: UUID, log_id: UUID):
    return await fetch_one(
        "SELECT * FROM enforcement_log WHERE id = $1 AND org_id = $2",
        log_id,
        org_id,
    )
