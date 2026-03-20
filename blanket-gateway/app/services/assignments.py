from __future__ import annotations

from uuid import UUID

import asyncpg

from app.database import execute, fetch_all, fetch_one


class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


async def list_assignments(org_id: UUID, project_id: UUID) -> list:
    return await fetch_all(
        """SELECT pp.project_id, pp.policy_id, pp.is_enabled,
                  pp.enabled_at, pp.enabled_by,
                  p.name AS policy_name,
                  p.category::text AS policy_category,
                  p.severity::text AS policy_severity
           FROM project_policies pp
           JOIN policies p ON p.id = pp.policy_id
           JOIN projects pr ON pr.id = pp.project_id
           WHERE pr.org_id = $1 AND pp.project_id = $2
           ORDER BY pp.enabled_at DESC""",
        org_id,
        project_id,
    )


async def assign_policy(
    org_id: UUID,
    project_id: UUID,
    policy_id: UUID,
    is_enabled: bool = True,
) -> dict:
    project = await fetch_one(
        "SELECT id FROM projects WHERE id = $1 AND org_id = $2",
        project_id,
        org_id,
    )
    if not project:
        raise NotFoundError("Project not found")

    policy = await fetch_one(
        "SELECT id FROM policies WHERE id = $1 AND org_id = $2",
        policy_id,
        org_id,
    )
    if not policy:
        raise NotFoundError("Policy not found")

    try:
        row = await fetch_one(
            """INSERT INTO project_policies (project_id, policy_id, is_enabled)
               VALUES ($1, $2, $3)
               RETURNING *""",
            project_id,
            policy_id,
            is_enabled,
        )
        return dict(row) if row else {}
    except asyncpg.UniqueViolationError:
        raise ConflictError("Policy already assigned to this project")


async def update_assignment(
    org_id: UUID,
    project_id: UUID,
    policy_id: UUID,
    is_enabled: bool,
):
    row = await fetch_one(
        """UPDATE project_policies pp
           SET is_enabled = $3
           FROM projects pr
           WHERE pp.project_id = $1 AND pp.policy_id = $2
             AND pr.id = pp.project_id AND pr.org_id = $4
           RETURNING pp.project_id, pp.policy_id, pp.is_enabled,
                     pp.enabled_at, pp.enabled_by""",
        project_id,
        policy_id,
        is_enabled,
        org_id,
    )
    return row


async def remove_assignment(
    org_id: UUID,
    project_id: UUID,
    policy_id: UUID,
) -> bool:
    result = await execute(
        """DELETE FROM project_policies pp
           USING projects pr
           WHERE pp.project_id = $1 AND pp.policy_id = $2
             AND pr.id = pp.project_id AND pr.org_id = $3""",
        project_id,
        policy_id,
        org_id,
    )
    return "DELETE 1" in result
