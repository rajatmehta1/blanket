from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from uuid import UUID

from fastapi import Header, HTTPException

from app.database import execute, fetch_one

logger = logging.getLogger("blanket.auth")


@dataclass
class AuthContext:
    org_id: UUID
    api_key_id: UUID
    key_prefix: str


async def require_auth(x_api_key: str = Header(...)) -> AuthContext:
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

    row = await fetch_one(
        """
        SELECT id, org_id, key_prefix
        FROM api_keys
        WHERE key_hash = $1 AND is_active = true
        """,
        key_hash,
    )
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    await execute(
        "UPDATE api_keys SET last_used_at = now() WHERE id = $1",
        row["id"],
    )

    return AuthContext(
        org_id=row["org_id"],
        api_key_id=row["id"],
        key_prefix=row["key_prefix"],
    )
