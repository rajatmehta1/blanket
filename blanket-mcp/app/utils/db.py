from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from typing import Any,
import asyncpg
from app.utils.config import Settings, get_settings

"""Blanket MCP Server — Database connection pool."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import asyncpg

from app.utils.config import Settings, get_settings

logger = logging.getLogger("blanket.db")

_pool: asyncpg.Pool | None = None


async def init_pool(settings: Settings | None = None) -> asyncpg.Pool:
    """Create and return the connection pool. Idempotent."""
    global _pool
    if _pool is not None:
        return _pool

    s = settings or get_settings()
    logger.info(
        "Connecting to database (pool: %d–%d connections)",
        s.db_pool_min,
        s.db_pool_max,
    )
    _pool = await asyncpg.create_pool(
        dsn=s.database_url,
        min_size=s.db_pool_min,
        max_size=s.db_pool_max,
        command_timeout=s.db_command_timeout,
        # Neon serverless: keep connections alive
        server_settings={"application_name": "blanket-mcp"},
    )
    logger.info("Database pool initialized")
    return _pool


async def close_pool() -> None:
    """Gracefully close the connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed")


def get_pool() -> asyncpg.Pool:
    """Return the active pool. Raises if not initialized."""
    if _pool is None:
        raise RuntimeError("Database pool not initialized — call init_pool() first")
    return _pool


@asynccontextmanager
async def acquire() -> AsyncGenerator[asyncpg.Connection, None]:
    """Acquire a connection from the pool with automatic release."""
    pool = get_pool()
    async with pool.acquire() as conn:
        yield conn


async def fetch_all(query: str, *args: Any) -> list[asyncpg.Record]:
    """Execute a query and return all rows."""
    async with acquire() as conn:
        return await conn.fetch(query, *args)


async def fetch_one(query: str, *args: Any) -> asyncpg.Record | None:
    """Execute a query and return a single row."""
    async with acquire() as conn:
        return await conn.fetchrow(query, *args)


async def execute(query: str, *args: Any) -> str:
    """Execute a query and return the status string."""
    async with acquire() as conn:
        return await conn.execute(query, *args)
