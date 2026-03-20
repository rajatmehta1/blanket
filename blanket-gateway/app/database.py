from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import asyncpg

from app.config import Settings, get_settings

logger = logging.getLogger("blanket.db")

_pool: asyncpg.Pool | None = None


async def init_pool(settings: Settings | None = None) -> asyncpg.Pool:
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
        server_settings={"application_name": "blanket-gateway"},
    )
    logger.info("Database pool initialized")
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed")


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialized — call init_pool() first")
    return _pool


@asynccontextmanager
async def acquire() -> AsyncGenerator[asyncpg.Connection, None]:
    pool = get_pool()
    async with pool.acquire() as conn:
        yield conn


async def fetch_all(query: str, *args: Any) -> list[asyncpg.Record]:
    async with acquire() as conn:
        return await conn.fetch(query, *args)


async def fetch_one(query: str, *args: Any) -> asyncpg.Record | None:
    async with acquire() as conn:
        return await conn.fetchrow(query, *args)


async def execute(query: str, *args: Any) -> str:
    async with acquire() as conn:
        return await conn.execute(query, *args)
