"""PostgreSQL store for cloud/API mode.

Optional — only used when deploying with a PostgreSQL database.
Falls back to SQLiteStore or InMemoryScanStore otherwise.
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit.exceptions import StorageError

logger = structlog.get_logger()


class PostgresStore:
    """SQLAlchemy async for PostgreSQL in cloud deployments.

    Mirrors the SQLiteStore interface. Requires ``sqlalchemy[asyncio]``
    and ``asyncpg`` to be installed.
    """

    def __init__(self, dsn: str = "") -> None:
        self._dsn = dsn
        self._engine: Any = None

    async def connect(self) -> None:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
            self._engine = create_async_engine(self._dsn, echo=False)
            logger.info("postgres.connected", dsn=self._dsn[:30] + "...")
        except ImportError:
            raise StorageError("sqlalchemy[asyncio] or asyncpg not installed")
        except Exception as exc:
            raise StorageError(f"PostgreSQL connection failed: {exc}")

    async def close(self) -> None:
        if self._engine:
            await self._engine.dispose()
            self._engine = None

    @property
    def is_connected(self) -> bool:
        return self._engine is not None
