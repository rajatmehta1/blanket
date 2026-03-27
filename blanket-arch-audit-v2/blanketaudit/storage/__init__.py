"""Storage abstraction — factory returns the right backend.

``get_graph_store()`` returns Neo4j or InMemoryGraph.
``get_scan_store()`` returns SQLite or InMemoryScanStore.
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit.config import get_settings

logger = structlog.get_logger()


async def get_graph_store() -> Any:
    """Return a graph store: Neo4j if available, else InMemoryGraph.

    Tries Neo4j first.  On connection failure or missing package,
    falls back to the in-memory graph.
    """
    settings = get_settings()

    if settings.neo4j_password:
        try:
            from blanketaudit.storage.neo4j_store import Neo4jStore

            store = Neo4jStore()
            await store.connect()
            return store
        except Exception as exc:
            logger.warning(
                "storage.neo4j_unavailable",
                error=str(exc)[:200],
                msg="Falling back to in-memory graph",
            )

    from blanketaudit.storage.memory_fallback import InMemoryGraph
    store = InMemoryGraph()
    await store.connect()
    return store


async def get_scan_store() -> Any:
    """Return a scan store: SQLite if aiosqlite available, else in-memory.

    Tries SQLite first.  On missing package or connection failure,
    falls back to InMemoryScanStore.
    """
    try:
        from blanketaudit.storage.sqlite_store import SQLiteStore

        store = SQLiteStore()
        await store.connect()
        return store
    except Exception as exc:
        logger.warning(
            "storage.sqlite_unavailable",
            error=str(exc)[:200],
            msg="Falling back to in-memory scan store",
        )

    from blanketaudit.storage.memory_fallback import InMemoryScanStore
    store = InMemoryScanStore()
    await store.connect()
    return store
