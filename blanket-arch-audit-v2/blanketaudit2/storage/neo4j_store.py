"""Neo4j knowledge graph store for code entities and call graph.

Used in cloud/full mode for rich graph queries (blast radius, taint
paths, call chains).  Falls back to InMemoryGraph when Neo4j is
unavailable.
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit2.config import get_settings
from blanketaudit2.exceptions import StorageError

logger = structlog.get_logger()


class Neo4jStore:
    """Manage Neo4j connections and CRUD for code entities and relationships.

    Wraps the ``neo4j`` async driver.  All Cypher queries go through
    ``query()`` or the convenience methods.
    """

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        settings = get_settings()
        self._uri = uri or settings.neo4j_uri
        self._user = user or settings.neo4j_user
        self._password = password or settings.neo4j_password
        self._driver: Any = None

    # ── Lifecycle ────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the Neo4j driver connection."""
        try:
            from neo4j import AsyncGraphDatabase  # type: ignore[import-untyped]

            self._driver = AsyncGraphDatabase.driver(
                self._uri,
                auth=(self._user, self._password),
            )
            # Verify connectivity
            await self._driver.verify_connectivity()
            logger.info("neo4j.connected", uri=self._uri)
        except ImportError:
            raise StorageError(
                "neo4j package not installed. Install with: pip install neo4j",
                details={"uri": self._uri},
            )
        except Exception as exc:
            raise StorageError(
                f"Failed to connect to Neo4j at {self._uri}: {exc}",
                details={"uri": self._uri},
            )

    async def close(self) -> None:
        """Close the Neo4j driver."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("neo4j.closed")

    @property
    def is_connected(self) -> bool:
        return self._driver is not None

    # ── Generic query ────────────────────────────────────────

    async def query(self, cypher: str, params: dict | None = None) -> list[dict]:
        """Execute a Cypher query and return records as dicts."""
        if not self._driver:
            raise StorageError("Neo4j not connected")

        async with self._driver.session() as session:
            result = await session.run(cypher, params or {})
            records = await result.data()
            return records

    # ── Entity CRUD ──────────────────────────────────────────

    async def store_methods(self, methods: list[dict]) -> int:
        """Upsert method nodes into the graph.

        Each dict should have: qualified_name, file_path, repo_name,
        line_start, line_end, is_entry_point, complexity.
        """
        if not methods:
            return 0
        cypher = """
        UNWIND $methods AS m
        MERGE (method:Method {qualified_name: m.qualified_name, repo: m.repo_name})
        SET method.file_path = m.file_path,
            method.line_start = m.line_start,
            method.line_end = m.line_end,
            method.is_entry_point = m.is_entry_point,
            method.complexity = m.complexity
        """
        await self.query(cypher, {"methods": methods})
        logger.info("neo4j.methods_stored", count=len(methods))
        return len(methods)

    async def store_calls(self, calls: list[dict]) -> int:
        """Create CALLS_DIRECTLY relationships between method nodes.

        Each dict should have: caller, callee, file_path, line_number, call_type.
        """
        if not calls:
            return 0
        cypher = """
        UNWIND $calls AS c
        MATCH (caller:Method {qualified_name: c.caller})
        MATCH (callee:Method {qualified_name: c.callee})
        MERGE (caller)-[r:CALLS_DIRECTLY]->(callee)
        SET r.file_path = c.file_path,
            r.line_number = c.line_number,
            r.call_type = c.call_type
        """
        await self.query(cypher, {"calls": calls})
        logger.info("neo4j.calls_stored", count=len(calls))
        return len(calls)

    async def store_classes(self, classes: list[dict]) -> int:
        """Upsert class nodes."""
        if not classes:
            return 0
        cypher = """
        UNWIND $classes AS c
        MERGE (cls:Class {name: c.name, repo: c.repo_name})
        SET cls.file_path = c.file_path,
            cls.line_start = c.line_start,
            cls.line_end = c.line_end
        """
        await self.query(cypher, {"classes": classes})
        return len(classes)

    # ── Graph queries ────────────────────────────────────────

    async def get_callers(self, method_name: str) -> list[dict]:
        """Find all methods that call the given method."""
        return await self.query(
            "MATCH (caller:Method)-[:CALLS_DIRECTLY]->(m:Method {qualified_name: $name}) "
            "RETURN caller.qualified_name AS name, caller.file_path AS file",
            {"name": method_name},
        )

    async def get_callees(self, method_name: str) -> list[dict]:
        """Find all methods called by the given method."""
        return await self.query(
            "MATCH (m:Method {qualified_name: $name})-[:CALLS_DIRECTLY]->(callee:Method) "
            "RETURN callee.qualified_name AS name, callee.file_path AS file",
            {"name": method_name},
        )

    async def get_entry_points(self) -> list[dict]:
        """Find all HTTP entry point methods."""
        return await self.query(
            "MATCH (m:Method {is_entry_point: true}) "
            "RETURN m.qualified_name AS name, m.file_path AS file, m.repo AS repo"
        )

    async def get_call_chain(self, start: str, end: str, max_depth: int = 10) -> list[list[str]]:
        """Find all paths from start to end method."""
        records = await self.query(
            "MATCH path = (s:Method {qualified_name: $start})"
            "-[:CALLS_DIRECTLY*1.." + str(max_depth) + "]->"
            "(e:Method {qualified_name: $end}) "
            "RETURN [n IN nodes(path) | n.qualified_name] AS chain "
            "LIMIT 10",
            {"start": start, "end": end},
        )
        return [r["chain"] for r in records]

    async def count_nodes(self, label: str = "Method") -> int:
        """Count nodes with the given label."""
        records = await self.query(
            f"MATCH (n:{label}) RETURN count(n) AS cnt"
        )
        return records[0]["cnt"] if records else 0

    async def clear(self) -> None:
        """Delete all nodes and relationships (for testing)."""
        await self.query("MATCH (n) DETACH DELETE n")
