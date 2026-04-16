"""
Neo4j store - graph database wrapper

schema -
         Nodes: repository, module, class, function, service, endpoint, InfraResource, Dependency,
         SQLTable, ConfigResource, CICDPipeline, DomainConcept
         Relationships: Imports,

"""
from __future__ import annotations

import logging
from typing import Any

from neo4j import AsyncGraphDatabase, AsyncDriver

logger = logging.getLogger(__name__)

NODE_LABELS = [
    "Repository", "Module", "Class", "Function", "Service",
    "Endpoint", "InfraResource", "Dependency", "SQLTable",
    "ConfigResource", "CICDPipeline", "DomainConcept",
]

RELATIONSHIP_TYPES = [
    "IMPORTS", "CALLS", "DEPENDS_ON", "CONTAINS", "EXPOSES",
    "CONNECTS_TO", "CONFIGURES", "DEPLOYS",
]

SCHEMA_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Repository) REQUIRE r.url IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (m:Module) REQUIRE m.path IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Class) REQUIRE c.qualified_name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (f:Function) REQUIRE f.qualified_name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.path IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Dependency) REQUIRE d.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (t:SQLTable) REQUIRE t.name IS UNIQUE",
]

SCHEMA_INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (m:Module) ON (m.language)",
    "CREATE INDEX IF NOT EXISTS FOR (c:Class) ON (c.module_path)",
    "CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.module_path)",
]


class Neo4jStore:
    def __init__(self, uri: str, username: str, password: str, database: str = "neo4j"):
        self._uri = uri
        self._username = username
        self._password = password
        self._database = database
        self._driver: AsyncDriver | None = None

    @property
    def driver(self) -> AsyncDriver:
        if self._driver is None:
            raise RuntimeError("Not connected. Call connect() first.")
        return self._driver

    async def connect(self) -> None:
        self._driver = AsyncGraphDatabase.driver(
            self._uri,
            auth=(self._username, self._password),
        )
        await self._driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", self._uri)

    async def close(self) -> None:
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")

    async def setup_schema(self) -> None:
        async with self.driver.session(database=self._database) as session:
            for stmt in SCHEMA_CONSTRAINTS + SCHEMA_INDEXES:
                await session.run(stmt)
        logger.info("Neo4j schema setup complete (%d constraints, %d indexes)",
                     len(SCHEMA_CONSTRAINTS), len(SCHEMA_INDEXES))

    async def execute(self, query: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        async with self.driver.session(database=self._database) as session:
            result = await session.run(query, parameters or {})
            records = [record.data() async for record in result]
            return records

    async def __aenter__(self) -> Neo4jStore:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
