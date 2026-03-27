"""Zero-infrastructure in-memory fallback for all storage operations.

Provides InMemoryGraph (replacing Neo4j) and InMemoryScanStore
(replacing SQLite) when external services are unavailable.
Used in dev/test and single-scan CLI mode.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger()


# ═══════════════════════════════════════════════════════════════
# In-memory graph (Neo4j replacement)
# ═══════════════════════════════════════════════════════════════


class InMemoryGraph:
    """In-memory graph store matching Neo4jStore's interface.

    Stores nodes as dicts indexed by label + key, and edges as
    adjacency lists.  Supports basic graph traversal.
    """

    def __init__(self) -> None:
        # {label: {key: node_dict}}
        self._nodes: dict[str, dict[str, dict]] = defaultdict(dict)
        # {from_key: [(to_key, edge_dict)]}
        self._edges: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        # Reverse edges for caller lookup
        self._reverse_edges: dict[str, list[tuple[str, dict]]] = defaultdict(list)

    @property
    def is_connected(self) -> bool:
        return True

    async def connect(self) -> None:
        logger.info("memory_graph.ready")

    async def close(self) -> None:
        pass

    # ── Node operations ──────────────────────────────────────

    async def store_methods(self, methods: list[dict]) -> int:
        for m in methods:
            key = f"{m.get('repo_name', '')}::{m.get('qualified_name', '')}"
            self._nodes["Method"][key] = m
        return len(methods)

    async def store_calls(self, calls: list[dict]) -> int:
        for c in calls:
            caller = c.get("caller", "")
            callee = c.get("callee", "")
            self._edges[caller].append((callee, c))
            self._reverse_edges[callee].append((caller, c))
        return len(calls)

    async def store_classes(self, classes: list[dict]) -> int:
        for cls in classes:
            key = f"{cls.get('repo_name', '')}::{cls.get('name', '')}"
            self._nodes["Class"][key] = cls
        return len(classes)

    # ── Query operations ─────────────────────────────────────

    async def query(self, cypher: str, params: dict | None = None) -> list[dict]:
        """Minimal Cypher-like query support (keyword matching only)."""
        # For the in-memory fallback, we don't parse Cypher.
        # Callers should use the specific methods below instead.
        logger.debug("memory_graph.query_passthrough", cypher=cypher[:80])
        return []

    async def get_callers(self, method_name: str) -> list[dict]:
        return [
            {"name": caller, "file": edge.get("file_path", "")}
            for caller, edge in self._reverse_edges.get(method_name, [])
        ]

    async def get_callees(self, method_name: str) -> list[dict]:
        return [
            {"name": callee, "file": edge.get("file_path", "")}
            for callee, edge in self._edges.get(method_name, [])
        ]

    async def get_entry_points(self) -> list[dict]:
        return [
            {"name": key, "file": m.get("file_path", ""), "repo": m.get("repo_name", "")}
            for key, m in self._nodes["Method"].items()
            if m.get("is_entry_point")
        ]

    async def get_call_chain(self, start: str, end: str, max_depth: int = 10) -> list[list[str]]:
        """BFS to find paths from start to end."""
        from collections import deque
        results: list[list[str]] = []
        queue: deque[list[str]] = deque([[start]])
        while queue and len(results) < 10:
            path = queue.popleft()
            if len(path) > max_depth:
                continue
            current = path[-1]
            if current == end and len(path) > 1:
                results.append(path)
                continue
            for callee, _ in self._edges.get(current, []):
                if callee not in path:
                    queue.append(path + [callee])
        return results

    async def count_nodes(self, label: str = "Method") -> int:
        return len(self._nodes.get(label, {}))

    async def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._reverse_edges.clear()


# ═══════════════════════════════════════════════════════════════
# In-memory scan store (SQLite replacement)
# ═══════════════════════════════════════════════════════════════


class InMemoryScanStore:
    """In-memory store matching SQLiteStore's interface.

    Stores scans and findings in dicts.  No persistence — data is
    lost when the process exits.  Suitable for single-scan CLI mode.
    """

    def __init__(self) -> None:
        self._scans: dict[str, dict] = {}
        self._findings: dict[str, list[dict]] = defaultdict(list)

    @property
    def is_connected(self) -> bool:
        return True

    async def connect(self) -> None:
        logger.info("memory_scan_store.ready")

    async def close(self) -> None:
        pass

    async def save_scan(
        self,
        scan_id: str,
        manifest_json: str,
        report_json: str | None = None,
        timestamp: str | None = None,
    ) -> str:
        self._scans[scan_id] = {
            "scan_id": scan_id,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "manifest": json.loads(manifest_json),
            "report": json.loads(report_json) if report_json else None,
            "status": "completed",
        }
        return scan_id

    async def get_scan(self, scan_id: str) -> dict | None:
        return self._scans.get(scan_id)

    async def list_scans(self, limit: int = 20) -> list[dict]:
        scans = sorted(
            self._scans.values(),
            key=lambda s: s.get("timestamp", ""),
            reverse=True,
        )[:limit]
        return [
            {"scan_id": s["scan_id"], "timestamp": s["timestamp"], "status": s["status"]}
            for s in scans
        ]

    async def delete_scan(self, scan_id: str) -> None:
        self._scans.pop(scan_id, None)
        self._findings.pop(scan_id, None)

    async def save_findings(self, scan_id: str, findings: list[dict]) -> int:
        self._findings[scan_id].extend(findings)
        return len(findings)

    async def get_findings(self, scan_id: str) -> list[dict]:
        return self._findings.get(scan_id, [])

    async def get_finding_counts(self, scan_id: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self._findings.get(scan_id, []):
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    async def get_scan_trend(self, limit: int = 10) -> list[dict]:
        result: list[dict] = []
        for s in (await self.list_scans(limit)):
            findings = self._findings.get(s["scan_id"], [])
            result.append({
                "scan_id": s["scan_id"],
                "timestamp": s["timestamp"],
                "total": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
            })
        return result
