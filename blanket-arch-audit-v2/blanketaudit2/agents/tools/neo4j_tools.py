"""Knowledge graph query tools for LangGraph agents.

These are ``@tool`` functions that agents can call to query the
call graph and entity relationships.  They work with both Neo4jStore
and InMemoryGraph via the storage factory.

All tools return JSON strings and handle unavailability gracefully.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger()

# Module-level store reference — set by the orchestrator before agents run.
_graph_store: Any = None


def set_graph_store(store: Any) -> None:
    """Set the graph store for tool functions (called by orchestrator)."""
    global _graph_store
    _graph_store = store


def _ensure_store() -> Any:
    if _graph_store is None:
        logger.warning("neo4j_tools.no_store", msg="Graph store not initialized")
    return _graph_store


# ── Tool functions ───────────────────────────────────────────


async def query_call_graph(method_name: str) -> str:
    """Get callers and callees of a method from the knowledge graph.

    Returns JSON with ``callers`` and ``callees`` lists.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Graph store not available", "callers": [], "callees": []})

    try:
        callers = await store.get_callers(method_name)
        callees = await store.get_callees(method_name)
        return json.dumps({
            "method": method_name,
            "callers": callers,
            "callees": callees,
            "caller_count": len(callers),
            "callee_count": len(callees),
        })
    except Exception as exc:
        logger.warning("neo4j_tools.query_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200], "callers": [], "callees": []})


async def query_dependencies(file_path: str) -> str:
    """Get all methods in a file and their call relationships.

    Returns JSON with ``methods`` list.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Graph store not available", "methods": []})

    try:
        # Query methods in the file
        if hasattr(store, "query"):
            records = await store.query(
                "MATCH (m:Method {file_path: $path}) RETURN m.qualified_name AS name",
                {"path": file_path},
            )
        else:
            records = []
        return json.dumps({"file": file_path, "methods": records})
    except Exception as exc:
        logger.warning("neo4j_tools.deps_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200], "methods": []})


async def get_entry_points() -> str:
    """Get all HTTP entry points from the knowledge graph.

    Returns JSON with ``entry_points`` list.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Graph store not available", "entry_points": []})

    try:
        entries = await store.get_entry_points()
        return json.dumps({"entry_points": entries, "count": len(entries)})
    except Exception as exc:
        logger.warning("neo4j_tools.entries_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200], "entry_points": []})


async def get_blast_radius(method_name: str) -> str:
    """Compute blast radius for a method — how many entry points reach it.

    Returns JSON with caller chain info.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Graph store not available"})

    try:
        callers = await store.get_callers(method_name)
        entries = await store.get_entry_points()
        entry_names = {e.get("name", "") for e in entries}

        # Simple: count how many entry points are in the caller chain
        reaching_entries = [c for c in callers if c.get("name", "") in entry_names]

        return json.dumps({
            "method": method_name,
            "direct_callers": len(callers),
            "reaching_entry_points": len(reaching_entries),
            "entry_points": reaching_entries,
        })
    except Exception as exc:
        logger.warning("neo4j_tools.blast_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200]})


async def find_call_chain(start: str, end: str, max_depth: int = 10) -> str:
    """Find call paths from start method to end method.

    Returns JSON with ``chains`` list of method name lists.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Graph store not available", "chains": []})

    try:
        chains = await store.get_call_chain(start, end, max_depth)
        return json.dumps({
            "start": start,
            "end": end,
            "chains": chains,
            "count": len(chains),
        })
    except Exception as exc:
        logger.warning("neo4j_tools.chain_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200], "chains": []})
