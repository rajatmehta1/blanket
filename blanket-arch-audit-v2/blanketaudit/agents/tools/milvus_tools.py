"""Semantic code search and compliance clause RAG tools for LangGraph agents.

These tools query the Milvus vector store (or its in-memory fallback)
for semantic similarity search on code chunks and compliance clauses.
All tools return JSON strings.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger()

# Module-level store reference — set by orchestrator.
_vector_store: Any = None


def set_vector_store(store: Any) -> None:
    """Set the MilvusStore for tool functions (called by orchestrator)."""
    global _vector_store
    _vector_store = store


def _ensure_store() -> Any:
    if _vector_store is None:
        logger.warning("milvus_tools.no_store", msg="Vector store not initialized")
    return _vector_store


# ── Tool functions ───────────────────────────────────────────


async def semantic_search(query: str, top_k: int = 10) -> str:
    """Search code chunks by semantic similarity.

    Returns JSON with ``results`` list of {content, metadata, score}.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Vector store not available", "results": []})

    try:
        results = await store.search_code(query, top_k=top_k)
        return json.dumps({"query": query, "results": results, "count": len(results)})
    except Exception as exc:
        logger.warning("milvus_tools.search_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200], "results": []})


async def compliance_rag(query: str, top_k: int = 5) -> str:
    """Search compliance clauses for RAG context.

    Returns JSON with matching compliance controls and their text.
    Agents use this to map findings to real compliance controls.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Vector store not available", "clauses": []})

    try:
        results = await store.search_compliance(query, top_k=top_k)
        # Flatten to just the useful fields for the agent
        clauses = []
        for r in results:
            meta = r.get("metadata", {})
            clauses.append({
                "framework": meta.get("framework", ""),
                "clause": meta.get("clause", ""),
                "title": meta.get("title", ""),
                "text": r.get("content", ""),
                "relevance_score": r.get("score", 0),
            })
        return json.dumps({"query": query, "clauses": clauses, "count": len(clauses)})
    except Exception as exc:
        logger.warning("milvus_tools.rag_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200], "clauses": []})


async def search_vuln_patterns(query: str, top_k: int = 5) -> str:
    """Search vulnerability pattern descriptions.

    Used by agents to find similar known vulnerabilities.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Vector store not available", "patterns": []})

    try:
        results = await store.search_vuln_patterns(query, top_k=top_k)
        return json.dumps({"query": query, "patterns": results, "count": len(results)})
    except Exception as exc:
        logger.warning("milvus_tools.vuln_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200], "patterns": []})


async def add_code_chunk(content: str, file_path: str, repo: str, language: str = "") -> str:
    """Add a code chunk to the vector store for future search.

    Returns JSON with the chunk ID.
    """
    store = _ensure_store()
    if store is None:
        return json.dumps({"error": "Vector store not available"})

    try:
        ids = await store.add_code_chunks([{
            "content": content,
            "file_path": file_path,
            "repo": repo,
            "language": language,
        }])
        return json.dumps({"id": ids[0] if ids else "", "status": "added"})
    except Exception as exc:
        logger.warning("milvus_tools.add_failed", error=str(exc)[:200])
        return json.dumps({"error": str(exc)[:200]})
