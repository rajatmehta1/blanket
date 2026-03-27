"""Milvus vector DB for code embeddings, compliance clause RAG, and pattern search.

Uses LangChain's vector store abstraction so the embedding provider is
pluggable via ``get_embeddings()``.  Falls back to an in-memory vector
store when Milvus is unavailable.

Three collections:
- ``code_chunks``:  embedded code snippets for semantic search
- ``compliance_clauses``:  embedded compliance control text for RAG
- ``vulnerability_patterns``:  embedded vulnerability descriptions for matching
"""

from __future__ import annotations

from typing import Any

import structlog

from blanketaudit.config import get_settings
from blanketaudit.llm.embeddings import get_embeddings

logger = structlog.get_logger()

# Default collection names
COLLECTION_CODE_CHUNKS = "code_chunks"
COLLECTION_COMPLIANCE_CLAUSES = "compliance_clauses"
COLLECTION_VULN_PATTERNS = "vulnerability_patterns"

ALL_COLLECTIONS = [
    COLLECTION_CODE_CHUNKS,
    COLLECTION_COMPLIANCE_CLAUSES,
    COLLECTION_VULN_PATTERNS,
]


class MilvusStore:
    """Manage Milvus vector collections with LangChain integration.

    Automatically falls back to ``InMemoryVectorStore`` when Milvus is
    unreachable or ``pymilvus`` is not installed.

    Usage::

        store = MilvusStore()
        await store.connect()
        await store.add_texts("code_chunks", texts, metadatas)
        results = await store.search("code_chunks", "SQL injection pattern", top_k=5)
        await store.close()
    """

    def __init__(
        self,
        uri: str | None = None,
        embedding_override: Any | None = None,
    ) -> None:
        settings = get_settings()
        self._uri = uri or settings.milvus_uri
        self._embedding_override = embedding_override
        self._stores: dict[str, Any] = {}
        self._using_fallback = False
        self._embeddings: Any = None

    # ── Lifecycle ────────────────────────────────────────────

    async def connect(self) -> None:
        """Initialize embedding model and create vector store collections."""
        self._embeddings = self._embedding_override or get_embeddings()

        if self._embeddings is None:
            logger.warning(
                "milvus.no_embeddings",
                msg="No embedding provider configured — vector search disabled",
            )
            self._using_fallback = True
            return

        # Try Milvus first, fall back to in-memory
        for collection_name in ALL_COLLECTIONS:
            store = self._create_store(collection_name)
            self._stores[collection_name] = store

        logger.info(
            "milvus.connected",
            collections=list(self._stores.keys()),
            using_fallback=self._using_fallback,
        )

    def _create_store(self, collection_name: str) -> Any:
        """Create a LangChain vector store for one collection."""
        if not self._using_fallback:
            try:
                from langchain_milvus import Milvus  # type: ignore[import-untyped]

                store = Milvus(
                    embedding_function=self._embeddings,
                    collection_name=collection_name,
                    connection_args={"uri": self._uri},
                    auto_id=True,
                )
                return store
            except ImportError:
                logger.warning(
                    "milvus.import_failed",
                    msg="langchain-milvus not installed — using in-memory fallback",
                )
                self._using_fallback = True
            except Exception as exc:
                logger.warning(
                    "milvus.connection_failed",
                    error=str(exc)[:200],
                    msg="Milvus unavailable — using in-memory fallback",
                )
                self._using_fallback = True

        # In-memory fallback
        return self._create_memory_store()

    def _create_memory_store(self) -> Any:
        """Create an in-memory vector store fallback.

        Uses our own _SimpleMemoryStore which doesn't require real
        embeddings — just keyword matching.  This ensures tests work
        with mock embedding objects.
        """
        return _SimpleMemoryStore(self._embeddings)

    async def close(self) -> None:
        """Release resources."""
        self._stores.clear()
        logger.info("milvus.closed")

    # ── Properties ───────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return len(self._stores) > 0

    @property
    def using_fallback(self) -> bool:
        return self._using_fallback

    @property
    def collections(self) -> list[str]:
        return list(self._stores.keys())

    # ── Document operations ──────────────────────────────────

    async def add_texts(
        self,
        collection: str,
        texts: list[str],
        metadatas: list[dict] | None = None,
    ) -> list[str]:
        """Add text documents to a collection.

        Parameters
        ----------
        collection:
            One of the collection names (code_chunks, compliance_clauses, etc.)
        texts:
            Text content to embed and store.
        metadatas:
            Optional per-document metadata dicts.

        Returns
        -------
        List of document IDs.
        """
        store = self._stores.get(collection)
        if store is None:
            logger.warning("milvus.collection_not_found", collection=collection)
            return []

        try:
            ids = await _async_add_texts(store, texts, metadatas)
            logger.info(
                "milvus.added",
                collection=collection,
                count=len(texts),
            )
            return ids
        except Exception as exc:
            logger.warning(
                "milvus.add_failed",
                collection=collection,
                error=str(exc)[:200],
            )
            return []

    async def search(
        self,
        collection: str,
        query: str,
        top_k: int = 10,
        filter_dict: dict | None = None,
    ) -> list[dict]:
        """Semantic similarity search.

        Parameters
        ----------
        collection:
            Collection to search in.
        query:
            Natural language query text.
        top_k:
            Number of results to return.
        filter_dict:
            Optional metadata filter.

        Returns
        -------
        List of ``{"content": str, "metadata": dict, "score": float}`` dicts.
        """
        store = self._stores.get(collection)
        if store is None:
            logger.warning("milvus.collection_not_found", collection=collection)
            return []

        try:
            results = await _async_search(store, query, top_k)
            logger.info(
                "milvus.search",
                collection=collection,
                query=query[:50],
                results=len(results),
            )
            return results
        except Exception as exc:
            logger.warning(
                "milvus.search_failed",
                collection=collection,
                error=str(exc)[:200],
            )
            return []

    async def delete_collection(self, collection: str) -> None:
        """Remove all documents from a collection."""
        if collection in self._stores:
            self._stores[collection] = self._create_store(collection)
            logger.info("milvus.collection_cleared", collection=collection)

    # ── Convenience: domain-specific operations ──────────────

    async def add_code_chunks(
        self,
        chunks: list[dict],
    ) -> list[str]:
        """Add code chunks with metadata (file_path, repo, language, etc.)."""
        texts = [c.get("content", "") for c in chunks]
        metadatas = [
            {k: v for k, v in c.items() if k != "content"}
            for c in chunks
        ]
        return await self.add_texts(COLLECTION_CODE_CHUNKS, texts, metadatas)

    async def search_code(self, query: str, top_k: int = 10) -> list[dict]:
        """Search code chunks by semantic similarity."""
        return await self.search(COLLECTION_CODE_CHUNKS, query, top_k)

    async def add_compliance_clauses(
        self,
        clauses: list[dict],
    ) -> list[str]:
        """Add compliance control clauses for RAG."""
        texts = [
            f"{c.get('framework', '')} {c.get('clause', '')}: {c.get('text', '')}"
            for c in clauses
        ]
        return await self.add_texts(COLLECTION_COMPLIANCE_CLAUSES, texts, clauses)

    async def search_compliance(self, query: str, top_k: int = 5) -> list[dict]:
        """Search compliance clauses for RAG context."""
        return await self.search(COLLECTION_COMPLIANCE_CLAUSES, query, top_k)

    async def add_vuln_patterns(
        self,
        patterns: list[dict],
    ) -> list[str]:
        """Add vulnerability pattern descriptions."""
        texts = [p.get("description", "") for p in patterns]
        return await self.add_texts(COLLECTION_VULN_PATTERNS, texts, patterns)

    async def search_vuln_patterns(self, query: str, top_k: int = 5) -> list[dict]:
        """Search vulnerability patterns."""
        return await self.search(COLLECTION_VULN_PATTERNS, query, top_k)


# ── Async wrappers ───────────────────────────────────────────
# LangChain vector stores have sync APIs; we wrap them for async.


async def _async_add_texts(
    store: Any,
    texts: list[str],
    metadatas: list[dict] | None,
) -> list[str]:
    """Add texts to a LangChain vector store (handles both sync and async)."""
    if hasattr(store, "aadd_texts"):
        return await store.aadd_texts(texts, metadatas=metadatas)
    # Sync fallback
    import asyncio
    return await asyncio.to_thread(store.add_texts, texts, metadatas=metadatas)


async def _async_search(
    store: Any,
    query: str,
    top_k: int,
) -> list[dict]:
    """Search a LangChain vector store (handles both sync and async)."""
    if hasattr(store, "asimilarity_search_with_score"):
        results = await store.asimilarity_search_with_score(query, k=top_k)
    elif hasattr(store, "similarity_search_with_score"):
        import asyncio
        results = await asyncio.to_thread(
            store.similarity_search_with_score, query, k=top_k
        )
    else:
        return []

    return [
        {
            "content": doc.page_content,
            "metadata": doc.metadata,
            "score": score,
        }
        for doc, score in results
    ]


# ── Ultra-minimal in-memory fallback ─────────────────────────
# Used only when even langchain_core.vectorstores is unavailable.


class _SimpleMemoryStore:
    """Bare-bones in-memory store when no vector store library is available."""

    def __init__(self, embeddings: Any = None) -> None:
        self._docs: list[tuple[str, dict]] = []  # (text, metadata)
        self._embeddings = embeddings

    def add_texts(
        self,
        texts: list[str],
        metadatas: list[dict] | None = None,
    ) -> list[str]:
        ids: list[str] = []
        for i, text in enumerate(texts):
            meta = metadatas[i] if metadatas and i < len(metadatas) else {}
            self._docs.append((text, meta))
            ids.append(str(len(self._docs) - 1))
        return ids

    async def aadd_texts(
        self,
        texts: list[str],
        metadatas: list[dict] | None = None,
    ) -> list[str]:
        return self.add_texts(texts, metadatas=metadatas)

    def similarity_search_with_score(
        self,
        query: str,
        k: int = 10,
    ) -> list[tuple[Any, float]]:
        """Brute-force search using substring matching (no real embeddings)."""
        scored: list[tuple[int, float]] = []
        query_lower = query.lower()
        for idx, (text, meta) in enumerate(self._docs):
            # Simple substring overlap score
            words = set(query_lower.split())
            text_lower = text.lower()
            matches = sum(1 for w in words if w in text_lower)
            score = matches / max(len(words), 1)
            scored.append((idx, score))

        scored.sort(key=lambda x: -x[1])
        top = scored[:k]

        # Create Document-like objects
        results = []
        for idx, score in top:
            text, meta = self._docs[idx]
            results.append((_SimpleDoc(text, meta), score))
        return results

    async def asimilarity_search_with_score(
        self,
        query: str,
        k: int = 10,
    ) -> list[tuple[Any, float]]:
        return self.similarity_search_with_score(query, k=k)


class _SimpleDoc:
    """Minimal document object matching LangChain Document interface."""

    def __init__(self, page_content: str, metadata: dict) -> None:
        self.page_content = page_content
        self.metadata = metadata
