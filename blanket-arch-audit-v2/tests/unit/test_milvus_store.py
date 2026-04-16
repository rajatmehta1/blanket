"""Tests for blanketaudit2.storage.milvus_store.

Uses the in-memory fallback (no Milvus server needed) and the
_SimpleMemoryStore for tests without any LangChain vector store deps.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blanketaudit2.config import Settings, get_settings
from blanketaudit2.storage.milvus_store import (
    ALL_COLLECTIONS,
    COLLECTION_CODE_CHUNKS,
    COLLECTION_COMPLIANCE_CLAUSES,
    COLLECTION_VULN_PATTERNS,
    MilvusStore,
    _SimpleDoc,
    _SimpleMemoryStore,
)


# ── Helpers ──────────────────────────────────────────────────


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(
        llm={"provider": "none"},
        embedding={"provider": "none"},
        milvus_uri="http://localhost:19530",
    )


def _mock_embeddings():
    """Create a mock embedding model."""
    mock = MagicMock()
    mock.embed_documents = MagicMock(return_value=[[0.1, 0.2, 0.3]])
    mock.embed_query = MagicMock(return_value=[0.1, 0.2, 0.3])
    return mock


# ═══════════════════════════════════════════════════════════════
# _SimpleMemoryStore (ultra-minimal fallback)
# ═══════════════════════════════════════════════════════════════


class TestSimpleMemoryStore:
    def test_add_and_search(self):
        store = _SimpleMemoryStore()
        ids = store.add_texts(
            ["SQL injection vulnerability in user input"],
            metadatas=[{"type": "vuln"}],
        )
        assert len(ids) == 1
        results = store.similarity_search_with_score("SQL injection", k=1)
        assert len(results) == 1
        doc, score = results[0]
        assert "SQL injection" in doc.page_content
        assert score > 0

    def test_empty_store_returns_empty(self):
        store = _SimpleMemoryStore()
        results = store.similarity_search_with_score("query", k=5)
        assert results == []

    def test_multiple_docs_ranked(self):
        store = _SimpleMemoryStore()
        store.add_texts([
            "XSS reflected vulnerability",
            "SQL injection via string concatenation",
            "Unrelated documentation about deployment",
        ])
        results = store.similarity_search_with_score("SQL injection", k=3)
        # SQL injection doc should rank higher than XSS or deployment
        assert "SQL" in results[0][0].page_content

    def test_metadata_preserved(self):
        store = _SimpleMemoryStore()
        store.add_texts(
            ["code snippet"],
            metadatas=[{"file": "main.py", "line": 42}],
        )
        results = store.similarity_search_with_score("code", k=1)
        assert results[0][0].metadata["file"] == "main.py"
        assert results[0][0].metadata["line"] == 42

    @pytest.mark.asyncio
    async def test_async_add_and_search(self):
        store = _SimpleMemoryStore()
        ids = await store.aadd_texts(["async test doc"])
        assert len(ids) == 1
        results = await store.asimilarity_search_with_score("async test", k=1)
        assert len(results) == 1

    def test_add_without_metadata(self):
        store = _SimpleMemoryStore()
        ids = store.add_texts(["doc1", "doc2"])
        assert len(ids) == 2
        results = store.similarity_search_with_score("doc1", k=2)
        assert len(results) == 2
        assert results[0][0].metadata == {}

    def test_top_k_limits_results(self):
        store = _SimpleMemoryStore()
        store.add_texts([f"document {i}" for i in range(20)])
        results = store.similarity_search_with_score("document", k=5)
        assert len(results) == 5


class TestSimpleDoc:
    def test_has_page_content_and_metadata(self):
        doc = _SimpleDoc("hello world", {"key": "value"})
        assert doc.page_content == "hello world"
        assert doc.metadata == {"key": "value"}


# ═══════════════════════════════════════════════════════════════
# MilvusStore — with fallback to _SimpleMemoryStore
# ═══════════════════════════════════════════════════════════════


class TestMilvusStoreConnect:
    @pytest.mark.asyncio
    async def test_connect_no_embeddings_disables(self):
        """No embedding provider → store connects but is in fallback mode."""
        with patch("blanketaudit2.storage.milvus_store.get_settings", return_value=_settings()), \
             patch("blanketaudit2.storage.milvus_store.get_embeddings", return_value=None):
            store = MilvusStore()
            await store.connect()
        assert store.using_fallback is True
        assert store.is_connected is False
        await store.close()

    @pytest.mark.asyncio
    async def test_connect_with_embeddings_creates_collections(self):
        """With embeddings but no Milvus → falls back to in-memory."""
        mock_emb = _mock_embeddings()
        with patch("blanketaudit2.storage.milvus_store.get_settings", return_value=_settings()):
            store = MilvusStore(embedding_override=mock_emb)
            await store.connect()
        assert store.is_connected is True
        assert store.using_fallback is True  # Milvus not installed
        assert set(store.collections) == set(ALL_COLLECTIONS)
        await store.close()

    @pytest.mark.asyncio
    async def test_close_clears_stores(self):
        mock_emb = _mock_embeddings()
        with patch("blanketaudit2.storage.milvus_store.get_settings", return_value=_settings()):
            store = MilvusStore(embedding_override=mock_emb)
            await store.connect()
            assert store.is_connected
            await store.close()
            assert not store.is_connected


class TestMilvusStoreOperations:
    """Test add/search operations using the in-memory fallback."""

    @pytest.fixture
    async def store(self):
        mock_emb = _mock_embeddings()
        with patch("blanketaudit2.storage.milvus_store.get_settings", return_value=_settings()):
            s = MilvusStore(embedding_override=mock_emb)
            await s.connect()
        yield s
        await s.close()

    @pytest.mark.asyncio
    async def test_add_texts(self, store):
        ids = await store.add_texts(
            COLLECTION_CODE_CHUNKS,
            ["def hello(): pass", "class User: pass"],
            [{"file": "a.py"}, {"file": "b.py"}],
        )
        assert len(ids) == 2

    @pytest.mark.asyncio
    async def test_search(self, store):
        await store.add_texts(
            COLLECTION_CODE_CHUNKS,
            ["SQL injection in user query", "Normal helper function"],
        )
        results = await store.search(COLLECTION_CODE_CHUNKS, "SQL injection", top_k=2)
        assert len(results) >= 1
        assert "content" in results[0]
        assert "score" in results[0]

    @pytest.mark.asyncio
    async def test_add_to_nonexistent_collection(self, store):
        ids = await store.add_texts("nonexistent", ["text"])
        assert ids == []

    @pytest.mark.asyncio
    async def test_search_nonexistent_collection(self, store):
        results = await store.search("nonexistent", "query")
        assert results == []


class TestMilvusStoreDomainOps:
    """Test domain-specific convenience methods."""

    @pytest.fixture
    async def store(self):
        mock_emb = _mock_embeddings()
        with patch("blanketaudit2.storage.milvus_store.get_settings", return_value=_settings()):
            s = MilvusStore(embedding_override=mock_emb)
            await s.connect()
        yield s
        await s.close()

    @pytest.mark.asyncio
    async def test_add_code_chunks(self, store):
        ids = await store.add_code_chunks([
            {"content": "def login(user, pw): pass", "file": "auth.py", "repo": "api"},
            {"content": "class Payment: pass", "file": "pay.py", "repo": "api"},
        ])
        assert len(ids) == 2

    @pytest.mark.asyncio
    async def test_search_code(self, store):
        await store.add_code_chunks([
            {"content": "SQL query with f-string interpolation", "file": "db.py"},
            {"content": "Unit test for login function", "file": "test_auth.py"},
        ])
        results = await store.search_code("SQL injection", top_k=2)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_add_compliance_clauses(self, store):
        ids = await store.add_compliance_clauses([
            {"framework": "HIPAA", "clause": "§164.312(a)(1)", "text": "Access control for ePHI"},
            {"framework": "SOC2", "clause": "CC6.1", "text": "Logical access security"},
        ])
        assert len(ids) == 2

    @pytest.mark.asyncio
    async def test_search_compliance(self, store):
        await store.add_compliance_clauses([
            {"framework": "HIPAA", "clause": "§164.312(e)(1)", "text": "Encryption of ePHI in transit"},
            {"framework": "PCI-DSS", "clause": "Req 4.1", "text": "Encrypt cardholder data in transit"},
        ])
        results = await store.search_compliance("encryption in transit", top_k=2)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_add_vuln_patterns(self, store):
        ids = await store.add_vuln_patterns([
            {"description": "SQL injection via string interpolation", "cwe": "CWE-89"},
            {"description": "Cross-site scripting in reflected input", "cwe": "CWE-79"},
        ])
        assert len(ids) == 2

    @pytest.mark.asyncio
    async def test_search_vuln_patterns(self, store):
        await store.add_vuln_patterns([
            {"description": "SQL injection via f-string in Python"},
            {"description": "Insecure deserialization of pickle data"},
        ])
        results = await store.search_vuln_patterns("SQL injection", top_k=1)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_delete_collection(self, store):
        await store.add_code_chunks([{"content": "some code"}])
        results_before = await store.search_code("code", top_k=5)
        # Delete recreates the collection (empty)
        await store.delete_collection(COLLECTION_CODE_CHUNKS)
        # After delete, store should still exist but be empty
        assert COLLECTION_CODE_CHUNKS in store.collections


# ═══════════════════════════════════════════════════════════════
# Collection constants
# ═══════════════════════════════════════════════════════════════


class TestCollectionConstants:
    def test_three_collections_defined(self):
        assert len(ALL_COLLECTIONS) == 3

    def test_collection_names(self):
        assert COLLECTION_CODE_CHUNKS == "code_chunks"
        assert COLLECTION_COMPLIANCE_CLAUSES == "compliance_clauses"
        assert COLLECTION_VULN_PATTERNS == "vulnerability_patterns"
