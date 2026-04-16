"""Tests for storage layer — InMemoryGraph, InMemoryScanStore, SQLiteStore, factory."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from blanketaudit2.config import Settings, get_settings
from blanketaudit2.storage.memory_fallback import InMemoryGraph, InMemoryScanStore


# ── Helpers ──────────────────────────────────────────────────


def _settings(**overrides) -> Settings:
    get_settings.cache_clear()
    return Settings(llm={"provider": "none"}, **overrides)


# ═══════════════════════════════════════════════════════════════
# InMemoryGraph
# ═══════════════════════════════════════════════════════════════


class TestInMemoryGraph:
    @pytest.mark.asyncio
    async def test_connect_and_close(self):
        g = InMemoryGraph()
        await g.connect()
        assert g.is_connected
        await g.close()

    @pytest.mark.asyncio
    async def test_store_methods(self):
        g = InMemoryGraph()
        count = await g.store_methods([
            {"qualified_name": "Service.get", "repo_name": "api",
             "file_path": "s.py", "line_start": 1, "line_end": 10,
             "is_entry_point": True, "complexity": 3},
            {"qualified_name": "Service.save", "repo_name": "api",
             "file_path": "s.py", "line_start": 12, "line_end": 20,
             "is_entry_point": False, "complexity": 1},
        ])
        assert count == 2
        assert await g.count_nodes("Method") == 2

    @pytest.mark.asyncio
    async def test_store_calls(self):
        g = InMemoryGraph()
        await g.store_methods([
            {"qualified_name": "A", "repo_name": "r", "file_path": "a.py",
             "line_start": 1, "line_end": 5, "is_entry_point": False, "complexity": 1},
            {"qualified_name": "B", "repo_name": "r", "file_path": "b.py",
             "line_start": 1, "line_end": 5, "is_entry_point": False, "complexity": 1},
        ])
        count = await g.store_calls([
            {"caller": "A", "callee": "B", "file_path": "a.py",
             "line_number": 3, "call_type": "direct"},
        ])
        assert count == 1

    @pytest.mark.asyncio
    async def test_get_callers(self):
        g = InMemoryGraph()
        await g.store_calls([
            {"caller": "A", "callee": "B", "file_path": "a.py", "line_number": 1, "call_type": "direct"},
            {"caller": "C", "callee": "B", "file_path": "c.py", "line_number": 1, "call_type": "direct"},
        ])
        callers = await g.get_callers("B")
        assert len(callers) == 2
        names = {c["name"] for c in callers}
        assert names == {"A", "C"}

    @pytest.mark.asyncio
    async def test_get_callees(self):
        g = InMemoryGraph()
        await g.store_calls([
            {"caller": "A", "callee": "B", "file_path": "a.py", "line_number": 1, "call_type": "direct"},
            {"caller": "A", "callee": "C", "file_path": "a.py", "line_number": 2, "call_type": "direct"},
        ])
        callees = await g.get_callees("A")
        assert len(callees) == 2

    @pytest.mark.asyncio
    async def test_get_entry_points(self):
        g = InMemoryGraph()
        await g.store_methods([
            {"qualified_name": "handler", "repo_name": "api", "file_path": "r.py",
             "line_start": 1, "line_end": 10, "is_entry_point": True, "complexity": 1},
            {"qualified_name": "helper", "repo_name": "api", "file_path": "h.py",
             "line_start": 1, "line_end": 5, "is_entry_point": False, "complexity": 1},
        ])
        entries = await g.get_entry_points()
        assert len(entries) == 1
        assert entries[0]["name"] == "api::handler"

    @pytest.mark.asyncio
    async def test_get_call_chain(self):
        g = InMemoryGraph()
        await g.store_calls([
            {"caller": "A", "callee": "B", "file_path": "a.py", "line_number": 1, "call_type": "d"},
            {"caller": "B", "callee": "C", "file_path": "b.py", "line_number": 1, "call_type": "d"},
        ])
        chains = await g.get_call_chain("A", "C")
        assert len(chains) == 1
        assert chains[0] == ["A", "B", "C"]

    @pytest.mark.asyncio
    async def test_get_call_chain_no_path(self):
        g = InMemoryGraph()
        await g.store_calls([
            {"caller": "A", "callee": "B", "file_path": "a.py", "line_number": 1, "call_type": "d"},
        ])
        chains = await g.get_call_chain("A", "Z")
        assert chains == []

    @pytest.mark.asyncio
    async def test_store_classes(self):
        g = InMemoryGraph()
        count = await g.store_classes([
            {"name": "UserService", "repo_name": "api", "file_path": "s.py",
             "line_start": 1, "line_end": 50},
        ])
        assert count == 1
        assert await g.count_nodes("Class") == 1

    @pytest.mark.asyncio
    async def test_clear(self):
        g = InMemoryGraph()
        await g.store_methods([
            {"qualified_name": "A", "repo_name": "r", "file_path": "a.py",
             "line_start": 1, "line_end": 5, "is_entry_point": False, "complexity": 1},
        ])
        await g.clear()
        assert await g.count_nodes("Method") == 0

    @pytest.mark.asyncio
    async def test_query_passthrough(self):
        g = InMemoryGraph()
        result = await g.query("MATCH (n) RETURN n")
        assert result == []  # No real Cypher parsing


# ═══════════════════════════════════════════════════════════════
# InMemoryScanStore
# ═══════════════════════════════════════════════════════════════


class TestInMemoryScanStore:
    @pytest.mark.asyncio
    async def test_save_and_get_scan(self):
        store = InMemoryScanStore()
        await store.save_scan("scan-1", json.dumps({"id": "scan-1"}))
        result = await store.get_scan("scan-1")
        assert result is not None
        assert result["scan_id"] == "scan-1"

    @pytest.mark.asyncio
    async def test_get_nonexistent_scan(self):
        store = InMemoryScanStore()
        assert await store.get_scan("nope") is None

    @pytest.mark.asyncio
    async def test_list_scans(self):
        store = InMemoryScanStore()
        await store.save_scan("s1", json.dumps({}), timestamp="2026-01-01T00:00:00")
        await store.save_scan("s2", json.dumps({}), timestamp="2026-01-02T00:00:00")
        scans = await store.list_scans(limit=10)
        assert len(scans) == 2
        assert scans[0]["scan_id"] == "s2"  # Newest first

    @pytest.mark.asyncio
    async def test_delete_scan(self):
        store = InMemoryScanStore()
        await store.save_scan("s1", json.dumps({}))
        await store.save_findings("s1", [{"id": "BLK-001", "severity": "high"}])
        await store.delete_scan("s1")
        assert await store.get_scan("s1") is None
        assert await store.get_findings("s1") == []

    @pytest.mark.asyncio
    async def test_save_and_get_findings(self):
        store = InMemoryScanStore()
        count = await store.save_findings("s1", [
            {"id": "BLK-001", "severity": "critical", "title": "SQLi"},
            {"id": "BLK-002", "severity": "high", "title": "XSS"},
        ])
        assert count == 2
        findings = await store.get_findings("s1")
        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_finding_counts(self):
        store = InMemoryScanStore()
        await store.save_findings("s1", [
            {"severity": "critical"}, {"severity": "critical"},
            {"severity": "high"}, {"severity": "low"},
        ])
        counts = await store.get_finding_counts("s1")
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["low"] == 1

    @pytest.mark.asyncio
    async def test_scan_trend(self):
        store = InMemoryScanStore()
        await store.save_scan("s1", json.dumps({}), timestamp="2026-01-01T00:00:00")
        await store.save_findings("s1", [
            {"severity": "critical"}, {"severity": "high"}, {"severity": "high"},
        ])
        trend = await store.get_scan_trend(limit=5)
        assert len(trend) == 1
        assert trend[0]["total"] == 3
        assert trend[0]["critical"] == 1
        assert trend[0]["high"] == 2


# ═══════════════════════════════════════════════════════════════
# SQLiteStore (with real aiosqlite)
# ═══════════════════════════════════════════════════════════════


class TestSQLiteStore:
    @pytest.fixture
    async def store(self, tmp_path):
        try:
            import aiosqlite
        except ImportError:
            pytest.skip("aiosqlite not installed")
        from blanketaudit2.storage.sqlite_store import SQLiteStore
        with patch("blanketaudit2.storage.sqlite_store.get_settings", return_value=_settings()):
            s = SQLiteStore(db_path=tmp_path / "test.db")
            await s.connect()
        yield s
        await s.close()

    @pytest.mark.asyncio
    async def test_save_and_get_scan(self, store):
        await store.save_scan("scan-1", json.dumps({"id": "scan-1"}))
        result = await store.get_scan("scan-1")
        assert result is not None
        assert result["scan_id"] == "scan-1"

    @pytest.mark.asyncio
    async def test_list_scans(self, store):
        await store.save_scan("s1", json.dumps({}), timestamp="2026-01-01")
        await store.save_scan("s2", json.dumps({}), timestamp="2026-01-02")
        scans = await store.list_scans()
        assert len(scans) == 2
        assert scans[0]["scan_id"] == "s2"

    @pytest.mark.asyncio
    async def test_save_and_get_findings(self, store):
        await store.save_scan("s1", json.dumps({}))
        await store.save_findings("s1", [
            {"id": "BLK-001", "severity": "critical", "category": "security",
             "title": "SQLi", "file_path": "a.py"},
        ])
        findings = await store.get_findings("s1")
        assert len(findings) == 1
        assert findings[0]["id"] == "BLK-001"

    @pytest.mark.asyncio
    async def test_finding_counts(self, store):
        await store.save_scan("s1", json.dumps({}))
        await store.save_findings("s1", [
            {"id": "1", "severity": "critical", "category": "security", "title": "A"},
            {"id": "2", "severity": "critical", "category": "security", "title": "B"},
            {"id": "3", "severity": "high", "category": "security", "title": "C"},
        ])
        counts = await store.get_finding_counts("s1")
        assert counts["critical"] == 2
        assert counts["high"] == 1

    @pytest.mark.asyncio
    async def test_delete_scan(self, store):
        await store.save_scan("s1", json.dumps({}))
        await store.save_findings("s1", [
            {"id": "1", "severity": "high", "category": "security", "title": "X"},
        ])
        await store.delete_scan("s1")
        assert await store.get_scan("s1") is None
        assert await store.get_findings("s1") == []

    @pytest.mark.asyncio
    async def test_scan_trend(self, store):
        await store.save_scan("s1", json.dumps({}), timestamp="2026-01-01")
        await store.save_findings("s1", [
            {"id": "1", "severity": "critical", "category": "security", "title": "A"},
            {"id": "2", "severity": "high", "category": "security", "title": "B"},
        ])
        trend = await store.get_scan_trend()
        assert len(trend) == 1
        assert trend[0]["total"] == 2


# ═══════════════════════════════════════════════════════════════
# Storage factory
# ═══════════════════════════════════════════════════════════════


class TestStorageFactory:
    @pytest.mark.asyncio
    async def test_get_graph_store_falls_back_to_memory(self):
        with patch("blanketaudit2.storage.get_settings", return_value=_settings(neo4j_password="")):
            from blanketaudit2.storage import get_graph_store
            store = await get_graph_store()
        assert isinstance(store, InMemoryGraph)
        assert store.is_connected

    @pytest.mark.asyncio
    async def test_get_scan_store_falls_back_to_memory(self):
        with patch("blanketaudit2.storage.get_settings", return_value=_settings()), \
             patch("blanketaudit2.storage.sqlite_store.SQLiteStore.connect",
                    side_effect=Exception("no sqlite")):
            from blanketaudit2.storage import get_scan_store
            store = await get_scan_store()
        assert isinstance(store, InMemoryScanStore)

    @pytest.mark.asyncio
    async def test_get_scan_store_uses_sqlite_when_available(self, tmp_path):
        try:
            import aiosqlite
        except ImportError:
            pytest.skip("aiosqlite not installed")

        s = _settings(sqlite_path=str(tmp_path / "test.db"))
        with patch("blanketaudit2.storage.get_settings", return_value=s), \
             patch("blanketaudit2.storage.sqlite_store.get_settings", return_value=s):
            from blanketaudit2.storage import get_scan_store
            store = await get_scan_store()

        from blanketaudit2.storage.sqlite_store import SQLiteStore
        assert isinstance(store, SQLiteStore)
        await store.close()
