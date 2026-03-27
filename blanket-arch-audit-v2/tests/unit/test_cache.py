"""Tests for blanketaudit.cache — diff scanner, content cache, scan manifest."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit.cache.content_cache import ContentCache
from blanketaudit.cache.diff_scanner import DiffScanner
from blanketaudit.cache.scan_manifest import ScanManifestRecorder, _sha256_str
from blanketaudit.config import Settings, get_settings
from blanketaudit.ingestion.models import FileMetadata, ImportInfo
from blanketaudit.models.manifest import ScanManifest


# ── Helpers ──────────────────────────────────────────────────


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(
        llm={"provider": "none"},
        cache={"enabled": True, "ttl_hours": 24, "cache_dir": ".test_cache"},
    )


def _file(path: str) -> FileMetadata:
    return FileMetadata(path=path, repo_name="api", language="python")


# ═══════════════════════════════════════════════════════════════
# DiffScanner
# ═══════════════════════════════════════════════════════════════


class TestDiffScannerChangedFiles:
    @pytest.mark.asyncio
    async def test_parses_git_diff_output(self):
        scanner = DiffScanner()
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(b"src/main.py\nsrc/auth.py\nREADME.md\n", b"")
        )
        with patch("blanketaudit.cache.diff_scanner.asyncio.create_subprocess_exec",
                    return_value=mock_proc):
            changed = await scanner.get_changed_files("/tmp/repo", "abc123")
        assert changed == {"src/main.py", "src/auth.py", "README.md"}

    @pytest.mark.asyncio
    async def test_empty_diff_returns_empty(self):
        scanner = DiffScanner()
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        with patch("blanketaudit.cache.diff_scanner.asyncio.create_subprocess_exec",
                    return_value=mock_proc):
            changed = await scanner.get_changed_files("/tmp/repo", "abc123")
        assert changed == set()

    @pytest.mark.asyncio
    async def test_git_failure_returns_empty(self):
        scanner = DiffScanner()
        mock_proc = AsyncMock()
        mock_proc.returncode = 128
        mock_proc.communicate = AsyncMock(return_value=(b"", b"fatal: bad revision"))
        with patch("blanketaudit.cache.diff_scanner.asyncio.create_subprocess_exec",
                    return_value=mock_proc):
            changed = await scanner.get_changed_files("/tmp/repo", "bad_sha")
        assert changed == set()

    @pytest.mark.asyncio
    async def test_git_not_found_returns_empty(self):
        scanner = DiffScanner()
        with patch("blanketaudit.cache.diff_scanner.asyncio.create_subprocess_exec",
                    side_effect=FileNotFoundError("git not found")):
            changed = await scanner.get_changed_files("/tmp/repo", "abc")
        assert changed == set()


class TestDiffScannerAffectedFiles:
    def test_no_deps_returns_changed_only(self):
        scanner = DiffScanner()
        changed = {"a.py", "b.py"}
        affected = scanner.compute_affected_files(changed, {})
        assert affected == {"a.py", "b.py"}

    def test_direct_dependents_included(self):
        scanner = DiffScanner()
        changed = {"lib.py"}
        reverse_deps = {"lib.py": {"app.py", "cli.py"}}
        affected = scanner.compute_affected_files(changed, reverse_deps)
        assert affected == {"lib.py", "app.py", "cli.py"}

    def test_transitive_closure(self):
        scanner = DiffScanner()
        changed = {"core.py"}
        reverse_deps = {
            "core.py": {"service.py"},
            "service.py": {"routes.py"},
        }
        affected = scanner.compute_affected_files(changed, reverse_deps)
        assert affected == {"core.py", "service.py", "routes.py"}

    def test_circular_deps_no_infinite_loop(self):
        scanner = DiffScanner()
        changed = {"a.py"}
        reverse_deps = {
            "a.py": {"b.py"},
            "b.py": {"a.py"},
        }
        affected = scanner.compute_affected_files(changed, reverse_deps)
        assert affected == {"a.py", "b.py"}


class TestDiffScannerPartition:
    def test_affected_files_to_scan(self):
        scanner = DiffScanner()
        files = [_file("a.py"), _file("b.py"), _file("c.py")]
        affected = {"a.py"}
        cached = {"b.py"}
        to_scan, from_cache = scanner.partition_files(files, affected, cached)
        assert {f.path for f in to_scan} == {"a.py", "c.py"}
        assert {f.path for f in from_cache} == {"b.py"}

    def test_all_affected_none_cached(self):
        scanner = DiffScanner()
        files = [_file("a.py"), _file("b.py")]
        affected = {"a.py", "b.py"}
        to_scan, from_cache = scanner.partition_files(files, affected, set())
        assert len(to_scan) == 2
        assert len(from_cache) == 0

    def test_empty_files(self):
        scanner = DiffScanner()
        to_scan, from_cache = scanner.partition_files([], set(), set())
        assert to_scan == []
        assert from_cache == []


class TestBuildReverseDeps:
    def test_basic_imports(self):
        imports = [
            ImportInfo(source_file="app.py", imported_module="lib", line_number=1),
            ImportInfo(source_file="cli.py", imported_module="lib", line_number=1),
        ]
        file_paths = {"app.py", "cli.py", "lib.py"}
        reverse = DiffScanner.build_reverse_deps(imports, file_paths)
        assert "lib.py" in reverse
        assert reverse["lib.py"] == {"app.py", "cli.py"}

    def test_dotted_module(self):
        imports = [
            ImportInfo(source_file="routes.py", imported_module="services.auth", line_number=1),
        ]
        file_paths = {"routes.py", "services/auth.py"}
        reverse = DiffScanner.build_reverse_deps(imports, file_paths)
        assert "services/auth.py" in reverse
        assert "routes.py" in reverse["services/auth.py"]

    def test_unresolvable_module_ignored(self):
        imports = [
            ImportInfo(source_file="app.py", imported_module="flask", line_number=1),
        ]
        file_paths = {"app.py"}
        reverse = DiffScanner.build_reverse_deps(imports, file_paths)
        # flask is external — shouldn't be in reverse deps
        assert "flask.py" not in reverse


# ═══════════════════════════════════════════════════════════════
# ContentCache
# ═══════════════════════════════════════════════════════════════


class TestContentCacheKey:
    def test_deterministic(self):
        k1 = ContentCache.cache_key("content", "v1")
        k2 = ContentCache.cache_key("content", "v1")
        assert k1 == k2

    def test_different_content_different_key(self):
        k1 = ContentCache.cache_key("content_a", "v1")
        k2 = ContentCache.cache_key("content_b", "v1")
        assert k1 != k2

    def test_different_policy_different_key(self):
        k1 = ContentCache.cache_key("content", "v1")
        k2 = ContentCache.cache_key("content", "v2")
        assert k1 != k2

    def test_is_sha256(self):
        key = ContentCache.cache_key("x", "y")
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)


class TestContentCacheMemory:
    """Test in-memory fallback mode (no SQLite)."""

    @pytest.mark.asyncio
    async def test_miss_returns_none(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache()
        cache._use_memory = True
        result = await cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_put_then_get(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache()
        cache._use_memory = True
        findings = [{"id": "BLK-001", "title": "SQLi"}]
        await cache.put("key1", findings)
        result = await cache.get("key1")
        assert result == findings

    @pytest.mark.asyncio
    async def test_ttl_expiry(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache(ttl_hours=0)  # 0 hours = expires immediately
        cache._use_memory = True
        cache._ttl_seconds = 0  # Force immediate expiry
        await cache.put("key1", [{"id": "BLK-001"}])
        # Entry should be expired immediately
        result = await cache.get("key1")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate_expired(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache()
        cache._use_memory = True
        cache._ttl_seconds = 0
        await cache.put("expired1", [])
        await cache.put("expired2", [])
        count = await cache.invalidate_expired()
        assert count == 2

    @pytest.mark.asyncio
    async def test_clear(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache()
        cache._use_memory = True
        await cache.put("k1", [])
        await cache.put("k2", [])
        await cache.clear()
        assert await cache.size() == 0

    @pytest.mark.asyncio
    async def test_size(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache()
        cache._use_memory = True
        cache._ttl_seconds = 3600
        assert await cache.size() == 0
        await cache.put("k1", [])
        assert await cache.size() == 1
        await cache.put("k2", [])
        assert await cache.size() == 2

    @pytest.mark.asyncio
    async def test_overwrite_existing_key(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache()
        cache._use_memory = True
        cache._ttl_seconds = 3600
        await cache.put("k1", [{"v": 1}])
        await cache.put("k1", [{"v": 2}])
        result = await cache.get("k1")
        assert result == [{"v": 2}]

    @pytest.mark.asyncio
    async def test_get_cached_keys(self):
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache()
        cache._use_memory = True
        cache._ttl_seconds = 3600
        await cache.put("k1", [])
        await cache.put("k2", [])
        keys = cache.get_cached_keys()
        assert keys == {"k1", "k2"}


class TestContentCacheSQLite:
    """Test with actual aiosqlite (if available)."""

    @pytest.mark.asyncio
    async def test_sqlite_roundtrip(self, tmp_path):
        try:
            import aiosqlite
        except ImportError:
            pytest.skip("aiosqlite not installed")

        db_path = tmp_path / "test_cache.db"
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache(db_path=db_path, ttl_hours=1)
        await cache.connect()

        try:
            # Miss
            assert await cache.get("missing") is None

            # Put + Get
            findings = [{"id": "BLK-001", "severity": "critical"}]
            await cache.put("key1", findings)
            result = await cache.get("key1")
            assert result == findings

            # Size
            assert await cache.size() == 1

            # Clear
            await cache.clear()
            assert await cache.size() == 0
        finally:
            await cache.close()

    @pytest.mark.asyncio
    async def test_sqlite_ttl_expiry(self, tmp_path):
        try:
            import aiosqlite
        except ImportError:
            pytest.skip("aiosqlite not installed")

        db_path = tmp_path / "test_cache_ttl.db"
        with patch("blanketaudit.cache.content_cache.get_settings", return_value=_settings()):
            cache = ContentCache(db_path=db_path, ttl_hours=0)
        cache._ttl_seconds = 0  # Immediate expiry
        await cache.connect()

        try:
            await cache.put("key1", [{"id": "BLK-001"}])
            result = await cache.get("key1")
            assert result is None  # Expired
        finally:
            await cache.close()


# ═══════════════════════════════════════════════════════════════
# ScanManifestRecorder
# ═══════════════════════════════════════════════════════════════


class TestScanManifestRecorder:
    def _recorder(self):
        s = _settings()
        with patch("blanketaudit.cache.scan_manifest.get_settings", return_value=s):
            return ScanManifestRecorder(settings=s)

    def test_record_sync_creates_manifest(self):
        recorder = self._recorder()
        manifest = recorder.record_sync(
            repo_commits={"api": "abc123", "engine": "def456"},
        )
        assert isinstance(manifest, ScanManifest)
        assert manifest.scan_id.startswith("scan-")
        assert manifest.repo_commits == {"api": "abc123", "engine": "def456"}
        assert len(manifest.config_hash) == 64

    def test_record_sync_with_policy_versions(self):
        recorder = self._recorder()
        manifest = recorder.record_sync(
            repo_commits={"api": "abc"},
            policy_versions={"security/sql_injection.yaml": "aaa" * 21 + "a"},
        )
        assert "security/sql_injection.yaml" in manifest.policy_versions

    def test_record_sync_with_prompt_versions(self):
        recorder = self._recorder()
        manifest = recorder.record_sync(
            repo_commits={"api": "abc"},
            prompt_versions={"security": "v2", "compliance": "v1"},
        )
        assert manifest.prompt_versions["security"] == "v2"

    def test_config_hash_deterministic(self):
        recorder = self._recorder()
        m1 = recorder.record_sync(repo_commits={"a": "1"})
        m2 = recorder.record_sync(repo_commits={"a": "1"})
        assert m1.config_hash == m2.config_hash

    def test_different_scan_ids(self):
        recorder = self._recorder()
        m1 = recorder.record_sync(repo_commits={"a": "1"})
        m2 = recorder.record_sync(repo_commits={"a": "1"})
        assert m1.scan_id != m2.scan_id

    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path):
        recorder = self._recorder()
        manifest = recorder.record_sync(
            repo_commits={"api": "abc123"},
            tool_versions={"semgrep": "1.60.0"},
        )

        path = await recorder.save(manifest, tmp_path / "test.manifest.json")
        assert path.exists()

        # Load back
        loaded = await recorder.load(manifest.scan_id, search_dir=tmp_path)
        assert loaded is not None
        assert loaded.scan_id == manifest.scan_id
        assert loaded.repo_commits == manifest.repo_commits

    @pytest.mark.asyncio
    async def test_load_from_memory(self):
        recorder = self._recorder()
        manifest = recorder.record_sync(repo_commits={"api": "abc"})

        loaded = await recorder.load(manifest.scan_id)
        assert loaded is not None
        assert loaded.scan_id == manifest.scan_id

    @pytest.mark.asyncio
    async def test_load_nonexistent_returns_none(self, tmp_path):
        recorder = self._recorder()
        loaded = await recorder.load("scan-nonexistent", search_dir=tmp_path)
        assert loaded is None

    @pytest.mark.asyncio
    async def test_list_scans(self, tmp_path):
        recorder = self._recorder()
        m1 = recorder.record_sync(repo_commits={"a": "1"})
        m2 = recorder.record_sync(repo_commits={"b": "2"})
        await recorder.save(m1, tmp_path / f"{m1.scan_id}.manifest.json")
        await recorder.save(m2, tmp_path / f"{m2.scan_id}.manifest.json")

        scans = await recorder.list_scans(search_dir=tmp_path)
        assert len(scans) == 2
        assert m1.scan_id in scans
        assert m2.scan_id in scans

    @pytest.mark.asyncio
    async def test_record_async_with_policy_dir(self, tmp_path):
        # Create some policy files
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "sec.yaml").write_text("id: SEC-001\n")
        (policy_dir / "comp.yaml").write_text("id: COMP-001\n")

        recorder = self._recorder()
        with patch("blanketaudit.cache.scan_manifest._get_tool_version",
                    return_value="1.0.0"):
            manifest = await recorder.record(
                repo_commits={"api": "abc"},
                policy_dir=policy_dir,
            )

        assert len(manifest.policy_versions) == 2
        # Each should be a SHA-256 hash
        for v in manifest.policy_versions.values():
            assert len(v) == 64

    def test_manifest_json_serialization(self):
        recorder = self._recorder()
        manifest = recorder.record_sync(repo_commits={"api": "abc"})
        json_str = manifest.model_dump_json()
        restored = ScanManifest.model_validate_json(json_str)
        assert restored.scan_id == manifest.scan_id
        assert restored.config_hash == manifest.config_hash
