"""SHA-256(file_content + policy_version) keyed cache for incremental scanning.

Design doc §12.2: cache scan results so unchanged files are not re-analysed.
Stored in SQLite via aiosqlite.  Configurable TTL (default 24h).
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import structlog

from blanketaudit2.config import get_settings

logger = structlog.get_logger()


class ContentCache:
    """Cache scan results keyed by ``SHA-256(content + policy_version)``.

    Uses aiosqlite for async persistence.  Falls back to in-memory dict
    when SQLite is unavailable.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        ttl_hours: int | None = None,
    ) -> None:
        cfg = get_settings().cache
        self._db_path = str(db_path) if db_path else cfg.cache_dir + "/cache.db"
        self._ttl_seconds = (ttl_hours if ttl_hours is not None else cfg.ttl_hours) * 3600
        self._db: Any = None
        # In-memory fallback
        self._memory: dict[str, dict] = {}
        self._use_memory = False

    # ── Cache key ────────────────────────────────────────────

    @staticmethod
    def cache_key(content: str, policy_version: str) -> str:
        """Compute a deterministic cache key from file content + policy version."""
        payload = f"{content}\x00{policy_version}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # ── Lifecycle ────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the SQLite database and create the cache table."""
        try:
            import aiosqlite

            db_dir = Path(self._db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)

            self._db = await aiosqlite.connect(self._db_path)
            await self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_cache (
                    key       TEXT PRIMARY KEY,
                    findings  TEXT NOT NULL,
                    created   REAL NOT NULL,
                    expires   REAL NOT NULL
                )
                """
            )
            await self._db.commit()
            logger.info("cache.connected", db=self._db_path)
        except (ImportError, Exception) as exc:
            logger.warning(
                "cache.sqlite_unavailable",
                error=str(exc)[:200],
                msg="Falling back to in-memory cache",
            )
            self._use_memory = True

    async def close(self) -> None:
        """Close the database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None

    # ── Core operations ──────────────────────────────────────

    async def get(self, key: str) -> list[dict] | None:
        """Retrieve cached findings by key.  Returns *None* on cache miss."""
        now = time.time()

        if self._use_memory:
            entry = self._memory.get(key)
            if entry and entry["expires"] > now:
                logger.debug("cache.hit", key=key[:12])
                return entry["findings"]
            if entry:
                del self._memory[key]
            return None

        if self._db is None:
            return None

        cursor = await self._db.execute(
            "SELECT findings, expires FROM scan_cache WHERE key = ?",
            (key,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None

        findings_json, expires = row
        if expires <= now:
            await self._db.execute("DELETE FROM scan_cache WHERE key = ?", (key,))
            await self._db.commit()
            return None

        logger.debug("cache.hit", key=key[:12])
        return json.loads(findings_json)

    async def put(self, key: str, findings: list[dict]) -> None:
        """Store findings in the cache with TTL."""
        now = time.time()
        expires = now + self._ttl_seconds
        findings_json = json.dumps(findings, default=str)

        if self._use_memory:
            self._memory[key] = {
                "findings": findings,
                "created": now,
                "expires": expires,
            }
            return

        if self._db is None:
            return

        await self._db.execute(
            """
            INSERT OR REPLACE INTO scan_cache (key, findings, created, expires)
            VALUES (?, ?, ?, ?)
            """,
            (key, findings_json, now, expires),
        )
        await self._db.commit()
        logger.debug("cache.put", key=key[:12])

    async def invalidate_expired(self) -> int:
        """Remove all expired cache entries.  Returns count of removed entries."""
        now = time.time()

        if self._use_memory:
            expired_keys = [
                k for k, v in self._memory.items() if v["expires"] <= now
            ]
            for k in expired_keys:
                del self._memory[k]
            return len(expired_keys)

        if self._db is None:
            return 0

        cursor = await self._db.execute(
            "DELETE FROM scan_cache WHERE expires <= ?", (now,)
        )
        await self._db.commit()
        count = cursor.rowcount
        logger.info("cache.invalidated_expired", count=count)
        return count

    async def clear(self) -> None:
        """Remove all cache entries."""
        if self._use_memory:
            self._memory.clear()
            return

        if self._db is None:
            return

        await self._db.execute("DELETE FROM scan_cache")
        await self._db.commit()

    async def size(self) -> int:
        """Return the number of cached entries."""
        if self._use_memory:
            return len(self._memory)

        if self._db is None:
            return 0

        cursor = await self._db.execute("SELECT COUNT(*) FROM scan_cache")
        row = await cursor.fetchone()
        return row[0] if row else 0

    def get_cached_keys(self) -> set[str]:
        """Return all cached keys (synchronous — for partitioning)."""
        if self._use_memory:
            now = time.time()
            return {k for k, v in self._memory.items() if v["expires"] > now}
        return set()
