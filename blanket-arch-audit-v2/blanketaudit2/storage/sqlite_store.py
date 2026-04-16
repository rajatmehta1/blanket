"""SQLite store for CLI mode — scan history, cache, manifests.

Uses aiosqlite for async access.  Stores scan manifests, report
summaries, and findings for trend tracking across scans.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from blanketaudit2.config import get_settings
from blanketaudit2.exceptions import StorageError

logger = structlog.get_logger()


class SQLiteStore:
    """Async SQLite store for local CLI scan persistence."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = str(db_path or get_settings().sqlite_path)
        self._db: Any = None

    # ── Lifecycle ────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the database and create tables if needed."""
        try:
            import aiosqlite

            self._db = await aiosqlite.connect(self._db_path)
            await self._create_tables()
            logger.info("sqlite.connected", path=self._db_path)
        except ImportError:
            raise StorageError(
                "aiosqlite not installed. Install with: pip install aiosqlite"
            )
        except Exception as exc:
            raise StorageError(f"Failed to open SQLite: {exc}")

    async def close(self) -> None:
        """Close the database."""
        if self._db:
            await self._db.close()
            self._db = None
            logger.info("sqlite.closed")

    @property
    def is_connected(self) -> bool:
        return self._db is not None

    # ── Schema ───────────────────────────────────────────────

    async def _create_tables(self) -> None:
        assert self._db
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                timestamp   TEXT NOT NULL,
                manifest    TEXT NOT NULL,
                report_json TEXT,
                status      TEXT DEFAULT 'completed',
                created_at  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                finding_id  TEXT NOT NULL,
                severity    TEXT NOT NULL,
                category    TEXT NOT NULL,
                title       TEXT NOT NULL,
                file_path   TEXT,
                data_json   TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan
                ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity
                ON findings(severity);
        """)
        await self._db.commit()

    # ── Scan CRUD ────────────────────────────────────────────

    async def save_scan(
        self,
        scan_id: str,
        manifest_json: str,
        report_json: str | None = None,
        timestamp: str | None = None,
    ) -> str:
        """Save a scan record."""
        assert self._db
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            "INSERT OR REPLACE INTO scans (scan_id, timestamp, manifest, report_json) "
            "VALUES (?, ?, ?, ?)",
            (scan_id, ts, manifest_json, report_json),
        )
        await self._db.commit()
        logger.info("sqlite.scan_saved", scan_id=scan_id)
        return scan_id

    async def get_scan(self, scan_id: str) -> dict | None:
        """Retrieve a scan record by ID."""
        assert self._db
        cursor = await self._db.execute(
            "SELECT scan_id, timestamp, manifest, report_json, status "
            "FROM scans WHERE scan_id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "scan_id": row[0],
            "timestamp": row[1],
            "manifest": json.loads(row[2]),
            "report": json.loads(row[3]) if row[3] else None,
            "status": row[4],
        }

    async def list_scans(self, limit: int = 20) -> list[dict]:
        """List recent scans, newest first."""
        assert self._db
        cursor = await self._db.execute(
            "SELECT scan_id, timestamp, status FROM scans "
            "ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [
            {"scan_id": r[0], "timestamp": r[1], "status": r[2]}
            for r in rows
        ]

    async def delete_scan(self, scan_id: str) -> None:
        """Delete a scan and its findings."""
        assert self._db
        await self._db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        await self._db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await self._db.commit()

    # ── Finding CRUD ─────────────────────────────────────────

    async def save_findings(self, scan_id: str, findings: list[dict]) -> int:
        """Save findings for a scan."""
        assert self._db
        for f in findings:
            await self._db.execute(
                "INSERT INTO findings (scan_id, finding_id, severity, category, title, file_path, data_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    f.get("id", ""),
                    f.get("severity", ""),
                    f.get("category", ""),
                    f.get("title", ""),
                    f.get("file_path", ""),
                    json.dumps(f, default=str),
                ),
            )
        await self._db.commit()
        logger.info("sqlite.findings_saved", scan_id=scan_id, count=len(findings))
        return len(findings)

    async def get_findings(self, scan_id: str) -> list[dict]:
        """Retrieve findings for a scan."""
        assert self._db
        cursor = await self._db.execute(
            "SELECT data_json FROM findings WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        return [json.loads(r[0]) for r in rows]

    async def get_finding_counts(self, scan_id: str) -> dict[str, int]:
        """Get severity counts for a scan."""
        assert self._db
        cursor = await self._db.execute(
            "SELECT severity, COUNT(*) FROM findings "
            "WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        return {r[0]: r[1] for r in rows}

    # ── Trend queries ────────────────────────────────────────

    async def get_scan_trend(self, limit: int = 10) -> list[dict]:
        """Get finding counts per scan for trend visualization."""
        assert self._db
        cursor = await self._db.execute(
            "SELECT s.scan_id, s.timestamp, "
            "  COUNT(f.id) AS total, "
            "  SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical, "
            "  SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high "
            "FROM scans s LEFT JOIN findings f ON s.scan_id = f.scan_id "
            "GROUP BY s.scan_id ORDER BY s.timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "scan_id": r[0], "timestamp": r[1],
                "total": r[2], "critical": r[3], "high": r[4],
            }
            for r in rows
        ]
