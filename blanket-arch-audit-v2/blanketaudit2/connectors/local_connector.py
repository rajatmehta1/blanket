"""Local directory or zip upload connector."""
from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import structlog

from blanketaudit2.connectors.base import RepositorySource
from blanketaudit2.exceptions import IngestionError

logger = structlog.get_logger()

MAX_ZIP_SIZE_MB = 500


class LocalConnector(RepositorySource):
    """Use a local directory or zip file as the repository source."""

    def __init__(self, path: str | Path) -> None:
        self.source_path = Path(path)
        self._local_path: Path | None = None
        self._is_temp: bool = False  # True if we extracted a zip

    async def clone(self, workspace: Path) -> Path:
        if not self.source_path.exists():
            raise IngestionError(f"Path does not exist: {self.source_path}")

        if self.source_path.is_dir():
            # Use directory directly — no copy needed
            self._local_path = self.source_path
            self._is_temp = False
        elif self.source_path.suffix in (".zip",):
            # Extract zip to workspace
            size_mb = self.source_path.stat().st_size / (1024 * 1024)
            if size_mb > MAX_ZIP_SIZE_MB:
                raise IngestionError(
                    f"Zip file too large: {size_mb:.0f}MB (max {MAX_ZIP_SIZE_MB}MB)"
                )
            self._local_path = self._make_temp_dir(workspace, prefix="local_zip_")
            self._is_temp = True
            with zipfile.ZipFile(self.source_path) as zf:
                zf.extractall(self._local_path)
            logger.info("connector.extract_zip", path=str(self.source_path))
        else:
            raise IngestionError(
                f"Unsupported file type: {self.source_path.suffix}. Use a directory or .zip"
            )

        return self._local_path

    async def get_commit_sha(self) -> str:
        """Try to read HEAD from .git directory if it exists."""
        if not self._local_path:
            return ""
        import asyncio

        git_dir = self._local_path / ".git"
        if git_dir.exists():
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", str(self._local_path), "rev-parse", "HEAD",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                return stdout.decode().strip()
        return ""

    async def cleanup(self) -> None:
        if self._is_temp and self._local_path and self._local_path.exists():
            shutil.rmtree(self._local_path, ignore_errors=True)
            logger.info("connector.cleanup", provider="local", path=str(self._local_path))
            self._local_path = None
