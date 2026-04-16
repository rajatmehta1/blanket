"""Bitbucket connector — App Password authentication."""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import structlog

from blanketaudit2.connectors.base import (
    CLONE_TIMEOUT_SECONDS,
    RepositorySource,
    validate_url,
)
from blanketaudit2.exceptions import IngestionError

logger = structlog.get_logger()


class BitbucketConnector(RepositorySource):
    """Clone a Bitbucket repository via HTTPS with optional App Password auth."""

    def __init__(
        self,
        url: str,
        branch: str = "main",
        username: str = "",
        app_password: str = "",
    ) -> None:
        self.url = validate_url(url)
        self.branch = branch
        self.username = username
        self.app_password = app_password
        self._local_path: Path | None = None

    def _build_clone_url(self) -> str:
        """Inject username and app password into HTTPS URL."""
        if not self.username or not self.app_password:
            return self.url
        # https://bitbucket.org/org/repo → https://<user>:<pass>@bitbucket.org/org/repo
        return self.url.replace(
            "https://", f"https://{self.username}:{self.app_password}@"
        )

    async def clone(self, workspace: Path) -> Path:
        self._local_path = self._make_temp_dir(workspace, prefix="bitbucket_")
        clone_url = self._build_clone_url()
        cmd = [
            "git", "clone",
            "--depth", "1",
            "--single-branch",
            "--branch", self.branch,
            "--no-recurse-submodules",
            clone_url,
            str(self._local_path),
        ]
        logger.info("connector.clone", provider="bitbucket", branch=self.branch)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=CLONE_TIMEOUT_SECONDS
            )
            if proc.returncode != 0:
                raise IngestionError(
                    f"git clone failed (exit {proc.returncode}): {stderr.decode()[:500]}",
                    details={"url": self.url, "branch": self.branch},
                )
        except asyncio.TimeoutError:
            raise IngestionError(
                f"git clone timed out after {CLONE_TIMEOUT_SECONDS}s",
                details={"url": self.url},
            )
        return self._local_path

    async def get_commit_sha(self) -> str:
        if not self._local_path:
            return ""
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(self._local_path), "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()

    async def cleanup(self) -> None:
        if self._local_path and self._local_path.exists():
            shutil.rmtree(self._local_path, ignore_errors=True)
            logger.info("connector.cleanup", provider="bitbucket", path=str(self._local_path))
            self._local_path = None
