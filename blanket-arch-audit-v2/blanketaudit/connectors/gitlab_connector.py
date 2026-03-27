"""GitLab connector — Project Access Token authentication."""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import structlog

from blanketaudit.connectors.base import (
    CLONE_TIMEOUT_SECONDS,
    RepositorySource,
    validate_url,
)
from blanketaudit.exceptions import IngestionError

logger = structlog.get_logger()


class GitLabConnector(RepositorySource):
    """Clone a GitLab repository via HTTPS with optional PAT auth."""

    def __init__(self, url: str, branch: str = "main", token: str = "") -> None:
        self.url = validate_url(url)
        self.branch = branch
        self.token = token
        self._local_path: Path | None = None

    def _build_clone_url(self) -> str:
        """Inject token into HTTPS URL using GitLab oauth2 format."""
        if not self.token:
            return self.url
        # https://gitlab.com/org/repo → https://oauth2:<token>@gitlab.com/org/repo
        return self.url.replace("https://", f"https://oauth2:{self.token}@")

    async def clone(self, workspace: Path) -> Path:
        self._local_path = self._make_temp_dir(workspace, prefix="gitlab_")
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
        logger.info("connector.clone", provider="gitlab", branch=self.branch)
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
            logger.info("connector.cleanup", provider="gitlab", path=str(self._local_path))
            self._local_path = None
