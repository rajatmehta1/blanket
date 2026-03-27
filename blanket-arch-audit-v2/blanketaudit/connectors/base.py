"""Repository source interface — common contract for all connectors.

Design doc §2.1 Tier 1: all connectors validate inputs, enforce security
limits, and return a local filesystem path.
"""
from __future__ import annotations

import abc
import ipaddress
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import structlog

from blanketaudit.exceptions import IngestionError

logger = structlog.get_logger()

MAX_REPO_SIZE_MB = 500
CLONE_TIMEOUT_SECONDS = 120

# Private/internal IP ranges — block to prevent SSRF
_PRIVATE_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def validate_url(url: str) -> str:
    """Validate a repository URL. Reject private IPs (SSRF prevention).

    Accepts:
    - https://github.com/org/repo
    - github.com/org/repo (auto-prefix https://)
    - git@github.com:org/repo.git (SSH)

    Rejects:
    - Private IPs (127.x, 10.x, 192.168.x, etc.)
    - localhost
    """
    # Auto-prefix https:// if no scheme
    if not url.startswith(("https://", "http://", "git@", "ssh://")):
        url = f"https://{url}"

    # For HTTPS URLs, validate host
    if url.startswith(("https://", "http://")):
        parsed = urlparse(url)
        host = parsed.hostname or ""

        if host in _PRIVATE_HOSTS:
            raise IngestionError(f"Private/local hosts not allowed: {host}")

        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                raise IngestionError(f"Private/reserved IP not allowed: {host}")
        except ValueError:
            pass  # Not an IP — hostname is fine

    return url


class RepositorySource(abc.ABC):
    """Abstract base for source input connectors."""

    @abc.abstractmethod
    async def clone(self, workspace: Path) -> Path:
        """Clone/checkout/copy the repo into *workspace*. Return the local path."""
        ...

    @abc.abstractmethod
    async def get_commit_sha(self) -> str:
        """Return the HEAD commit SHA of the cloned repo."""
        ...

    @abc.abstractmethod
    async def cleanup(self) -> None:
        """Remove temporary files created during clone."""
        ...

    def _make_temp_dir(self, workspace: Path, prefix: str = "repo_") -> Path:
        """Create a temp directory inside *workspace*."""
        return Path(tempfile.mkdtemp(dir=workspace, prefix=prefix))
