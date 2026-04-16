"""Tests for blanketaudit2.connectors — URL validation, connectors."""
from __future__ import annotations

import asyncio
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit2.connectors.base import validate_url
from blanketaudit2.connectors.github_connector import GitHubConnector
from blanketaudit2.connectors.gitlab_connector import GitLabConnector
from blanketaudit2.connectors.bitbucket_connector import BitbucketConnector
from blanketaudit2.connectors.local_connector import LocalConnector
from blanketaudit2.exceptions import IngestionError


# ── URL Validation ──────────────────────────────────────────


class TestValidateUrl:
    def test_https_url_passes(self):
        assert validate_url("https://github.com/org/repo") == "https://github.com/org/repo"

    def test_auto_prefix_https(self):
        assert validate_url("github.com/org/repo") == "https://github.com/org/repo"

    def test_rejects_localhost(self):
        with pytest.raises(IngestionError):
            validate_url("http://localhost/repo")

    def test_rejects_127_0_0_1(self):
        with pytest.raises(IngestionError):
            validate_url("http://127.0.0.1/repo")

    def test_rejects_private_ip_10(self):
        with pytest.raises(IngestionError):
            validate_url("http://10.0.0.1/repo")

    def test_rejects_private_ip_192(self):
        with pytest.raises(IngestionError):
            validate_url("http://192.168.1.1/repo")

    def test_ssh_url_passes(self):
        result = validate_url("git@github.com:org/repo.git")
        assert result == "git@github.com:org/repo.git"

    def test_http_url_with_valid_host(self):
        result = validate_url("http://gitlab.example.com/org/repo")
        assert result == "http://gitlab.example.com/org/repo"

    def test_rejects_0_0_0_0(self):
        with pytest.raises(IngestionError):
            validate_url("http://0.0.0.0/repo")

    def test_rejects_ipv6_loopback(self):
        # ::1 in brackets as urlparse expects for IPv6
        with pytest.raises(IngestionError):
            validate_url("http://[::1]/repo")

    def test_ssh_scheme_passes(self):
        result = validate_url("ssh://git@github.com/org/repo.git")
        assert result == "ssh://git@github.com/org/repo.git"


# ── GitHub Connector ────────────────────────────────────────


class TestGitHubConnector:
    def test_build_clone_url_without_token(self):
        c = GitHubConnector("https://github.com/org/repo", branch="main")
        assert c._build_clone_url() == "https://github.com/org/repo"

    def test_build_clone_url_with_token(self):
        c = GitHubConnector("https://github.com/org/repo", token="ghp_abc123")
        assert c._build_clone_url() == "https://ghp_abc123@github.com/org/repo"

    def test_url_validated_on_init(self):
        with pytest.raises(IngestionError):
            GitHubConnector("http://127.0.0.1/repo")

    @pytest.mark.asyncio
    async def test_clone_calls_git(self, tmp_path):
        c = GitHubConnector("https://github.com/org/repo")
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("blanketaudit2.connectors.github_connector.asyncio.create_subprocess_exec",
                    return_value=mock_proc) as mock_exec, \
             patch("blanketaudit2.connectors.github_connector.asyncio.wait_for",
                    return_value=(b"", b"")):
            path = await c.clone(tmp_path)
            assert path.exists()
            mock_exec.assert_called_once()
            # Verify git clone command includes the URL
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "git"
            assert call_args[1] == "clone"

    @pytest.mark.asyncio
    async def test_clone_timeout_raises(self, tmp_path):
        c = GitHubConnector("https://github.com/org/repo")
        with patch("blanketaudit2.connectors.github_connector.asyncio.create_subprocess_exec") as mock_exec, \
             patch("blanketaudit2.connectors.github_connector.asyncio.wait_for",
                    side_effect=asyncio.TimeoutError):
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with pytest.raises(IngestionError, match="timed out"):
                await c.clone(tmp_path)

    @pytest.mark.asyncio
    async def test_clone_nonzero_exit_raises(self, tmp_path):
        c = GitHubConnector("https://github.com/org/repo")
        mock_proc = AsyncMock()
        mock_proc.returncode = 128
        mock_proc.communicate = AsyncMock(return_value=(b"", b"fatal: repo not found"))

        with patch("blanketaudit2.connectors.github_connector.asyncio.create_subprocess_exec",
                    return_value=mock_proc), \
             patch("blanketaudit2.connectors.github_connector.asyncio.wait_for",
                    return_value=(b"", b"fatal: repo not found")):
            # wait_for returns the communicate result; returncode is checked after
            # Need to ensure returncode is 128 so it raises
            mock_proc.returncode = 128
            with pytest.raises(IngestionError, match="git clone failed"):
                await c.clone(tmp_path)


# ── GitLab Connector ────────────────────────────────────────


class TestGitLabConnector:
    def test_build_clone_url_without_token(self):
        c = GitLabConnector("https://gitlab.com/org/repo")
        assert c._build_clone_url() == "https://gitlab.com/org/repo"

    def test_build_clone_url_with_token(self):
        c = GitLabConnector("https://gitlab.com/org/repo", token="glpat-abc")
        assert c._build_clone_url() == "https://oauth2:glpat-abc@gitlab.com/org/repo"


# ── Bitbucket Connector ────────────────────────────────────


class TestBitbucketConnector:
    def test_build_clone_url_without_creds(self):
        c = BitbucketConnector("https://bitbucket.org/org/repo")
        assert c._build_clone_url() == "https://bitbucket.org/org/repo"

    def test_build_clone_url_with_creds(self):
        c = BitbucketConnector(
            "https://bitbucket.org/org/repo",
            username="user",
            app_password="pass123",
        )
        assert c._build_clone_url() == "https://user:pass123@bitbucket.org/org/repo"

    def test_build_clone_url_requires_both_username_and_password(self):
        # Only username — no injection
        c = BitbucketConnector(
            "https://bitbucket.org/org/repo", username="user"
        )
        assert c._build_clone_url() == "https://bitbucket.org/org/repo"


# ── Local Connector ─────────────────────────────────────────


class TestLocalConnector:
    @pytest.mark.asyncio
    async def test_directory_used_directly(self, tmp_path):
        src = tmp_path / "myrepo"
        src.mkdir()
        (src / "main.py").write_text("x=1")

        c = LocalConnector(src)
        path = await c.clone(tmp_path)
        assert path == src

    @pytest.mark.asyncio
    async def test_nonexistent_path_raises(self, tmp_path):
        c = LocalConnector(tmp_path / "nope")
        with pytest.raises(IngestionError, match="does not exist"):
            await c.clone(tmp_path)

    @pytest.mark.asyncio
    async def test_zip_extraction(self, tmp_path):
        # Create a zip file
        zip_path = tmp_path / "repo.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("main.py", "print('hello')")

        c = LocalConnector(zip_path)
        path = await c.clone(tmp_path)
        assert (path / "main.py").exists()

    @pytest.mark.asyncio
    async def test_cleanup_removes_temp_zip(self, tmp_path):
        zip_path = tmp_path / "repo.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("main.py", "x=1")

        c = LocalConnector(zip_path)
        path = await c.clone(tmp_path)
        assert path.exists()
        await c.cleanup()
        assert not path.exists()

    @pytest.mark.asyncio
    async def test_cleanup_does_not_delete_user_dir(self, tmp_path):
        src = tmp_path / "myrepo"
        src.mkdir()
        (src / "main.py").write_text("x=1")

        c = LocalConnector(src)
        await c.clone(tmp_path)
        await c.cleanup()
        # User's directory should NOT be deleted
        assert src.exists()

    @pytest.mark.asyncio
    async def test_unsupported_file_type(self, tmp_path):
        bad = tmp_path / "repo.tar.gz"
        bad.write_bytes(b"fake")
        c = LocalConnector(bad)
        with pytest.raises(IngestionError, match="Unsupported"):
            await c.clone(tmp_path)

    @pytest.mark.asyncio
    async def test_zip_too_large_raises(self, tmp_path):
        zip_path = tmp_path / "big.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("main.py", "x=1")

        c = LocalConnector(zip_path)
        # Patch the MAX_ZIP_SIZE_MB to a tiny value so the real zip exceeds it
        with patch("blanketaudit2.connectors.local_connector.MAX_ZIP_SIZE_MB", 0):
            with pytest.raises(IngestionError, match="too large"):
                await c.clone(tmp_path)

    @pytest.mark.asyncio
    async def test_get_commit_sha_no_git(self, tmp_path):
        src = tmp_path / "myrepo"
        src.mkdir()
        (src / "main.py").write_text("x=1")

        c = LocalConnector(src)
        await c.clone(tmp_path)
        sha = await c.get_commit_sha()
        assert sha == ""
