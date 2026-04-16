"""Shared pytest fixtures for BlanketAudit tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from blanketaudit2.config import Settings, get_settings


@pytest.fixture()
def tmp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory(prefix="blanketaudit_test_") as d:
        yield Path(d)


@pytest.fixture()
def test_settings() -> Settings:
    """Return a Settings instance with safe defaults for testing.

    Clears the lru_cache so each test gets a fresh singleton.
    """
    get_settings.cache_clear()
    return Settings(
        domain="test",
        active_frameworks=["hipaa"],
        llm={"provider": "none"},
        embedding={"provider": "none"},
        cost={"max_scan_cost_usd": 0.0, "require_dry_run": False},
        log_level="DEBUG",
        log_json=False,
    )


@pytest.fixture()
def sample_repo(tmp_dir: Path) -> Path:
    """Create a minimal repo structure for testing."""
    src = tmp_dir / "src"
    src.mkdir()
    (src / "main.py").write_text('print("hello")\n')
    (src / "utils.py").write_text("def helper():\n    pass\n")
    (tmp_dir / "requirements.txt").write_text("flask==3.0.0\n")
    return tmp_dir
