"""Scan manifest for reproducibility."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, field_validator


class ScanManifest(BaseModel):
    """Records exact versions of everything used in a scan for reproducibility."""

    scan_id: str
    timestamp: datetime
    policy_versions: dict[str, str]
    prompt_versions: dict[str, str]
    model_ids: dict[str, str]
    tool_versions: dict[str, str]
    repo_commits: dict[str, str]
    config_hash: str

    @field_validator("config_hash")
    @classmethod
    def validate_config_hash(cls, v: str) -> str:
        if v and len(v) != 64:
            raise ValueError("config_hash must be a 64-char SHA-256 hex digest")
        return v
