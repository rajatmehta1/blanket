"""Record and replay exact scan configuration for reproducibility.

Design doc §12.3, §3.3: every scan records a ScanManifest with exact
policy versions, prompt versions, model IDs, tool versions, and repo
commit SHAs.  Past scans can be replayed deterministically.

This is a SOC2 requirement for audit trail.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from blanketaudit.config import Settings, get_settings
from blanketaudit.models.manifest import ScanManifest

logger = structlog.get_logger()


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file.  Returns empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, FileNotFoundError):
        return ""


def _sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def _get_tool_version(tool: str) -> str:
    """Run ``tool --version`` and return first line of output."""
    try:
        proc = await asyncio.create_subprocess_exec(
            tool, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return stdout.decode().strip().splitlines()[0] if stdout else ""
    except (OSError, FileNotFoundError, asyncio.TimeoutError):
        return ""


class ScanManifestRecorder:
    """Record exact scan environment for reproducibility."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._manifests: dict[str, ScanManifest] = {}  # in-memory store

    # ── Recording ────────────────────────────────────────────

    async def record(
        self,
        repo_commits: dict[str, str],
        policy_dir: str | Path | None = None,
        prompt_versions: dict[str, str] | None = None,
    ) -> ScanManifest:
        """Capture the full scan environment and return a ScanManifest.

        Parameters
        ----------
        repo_commits:
            ``{repo_name: commit_sha}`` from connectors.
        policy_dir:
            Path to policy YAML files.  If provided, hashes each file.
        prompt_versions:
            Optional explicit prompt version map.  If omitted, a
            placeholder is used.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        # Policy versions: hash each YAML file
        policy_versions: dict[str, str] = {}
        if policy_dir:
            pd = Path(policy_dir)
            if pd.is_dir():
                for f in sorted(pd.rglob("*.yaml")):
                    rel = str(f.relative_to(pd)).replace("\\", "/")
                    policy_versions[rel] = _sha256_file(f)
                for f in sorted(pd.rglob("*.yml")):
                    rel = str(f.relative_to(pd)).replace("\\", "/")
                    policy_versions[rel] = _sha256_file(f)

        # Model IDs
        llm_cfg = self._settings.llm
        model_ids: dict[str, str] = {}
        if llm_cfg.model:
            model_ids["default"] = llm_cfg.model
        if llm_cfg.compliance_model:
            model_ids["compliance"] = llm_cfg.compliance_model
        for agent, model in llm_cfg.agent_model_overrides.items():
            model_ids[agent] = model

        # Tool versions
        tool_versions = await self._collect_tool_versions()

        # Config hash
        config_hash = self._compute_config_hash()

        manifest = ScanManifest(
            scan_id=scan_id,
            timestamp=now,
            policy_versions=policy_versions,
            prompt_versions=prompt_versions or {"default": "v1"},
            model_ids=model_ids,
            tool_versions=tool_versions,
            repo_commits=repo_commits,
            config_hash=config_hash,
        )

        self._manifests[scan_id] = manifest

        logger.info(
            "manifest.recorded",
            scan_id=scan_id,
            repos=len(repo_commits),
            policies=len(policy_versions),
        )
        return manifest

    def record_sync(
        self,
        repo_commits: dict[str, str],
        policy_versions: dict[str, str] | None = None,
        prompt_versions: dict[str, str] | None = None,
        tool_versions: dict[str, str] | None = None,
    ) -> ScanManifest:
        """Synchronous version of ``record`` for simpler call sites."""
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"

        llm_cfg = self._settings.llm
        model_ids: dict[str, str] = {}
        if llm_cfg.model:
            model_ids["default"] = llm_cfg.model
        if llm_cfg.compliance_model:
            model_ids["compliance"] = llm_cfg.compliance_model

        manifest = ScanManifest(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            policy_versions=policy_versions or {},
            prompt_versions=prompt_versions or {"default": "v1"},
            model_ids=model_ids,
            tool_versions=tool_versions or {},
            repo_commits=repo_commits,
            config_hash=self._compute_config_hash(),
        )

        self._manifests[scan_id] = manifest
        return manifest

    # ── Storage ──────────────────────────────────────────────

    async def save(self, manifest: ScanManifest, path: Path | str | None = None) -> Path:
        """Persist a manifest to a JSON file."""
        if path is None:
            out_dir = Path(self._settings.cache.cache_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"{manifest.scan_id}.manifest.json"
        else:
            path = Path(path)

        path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        logger.info("manifest.saved", path=str(path))
        return path

    async def load(self, scan_id: str, search_dir: Path | str | None = None) -> ScanManifest | None:
        """Load a manifest from the in-memory store or from disk."""
        # Check in-memory first
        if scan_id in self._manifests:
            return self._manifests[scan_id]

        # Search on disk
        search = Path(search_dir) if search_dir else Path(self._settings.cache.cache_dir)
        manifest_file = search / f"{scan_id}.manifest.json"
        if manifest_file.exists():
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest = ScanManifest.model_validate(data)
            self._manifests[scan_id] = manifest
            return manifest

        logger.warning("manifest.not_found", scan_id=scan_id)
        return None

    async def list_scans(self, search_dir: Path | str | None = None) -> list[str]:
        """List all scan IDs with saved manifests."""
        search = Path(search_dir) if search_dir else Path(self._settings.cache.cache_dir)
        if not search.exists():
            return []
        return [
            f.name.replace(".manifest.json", "")
            for f in sorted(search.glob("*.manifest.json"))
        ]

    # ── Internals ────────────────────────────────────────────

    async def _collect_tool_versions(self) -> dict[str, str]:
        """Collect versions of external tools."""
        tools = ["semgrep", "gitleaks", "osv-scanner"]
        versions: dict[str, str] = {}
        for tool in tools:
            ver = await _get_tool_version(tool)
            if ver:
                versions[tool] = ver
        return versions

    def _compute_config_hash(self) -> str:
        """SHA-256 of the current settings for reproducibility."""
        config_str = self._settings.model_dump_json(exclude={"neo4j_password"})
        return _sha256_str(config_str)
