"""Secret detection via Gitleaks subprocess.

Gitleaks is called with ``--report-format json`` for structured output.
If gitleaks is not installed, returns an empty list with a warning log.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_TIMEOUT = 120


class GitleaksFinding:
    """One secret finding from Gitleaks."""

    def __init__(
        self,
        rule_id: str,
        description: str,
        file_path: str,
        line_number: int,
        match: str,
        secret: str,
        commit: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.match = match
        self.secret = self._mask_secret(secret)
        self.commit = commit

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Mask the secret value — never log full secrets."""
        if len(secret) <= 8:
            return "***"
        return secret[:4] + "***" + secret[-4:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "gitleaks",
            "rule_id": self.rule_id,
            "description": self.description,
            "file_path": self.file_path,
            "line_start": self.line_number,
            "line_end": self.line_number,
            "message": f"Secret detected: {self.description}",
            "severity": "high",
            "code_snippet": self.match[:200],
            "secret_masked": self.secret,
        }


def _parse_gitleaks_json(data: list[dict], repo_path: str) -> list[GitleaksFinding]:
    """Parse Gitleaks JSON output."""
    findings: list[GitleaksFinding] = []
    repo_prefix = str(Path(repo_path).resolve()).replace("\\", "/")

    for item in data:
        file_path = item.get("File", "")
        # Make relative
        file_path = file_path.replace("\\", "/")
        if file_path.startswith(repo_prefix):
            file_path = file_path[len(repo_prefix):].lstrip("/")

        findings.append(GitleaksFinding(
            rule_id=item.get("RuleID", "unknown"),
            description=item.get("Description", ""),
            file_path=file_path,
            line_number=item.get("StartLine", 1),
            match=item.get("Match", ""),
            secret=item.get("Secret", ""),
            commit=item.get("Commit", ""),
        ))

    return findings


async def check_gitleaks_installed() -> bool:
    """Check if gitleaks is available on PATH."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
        return proc.returncode == 0
    except (FileNotFoundError, OSError, asyncio.TimeoutError):
        return False


async def run_gitleaks(
    repo_path: str | Path,
    *,
    timeout: int = _TIMEOUT,
    no_git: bool = False,
    extra_args: list[str] | None = None,
) -> list[dict]:
    """Run Gitleaks on a repository and return parsed findings.

    Parameters
    ----------
    repo_path:
        Path to the repository to scan.
    timeout:
        Max execution time in seconds.
    no_git:
        If True, use ``detect --no-git`` mode (scan files without git history).
    extra_args:
        Additional CLI arguments.

    Returns
    -------
    List of finding dicts.  Empty if gitleaks is not installed.
    """
    repo_path = Path(repo_path)

    if not await check_gitleaks_installed():
        logger.warning("gitleaks.not_installed", msg="Gitleaks not found — skipping secret scan")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    try:
        cmd = [
            "gitleaks", "detect",
            "--source", str(repo_path),
            "--report-format", "json",
            "--report-path", output_path,
            "--exit-code", "0",  # Don't fail on findings
        ]

        if no_git:
            cmd.append("--no-git")

        if extra_args:
            cmd.extend(extra_args)

        logger.info("gitleaks.starting", repo=str(repo_path))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            logger.error("gitleaks.timeout", timeout=timeout)
            return []

        if proc.returncode not in (0, 1):
            logger.warning(
                "gitleaks.error",
                returncode=proc.returncode,
                stderr=stderr.decode()[:500],
            )
            return []

        output_file = Path(output_path)
        if not output_file.exists() or output_file.stat().st_size == 0:
            return []

        raw = json.loads(output_file.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            return []

        findings = _parse_gitleaks_json(raw, str(repo_path))
        logger.info("gitleaks.completed", finding_count=len(findings))
        return [f.to_dict() for f in findings]

    except (json.JSONDecodeError, KeyError) as exc:
        logger.warning("gitleaks.parse_error", error=str(exc)[:200])
        return []
    finally:
        Path(output_path).unlink(missing_ok=True)
