"""Run Semgrep SAST rules as a subprocess and parse SARIF output.

Semgrep is called with ``--sarif`` for structured output.  If semgrep
is not installed, returns an empty list with a warning log.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Default timeout for semgrep execution (seconds).
_TIMEOUT = 300

# Default Semgrep config — uses the "auto" config which pulls community rules.
_DEFAULT_CONFIGS = ["auto"]


class SemgrepFinding:
    """One finding from Semgrep SARIF output."""

    def __init__(
        self,
        rule_id: str,
        file_path: str,
        line_start: int,
        line_end: int,
        message: str,
        severity: str,
        code_snippet: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.message = message
        self.severity = severity
        self.code_snippet = code_snippet

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "semgrep",
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "message": self.message,
            "severity": self.severity,
            "code_snippet": self.code_snippet,
        }


def _map_sarif_level(level: str) -> str:
    """Map SARIF result level to our severity."""
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "low",
    }.get(level, "medium")


def _parse_sarif(sarif_data: dict, repo_path: str) -> list[SemgrepFinding]:
    """Parse Semgrep SARIF JSON into SemgrepFinding objects."""
    findings: list[SemgrepFinding] = []
    repo_prefix = str(Path(repo_path).resolve()).replace("\\", "/")

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            level = result.get("level", "warning")

            for location in result.get("locations", []):
                phys = location.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                uri = artifact.get("uri", "")

                # Make path relative to repo
                file_path = uri.replace("file://", "")
                if file_path.startswith(repo_prefix):
                    file_path = file_path[len(repo_prefix):].lstrip("/")

                region = phys.get("region", {})
                line_start = region.get("startLine", 1)
                line_end = region.get("endLine", line_start)
                snippet = region.get("snippet", {}).get("text", "")

                findings.append(SemgrepFinding(
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    message=message,
                    severity=_map_sarif_level(level),
                    code_snippet=snippet,
                ))

    return findings


async def check_semgrep_installed() -> bool:
    """Check if semgrep is available on PATH."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
        return proc.returncode == 0
    except (FileNotFoundError, OSError, asyncio.TimeoutError):
        return False


async def run_semgrep(
    repo_path: str | Path,
    *,
    configs: list[str] | None = None,
    rules_dir: str | Path | None = None,
    timeout: int = _TIMEOUT,
    extra_args: list[str] | None = None,
) -> list[dict]:
    """Run Semgrep SAST on a repository and return parsed findings.

    Parameters
    ----------
    repo_path:
        Path to the repository to scan.
    configs:
        Semgrep config strings (e.g., ``["auto"]``, ``["p/python"]``).
    rules_dir:
        Path to custom rule YAML files.
    timeout:
        Max execution time in seconds.
    extra_args:
        Additional CLI arguments passed to semgrep.

    Returns
    -------
    List of finding dicts.  Empty list if semgrep is not installed.
    """
    repo_path = Path(repo_path)

    if not await check_semgrep_installed():
        logger.warning("semgrep.not_installed", msg="Semgrep not found — skipping SAST scan")
        return []

    configs = configs or _DEFAULT_CONFIGS

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    try:
        cmd = ["semgrep", "--sarif", "--output", output_path, "--quiet"]

        for config in configs:
            cmd.extend(["--config", config])

        if rules_dir:
            cmd.extend(["--config", str(rules_dir)])

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(str(repo_path))

        logger.info("semgrep.starting", repo=str(repo_path), configs=configs)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            logger.error("semgrep.timeout", timeout=timeout)
            return []

        # Semgrep returns exit code 1 when findings are present (not an error)
        if proc.returncode not in (0, 1):
            logger.warning(
                "semgrep.error",
                returncode=proc.returncode,
                stderr=stderr.decode()[:500],
            )
            return []

        # Parse SARIF output
        output_file = Path(output_path)
        if not output_file.exists() or output_file.stat().st_size == 0:
            return []

        sarif_data = json.loads(output_file.read_text(encoding="utf-8"))
        findings = _parse_sarif(sarif_data, str(repo_path))

        logger.info("semgrep.completed", finding_count=len(findings))
        return [f.to_dict() for f in findings]

    except (json.JSONDecodeError, KeyError) as exc:
        logger.warning("semgrep.parse_error", error=str(exc)[:200])
        return []
    finally:
        Path(output_path).unlink(missing_ok=True)
