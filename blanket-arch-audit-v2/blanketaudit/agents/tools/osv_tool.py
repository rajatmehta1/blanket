"""CVE scanning via OSV-scanner subprocess.

Scans dependency manifests (package.json, requirements.txt, pom.xml, etc.)
for known vulnerabilities.  If osv-scanner is not installed, returns an
empty list with a warning log.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_TIMEOUT = 180

# Recognized manifest filenames
_MANIFEST_FILES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile.lock", "poetry.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "go.sum", "go.mod",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
}


class OSVFinding:
    """One CVE finding from OSV-scanner."""

    def __init__(
        self,
        vuln_id: str,
        package_name: str,
        package_version: str,
        severity: str,
        summary: str,
        manifest_file: str,
        aliases: list[str] | None = None,
        fixed_version: str = "",
    ) -> None:
        self.vuln_id = vuln_id
        self.package_name = package_name
        self.package_version = package_version
        self.severity = severity
        self.summary = summary
        self.manifest_file = manifest_file
        self.aliases = aliases or []
        self.fixed_version = fixed_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "osv",
            "vuln_id": self.vuln_id,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "severity": self.severity,
            "message": self.summary,
            "file_path": self.manifest_file,
            "line_start": 1,
            "line_end": 1,
            "code_snippet": f"{self.package_name}@{self.package_version}",
            "aliases": self.aliases,
            "fixed_version": self.fixed_version,
        }


def _map_osv_severity(database_specific: dict, groups: list) -> str:
    """Extract severity from OSV output."""
    # Check groups for CVSS severity
    for group in groups:
        max_severity = group.get("max_severity", "")
        if isinstance(max_severity, str) and max_severity:
            return max_severity.lower()

    # Check database_specific for severity
    severity = database_specific.get("severity", "")
    if isinstance(severity, str):
        sev = severity.upper()
        if sev in ("CRITICAL",):
            return "critical"
        if sev in ("HIGH",):
            return "high"
        if sev in ("MODERATE", "MEDIUM"):
            return "medium"
        return "low"

    return "medium"


def _parse_osv_json(data: dict, repo_path: str) -> list[OSVFinding]:
    """Parse OSV-scanner JSON output into findings."""
    findings: list[OSVFinding] = []
    repo_prefix = str(Path(repo_path).resolve()).replace("\\", "/")

    for result in data.get("results", []):
        source = result.get("source", {})
        manifest = source.get("path", "")
        manifest = manifest.replace("\\", "/")
        if manifest.startswith(repo_prefix):
            manifest = manifest[len(repo_prefix):].lstrip("/")

        for package_info in result.get("packages", []):
            pkg = package_info.get("package", {})
            pkg_name = pkg.get("name", "unknown")
            pkg_version = pkg.get("version", "")

            for vuln in package_info.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "")
                summary = vuln.get("summary", vuln.get("details", "")[:300])
                aliases = vuln.get("aliases", [])
                db_specific = vuln.get("database_specific", {})

                groups = package_info.get("groups", [])
                severity = _map_osv_severity(db_specific, groups)

                # Try to find fixed version
                fixed = ""
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed = event["fixed"]
                                break

                findings.append(OSVFinding(
                    vuln_id=vuln_id,
                    package_name=pkg_name,
                    package_version=pkg_version,
                    severity=severity,
                    summary=summary[:300],
                    manifest_file=manifest,
                    aliases=aliases,
                    fixed_version=fixed,
                ))

    return findings


def find_manifests(repo_path: Path) -> list[Path]:
    """Find all dependency manifest files in a repository."""
    manifests: list[Path] = []
    for root, dirs, files in _walk(repo_path):
        for fname in files:
            if fname in _MANIFEST_FILES:
                manifests.append(root / fname)
    return manifests


def _walk(path: Path):
    """Fallback walk for older Python."""
    import os
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "vendor", "__pycache__"}]
        yield Path(root), dirs, files


async def check_osv_installed() -> bool:
    """Check if osv-scanner is available on PATH."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "osv-scanner", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
        return proc.returncode == 0
    except (FileNotFoundError, OSError, asyncio.TimeoutError):
        return False


async def run_osv_scan(
    repo_path: str | Path,
    *,
    manifest_paths: list[str | Path] | None = None,
    timeout: int = _TIMEOUT,
    extra_args: list[str] | None = None,
) -> list[dict]:
    """Run OSV-scanner on dependency manifests and return CVE findings.

    Parameters
    ----------
    repo_path:
        Path to the repository.
    manifest_paths:
        Specific manifest files to scan.  If None, auto-detects.
    timeout:
        Max execution time in seconds.
    extra_args:
        Additional CLI arguments.

    Returns
    -------
    List of finding dicts.  Empty if osv-scanner is not installed.
    """
    repo_path = Path(repo_path)

    if not await check_osv_installed():
        logger.warning("osv.not_installed", msg="OSV-scanner not found — skipping CVE scan")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    try:
        cmd = [
            "osv-scanner",
            "--format", "json",
            "--output", output_path,
        ]

        if manifest_paths:
            for mp in manifest_paths:
                cmd.extend(["--lockfile", str(mp)])
        else:
            cmd.extend(["--recursive", str(repo_path)])

        if extra_args:
            cmd.extend(extra_args)

        logger.info("osv.starting", repo=str(repo_path))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            logger.error("osv.timeout", timeout=timeout)
            return []

        # osv-scanner returns 1 when vulnerabilities found (not an error)
        if proc.returncode not in (0, 1):
            logger.warning(
                "osv.error",
                returncode=proc.returncode,
                stderr=stderr.decode()[:500],
            )
            return []

        output_file = Path(output_path)
        if not output_file.exists() or output_file.stat().st_size == 0:
            return []

        raw = json.loads(output_file.read_text(encoding="utf-8"))
        findings = _parse_osv_json(raw, str(repo_path))

        logger.info("osv.completed", finding_count=len(findings))
        return [f.to_dict() for f in findings]

    except (json.JSONDecodeError, KeyError) as exc:
        logger.warning("osv.parse_error", error=str(exc)[:200])
        return []
    finally:
        Path(output_path).unlink(missing_ok=True)
