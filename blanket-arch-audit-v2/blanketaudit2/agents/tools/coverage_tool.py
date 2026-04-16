"""Test coverage report parsing tool for LangGraph agents.

Parses coverage reports from common formats:
- coverage.py XML (Python)
- lcov.info (JavaScript/TypeScript)
- JaCoCo XML (Java)

Returns per-file coverage percentages.  All tools return JSON strings
and handle missing reports gracefully.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class CoverageResult:
    """Parsed coverage data for one file."""

    def __init__(
        self,
        file_path: str,
        line_rate: float,
        lines_covered: int = 0,
        lines_total: int = 0,
    ) -> None:
        self.file_path = file_path
        self.line_rate = line_rate
        self.lines_covered = lines_covered
        self.lines_total = lines_total

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_rate": round(self.line_rate, 4),
            "lines_covered": self.lines_covered,
            "lines_total": self.lines_total,
            "percent": round(self.line_rate * 100, 1),
        }


class CoverageSummary:
    """Aggregated coverage across all files."""

    def __init__(self, files: list[CoverageResult], source: str = "") -> None:
        self.files = files
        self.source = source

    @property
    def overall_rate(self) -> float:
        total = sum(f.lines_total for f in self.files)
        covered = sum(f.lines_covered for f in self.files)
        return covered / total if total > 0 else 0.0

    @property
    def file_count(self) -> int:
        return len(self.files)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "overall_percent": round(self.overall_rate * 100, 1),
            "file_count": self.file_count,
            "files": [f.to_dict() for f in self.files],
        }

    def uncovered_files(self, threshold: float = 0.5) -> list[dict]:
        """Files with coverage below the threshold."""
        return [
            f.to_dict() for f in self.files
            if f.line_rate < threshold
        ]


# ── Parsers ──────────────────────────────────────────────────


def parse_coverage_xml(xml_path: Path) -> CoverageSummary:
    """Parse a coverage.py XML report (Cobertura format)."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        logger.warning("coverage.xml_parse_error", error=str(exc)[:200])
        return CoverageSummary([], source="coverage.xml")

    files: list[CoverageResult] = []
    for pkg in root.findall(".//package"):
        for cls in pkg.findall(".//class"):
            filename = cls.get("filename", "")
            line_rate = float(cls.get("line-rate", "0"))
            lines = cls.findall(".//line")
            total = len(lines)
            covered = sum(1 for l in lines if int(l.get("hits", "0")) > 0)
            files.append(CoverageResult(
                file_path=filename,
                line_rate=line_rate,
                lines_covered=covered,
                lines_total=total,
            ))

    return CoverageSummary(files, source="coverage.xml")


def parse_lcov(lcov_path: Path) -> CoverageSummary:
    """Parse an lcov.info coverage report."""
    try:
        content = lcov_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("coverage.lcov_read_error", error=str(exc)[:200])
        return CoverageSummary([], source="lcov.info")

    files: list[CoverageResult] = []
    current_file = ""
    lines_found = 0
    lines_hit = 0

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("SF:"):
            current_file = line[3:]
            lines_found = 0
            lines_hit = 0
        elif line.startswith("LF:"):
            lines_found = int(line[3:])
        elif line.startswith("LH:"):
            lines_hit = int(line[3:])
        elif line == "end_of_record" and current_file:
            rate = lines_hit / lines_found if lines_found > 0 else 0.0
            files.append(CoverageResult(
                file_path=current_file,
                line_rate=rate,
                lines_covered=lines_hit,
                lines_total=lines_found,
            ))
            current_file = ""

    return CoverageSummary(files, source="lcov.info")


def parse_jacoco_xml(xml_path: Path) -> CoverageSummary:
    """Parse a JaCoCo XML coverage report."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        logger.warning("coverage.jacoco_parse_error", error=str(exc)[:200])
        return CoverageSummary([], source="jacoco.xml")

    files: list[CoverageResult] = []
    for pkg in root.findall(".//package"):
        pkg_name = pkg.get("name", "").replace("/", ".")
        for src in pkg.findall("sourcefile"):
            filename = src.get("name", "")
            full_path = f"{pkg_name}/{filename}" if pkg_name else filename

            missed = 0
            covered = 0
            for counter in src.findall("counter"):
                if counter.get("type") == "LINE":
                    missed = int(counter.get("missed", "0"))
                    covered = int(counter.get("covered", "0"))
                    break

            total = missed + covered
            rate = covered / total if total > 0 else 0.0
            files.append(CoverageResult(
                file_path=full_path,
                line_rate=rate,
                lines_covered=covered,
                lines_total=total,
            ))

    return CoverageSummary(files, source="jacoco.xml")


# ── Auto-detect + tool function ──────────────────────────────


def find_coverage_reports(repo_path: Path) -> list[tuple[str, Path]]:
    """Auto-detect coverage reports in a repository.

    Returns list of (format, path) tuples.
    """
    reports: list[tuple[str, Path]] = []
    candidates = [
        ("coverage_xml", "coverage.xml"),
        ("coverage_xml", "coverage/coverage.xml"),
        ("lcov", "coverage/lcov.info"),
        ("lcov", "lcov.info"),
        ("jacoco", "target/site/jacoco/jacoco.xml"),
        ("jacoco", "build/reports/jacoco/test/jacocoTestReport.xml"),
    ]
    for fmt, rel_path in candidates:
        full = repo_path / rel_path
        if full.exists():
            reports.append((fmt, full))
    return reports


def parse_coverage_report(repo_path: str) -> str:
    """Auto-detect and parse coverage reports in a repository.

    Returns JSON with overall coverage and per-file breakdown.
    """
    rp = Path(repo_path)
    if not rp.exists():
        return json.dumps({"error": f"Path not found: {repo_path}", "files": []})

    reports = find_coverage_reports(rp)
    if not reports:
        return json.dumps({
            "error": "No coverage report found",
            "hint": "Supported: coverage.xml, lcov.info, jacoco.xml",
            "files": [],
        })

    # Parse the first found report
    fmt, path = reports[0]
    if fmt == "coverage_xml":
        summary = parse_coverage_xml(path)
    elif fmt == "lcov":
        summary = parse_lcov(path)
    elif fmt == "jacoco":
        summary = parse_jacoco_xml(path)
    else:
        return json.dumps({"error": f"Unknown format: {fmt}", "files": []})

    return json.dumps(summary.to_dict())


def get_uncovered_files(repo_path: str, threshold: float = 0.5) -> str:
    """Find files with coverage below the threshold.

    Returns JSON with ``uncovered_files`` list.
    """
    rp = Path(repo_path)
    reports = find_coverage_reports(rp) if rp.exists() else []
    if not reports:
        return json.dumps({"error": "No coverage report found", "uncovered_files": []})

    fmt, path = reports[0]
    if fmt == "coverage_xml":
        summary = parse_coverage_xml(path)
    elif fmt == "lcov":
        summary = parse_lcov(path)
    elif fmt == "jacoco":
        summary = parse_jacoco_xml(path)
    else:
        return json.dumps({"error": f"Unknown format: {fmt}", "uncovered_files": []})

    uncovered = summary.uncovered_files(threshold)
    return json.dumps({
        "threshold_percent": round(threshold * 100, 1),
        "uncovered_files": uncovered,
        "count": len(uncovered),
    })
