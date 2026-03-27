"""Dependency manifest extraction (package.json, pom.xml, requirements.txt).

Parses manifest files to extract dependency names and versions
for CVE scanning via OSV-scanner.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class Dependency:
    """One parsed dependency."""

    def __init__(self, name: str, version: str = "", source: str = "") -> None:
        self.name = name
        self.version = version
        self.source = source

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "source": self.source}


class ManifestParser:
    """Extract dependency lists from package manifests."""

    def parse(self, manifest_path: str | Path) -> list[Dependency]:
        """Parse a manifest file and return dependencies."""
        path = Path(manifest_path)
        if not path.exists():
            return []

        name = path.name.lower()
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        if name == "requirements.txt":
            return self._parse_requirements(content, str(path))
        if name == "package.json":
            return self._parse_package_json(content, str(path))
        if name == "pom.xml":
            return self._parse_pom(content, str(path))
        if name in ("go.mod", "go.sum"):
            return self._parse_go_mod(content, str(path))

        return []

    @staticmethod
    def _parse_requirements(content: str, source: str) -> list[Dependency]:
        deps: list[Dependency] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+\s*[\d\.\*]+)?", line)
            if match:
                name = match.group(1)
                version = (match.group(2) or "").strip().lstrip("=<>!~").strip()
                deps.append(Dependency(name, version, source))
        return deps

    @staticmethod
    def _parse_package_json(content: str, source: str) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            data = json.loads(content)
            for section in ("dependencies", "devDependencies"):
                for name, version in data.get(section, {}).items():
                    deps.append(Dependency(name, version.lstrip("^~>="), source))
        except (json.JSONDecodeError, AttributeError):
            pass
        return deps

    @staticmethod
    def _parse_pom(content: str, source: str) -> list[Dependency]:
        deps: list[Dependency] = []
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(content)
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            for dep in root.findall(".//m:dependency", ns) + root.findall(".//dependency"):
                aid = dep.findtext("m:artifactId", "", ns) or dep.findtext("artifactId", "")
                ver = dep.findtext("m:version", "", ns) or dep.findtext("version", "")
                if aid:
                    deps.append(Dependency(aid, ver, source))
        except ET.ParseError:
            pass
        return deps

    @staticmethod
    def _parse_go_mod(content: str, source: str) -> list[Dependency]:
        deps: list[Dependency] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("module") or line.startswith("go "):
                continue
            if line in ("require (", "require(", ")"):
                continue
            parts = line.split()
            if len(parts) >= 2 and "/" in parts[0]:
                deps.append(Dependency(parts[0], parts[1], source))
        return deps
