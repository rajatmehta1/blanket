"""Dockerfile directive extractor — no tree-sitter, uses regex parsing."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Pydantic model for extracted Docker info
from pydantic import BaseModel


class DockerDirective(BaseModel):
    """One directive extracted from a Dockerfile."""
    instruction: str      # FROM, RUN, ENV, EXPOSE, USER, COPY, etc.
    value: str            # The argument(s)
    line_number: int
    file_path: str


class DockerExtractionResult(BaseModel):
    """All directives from one Dockerfile."""
    file_path: str
    base_image: str = ""
    user: str = ""        # USER directive — "root" is a security finding
    exposed_ports: list[int] = []
    env_vars: list[str] = []
    directives: list[DockerDirective] = []
    has_healthcheck: bool = False
    runs_as_root: bool = True  # True until we see a USER non-root


# Regex: INSTRUCTION arguments (handles line continuations with \)
_DIRECTIVE_RE = re.compile(
    r"^(FROM|RUN|CMD|LABEL|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|"
    r"WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\s+(.+)",
    re.IGNORECASE,
)


class DockerExtractor:
    """Extract security-relevant directives from Dockerfiles."""

    def extract(self, file_path: str, content: str) -> DockerExtractionResult:
        result = DockerExtractionResult(file_path=file_path)

        # Join continuation lines
        content = re.sub(r"\\\s*\n", " ", content)

        for i, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            match = _DIRECTIVE_RE.match(stripped)
            if not match:
                continue

            instruction = match.group(1).upper()
            value = match.group(2).strip()

            result.directives.append(DockerDirective(
                instruction=instruction,
                value=value,
                line_number=i,
                file_path=file_path,
            ))

            if instruction == "FROM":
                result.base_image = value.split(" AS ")[0].split(" as ")[0].strip()
            elif instruction == "USER":
                result.user = value
                result.runs_as_root = value.strip().lower() in ("root", "0")
            elif instruction == "EXPOSE":
                for port_str in re.findall(r"\d+", value):
                    result.exposed_ports.append(int(port_str))
            elif instruction == "ENV":
                result.env_vars.append(value.split("=")[0].split()[0])
            elif instruction == "HEALTHCHECK":
                result.has_healthcheck = True

        return result
