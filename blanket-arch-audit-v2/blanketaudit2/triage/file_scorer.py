"""Score each file 0-100 for audit relevance (NO LLM — pure heuristics).

Design doc §7.1: determines how much LLM budget a file deserves.
Higher scores → Tier 1 (full AI).  Lower → Tier 3 (static only).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import structlog

from blanketaudit2.ingestion.models import FileMetadata, FileType

logger = structlog.get_logger()

# ── Scoring constants ────────────────────────────────────────

# Language relevance (source > config > IaC > docs)
_LANGUAGE_SCORES: dict[str, int] = {
    "python": 15, "java": 15, "typescript": 15, "javascript": 15,
    "go": 15, "rust": 15, "csharp": 15, "kotlin": 15, "scala": 15,
    "ruby": 12, "php": 12, "swift": 12,
    "sql": 8,
    "shell": 5, "powershell": 5,
}

_FILE_TYPE_SCORES: dict[FileType, int] = {
    FileType.SOURCE: 10,
    FileType.IAC: 8,
    FileType.CICD: 6,
    FileType.CONFIG: 4,
    FileType.BUILD: 2,
    FileType.DOC: 0,
    FileType.TEST: 0,
    FileType.OTHER: 0,
}

# Path patterns that suggest security/business-critical code.
_HIGH_VALUE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"auth", r"login", r"password", r"credential",
        r"payment", r"billing", r"charge", r"invoice",
        r"patient", r"medical", r"hipaa", r"phi",
        r"encrypt", r"crypto", r"secret", r"token",
        r"admin", r"permission", r"role", r"access.?control",
        r"route", r"controller", r"handler", r"endpoint", r"api",
        r"middleware",
    )
]

# Path patterns for generated/low-value code.
_GENERATED_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"_pb2\.py$", r"_pb2_grpc\.py$",
        r"\.generated\.", r"codegen", r"auto.?gen",
        r"migration", r"alembic/versions",
        r"\.min\.(js|css)$", r"bundle\.",
        r"swagger|openapi.*\.json$",
        r"__snapshots__", r"\.snap$",
        r"vendor/", r"node_modules/",
        r"\.d\.ts$",
    )
]

# Path patterns for route handlers / controllers (extra boost).
_HANDLER_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"routes?[/\\]", r"controllers?[/\\]", r"handlers?[/\\]",
        r"views?[/\\]", r"endpoints?[/\\]", r"api[/\\]",
    )
]

_SERVICE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"services?[/\\]", r"providers?[/\\]", r"managers?[/\\]",
        r"repositories?[/\\]", r"stores?[/\\]",
    )
]


class FileScorer:
    """Score every file 0-100 for audit relevance.  No LLM calls.

    Factors:
    - Language relevance (source > config > docs)
    - File type (route handler > service > utility)
    - Recency (modified in last 30 days)
    - Import count / fan-out (architecturally important)
    - File size (100-500 LOC sweet spot)
    - High-value name patterns (auth, payment, patient)
    - Test file penalty
    - Generated code penalty
    """

    def __init__(
        self,
        import_counts: dict[str, int] | None = None,
        now: datetime | None = None,
    ) -> None:
        # import_counts: {file_path: number_of_files_that_import_it}
        self._import_counts = import_counts or {}
        self._now = now or datetime.now(timezone.utc)

    def score(self, file: FileMetadata) -> int:
        """Return a score in [0, 100]."""
        s = 0

        # 1. Language relevance (0-15)
        s += _LANGUAGE_SCORES.get(file.language, 0)

        # 2. File type (0-10)
        s += _FILE_TYPE_SCORES.get(file.file_type, 0)

        # 3. Handler / service / utility pattern (0-20)
        if any(p.search(file.path) for p in _HANDLER_PATTERNS):
            s += 20
        elif any(p.search(file.path) for p in _SERVICE_PATTERNS):
            s += 10
        else:
            s += 5  # Utility / other source

        # 4. High-value name patterns (0-15)
        if any(p.search(file.path) for p in _HIGH_VALUE_PATTERNS):
            s += 15

        # 5. Recent changes (0-20)
        if file.last_modified:
            try:
                mod_dt = datetime.fromisoformat(file.last_modified)
                days_ago = (self._now - mod_dt).days
                if days_ago <= 30:
                    s += 20
                elif days_ago <= 90:
                    s += 10
            except (ValueError, TypeError):
                pass

        # 6. Import count / fan-out (0-15)
        imports = self._import_counts.get(file.path, 0)
        if imports >= 10:
            s += 15
        elif imports >= 5:
            s += 10
        elif imports >= 2:
            s += 5

        # 7. File size (0-10)
        if 100 <= file.loc <= 500:
            s += 10
        elif file.loc > 500:
            s += 5  # Diminishing returns — huge files hard to analyse
        elif 20 <= file.loc < 100:
            s += 3

        # ── Penalties ────────────────────────────────────────

        # 8. Test file (-30)
        if file.file_type is FileType.TEST:
            s -= 30

        # 9. Generated code (-40)
        if any(p.search(file.path) for p in _GENERATED_PATTERNS):
            s -= 40

        # 10. Doc / other file type (-10)
        if file.file_type in (FileType.DOC, FileType.OTHER):
            s -= 10

        return max(0, min(100, s))

    def score_all(self, files: list[FileMetadata]) -> dict[str, int]:
        """Score every file.  Returns ``{file_path: score}``."""
        scores: dict[str, int] = {}
        for f in files:
            scores[f.path] = self.score(f)
        logger.info(
            "triage.scored",
            total=len(scores),
            avg=round(sum(scores.values()) / max(len(scores), 1), 1),
        )
        return scores
