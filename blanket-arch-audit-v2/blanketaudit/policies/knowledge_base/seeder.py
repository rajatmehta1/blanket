"""Knowledge base seeder — load compliance clause YAMLs into vector store.

On first run (or when ``--reseed`` is passed), reads all clause YAML files
and upserts them into the ``compliance_clauses`` Milvus collection for
RAG-based compliance mapping.

Usage::

    seeder = KnowledgeBaseSeeder(milvus_store)
    stats = await seeder.seed()
    print(stats)  # {"hipaa": 15, "soc2": 12, "pci_dss": 12, "gdpr": 10}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
import yaml

from blanketaudit.storage.milvus_store import (
    COLLECTION_COMPLIANCE_CLAUSES,
    COLLECTION_VULN_PATTERNS,
    MilvusStore,
)

logger = structlog.get_logger()

# Path to the knowledge base YAML files
_KB_DIR = Path(__file__).parent

# Sentinel file to track if seeding has already been done
_SEED_MARKER = ".seeded"


class ComplianceClause:
    """A parsed compliance clause ready for vector store insertion."""

    def __init__(
        self,
        id: str,
        framework: str,
        clause: str,
        title: str,
        text: str,
        technical_requirements: list[str],
        code_indicators: list[str],
    ) -> None:
        self.id = id
        self.framework = framework
        self.clause = clause
        self.title = title
        self.text = text
        self.technical_requirements = technical_requirements
        self.code_indicators = code_indicators

    @property
    def embedding_text(self) -> str:
        """Text to embed — combines clause text with technical requirements."""
        parts = [
            f"{self.framework} {self.clause}: {self.title}",
            self.text,
            "Technical requirements: " + "; ".join(self.technical_requirements),
            "Code indicators: " + "; ".join(self.code_indicators),
        ]
        return "\n".join(parts)

    def to_metadata(self) -> dict:
        return {
            "id": self.id,
            "framework": self.framework,
            "clause": self.clause,
            "title": self.title,
            "technical_requirements": "; ".join(self.technical_requirements),
            "code_indicators": "; ".join(self.code_indicators),
        }


def load_clauses_from_yaml(yaml_path: Path) -> list[ComplianceClause]:
    """Parse a clause YAML file into ComplianceClause objects."""
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning(
            "kb.parse_error",
            file=str(yaml_path),
            error=str(exc)[:200],
        )
        return []

    if not isinstance(data, dict) or "clauses" not in data:
        logger.warning("kb.invalid_format", file=str(yaml_path))
        return []

    clauses: list[ComplianceClause] = []
    for item in data["clauses"]:
        if not isinstance(item, dict):
            continue
        try:
            clauses.append(ComplianceClause(
                id=item.get("id", ""),
                framework=item.get("framework", ""),
                clause=item.get("clause", ""),
                title=item.get("title", ""),
                text=item.get("text", ""),
                technical_requirements=item.get("technical_requirements", []),
                code_indicators=item.get("code_indicators", []),
            ))
        except Exception as exc:
            logger.warning("kb.clause_error", error=str(exc)[:200])

    return clauses


def load_all_clauses(kb_dir: Path | None = None) -> dict[str, list[ComplianceClause]]:
    """Load all clause YAML files from the knowledge base directory.

    Returns ``{framework_file_stem: [clauses]}``.
    """
    kb_dir = kb_dir or _KB_DIR
    result: dict[str, list[ComplianceClause]] = {}

    yaml_files = [
        "hipaa_clauses.yaml",
        "soc2_criteria.yaml",
        "pci_dss_requirements.yaml",
        "gdpr_articles.yaml",
    ]

    for fname in yaml_files:
        path = kb_dir / fname
        if not path.exists():
            logger.warning("kb.file_missing", file=fname)
            continue

        stem = fname.replace("_clauses", "").replace("_criteria", "").replace(
            "_requirements", ""
        ).replace("_articles", "").replace(".yaml", "")
        clauses = load_clauses_from_yaml(path)
        result[stem] = clauses
        logger.info("kb.loaded_file", file=fname, clauses=len(clauses))

    return result


class KnowledgeBaseSeeder:
    """Seed compliance clauses into the vector store on first run."""

    def __init__(
        self,
        store: MilvusStore,
        kb_dir: Path | None = None,
    ) -> None:
        self._store = store
        self._kb_dir = kb_dir or _KB_DIR

    async def seed(self, force: bool = False) -> dict[str, int]:
        """Load clauses and insert into the vector store.

        Parameters
        ----------
        force:
            If True, reseed even if already seeded.

        Returns
        -------
        ``{framework_stem: clause_count}`` — number of clauses seeded per framework.
        """
        if not force and self._is_seeded():
            logger.info("kb.already_seeded")
            return {}

        all_clauses = load_all_clauses(self._kb_dir)
        stats: dict[str, int] = {}

        for stem, clauses in all_clauses.items():
            if not clauses:
                continue

            texts = [c.embedding_text for c in clauses]
            metadatas = [c.to_metadata() for c in clauses]

            ids = await self._store.add_texts(
                COLLECTION_COMPLIANCE_CLAUSES,
                texts,
                metadatas,
            )
            stats[stem] = len(ids)

        # Mark as seeded
        self._mark_seeded()

        total = sum(stats.values())
        logger.info("kb.seeded", total=total, per_framework=stats)
        return stats

    async def seed_vuln_patterns(self, patterns: list[dict]) -> int:
        """Seed vulnerability pattern descriptions into the vector store.

        Parameters
        ----------
        patterns:
            List of ``{"description": str, "cwe": str, ...}`` dicts.

        Returns
        -------
        Number of patterns seeded.
        """
        if not patterns:
            return 0
        ids = await self._store.add_vuln_patterns(patterns)
        logger.info("kb.vuln_patterns_seeded", count=len(ids))
        return len(ids)

    def _is_seeded(self) -> bool:
        """Check if seeding has already been done."""
        marker = self._kb_dir / _SEED_MARKER
        return marker.exists()

    def _mark_seeded(self) -> None:
        """Create the seed marker file."""
        try:
            marker = self._kb_dir / _SEED_MARKER
            marker.write_text("seeded\n")
        except OSError:
            pass  # Non-critical

    def clear_seed_marker(self) -> None:
        """Remove the seed marker (for testing or re-seeding)."""
        marker = self._kb_dir / _SEED_MARKER
        if marker.exists():
            marker.unlink()
