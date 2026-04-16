"""Exception hierarchy for BlanketAudit.

All exceptions inherit from BlanketAuditError so callers can catch
the base class for blanket (pun intended) error handling.
"""

from __future__ import annotations


class BlanketAuditError(Exception):
    """Base exception for all BlanketAudit errors."""

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


# ── Tier 1-2: Ingestion & Parsing ───────────────────────────

class IngestionError(BlanketAuditError):
    """Failed to ingest a repository (clone, checkout, or read)."""


class ParseError(BlanketAuditError):
    """Tree-sitter or manifest parsing failed for a file."""


class ExtractionError(BlanketAuditError):
    """Entity extraction (classes, methods, calls) failed."""


# ── Tier 3-4: Orchestration & Agents ────────────────────────

class PolicyError(BlanketAuditError):
    """Invalid or missing policy YAML definition."""


class AgentError(BlanketAuditError):
    """An analysis agent encountered an unrecoverable error."""


class LLMError(BlanketAuditError):
    """LLM provider call failed after retries."""


class BudgetExceededError(LLMError):
    """Token or cost budget exhausted for a scan or agent."""


class CircuitOpenError(LLMError):
    """Circuit breaker is open — too many recent LLM failures."""


# ── Tier 5: Validation ──────────────────────────────────────

class ValidationError(BlanketAuditError):
    """A finding failed one of the 4 hallucination gates."""


# ── Tier 6-7: Storage & Reporting ────────────────────────────

class StorageError(BlanketAuditError):
    """Database or cache operation failed (Neo4j, Milvus, SQLite, Postgres)."""


class ReportError(BlanketAuditError):
    """Report generation (PDF/HTML/JSON/SARIF) failed."""
