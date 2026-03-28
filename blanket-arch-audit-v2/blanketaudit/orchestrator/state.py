"""AuditState TypedDict for the LangGraph pipeline.

This is the single state object threaded through every node in the
StateGraph.  Fields are grouped by pipeline tier.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict


def _merge_lists(a: list, b: list) -> list:
    """Reducer: concatenate lists from parallel branches."""
    return (a or []) + (b or [])


class AuditState(TypedDict, total=False):
    """State passed through every LangGraph node.

    Fields marked with ``Annotated[list, _merge_lists]`` are automatically
    merged when parallel branches rejoin.
    """

    # ── Input (set before pipeline starts) ───────────────────
    project_name: str
    scan_id: str
    domain: str
    frameworks: list[str]
    repo_sources: list[dict]       # [{url, branch, token, ...}]
    config: dict                    # Merged audit.yaml + env + CLI

    # ── Tier 1-2: Ingestion ──────────────────────────────────
    repo_paths: list[dict]          # [{repo_name, local_path, commit_sha}]
    files: list[dict]               # FileMetadata dicts
    analysis_contexts: list[dict]   # AnalysisContext dicts
    dep_graph: dict                 # Serialized file-level dependency graph
    call_graph: Any                 # CallGraph object

    # ── Tier 3: Triage ───────────────────────────────────────
    file_scores: dict[str, int]     # {path: score 0-100}
    file_tiers: dict[str, int]      # {path: 1|2|3}
    batches: list[list[dict]]       # Token-limited file batches
    cost_estimate: dict             # CostEstimate dict

    # ── Tier 3.5: Static analysis (before agents) ────────────
    static_findings: Annotated[list[dict], _merge_lists]
    static_raw_count: int               # Raw tool findings before conversion

    # ── Tier 4: Agent results ────────────────────────────────
    agent_findings: Annotated[list[dict], _merge_lists]

    # ── Tier 5: Aggregated + scored ──────────────────────────
    validated_findings: list[dict]   # After 4 hallucination gates
    health_score: dict               # HealthScore dict
    compliance_matrix: list[dict]    # ComplianceMatrix dicts
    remediation_phases: list[dict]   # RemediationPhase dicts

    # ── Tier 6: Report ───────────────────────────────────────
    executive_summary: dict          # ExecutiveSummary dict
    report: dict                     # Full AuditReport dict
    report_paths: dict[str, str]     # {format: file_path}

    # ── Metadata ─────────────────────────────────────────────
    scan_manifest: dict              # ScanManifest dict
    cost_tracker_summary: dict       # CostTracker.summary()
    errors: Annotated[list[str], _merge_lists]
    status: str                      # "running" | "completed" | "failed" | "aborted"
    dry_run: bool                    # If True, stop after cost estimate
