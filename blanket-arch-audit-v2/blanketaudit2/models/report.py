"""Top-level AuditReport model — everything needed for report generation."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel
from blanketaudit2.models.finding import AuditFinding
from blanketaudit2.models.compliance import ComplianceMatrix
from blanketaudit2.models.callgraph import CallGraphSummary
from blanketaudit2.models.scoring import HealthScore
from blanketaudit2.models.roadmap import RemediationPhase
from blanketaudit2.models.manifest import ScanManifest

class InfraFinding(BaseModel):
    severity: Literal["critical", "high", "medium", "low"]
    title: str
    file: str
    detail: str
    fix: str

class ExecutiveSummary(BaseModel):
    paragraphs: list[str]
    immediate_actions: list[str]

class AuditReport(BaseModel):
    project_name: str
    project_tagline: str
    domain: str
    repos: list[dict]
    scan_date: str
    scan_duration: str
    total_files: int
    total_lines: str
    total_methods: int
    cross_repo_edge_count: int
    entry_point_count: int
    max_call_depth: int
    health_score: HealthScore
    executive_summary: ExecutiveSummary
    findings: list[AuditFinding]
    infra_findings: list[InfraFinding]
    compliance_matrix: list[ComplianceMatrix]
    call_graph_summary: CallGraphSummary
    remediation_phases: list[RemediationPhase]
    scan_manifest: ScanManifest
    llm_provider: str
    llm_model: str
    active_frameworks: list[str]
