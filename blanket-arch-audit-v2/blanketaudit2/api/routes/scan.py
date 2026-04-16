"""Scan endpoints — start scan, cost estimate, status, list."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(tags=["scan"])

# In-memory scan tracker (production would use DB)
_scans: dict[str, dict] = {}


# ── Request/response models ──────────────────────────────────


class ScanRequest(BaseModel):
    project_name: str = "audit"
    domain: str = "general"
    frameworks: list[str] = []
    repos: list[dict] = Field(default_factory=list, description="[{url, branch}] or [{local_path}]")
    max_cost_usd: float | None = None


class CostEstimateRequest(BaseModel):
    project_name: str = "audit"
    domain: str = "general"
    frameworks: list[str] = []
    repos: list[dict] = Field(default_factory=list)


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    health_score: dict | None = None
    finding_count: int = 0
    error: str | None = None


# ── Endpoints ────────────────────────────────────────────────


@router.post("/scan", response_model=ScanStatusResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """Start an asynchronous audit scan.

    Returns immediately with a scan_id.  Poll ``GET /scan/{scan_id}``
    for status and results.
    """
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"

    state = {
        "scan_id": scan_id,
        "project_name": request.project_name,
        "domain": request.domain,
        "frameworks": request.frameworks,
        "repo_sources": request.repos,
        "dry_run": False,
        "config": {},
    }

    if request.max_cost_usd:
        state["config"] = {"cost": {"max_scan_cost_usd": request.max_cost_usd}}

    _scans[scan_id] = {"scan_id": scan_id, "status": "queued", "state": state}

    background_tasks.add_task(_run_scan_bg, scan_id, state)

    return {"scan_id": scan_id, "status": "queued"}


@router.post("/scan/cost-estimate")
async def cost_estimate(request: CostEstimateRequest) -> dict:
    """Dry-run cost projection without running agents.

    Clones repos, indexes files, runs triage, projects cost.
    Returns estimated USD, token counts, and tier breakdown.
    """
    state = {
        "project_name": request.project_name,
        "domain": request.domain,
        "frameworks": request.frameworks,
        "repo_sources": request.repos,
        "dry_run": True,
        "config": {},
    }

    try:
        from blanketaudit2.orchestrator.pipeline import AuditPipeline

        pipeline = AuditPipeline()
        pipeline.build()
        result = await pipeline.run(state)

        return {
            "status": "completed",
            "cost_estimate": result.get("cost_estimate", {}),
            "file_count": len(result.get("files", [])),
            "tiers": result.get("file_tiers", {}),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)[:500])


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> dict:
    """Get the status and results of a scan."""
    scan = _scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    result = scan.get("result", {})
    hs = result.get("health_score", {})
    findings = result.get("validated_findings", result.get("findings", []))

    return {
        "scan_id": scan_id,
        "status": scan.get("status", "unknown"),
        "health_score": hs if hs else None,
        "finding_count": len(findings),
        "error": scan.get("error"),
    }


@router.get("/scans")
async def list_scans(limit: int = 20) -> list[dict]:
    """List recent scans."""
    scans = sorted(
        _scans.values(),
        key=lambda s: s.get("scan_id", ""),
        reverse=True,
    )[:limit]
    return [
        {
            "scan_id": s["scan_id"],
            "status": s.get("status", "unknown"),
            "project": s.get("state", {}).get("project_name", ""),
        }
        for s in scans
    ]


@router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json") -> Any:
    """Get the full report for a completed scan."""
    scan = _scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    if scan.get("status") != "completed":
        raise HTTPException(status_code=409, detail=f"Scan not completed: {scan['status']}")

    result = scan.get("result", {})
    report = result.get("report", result)

    if format == "sarif":
        from blanketaudit2.report.sarif_exporter import SARIFExporter
        return SARIFExporter().to_sarif(report)

    return report


# ── Background task ──────────────────────────────────────────


async def _run_scan_bg(scan_id: str, state: dict) -> None:
    """Run scan in background and update status."""
    _scans[scan_id]["status"] = "running"
    try:
        from blanketaudit2.orchestrator.pipeline import AuditPipeline

        pipeline = AuditPipeline()
        pipeline.build()
        result = await pipeline.run(state)

        _scans[scan_id]["status"] = result.get("status", "completed")
        _scans[scan_id]["result"] = result
    except Exception as exc:
        _scans[scan_id]["status"] = "failed"
        _scans[scan_id]["error"] = str(exc)[:500]
