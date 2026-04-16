"""FastAPI application for cloud/API mode.

Endpoints:
  GET  /health                     — detailed health + provider status
  POST /api/v1/scan                — start a scan (async)
  POST /api/v1/scan/cost-estimate  — dry-run cost projection
  GET  /api/v1/scan/{scan_id}      — get scan status/results
  GET  /api/v1/scans               — list recent scans
  GET  /api/v1/policies            — list loaded policies
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from blanketaudit2 import __version__
from blanketaudit2.api.routes.scan import router as scan_router
from blanketaudit2.api.routes.health import router as health_router
from blanketaudit2.api.routes.policies import router as policies_router

app = FastAPI(
    title="BlanketAudit API",
    description="AI-powered architecture governance platform",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(scan_router, prefix="/api/v1")
app.include_router(policies_router, prefix="/api/v1")
