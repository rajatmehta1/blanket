from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database import close_pool, init_pool
from app.routers import activity_logs, assignments, policies, projects, templates

logger = logging.getLogger("blanket.gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    logger.info("Starting Blanket Gateway")
    await init_pool(settings)
    yield
    await close_pool()
    logger.info("Blanket Gateway shut down")


app = FastAPI(
    title="Blanket Gateway",
    description="REST API for Blanket — AI code governance platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
_settings = get_settings()
_origins = [o.strip() for o in _settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "ok", "service": "blanket-gateway"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "detail": "Internal server error"},
    )


app.include_router(projects.router)
app.include_router(policies.router)
app.include_router(assignments.router)
app.include_router(activity_logs.router)
app.include_router(templates.router)
