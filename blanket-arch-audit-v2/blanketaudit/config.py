"""Centralised configuration via pydantic-settings.

Precedence (highest wins): CLI flags → env vars → audit.yaml → defaults.
All env vars use the ``BLANKETAUDIT_`` prefix.
"""

from __future__ import annotations

import enum
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Enums ────────────────────────────────────────────────────

class LLMProvider(str, enum.Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OLLAMA = "ollama"
    GROQ = "groq"
    GOOGLE = "google"
    AZURE = "azure"
    NONE = "none"


class EmbeddingProvider(str, enum.Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    VOYAGE = "voyage"
    NONE = "none"


# ── Nested config groups (plain BaseModel, not settings) ─────

class LLMConfig(BaseModel):
    """LLM provider and model configuration."""
    provider: LLMProvider = LLMProvider.NONE
    model: str = ""  # empty → auto-select per provider
    compliance_model: str = ""  # override for compliance agent (higher capability)
    temperature: float = 0.0
    max_retries: int = 3
    timeout_seconds: int = 120
    base_url: str = ""  # Custom base URL (e.g. remote Ollama: "http://192.168.1.50:11434")
    agent_model_overrides: dict[str, str] = Field(
        default_factory=dict,
        description="Per-agent model overrides, e.g. {'compliance': 'claude-opus-4-20250514'}",
    )


class EmbeddingConfig(BaseModel):
    """Embedding provider configuration."""
    provider: EmbeddingProvider = EmbeddingProvider.NONE
    model: str = ""
    dimension: int = 1536


class CostConfig(BaseModel):
    """Cost and token budget controls."""
    max_scan_cost_usd: float = 15.0
    per_agent_token_budget: int = 500_000
    require_dry_run: bool = False
    abort_on_budget: bool = True


class TriageConfig(BaseModel):
    """File triage thresholds."""
    tier1_threshold: int = 60  # score > this → full AI analysis
    tier2_threshold: int = 30  # score > this → light AI
    max_batch_tokens: int = 150_000
    response_token_reserve: int = 50_000


class CacheConfig(BaseModel):
    """Incremental scanning cache settings."""
    enabled: bool = True
    ttl_hours: int = 24
    cache_dir: str = ".blanketaudit_cache"


class CircuitBreakerConfig(BaseModel):
    """Circuit breaker for external services."""
    failure_threshold: int = 5  # failures in window → open
    window_seconds: int = 60
    recovery_timeout_seconds: int = 120


class RateLimiterConfig(BaseModel):
    """Async rate limiter (asyncio.Semaphore size)."""
    max_concurrent_api_calls: int = 5
    max_concurrent_tools: int = 3


class OutputConfig(BaseModel):
    """Report output settings."""
    formats: list[Literal["pdf", "html", "json", "sarif"]] = Field(
        default_factory=lambda: ["pdf", "json"],
    )
    path: str = "./audit-report"
    min_severity: Literal["critical", "high", "medium", "low"] = "low"


class AgentToggle(BaseModel):
    """Per-agent enable/disable."""
    enabled: bool = True


class AgentsConfig(BaseModel):
    """Which agents are active."""
    security: AgentToggle = Field(default_factory=AgentToggle)
    compliance: AgentToggle = Field(default_factory=AgentToggle)
    architecture: AgentToggle = Field(default_factory=AgentToggle)
    quality: AgentToggle = Field(default_factory=AgentToggle)


# ── Top-level Settings ───────────────────────────────────────

class Settings(BaseSettings):
    """Root configuration object.

    Loaded via: audit.yaml → env vars (BLANKETAUDIT_ prefix) → CLI flags.
    """

    model_config = SettingsConfigDict(
        env_prefix="BLANKETAUDIT_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    # Domain
    domain: str = "general"
    active_frameworks: list[str] = Field(default_factory=list)

    # Scan targets (populated from audit.yaml or CLI)
    repos: list[dict] = Field(
        default_factory=list,
        description="List of repo dicts with 'url' and optional 'branch'",
    )
    paths: list[str] = Field(
        default_factory=list,
        description="Sub-paths within repos to scan (empty = all)",
    )

    # Nested configs
    llm: LLMConfig = Field(default_factory=LLMConfig)
    embedding: EmbeddingConfig = Field(default_factory=EmbeddingConfig)
    cost: CostConfig = Field(default_factory=CostConfig)
    triage: TriageConfig = Field(default_factory=TriageConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    rate_limiter: RateLimiterConfig = Field(default_factory=RateLimiterConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)

    # Storage
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    milvus_uri: str = "http://localhost:19530"
    sqlite_path: str = "blanketaudit.db"

    # Observability
    log_level: str = "INFO"
    log_json: bool = True
    otel_endpoint: str = ""
    sentry_dsn: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance.

    For testing, call ``get_settings.cache_clear()`` first.
    """
    return Settings()
