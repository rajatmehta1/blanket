from __future__ import annotations
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from dotenv import load_dotenv

_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")

@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = ""
    db_pool_min: int = 2
    db_pool_max: int = 10
    db_command_timeout: float = 30.0

    #server
    host: str = "0.0.0.0"
    port: int = 8000
    transport: str = "streamable-http"
    log_level: str = "INFO"

    require_auth: bool = True

    # Enforcement
    max_policies_per_injection: int = 20

    def validate(self) -> None:
        if not self.database_url:
            raise ValueError("BLANKET_DATABASE_URL is required")
        if self.transport not in ("streamable-http", "stdio", "sse"):
            raise ValueError(f"Invalid transport: {self.transport}")

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings(
        database_url=os.getenv("BLANKET_DATABASE_URL", ""),
        db_pool_min=int(os.getenv("BLANKET_DB_POOL_MIN", "2")),
        db_pool_max=int(os.getenv("BLANKET_DB_POOL_MAX", "10")),
        db_command_timeout=float(os.getenv("BLANKET_DB_COMMAND_TIMEOUT", "30")),
        host=os.getenv("BLANKET_HOST", "0.0.0.0"),
        port=int(os.getenv("BLANKET_PORT", "8000")),
        transport=os.getenv("BLANKET_TRANSPORT", "streamable-http"),
        log_level=os.getenv("BLANKET_LOG_LEVEL", "INFO"),
        require_auth=os.getenv("BLANKET_REQUIRE_AUTH", "true").lower() == "true",
        max_policies_per_injection=int(os.getenv("BLANKET_MAX_POLICIES", "20")),
    )
    settings.validate()
    return settings
