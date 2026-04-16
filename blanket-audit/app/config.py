from dataclasses import dataclass, field
from functools import lru_cache
from typing import List
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    input_repos: tuple = ()
    output_dir: str = "./audit_output"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""


@lru_cache()
def get_settings() -> Settings:
    repos_raw = os.getenv("INPUT_REPOS", "")
    repos = tuple(r.strip() for r in repos_raw.split(",") if r.strip())
    return Settings(
        input_repos=repos,
        output_dir=os.getenv("OUTPUT_DIR", "./audit_output"),
        neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
        neo4j_password=os.getenv("NEO4J_PASSWORD", ""),
    )
