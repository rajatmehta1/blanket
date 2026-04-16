# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

BlanketAudit — AI-powered architecture governance platform. Scans repos (GitHub, GitLab, Bitbucket, local) to produce security, compliance, architecture, and quality reports with remediation steps. Supports CLI (`blanketaudit` via Typer) and API (FastAPI) interfaces.

Package: `blanketaudit` | Python 3.11+ | Entry point: `blanketaudit.cli.main:app`

## Build & Development Commands

```bash
# Install
pip install -e .

# Install with dev tools
make dev                    # or: pip install -e . && pip install pytest pytest-asyncio ruff mypy

# Run all tests (excludes LLM-as-Judge eval)
python -m pytest tests/ -k "not TestLLMJudge"

# Run unit tests only (~200 tests, <30s)
python -m pytest tests/unit/ -v --tb=short

# Run a single test file
python -m pytest tests/unit/test_scoring_risk.py -v

# Run a single test
python -m pytest tests/unit/test_scoring_risk.py::test_composite_score -v

# Integration tests (requires Neo4j/Milvus or uses memory fallback)
python -m pytest tests/integration/ -v --tb=short

# Lint
ruff check blanketaudit2/ tests/
mypy blanketaudit2/ --ignore-missing-imports

# Format
ruff format blanketaudit2/ tests/
ruff check --fix blanketaudit2/ tests/

# Run CLI
blanketaudit2 scan ./my-project
blanketaudit2 scan ./my-project --dry-run          # cost estimate only
blanketaudit2 scan ./my-project --domain healthcare --framework hipaa

# Run API server
uvicorn blanketaudit2.api.app:app --host 0.0.0.0 --port 8000
```

Ruff config: `target-version = "py311"`, `line-length = 100`. Pytest: `asyncio_mode = "auto"`.

## 6 Immutable Design Principles (ENFORCE IN ALL CODE)

1. **Dual-layer analysis**: Static scanners produce CANDIDATES. AI agents filter false positives and add context. Static ALWAYS runs first. AI NEVER runs alone.
2. **Graceful degradation**: One agent failure never kills a scan. LLM unavailable → fall back to static-only. Every external dependency has an explicit fallback.
3. **Cost-aware execution**: Every scan starts with dry-run cost estimate. Token budgets enforced per-agent with hard abort. No unbounded LLM spending.
4. **Reproducible audits**: ScanManifest records exact policy versions, prompt versions, model IDs, tool versions, repo commit SHAs. Past scans can be replayed.
5. **Hallucination guardrails**: 4 validation gates (schema, evidence, confidence, corroboration). NO finding enters the report without passing all 4 gates.
6. **Incremental scanning**: Only re-scan changed files + dependents. SHA-256(file_content + policy_version) cache keys.

## LLM Provider Abstraction (MANDATORY)

ALL LLM access goes through LangChain abstractions. NEVER import provider SDKs directly outside `blanketaudit/llm/`.

```python
# ✅ CORRECT — everywhere in the codebase:
from blanketaudit2.llm.provider import get_llm, get_llm_for_agent
from blanketaudit2.llm.embeddings import get_embeddings

llm = get_llm()  # Returns BaseChatModel or None

# ❌ NEVER — anywhere outside blanketaudit2/llm/:
from anthropic import Anthropic
import openai
```

Per-agent model routing: compliance agent → higher-capability model (Opus/GPT-4), others → standard model (Sonnet/GPT-4o-mini). Configured via `get_llm_for_agent(agent_name)`.

## Architecture Overview

Seven-tier pipeline orchestrated by LangGraph StateGraph (`blanketaudit/orchestrator/pipeline.py`):

```
Tier 1: Connectors (blanketaudit/connectors/) → clone/access repos
Tier 2: Ingestion (blanketaudit/ingestion/) → Tree-sitter AST, file-level dependency graph
Tier 2.5: Entity Extraction + Call Graph (blanketaudit/callgraph/) → method-level call graph in Neo4j
Tier 3: Orchestrator (blanketaudit/orchestrator/) → triage files (0-100 score, NO LLM), cost estimate, dispatch
Tier 4: Agents (blanketaudit/agents/) → 4 parallel agents: security, compliance, architecture, quality
Tier 5: Scoring (blanketaudit/scoring/) → dedup, 4 hallucination gates, 8-category risk scoring, report assembly
Tier 6: Report (blanketaudit/report/) → PDF (WeasyPrint), HTML, JSON, SARIF via Jinja2 templates
Tier 7: Delivery → filesystem, webhooks, SQLite history
```

**Key distinction**: File-level dependency graph (`ingestion/dependency_graph.py`, networkx, fast) ≠ Method-level call graph (`callgraph/`, Neo4j, expensive). They serve different purposes.

**Agent pattern** (`agents/base_agent.py`): Every agent follows `run_static_checks() → run_ai_analysis() → validate()`. Static always runs. AI is optional and budget-gated. Each agent has tools in `agents/tools/`.

**Hallucination gates** (`validation/`): Gate 1 (schema) → Gate 2 (evidence: file exists, line valid, 80% fuzzy match) → Gate 3 (confidence < 0.7 → REVIEW_NEEDED) → Gate 4 (lone critical from single agent → demote to high).

## Key Coding Rules

- **Models**: ALL Pydantic v2 BaseModel with strict validation. Defined in `blanketaudit/models/`. Top-level report model: `AuditReport` in `models/report.py`.
- **Prompts**: ALL via LangChain `ChatPromptTemplate` in `blanketaudit/llm/prompts/`. ALL structured output via `PydanticOutputParser`.
- **Error handling**: `tenacity` 3x exponential backoff on external calls. Circuit breaker (5 failures/60s → open → static fallback → half-open after 120s) in `llm/resilience.py`.
- **Output validation cycle**: parse → fail → correction prompt → retry parse → fail → discard AI, use static.
- **Logging**: `structlog` JSON. Log `scan_id, agent, step, duration_ms, tokens, cost_usd`. NEVER log source code content, secrets, or full prompts in production.
- **Prompt injection defense**: ALL system prompts must include the untrusted-data warning. Zero findings for non-trivial codebase = re-analyze.
- **Tests**: Use `LangChain FakeChatModel` for deterministic LLM tests. Fixture repos in `tests/fixtures/` have planted vulnerabilities at known locations.
- **Config**: `pydantic-settings` with env prefix `BLANKETAUDIT_` and nested delimiter `__` (e.g., `BLANKETAUDIT_LLM__PROVIDER`). Also reads `audit.yaml`.
- **Risk scoring**: 8 categories, weighted composite (0.35×security + 0.30×compliance_avg + 0.15×quality + 0.10×performance + 0.10×infra). Grade: A≥85, B≥70, C≥50, D≥30, F<30.

## Report PDF Requirements

- Dark theme: background `#0b0f1a`, text `#e2e8f0`, accent `#6C5CE7`
- Fonts: Sora (headings), JetBrains Mono (code/data/badges) via Google Fonts
- WeasyPrint: NO flexbox. Use CSS tables, floats, inline-block.
- 9 sections mapping 1:1 to `AuditReport` model fields (cover, executive summary, score dashboard, findings, compliance matrix, call graph, infrastructure, remediation roadmap, benefits)
- Severity colors: critical=`#ef4444`, high=`#f97316`, medium=`#fbbf24`, low=`#64748b`

## External Tools (subprocess)

Semgrep (SAST), Gitleaks (secrets), OSV-scanner (CVEs) — installed separately, called via subprocess in `agents/tools/`.

## Storage Backends

- Neo4j 5: call graph + entities (`storage/neo4j_store.py`)
- Milvus: vector embeddings for compliance RAG (`storage/milvus_store.py`)
- SQLite: CLI mode scan history + cache (`storage/sqlite_store.py`)
- PostgreSQL: cloud/API mode (`storage/postgres_store.py`)
- Memory fallback: zero-infrastructure mode (`storage/memory_fallback.py`)