# BlanketAudit

AI-powered architecture governance platform. Scans repositories to produce
comprehensive security, compliance, architecture, and quality reports with
specific remediation steps.

## Quick Start

```bash
pip install blanketaudit

# Scan a local repo (static-only, free)
blanketaudit scan ./my-project

# Scan with AI reasoning (requires API key)
export ANTHROPIC_API_KEY=sk-ant-...
blanketaudit scan ./my-project --domain healthcare --framework hipaa --framework soc2

# Dry-run cost estimate (no LLM spend)
blanketaudit scan ./my-project --dry-run

# Output formats
blanketaudit scan ./my-project --format pdf --format sarif --output ./reports
```

## Features

- **Dual-layer analysis**: Static scanners find candidates. AI agents filter false positives and add context.
- **4 compliance frameworks**: HIPAA, SOC2, PCI-DSS, GDPR with 88 policy rules.
- **4 analysis agents**: Security, Compliance, Architecture, Code Quality.
- **6 LLM providers**: Anthropic, OpenAI, Ollama (local), Groq, Google, Azure — or `none` for static-only.
- **4 hallucination gates**: Schema validation, evidence verification, confidence threshold, cross-agent corroboration.
- **4 output formats**: PDF (dark theme), interactive HTML, JSON (CI/CD), SARIF (GitHub/IDE).
- **Cost-aware**: Dry-run estimates, per-agent token budgets, abort thresholds.
- **Incremental scanning**: SHA-256 content cache, only re-scans changed files.

## Configuration

Create `audit.yaml` in your project root:

```yaml
scan:
  repos:
    - url: github.com/org/api-service
      branch: main
    - url: github.com/org/payment-service
      branch: main

frameworks: [hipaa, soc2]
domain: healthcare

agents:
  security: {enabled: true}
  compliance: {enabled: true}
  architecture: {enabled: true}
  quality: {enabled: true}

llm:
  provider: anthropic        # or openai, ollama, groq, google, none
  model: ""                  # empty = auto per provider
  compliance_model: ""       # higher model for compliance agent

cost:
  max_scan_cost_usd: 15.00
  require_dry_run: false
  per_agent_token_budget: 500000

output:
  formats: [pdf, json]
  path: ./audit-report
  min_severity: low

cache:
  enabled: true
  ttl_hours: 24
```

## Provider Configuration

Set your API key via environment variable:

```bash
# Anthropic (recommended)
export BLANKETAUDIT_LLM__PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
export BLANKETAUDIT_LLM__PROVIDER=openai
export OPENAI_API_KEY=sk-...

# Ollama (local, free)
export BLANKETAUDIT_LLM__PROVIDER=ollama
# No API key needed — ensure ollama is running on localhost:11434

# Static only (no AI, free)
export BLANKETAUDIT_LLM__PROVIDER=none
```

Per-agent model routing (compliance gets a higher-capability model):
```bash
export BLANKETAUDIT_LLM__COMPLIANCE_MODEL=claude-opus-4-20250514
```

## CLI Commands

```bash
blanketaudit scan [PATHS] [OPTIONS]     # Run audit scan
blanketaudit policies --list            # List all 88 policies
blanketaudit policies --validate        # Validate policy YAML files
blanketaudit providers --check          # Test provider connectivity
blanketaudit report SCAN_ID             # Regenerate report
blanketaudit --version                  # Show version
```

## CI/CD Integration

### GitHub Action

```yaml
- uses: tectoniclabs/blanketaudit-action@v1
  with:
    domain: healthcare
    frameworks: hipaa,soc2
    fail-on-critical: true
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### JSON Output for Pipelines

```bash
blanketaudit scan ./repo --json
# Exit codes: 0=pass, 1=critical findings, 2=error
```

## Docker

```bash
# CLI mode
docker run -v ./my-project:/repo blanketaudit scan /repo

# API server
docker compose up
# → API on localhost:8000, Neo4j on 7474, Web on 3000

# On-premises with Ollama (no cloud API keys)
docker compose -f docker-compose.onprem.yml up
```

## API

```bash
# Start API server
uvicorn blanketaudit.api.app:app --host 0.0.0.0 --port 8000

# Endpoints
GET  /health                      # Provider status, circuit breaker
POST /api/v1/scan                 # Start async scan
POST /api/v1/scan/cost-estimate   # Dry-run projection
GET  /api/v1/scan/{scan_id}       # Poll status
GET  /api/v1/policies             # List policies
GET  /docs                        # Swagger UI
```

## Architecture

```
Tier 1: Source Connectors (GitHub, GitLab, Bitbucket, Local)
Tier 2: Ingestion (Tree-sitter AST, file indexing, dependency graph)
Tier 3: Triage (file scoring 0-100, tier assignment, batch assembly)
       Cost Estimator (--dry-run)
       Static Analysis (Semgrep, Gitleaks, OSV-scanner)
Tier 4: AI Agents (Security, Compliance, Architecture, Quality)
Tier 5: Aggregation (dedup, 4 hallucination gates, 8-category scoring)
Tier 6: Report (PDF, HTML, JSON, SARIF)
Tier 7: Delivery (filesystem, webhooks, SQLite history)
```

## Development

```bash
git clone https://github.com/tectoniclabs/blanketaudit
cd blanketaudit
pip install -e .
pip install pytest pytest-asyncio ruff

# Run tests (1,565 tests)
python -m pytest tests/ -k "not TestLLMJudge"

# Lint
ruff check blanketaudit/ tests/
```

## License

MIT
