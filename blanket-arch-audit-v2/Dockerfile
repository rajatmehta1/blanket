FROM python:3.11-slim AS base

# System deps for WeasyPrint, tree-sitter, git
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev libcairo2 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install external tools
COPY --from=returntocorp/semgrep:latest /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=returntocorp/semgrep:latest /usr/local/lib/python3.11/ /usr/local/lib/python3.11/

WORKDIR /app

# Install Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir -e . 2>/dev/null || pip install --no-cache-dir .

# Copy source
COPY blanketaudit/ blanketaudit/
COPY tests/ tests/

# Non-root user
RUN useradd -m appuser
USER appuser

# CLI entrypoint
ENTRYPOINT ["blanketaudit"]
CMD ["--help"]

# API mode: override CMD
# docker run blanketaudit-api uvicorn blanketaudit.api.app:app --host 0.0.0.0 --port 8000
