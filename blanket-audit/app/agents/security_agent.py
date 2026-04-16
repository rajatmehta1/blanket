"""Security Agent — LangGraph node.

Detects: hardcoded secrets, shell injection, SQL injection, dangerous imports,
         missing input validation, insecure deserialization.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from app.models.common import Severity, FindingCategory, OWASPCategory
from app.models.state import AuditState

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (r"""(?:password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*["'][^"']{4,}["']""",
     "Hardcoded secret/credential"),
    (r"""(?:AWS_SECRET|aws_secret_access_key)\s*=\s*["'][^"']+["']""",
     "Hardcoded AWS credential"),
]

DANGEROUS_CALLS = {
    "eval(": ("Use of eval()", OWASPCategory.V5_INPUT_VALIDATION),
    "exec(": ("Use of exec()", OWASPCategory.V5_INPUT_VALIDATION),
    "os.system(": ("Shell command via os.system()", OWASPCategory.V5_INPUT_VALIDATION),
    "subprocess.call(": ("Subprocess call — check for shell injection", OWASPCategory.V5_INPUT_VALIDATION),
    "pickle.loads(": ("Insecure deserialization with pickle", OWASPCategory.V8_DATA_PROTECTION),
    "yaml.load(": ("Unsafe YAML load — use yaml.safe_load()", OWASPCategory.V8_DATA_PROTECTION),
    "marshal.loads(": ("Insecure deserialization with marshal", OWASPCategory.V8_DATA_PROTECTION),
    "__import__(": ("Dynamic import — potential code injection", OWASPCategory.V10_MALICIOUS_CODE),
}

SQL_PATTERN = re.compile(
    r"""(?:execute|cursor\.execute|raw|rawsql)\s*\(\s*(?:f["']|["'].*%s|["'].*\.format)""",
    re.IGNORECASE,
)


async def analyze_security(state: AuditState) -> dict:
    """LangGraph node: detect security issues via static pattern matching."""
    parsed_files = state.get("parsed_files", [])
    findings: List[Dict[str, Any]] = []
    agent_logs: List[str] = []
    errors: List[str] = []

    agent_logs.append("[Security] Starting security analysis")
    repo_metadata = state.get("repo_metadata", {})
    local_path = repo_metadata.get("local_path", "")

    try:
        for pf in parsed_files:
            filepath = pf["path"]
            full_path = f"{local_path}/{filepath}" if local_path else filepath
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except FileNotFoundError:
                continue

            lines = source.splitlines()
            for i, line in enumerate(lines, 1):
                # check secrets
                for pattern, desc in SECRET_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "title": desc,
                            "severity": Severity.CRITICAL.value,
                            "category": FindingCategory.SECURITY.value,
                            "owasp": OWASPCategory.V6_CRYPTOGRAPHY.value,
                            "file": filepath,
                            "line": i,
                            "evidence": _redact_line(line.strip()),
                            "recommendation": "Move secrets to environment variables or a vault.",
                        })

                # check dangerous calls
                for call, (desc, owasp) in DANGEROUS_CALLS.items():
                    if call in line and not line.lstrip().startswith("#") and not _is_string_literal(line, call):
                        findings.append({
                            "title": desc,
                            "severity": Severity.HIGH.value,
                            "category": FindingCategory.SECURITY.value,
                            "owasp": owasp.value,
                            "file": filepath,
                            "line": i,
                            "evidence": line.strip(),
                            "recommendation": f"Avoid {call.rstrip('(')} or sanitize inputs.",
                        })

                # check SQL injection
                if SQL_PATTERN.search(line):
                    findings.append({
                        "title": "Potential SQL injection",
                        "severity": Severity.CRITICAL.value,
                        "category": FindingCategory.SECURITY.value,
                        "owasp": OWASPCategory.V5_INPUT_VALIDATION.value,
                        "file": filepath,
                        "line": i,
                        "evidence": line.strip(),
                        "recommendation": "Use parameterized queries instead of string formatting.",
                    })
    except Exception as e:
        errors.append(f"[Security] Analysis failed: {e}")
        logger.error("[Security] Analysis failed", exc_info=True)

    agent_logs.append(f"[Security] Complete — {len(findings)} findings")
    return {
        "security_findings": findings,
        "agent_logs": agent_logs,
        "errors": errors,
    }


def _is_string_literal(line: str, call: str) -> bool:
    """Check if the call appears inside a string literal (dict key, comment, etc)."""
    stripped = line.strip()
    # skip lines that are just string definitions (dict entries, assignments to strings)
    if stripped.startswith('"') or stripped.startswith("'"):
        return True
    # skip if the call is inside quotes as a key/value
    idx = stripped.find(call)
    if idx > 0:
        before = stripped[:idx]
        if before.count('"') % 2 == 1 or before.count("'") % 2 == 1:
            return True
    return False


def _redact_line(line: str) -> str:
    """Redact potential secret values in evidence output."""
    return re.sub(r"""(=\s*["'])[^"']{4,}(["'])""", r"\1****\2", line)
