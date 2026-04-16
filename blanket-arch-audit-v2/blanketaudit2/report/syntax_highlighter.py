"""Pygments-based code highlighting for findings.

Produces HTML ``<pre>`` blocks with inline styles (no external CSS needed).
Falls back to plain ``<pre>`` when Pygments is not installed.
"""

from __future__ import annotations

import html
import os
from typing import Any

# File extension → Pygments lexer name
_EXT_TO_LEXER: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".sql": "sql",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".tf": "hcl",
}

_CODE_PRESTYLES = (
    "background: rgba(0,0,0,0.35); border-radius: 6px; "
    "padding: 10px; font-size: 9pt; line-height: 1.5;"
)
_FIX_PRESTYLES = (
    "background: rgba(52,211,153,0.04); border-left: 3px solid rgba(52,211,153,0.25); "
    "border-radius: 6px; padding: 10px; font-size: 9pt; line-height: 1.5;"
)


def _lang_from_path(file_path: str) -> str:
    """Infer Pygments lexer name from a file path."""
    _, ext = os.path.splitext(file_path)
    return _EXT_TO_LEXER.get(ext.lower(), "")


class SyntaxHighlighter:
    """Highlight code snippets for the PDF report.

    Uses Pygments with Monokai theme and inline styles (WeasyPrint
    doesn't support external CSS class references in code blocks).
    """

    def highlight(self, code: str, language: str = "") -> str:
        """Return syntax-highlighted HTML for a code snippet.

        Uses Pygments if available, otherwise returns escaped ``<pre>``.
        """
        if not code:
            return ""

        try:
            from pygments import highlight as pyg_highlight
            from pygments.formatters import HtmlFormatter
            from pygments.lexers import get_lexer_by_name, guess_lexer

            lexer = self._get_lexer(language, code, get_lexer_by_name, guess_lexer)
            formatter = HtmlFormatter(
                noclasses=True,
                style="monokai",
                nowrap=True,
            )
            highlighted = pyg_highlight(code, lexer, formatter)
            return f'<pre class="code-snippet" style="{_CODE_PRESTYLES}">{highlighted}</pre>'

        except ImportError:
            pass

        return f'<pre class="code-snippet" style="{_CODE_PRESTYLES}">{html.escape(code)}</pre>'

    def highlight_fix(self, code: str, language: str = "") -> str:
        """Highlight a fix/remediation code block (green theme)."""
        if not code:
            return ""

        try:
            from pygments import highlight as pyg_highlight
            from pygments.formatters import HtmlFormatter
            from pygments.lexers import get_lexer_by_name, guess_lexer

            lexer = self._get_lexer(language, code, get_lexer_by_name, guess_lexer)
            formatter = HtmlFormatter(noclasses=True, style="monokai", nowrap=True)
            highlighted = pyg_highlight(code, lexer, formatter)
            return f'<pre class="fix-code" style="{_FIX_PRESTYLES}">{highlighted}</pre>'

        except ImportError:
            pass

        return f'<pre class="fix-code" style="{_FIX_PRESTYLES}">{html.escape(code)}</pre>'

    def highlight_finding(self, finding: Any) -> tuple[str, str]:
        """Return ``(highlighted_code, highlighted_fix)`` for a finding.

        Detects language from ``evidence[0].file_path`` extension.
        """
        evidence = None
        if hasattr(finding, "evidence") and finding.evidence:
            evidence = finding.evidence[0]
        elif isinstance(finding, dict):
            ev_list = finding.get("evidence", [])
            if ev_list:
                evidence = ev_list[0]

        # Detect language from file extension
        file_path = ""
        code_snippet = ""
        if evidence:
            file_path = getattr(evidence, "file_path", "") or (evidence.get("file_path", "") if isinstance(evidence, dict) else "")
            code_snippet = getattr(evidence, "code_snippet", "") or (evidence.get("code_snippet", "") if isinstance(evidence, dict) else "")

        language = _lang_from_path(file_path)

        # Get fix code
        fix_code = ""
        if hasattr(finding, "fix_code"):
            fix_code = finding.fix_code
        elif isinstance(finding, dict):
            fix_code = finding.get("fix_code", "")

        highlighted_code = self.highlight(code_snippet, language)
        highlighted_fix = self.highlight_fix(fix_code, language) if fix_code else ""

        return highlighted_code, highlighted_fix

    @staticmethod
    def _get_lexer(language: str, code: str, get_by_name: Any, guess: Any) -> Any:
        """Get a Pygments lexer by name or guess from code."""
        if language:
            try:
                return get_by_name(language)
            except Exception:
                pass
        try:
            return guess(code)
        except Exception:
            return get_by_name("text")
