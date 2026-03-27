"""WeasyPrint HTML→PDF generation with dark theme.

INPUT: AuditReport dict (all data for the report)
OUTPUT: PDF bytes

Renders 9 section templates via Jinja2, combines into one HTML doc,
converts to PDF via WeasyPrint.  Falls back to HTML-only if WeasyPrint
is not installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from blanketaudit.report.svg_charts import SVGChartRenderer
from blanketaudit.report.syntax_highlighter import SyntaxHighlighter

logger = structlog.get_logger()

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_SECTION_TEMPLATES = [
    "cover.html",
    "executive_summary.html",
    "score_dashboard.html",
    "findings_detail.html",
    "compliance_matrix.html",
    "callgraph_summary.html",
    "infrastructure.html",
    "remediation.html",
    "benefits.html",
]


class PDFReportGenerator:
    """Generate dark-themed PDF report from an AuditReport dict."""

    def __init__(self, templates_dir: str | Path | None = None) -> None:
        self._templates_dir = Path(templates_dir) if templates_dir else _TEMPLATES_DIR
        self._svg = SVGChartRenderer()
        self._highlight = SyntaxHighlighter()
        self._env: Any = None

    def _get_env(self) -> Any:
        """Lazy-load Jinja2 environment."""
        if self._env is None:
            import jinja2
            self._env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(str(self._templates_dir)),
                autoescape=False,  # Templates embed SVG/HTML from our renderers
            )
        return self._env

    def render_html(self, report: dict) -> str:
        """Render the full HTML report (all 9 sections combined)."""
        env = self._get_env()

        # Render each section template
        sections_html: list[str] = []
        for template_name in _SECTION_TEMPLATES:
            try:
                template = env.get_template(template_name)
                section = template.render(
                    report=report,
                    svg=self._svg,
                    highlight=self._highlight,
                )
                sections_html.append(section)
            except Exception as exc:
                logger.warning(
                    "report.section_render_failed",
                    template=template_name,
                    error=str(exc)[:200],
                )
                sections_html.append(
                    f'<div class="section"><h2>Section Error</h2>'
                    f'<p class="muted">Failed to render {template_name}</p></div>'
                )

        # Combine with base layout
        base = env.get_template("base.html")
        full_html = base.render(
            sections=sections_html,
            report=report,
        )

        return full_html

    def generate(self, report: dict) -> bytes:
        """Render HTML and convert to PDF via WeasyPrint.

        Returns PDF bytes.  Raises ImportError if WeasyPrint is not installed.
        """
        html_str = self.render_html(report)

        try:
            import weasyprint
            pdf_bytes = weasyprint.HTML(
                string=html_str,
                base_url=str(self._templates_dir),
            ).write_pdf()
            logger.info("report.pdf_generated", size_bytes=len(pdf_bytes))
            return pdf_bytes
        except ImportError:
            raise ImportError(
                "WeasyPrint is not installed. Install with: pip install weasyprint"
            )

    def generate_to_file(self, report: dict, output_path: str | Path) -> Path:
        """Generate PDF and write to a file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        pdf_bytes = self.generate(report)
        output_path.write_bytes(pdf_bytes)
        logger.info("report.pdf_saved", path=str(output_path))
        return output_path
