"""Interactive HTML report with sortable tables, collapsible findings, search/filter.

Extends the PDF renderer output with JavaScript for interactivity.
The PDF version is static; the HTML version adds:
- Navigation bar with section anchors
- Search bar to filter findings by text
- Severity filter buttons
- Collapsible finding cards (click header to expand/collapse)
- Sortable tables (click column header)
"""

from __future__ import annotations

from pathlib import Path

import structlog

from blanketaudit2.report.pdf_generator import PDFReportGenerator

logger = structlog.get_logger()

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class HTMLGenerator:
    """Generate an interactive standalone HTML report."""

    def __init__(self, templates_dir: str | Path | None = None) -> None:
        self._templates_dir = Path(templates_dir) if templates_dir else _TEMPLATES_DIR
        self._renderer = PDFReportGenerator(self._templates_dir)

    def generate(self, report: dict) -> str:
        """Render the full interactive HTML report.

        Injects JavaScript for search, filter, sort, and collapse.
        """
        base_html = self._renderer.render_html(report)

        # Load the interactive template (JS + CSS)
        interactive_path = self._templates_dir / "interactive.html"
        interactive_block = ""
        if interactive_path.exists():
            interactive_block = interactive_path.read_text(encoding="utf-8")

        # Inject interactive block before </body>
        if interactive_block and "</body>" in base_html:
            html = base_html.replace("</body>", f"\n{interactive_block}\n</body>")
        else:
            html = base_html

        # Override @page CSS for screen (no print margins, scrollable)
        screen_css = """
<style media="screen">
  @page { margin: 0; }
  .section { page-break-before: auto; }
  body { max-width: 900px; margin: 0 auto; padding: 20px 20px 60px 20px; }
</style>
"""
        if "</head>" in html:
            html = html.replace("</head>", f"{screen_css}</head>")

        return html

    def generate_to_file(self, report: dict, output_path: str | Path) -> Path:
        """Generate interactive HTML and write to a file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        html_str = self.generate(report)
        output_path.write_text(html_str, encoding="utf-8")
        logger.info("report.html_saved", path=str(output_path), interactive=True)
        return output_path
