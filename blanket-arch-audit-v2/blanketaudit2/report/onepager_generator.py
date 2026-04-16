"""Board-ready Executive One-Pager PDF generator.

Produces a 1-2 page PDF that a non-technical executive can read in
under 2 minutes.  Includes: health score gauge, category bars, top 5
findings, compliance posture, remediation roadmap summary, and ROI box.

Usage::

    from blanketaudit2.report.onepager_generator import generate_executive_onepager
    pdf_bytes = generate_executive_onepager(report_dict)
    Path("executive_brief.pdf").write_bytes(pdf_bytes)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_executive_onepager(
    report: dict,
    output_path: str | Path | None = None,
) -> bytes:
    """Generate the board-ready executive one-pager PDF.

    Parameters
    ----------
    report:
        The full AuditReport dict (same data used for the main report).
    output_path:
        Optional path to write the PDF file.  If None, only returns bytes.

    Returns
    -------
    PDF content as bytes.
    """
    from jinja2 import Environment, FileSystemLoader

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("executive_onepager.html")

    # Prepare top findings: critical + high, sorted by severity then effort
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings = report.get("findings", [])
    top_findings = sorted(
        all_findings,
        key=lambda f: (
            severity_order.get(f.get("severity", "low") if isinstance(f, dict) else getattr(f, "severity", "low"), 4),
            -(f.get("effort_hours", 0) if isinstance(f, dict) else getattr(f, "effort_hours", 0)),
        ),
    )[:10]

    # Convert dicts to namespace objects for dot-access in Jinja2
    top_findings_objs = [_DictNamespace(f) if isinstance(f, dict) else f for f in top_findings]

    # Health score
    hs = report.get("health_score", {})
    if isinstance(hs, dict):
        hs_obj = _DictNamespace(hs)
        hs_obj.categories = [_DictNamespace(c) for c in hs.get("categories", [])]
        hs_obj.severity_counts = hs.get("severity_counts", {})
    else:
        hs_obj = hs

    # Executive summary
    es = report.get("executive_summary", {})
    es_obj = _DictNamespace(es) if isinstance(es, dict) else es

    # Compliance matrix
    cm = report.get("compliance_matrix", [])
    cm_objs = []
    for m in cm:
        if isinstance(m, dict):
            m_obj = _DictNamespace(m)
            m_obj.sections = [_DictNamespace(s) for s in m.get("sections", [])]
            cm_objs.append(m_obj)
        else:
            cm_objs.append(m)

    # Remediation phases
    rp = report.get("remediation_phases", [])
    rp_objs = [_DictNamespace(p) if isinstance(p, dict) else p for p in rp]
    for rp_obj in rp_objs:
        if isinstance(rp_obj, _DictNamespace):
            rp_obj.items = rp_obj._data.get("items", [])

    context = {
        "project_name": report.get("project_name", "Unknown"),
        "project_tagline": report.get("project_tagline", ""),
        "scan_date": report.get("scan_date", ""),
        "scan_duration": report.get("scan_duration", ""),
        "total_files": report.get("total_files", 0),
        "total_lines": report.get("total_lines", "0"),
        "repos": report.get("repos", []),
        "health_score": hs_obj,
        "executive_summary": es_obj,
        "findings": all_findings,
        "top_findings": top_findings_objs,
        "compliance_matrix": cm_objs,
        "remediation_phases": rp_objs,
        "llm_provider": report.get("llm_provider", ""),
        "llm_model": report.get("llm_model", ""),
    }

    html_content = template.render(**context)

    # Render to PDF via WeasyPrint
    pdf_bytes = _render_pdf(html_content)

    if output_path:
        output_path = Path(output_path)
        output_path.write_bytes(pdf_bytes)
        logger.info("onepager.written", path=str(output_path), size=len(pdf_bytes))

    return pdf_bytes


def generate_executive_onepager_html(report: dict) -> str:
    """Generate the one-pager as standalone HTML (fallback if no WeasyPrint)."""
    from jinja2 import Environment, FileSystemLoader

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("executive_onepager.html")

    hs = report.get("health_score", {})
    if isinstance(hs, dict):
        hs_obj = _DictNamespace(hs)
        hs_obj.categories = [_DictNamespace(c) for c in hs.get("categories", [])]
        hs_obj.severity_counts = hs.get("severity_counts", {})
    else:
        hs_obj = hs

    es = report.get("executive_summary", {})
    es_obj = _DictNamespace(es) if isinstance(es, dict) else es

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings = report.get("findings", [])
    top_findings = sorted(
        all_findings,
        key=lambda f: severity_order.get(f.get("severity", "low") if isinstance(f, dict) else getattr(f, "severity", "low"), 4),
    )[:10]
    top_findings_objs = [_DictNamespace(f) if isinstance(f, dict) else f for f in top_findings]

    cm = report.get("compliance_matrix", [])
    cm_objs = []
    for m in cm:
        if isinstance(m, dict):
            m_obj = _DictNamespace(m)
            m_obj.sections = [_DictNamespace(s) for s in m.get("sections", [])]
            cm_objs.append(m_obj)
        else:
            cm_objs.append(m)

    rp = report.get("remediation_phases", [])
    rp_objs = [_DictNamespace(p) if isinstance(p, dict) else p for p in rp]
    for rp_obj in rp_objs:
        if isinstance(rp_obj, _DictNamespace):
            rp_obj.items = rp_obj._data.get("items", [])

    context = {
        "project_name": report.get("project_name", "Unknown"),
        "project_tagline": report.get("project_tagline", ""),
        "scan_date": report.get("scan_date", ""),
        "scan_duration": report.get("scan_duration", ""),
        "total_files": report.get("total_files", 0),
        "total_lines": report.get("total_lines", "0"),
        "repos": report.get("repos", []),
        "health_score": hs_obj,
        "executive_summary": es_obj,
        "findings": all_findings,
        "top_findings": top_findings_objs,
        "compliance_matrix": cm_objs,
        "remediation_phases": rp_objs,
        "llm_provider": report.get("llm_provider", ""),
        "llm_model": report.get("llm_model", ""),
    }

    return template.render(**context)


def _render_pdf(html_content: str) -> bytes:
    """Render HTML to PDF using WeasyPrint, falling back to xhtml2pdf."""
    # Try WeasyPrint first
    try:
        from weasyprint import HTML
        return HTML(string=html_content).write_pdf()
    except (ImportError, OSError) as exc:
        logger.warning("onepager.weasyprint_unavailable", error=str(exc)[:150])

    # Fallback: xhtml2pdf (pure Python, no native dependencies)
    try:
        from io import BytesIO
        from xhtml2pdf import pisa

        buf = BytesIO()
        pisa.CreatePDF(html_content, dest=buf)
        pdf_bytes = buf.getvalue()
        logger.info("onepager.pdf_generated", renderer="xhtml2pdf", size=len(pdf_bytes))
        return pdf_bytes
    except ImportError:
        logger.warning("onepager.no_pdf_renderer", fallback="html")
        return html_content.encode("utf-8")


class _DictNamespace:
    """Lightweight dict wrapper that enables dot-access for Jinja2 templates."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return super().__getattribute__(name)
        return self._data.get(name, "")

    def __getitem__(self, key: str) -> Any:
        return self._data.get(key, "")

    def get(self, key: str, default: Any = "") -> Any:
        return self._data.get(key, default)

    def __bool__(self) -> bool:
        return bool(self._data)

    def __repr__(self) -> str:
        return f"_DictNamespace({self._data})"
