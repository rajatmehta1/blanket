"""SVG gauge and bar chart generation (inline in HTML).

All charts are pure SVG strings — no JavaScript, no external deps.
WeasyPrint renders inline SVG natively.
"""

from __future__ import annotations

import math


def _grade_color(score: int) -> str:
    if score >= 85:
        return "#34d399"  # Green
    if score >= 70:
        return "#60a5fa"  # Blue
    if score >= 50:
        return "#fbbf24"  # Yellow
    if score >= 30:
        return "#f97316"  # Orange
    return "#ef4444"      # Red


def _severity_color(severity: str) -> str:
    return {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#fbbf24",
        "low": "#64748b",
    }.get(severity, "#64748b")


def _status_color(status: str) -> str:
    return {
        "pass": "#34d399",
        "fail": "#ef4444",
        "partial": "#fbbf24",
        "gap": "#f97316",
        "review_needed": "#60a5fa",
        "not_applicable": "#64748b",
    }.get(status, "#64748b")


class SVGChartRenderer:
    """Generate inline SVG charts for the report."""

    def score_gauge(self, score: int, size: int = 180, label: str = "") -> str:
        """Render a circular score gauge (0-100).

        Returns an SVG string with a partial circle arc + centered score text.
        """
        cx = size // 2
        cy = size // 2
        r = (size // 2) - 15
        stroke_width = 10
        circumference = 2 * math.pi * r
        filled = circumference * (score / 100)
        color = _grade_color(score)

        # Grade letter
        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

        return f"""<svg width="{size}" height="{size + 30}" xmlns="http://www.w3.org/2000/svg">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
    stroke="rgba(255,255,255,0.05)" stroke-width="{stroke_width}"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
    stroke="{color}" stroke-width="{stroke_width}"
    stroke-dasharray="{filled:.1f} {circumference:.1f}"
    stroke-linecap="round"
    transform="rotate(-90 {cx} {cy})"/>
  <text x="{cx}" y="{cy - 8}" text-anchor="middle"
    font-family="Sora,sans-serif" font-size="{size // 4}px"
    font-weight="800" fill="{color}">{score}</text>
  <text x="{cx}" y="{cy + size // 8}" text-anchor="middle"
    font-family="JetBrains Mono,monospace" font-size="{size // 10}px"
    fill="rgba(255,255,255,0.4)">Grade {grade}</text>
  {f'<text x="{cx}" y="{size + 18}" text-anchor="middle" font-family="Sora,sans-serif" font-size="10px" fill="rgba(255,255,255,0.3)">{label}</text>' if label else ''}
</svg>"""

    def category_bars(self, categories: list[dict]) -> str:
        """Render horizontal bar chart for category scores.

        Each category gets a colored bar proportional to its score.
        """
        bar_height = 24
        label_width = 180
        bar_max = 280
        gap = 8
        total_height = len(categories) * (bar_height + gap) + 10

        bars = []
        for i, cat in enumerate(categories):
            name = cat.get("name", "")
            score = cat.get("score", 0)
            count = cat.get("finding_count", 0)
            color = _grade_color(score)
            y = i * (bar_height + gap) + 5
            bar_width = max(2, int(bar_max * score / 100))

            bars.append(f"""  <text x="0" y="{y + 16}" font-family="Sora,sans-serif"
    font-size="9px" fill="rgba(255,255,255,0.6)">{name}</text>
  <rect x="{label_width}" y="{y}" width="{bar_width}" height="{bar_height}"
    rx="4" fill="{color}" opacity="0.8"/>
  <text x="{label_width + bar_width + 8}" y="{y + 16}"
    font-family="JetBrains Mono,monospace" font-size="10px"
    fill="{color}" font-weight="700">{score}</text>
  <text x="{label_width + bar_max + 40}" y="{y + 16}"
    font-family="JetBrains Mono,monospace" font-size="9px"
    fill="rgba(255,255,255,0.3)">{count} findings</text>""")

        return f"""<svg width="540" height="{total_height}" xmlns="http://www.w3.org/2000/svg">
{''.join(bars)}
</svg>"""

    def severity_badges(self, counts: dict[str, int]) -> str:
        """Render inline severity count badges."""
        badges = []
        x = 0
        for sev in ("critical", "high", "medium", "low"):
            count = counts.get(sev, 0)
            if count == 0:
                continue
            color = _severity_color(sev)
            w = max(60, len(f"{count} {sev}") * 8 + 20)
            badges.append(
                f'<rect x="{x}" y="0" width="{w}" height="26" rx="13" '
                f'fill="{color}" opacity="0.15"/>'
                f'<text x="{x + w // 2}" y="17" text-anchor="middle" '
                f'font-family="JetBrains Mono,monospace" font-size="10px" '
                f'fill="{color}" font-weight="700">{count} {sev}</text>'
            )
            x += w + 8

        return f'<svg width="{x}" height="30" xmlns="http://www.w3.org/2000/svg">{"".join(badges)}</svg>'
