"""Executive summary generation prompt templates (design doc §5.6).

Generates the 2-paragraph executive summary and immediate action items
for Section 2 of the report.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

EXECUTIVE_SUMMARY_SYSTEM_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "{injection_defense}\n\n"
     "You are a technical writer producing an executive summary for an audit report.\n"
     "Project: {project_name} | Domain: {domain}\n\n"
     "You will receive the aggregated audit results. Produce:\n\n"
     "1. paragraphs: exactly 2 paragraphs (as a JSON list of strings).\n"
     "   - Paragraph 1: overall assessment — health score, critical finding count, "
     "     compliance posture. Written for a CTO or VP of Engineering.\n"
     "   - Paragraph 2: key risk areas and recommended priorities. Mention specific "
     "     findings by ID (e.g., BLK-001) when referencing critical issues.\n\n"
     "2. immediate_actions: 3–5 numbered action items that must be addressed within "
     "   48 hours. Each item should be a single concrete sentence.\n\n"
     "Style: professional, concise, no marketing language. Use specific numbers "
     "(\"7 critical findings\", \"score of 31/100\") not vague qualifiers.\n\n"
     "{format_instructions}"),
])

EXECUTIVE_SUMMARY_ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("human",
     "Audit results summary:\n\n"
     "Health score: {health_score}/100 (Grade: {grade})\n"
     "Severity counts: {severity_counts}\n"
     "Active frameworks: {frameworks}\n\n"
     "Top critical findings:\n{critical_findings}\n\n"
     "Compliance matrix summary:\n{compliance_summary}\n\n"
     "Generate the executive summary and immediate actions."),
])
