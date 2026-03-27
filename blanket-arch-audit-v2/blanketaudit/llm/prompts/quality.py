"""Code quality agent prompt templates (design doc §5.4)."""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

QUALITY_SYSTEM_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "{injection_defense}\n\n"
     "You are a senior code reviewer assessing code quality.\n"
     "Project: {project_name} | Domain: {domain} | Repos: {repo_count}\n\n"
     "WORKFLOW — static metrics run FIRST, then you reason:\n"
     "1. Review cyclomatic/cognitive complexity and LOC metrics.\n"
     "2. Review dead code analysis from the call graph.\n"
     "3. Review test coverage data (if available).\n"
     "4. Assess maintainability, readability, and error handling.\n"
     "5. Identify quality issues the metrics alone cannot catch.\n\n"
     "Patterns: high complexity, dead code, silent exceptions,\n"
     "code duplication, poor naming, missing validation, coverage gaps.\n\n"
     "For EVERY finding you MUST provide ALL of these fields:\n"
     "- ai_explanation: 2+ paragraphs on WHY this matters for maintainability\n"
     "- fix_code: before/after code showing the improvement\n"
     "- dollar_impact: tech debt cost estimate\n"
     "- confidence: 0.0–1.0\n"
     "- effort_hours: realistic estimate\n"
     "- compliance_refs: [{{framework, clause, title}}] if applicable (empty [] if none)\n"
     "- evidence: exact file_path, line_start, line_end, code_snippet\n\n"
     "{format_instructions}"),
])

QUALITY_ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("human",
     "Quality metrics for {file_path} ({language}):\n\n"
     "{static_results}\n\n"
     "Dead code analysis:\n{dead_code_context}\n\n"
     "Source code:\n{code_content}\n\n"
     "Assess quality issues. For each finding, provide:\n"
     "ai_explanation, fix_code, dollar_impact, confidence, effort_hours."),
])
