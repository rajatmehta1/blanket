"""Finding enrichment prompt templates (design doc §5.5).

Used after initial analysis to enrich findings with ALL required fields:
ai_explanation (2+ paragraphs), fix_code (before/after), dollar_impact,
effort_hours, compliance_refs (structured), confidence.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

ENRICHMENT_SYSTEM_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "{injection_defense}\n\n"
     "You are a senior security architect enriching audit findings.\n"
     "Project: {project_name} | Domain: {domain}\n\n"
     "For each finding, you MUST provide ALL of the following fields:\n\n"
     "1. ai_explanation: 2-3 paragraphs explaining WHY this is dangerous\n"
     "   for THIS specific codebase. Include technical details, attack\n"
     "   scenarios, and business impact.\n\n"
     "2. fix_code: Complete before/after code block showing the exact fix.\n"
     "   Format: '# BEFORE:\\n<vulnerable code>\\n\\n# AFTER:\\n<fixed code>'\n\n"
     "3. dollar_impact: Specific financial risk range using regulatory data.\n"
     "   Healthcare: HIPAA fines $100-$50,000/violation, max $1.9M/year.\n"
     "   Finance: PCI-DSS $5K-$100K/month. SOX up to $5M.\n"
     "   General: breach avg $4.45M (IBM 2023), $165/record.\n\n"
     "4. effort_hours: Realistic engineering hours to implement the fix.\n\n"
     "5. compliance_refs: List of objects with framework, clause, title.\n"
     "   Only include controls you are CERTAIN apply. Use real IDs:\n"
     "   - HIPAA: §164.xxx (e.g., §164.312(a)(1))\n"
     "   - SOC2: CC criteria (e.g., CC6.1)\n"
     "   - PCI-DSS: Req numbers (e.g., Req 6.5.1)\n"
     "   - GDPR: Art. numbers (e.g., Art. 32)\n\n"
     "6. confidence: 0.0-1.0 (be honest — 0.6 is fine if uncertain)\n\n"
     "Return JSON matching this schema:\n"
     "{format_instructions}"),
])

ENRICHMENT_ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("human",
     "Finding: {title}\n"
     "Severity: {severity}\n"
     "File: {file_path}:{line}\n"
     "Code:\n```\n{code_snippet}\n```\n"
     "Call chain: {call_chain_text}\n"
     "Blast radius: {blast_radius_text}\n"
     "Domain: {domain}\n"
     "Active frameworks: {frameworks}\n\n"
     "Enrich this finding with all 6 required fields."),
])

# JSON schema for the enrichment output (used with PydanticOutputParser)
ENRICHMENT_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["ai_explanation", "fix_code", "dollar_impact", "effort_hours",
                  "compliance_refs", "confidence"],
    "properties": {
        "ai_explanation": {"type": "string", "minLength": 100,
                           "description": "2-3 paragraphs explaining the risk"},
        "fix_code": {"type": "string",
                     "description": "Before/after code block"},
        "dollar_impact": {"type": "string",
                          "description": "Financial risk range (e.g., '$10,000 — $500,000')"},
        "effort_hours": {"type": "number", "minimum": 0.5,
                         "description": "Engineering hours to fix"},
        "compliance_refs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["framework", "clause", "title"],
                "properties": {
                    "framework": {"type": "string"},
                    "clause": {"type": "string"},
                    "title": {"type": "string"},
                },
            },
        },
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
    },
}
