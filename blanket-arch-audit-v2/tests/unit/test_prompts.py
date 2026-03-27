"""Tests for blanketaudit.llm.prompts — verify all prompt templates format correctly."""

from __future__ import annotations

import pytest

from blanketaudit.llm.guardrails import INJECTION_DEFENSE_PREFIX
from blanketaudit.llm.prompts.security import (
    SECURITY_ANALYSIS_PROMPT,
    SECURITY_SYSTEM_PROMPT,
)
from blanketaudit.llm.prompts.compliance import (
    COMPLIANCE_ANALYSIS_PROMPT,
    COMPLIANCE_SYSTEM_PROMPT,
)
from blanketaudit.llm.prompts.architecture import (
    ARCHITECTURE_ANALYSIS_PROMPT,
    ARCHITECTURE_SYSTEM_PROMPT,
)
from blanketaudit.llm.prompts.quality import (
    QUALITY_ANALYSIS_PROMPT,
    QUALITY_SYSTEM_PROMPT,
)
from blanketaudit.llm.prompts.enrichment import (
    ENRICHMENT_ANALYSIS_PROMPT,
    ENRICHMENT_SYSTEM_PROMPT,
)
from blanketaudit.llm.prompts.executive_summary import (
    EXECUTIVE_SUMMARY_ANALYSIS_PROMPT,
    EXECUTIVE_SUMMARY_SYSTEM_PROMPT,
)


# ── Shared fixtures ──────────────────────────────────────────


COMMON_VARS = {
    "injection_defense": INJECTION_DEFENSE_PREFIX,
    "project_name": "TestProject",
    "domain": "healthcare",
    "format_instructions": "Return JSON matching the schema.",
}

SECURITY_VARS = {
    **COMMON_VARS,
    "repo_count": "3",
}

COMPLIANCE_VARS = {
    **COMMON_VARS,
    "frameworks": "HIPAA, SOC2",
}

ARCHITECTURE_VARS = {
    **COMMON_VARS,
    "repo_count": "3",
}

QUALITY_VARS = {
    **COMMON_VARS,
    "repo_count": "3",
}

ANALYSIS_VARS = {
    "file_path": "src/main.py",
    "language": "python",
    "static_results": "No findings.",
    "code_content": "<untrusted_code>print('hi')</untrusted_code>",
    "call_graph_context": "No cross-repo calls.",
    "data_flow_context": "No sensitive data flows.",
    "dependency_graph": "main.py -> utils.py",
    "dead_code_context": "No dead code.",
}


# ── Helpers ──────────────────────────────────────────────────


def _format_system(template, variables: dict) -> str:
    """Format a system prompt template and return the system message content."""
    messages = template.format_messages(**variables)
    assert len(messages) == 1
    return messages[0].content


def _format_human(template, variables: dict) -> str:
    """Format a human prompt template and return the human message content."""
    messages = template.format_messages(**variables)
    assert len(messages) == 1
    return messages[0].content


# ── Security prompts ─────────────────────────────────────────


class TestSecurityPrompts:
    def test_system_prompt_formats(self):
        content = _format_system(SECURITY_SYSTEM_PROMPT, SECURITY_VARS)
        assert "UNTRUSTED USER DATA" in content
        assert "TestProject" in content
        assert "healthcare" in content
        assert "Return JSON" in content

    def test_system_prompt_has_workflow(self):
        content = _format_system(SECURITY_SYSTEM_PROMPT, SECURITY_VARS)
        assert "static analysis" in content.lower()
        assert "false positive" in content.lower()

    def test_system_prompt_requires_evidence(self):
        content = _format_system(SECURITY_SYSTEM_PROMPT, SECURITY_VARS)
        assert "file_path" in content
        assert "line_start" in content
        assert "confidence" in content

    def test_analysis_prompt_formats(self):
        content = _format_human(SECURITY_ANALYSIS_PROMPT, ANALYSIS_VARS)
        assert "src/main.py" in content
        assert "python" in content


# ── Compliance prompts ───────────────────────────────────────


class TestCompliancePrompts:
    def test_system_prompt_formats(self):
        content = _format_system(COMPLIANCE_SYSTEM_PROMPT, COMPLIANCE_VARS)
        assert "UNTRUSTED USER DATA" in content
        assert "HIPAA, SOC2" in content
        assert "compliance" in content.lower()

    def test_system_prompt_has_control_id_guidance(self):
        content = _format_system(COMPLIANCE_SYSTEM_PROMPT, COMPLIANCE_VARS)
        assert "§164" in content  # HIPAA
        assert "CC6" in content  # SOC2

    def test_system_prompt_warns_against_invented_ids(self):
        content = _format_system(COMPLIANCE_SYSTEM_PROMPT, COMPLIANCE_VARS)
        assert "NEVER invent" in content

    def test_analysis_prompt_formats(self):
        content = _format_human(COMPLIANCE_ANALYSIS_PROMPT, ANALYSIS_VARS)
        assert "src/main.py" in content


# ── Architecture prompts ─────────────────────────────────────


class TestArchitecturePrompts:
    def test_system_prompt_formats(self):
        content = _format_system(ARCHITECTURE_SYSTEM_PROMPT, ARCHITECTURE_VARS)
        assert "UNTRUSTED USER DATA" in content
        assert "architect" in content.lower()

    def test_system_prompt_covers_patterns(self):
        content = _format_system(ARCHITECTURE_SYSTEM_PROMPT, ARCHITECTURE_VARS)
        assert "circular" in content.lower()
        assert "layer" in content.lower()
        assert "dead code" in content.lower()

    def test_analysis_prompt_formats(self):
        content = _format_human(ARCHITECTURE_ANALYSIS_PROMPT, ANALYSIS_VARS)
        assert "src/main.py" in content
        assert "dependency_graph" not in content  # Variable should be substituted.


# ── Quality prompts ──────────────────────────────────────────


class TestQualityPrompts:
    def test_system_prompt_formats(self):
        content = _format_system(QUALITY_SYSTEM_PROMPT, QUALITY_VARS)
        assert "UNTRUSTED USER DATA" in content
        assert "quality" in content.lower()

    def test_system_prompt_covers_metrics(self):
        content = _format_system(QUALITY_SYSTEM_PROMPT, QUALITY_VARS)
        assert "complexity" in content.lower()
        assert "coverage" in content.lower()

    def test_analysis_prompt_formats(self):
        content = _format_human(QUALITY_ANALYSIS_PROMPT, ANALYSIS_VARS)
        assert "src/main.py" in content


# ── Enrichment prompts ───────────────────────────────────────


ENRICHMENT_VARS = {
    **COMMON_VARS,
}

ENRICHMENT_ANALYSIS_VARS = {
    "title": "SQL Injection",
    "severity": "critical",
    "file_path": "src/db.py",
    "line": "42",
    "code_snippet": 'f"SELECT * FROM users"',
    "call_chain_text": "entry→method→sink",
    "blast_radius_text": "5 entry points, 2 repos",
    "domain": "healthcare",
    "frameworks": "HIPAA, SOC2",
}


class TestEnrichmentPrompts:
    def test_system_prompt_formats(self):
        content = _format_system(ENRICHMENT_SYSTEM_PROMPT, ENRICHMENT_VARS)
        assert "UNTRUSTED USER DATA" in content
        assert "dollar_impact" in content

    def test_system_prompt_has_domain_guidance(self):
        content = _format_system(ENRICHMENT_SYSTEM_PROMPT, ENRICHMENT_VARS)
        assert "HIPAA" in content
        assert "PCI-DSS" in content

    def test_analysis_prompt_formats(self):
        content = _format_human(ENRICHMENT_ANALYSIS_PROMPT, ENRICHMENT_ANALYSIS_VARS)
        assert "SQL Injection" in content
        assert "src/db.py" in content
        assert "healthcare" in content


# ── Executive summary prompts ────────────────────────────────


EXEC_VARS = {
    **COMMON_VARS,
}

EXEC_ANALYSIS_VARS = {
    "health_score": "31",
    "grade": "F",
    "severity_counts": "critical: 7, high: 19, medium: 28, low: 31",
    "frameworks": "HIPAA, SOC2",
    "critical_findings": "BLK-001: SQL Injection in patient search",
    "compliance_summary": "HIPAA: 5 FAIL, 3 PARTIAL, 2 PASS",
}


class TestExecutiveSummaryPrompts:
    def test_system_prompt_formats(self):
        content = _format_system(EXECUTIVE_SUMMARY_SYSTEM_PROMPT, EXEC_VARS)
        assert "UNTRUSTED USER DATA" in content
        assert "executive summary" in content.lower()
        assert "paragraphs" in content

    def test_system_prompt_requires_actions(self):
        content = _format_system(EXECUTIVE_SUMMARY_SYSTEM_PROMPT, EXEC_VARS)
        assert "immediate_actions" in content

    def test_analysis_prompt_formats(self):
        content = _format_human(
            EXECUTIVE_SUMMARY_ANALYSIS_PROMPT, EXEC_ANALYSIS_VARS
        )
        assert "31" in content
        assert "Grade: F" in content
        assert "BLK-001" in content


# ── Cross-cutting checks ────────────────────────────────────


ALL_SYSTEM_PROMPTS = [
    ("security", SECURITY_SYSTEM_PROMPT, SECURITY_VARS),
    ("compliance", COMPLIANCE_SYSTEM_PROMPT, COMPLIANCE_VARS),
    ("architecture", ARCHITECTURE_SYSTEM_PROMPT, ARCHITECTURE_VARS),
    ("quality", QUALITY_SYSTEM_PROMPT, QUALITY_VARS),
    ("enrichment", ENRICHMENT_SYSTEM_PROMPT, ENRICHMENT_VARS),
    ("executive_summary", EXECUTIVE_SUMMARY_SYSTEM_PROMPT, EXEC_VARS),
]


class TestAllPromptsCrossCutting:
    @pytest.mark.parametrize("name,template,variables", ALL_SYSTEM_PROMPTS)
    def test_injection_defense_present(self, name, template, variables):
        content = _format_system(template, variables)
        assert "UNTRUSTED USER DATA" in content, f"{name} missing injection defense"

    @pytest.mark.parametrize("name,template,variables", ALL_SYSTEM_PROMPTS)
    def test_format_instructions_present(self, name, template, variables):
        content = _format_system(template, variables)
        assert "Return JSON" in content, f"{name} missing format instructions"

    @pytest.mark.parametrize("name,template,variables", ALL_SYSTEM_PROMPTS)
    def test_project_name_substituted(self, name, template, variables):
        content = _format_system(template, variables)
        assert "TestProject" in content, f"{name} missing project name"

    @pytest.mark.parametrize("name,template,variables", ALL_SYSTEM_PROMPTS)
    def test_prompt_under_token_limit(self, name, template, variables):
        """All system prompts should be under ~1500 tokens (~6000 chars)."""
        content = _format_system(template, variables)
        assert len(content) < 6000, (
            f"{name} prompt is {len(content)} chars — may exceed 1500 tokens"
        )
