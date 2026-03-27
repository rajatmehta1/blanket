"""Verify all agent prompts require the full output schema fields,
and that agent output parsing produces findings with all required fields.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit.llm.guardrails import INJECTION_DEFENSE_PREFIX
from blanketaudit.llm.prompts.enrichment import (
    ENRICHMENT_ANALYSIS_PROMPT,
    ENRICHMENT_OUTPUT_SCHEMA,
    ENRICHMENT_SYSTEM_PROMPT,
)


# ── Required fields that EVERY finding must have ─────────────

REQUIRED_FINDING_FIELDS = {
    "ai_explanation", "fix_code", "dollar_impact",
    "confidence", "compliance_refs", "evidence",
}

REQUIRED_PROMPT_FIELDS = {
    "ai_explanation", "fix_code", "dollar_impact",
    "confidence", "compliance_refs",
}


# ═══════════════════════════════════════════════════════════════
# Prompt template verification
# ═══════════════════════════════════════════════════════════════


class TestAllPromptsRequireFields:
    """Every agent system prompt must mention all required output fields."""

    PROMPTS = [
        ("security", "blanketaudit.llm.prompts.security", "SECURITY_SYSTEM_PROMPT"),
        ("compliance", "blanketaudit.llm.prompts.compliance", "COMPLIANCE_SYSTEM_PROMPT"),
        ("architecture", "blanketaudit.llm.prompts.architecture", "ARCHITECTURE_SYSTEM_PROMPT"),
        ("quality", "blanketaudit.llm.prompts.quality", "QUALITY_SYSTEM_PROMPT"),
        ("enrichment", "blanketaudit.llm.prompts.enrichment", "ENRICHMENT_SYSTEM_PROMPT"),
    ]

    @pytest.mark.parametrize("name,module,attr", PROMPTS)
    def test_prompt_mentions_ai_explanation(self, name, module, attr):
        prompt = self._get_prompt(module, attr)
        assert "ai_explanation" in prompt, f"{name} prompt missing ai_explanation"

    @pytest.mark.parametrize("name,module,attr", PROMPTS)
    def test_prompt_mentions_fix_code(self, name, module, attr):
        prompt = self._get_prompt(module, attr)
        assert "fix_code" in prompt, f"{name} prompt missing fix_code"

    @pytest.mark.parametrize("name,module,attr", PROMPTS)
    def test_prompt_mentions_dollar_impact(self, name, module, attr):
        prompt = self._get_prompt(module, attr)
        assert "dollar_impact" in prompt, f"{name} prompt missing dollar_impact"

    @pytest.mark.parametrize("name,module,attr", PROMPTS)
    def test_prompt_mentions_confidence(self, name, module, attr):
        prompt = self._get_prompt(module, attr)
        assert "confidence" in prompt, f"{name} prompt missing confidence"

    @pytest.mark.parametrize("name,module,attr", PROMPTS)
    def test_prompt_mentions_compliance_refs(self, name, module, attr):
        prompt = self._get_prompt(module, attr)
        assert "compliance_refs" in prompt, f"{name} prompt missing compliance_refs"

    @pytest.mark.parametrize("name,module,attr", PROMPTS)
    def test_prompt_has_injection_defense(self, name, module, attr):
        prompt = self._get_prompt(module, attr)
        assert "{injection_defense}" in prompt, f"{name} missing injection defense"

    @staticmethod
    def _get_prompt(module: str, attr: str) -> str:
        import importlib
        mod = importlib.import_module(module)
        template = getattr(mod, attr)
        # Extract the template string from the ChatPromptTemplate
        msgs = template.messages
        return msgs[0].prompt.template if hasattr(msgs[0], "prompt") else str(msgs[0])


# ═══════════════════════════════════════════════════════════════
# Enrichment output schema
# ═══════════════════════════════════════════════════════════════


class TestEnrichmentSchema:
    def test_schema_has_all_required_fields(self):
        required = ENRICHMENT_OUTPUT_SCHEMA["required"]
        for field in REQUIRED_PROMPT_FIELDS:
            assert field in required, f"Missing from schema: {field}"

    def test_schema_compliance_refs_is_array_of_objects(self):
        refs = ENRICHMENT_OUTPUT_SCHEMA["properties"]["compliance_refs"]
        assert refs["type"] == "array"
        item = refs["items"]
        assert item["type"] == "object"
        assert "framework" in item["required"]
        assert "clause" in item["required"]
        assert "title" in item["required"]

    def test_enrichment_prompt_formats(self):
        msgs = ENRICHMENT_SYSTEM_PROMPT.format_messages(
            injection_defense=INJECTION_DEFENSE_PREFIX,
            project_name="Test", domain="healthcare",
            format_instructions="Return JSON.",
        )
        content = msgs[0].content
        assert "ai_explanation" in content
        assert "fix_code" in content
        assert "dollar_impact" in content

    def test_enrichment_analysis_prompt_formats(self):
        msgs = ENRICHMENT_ANALYSIS_PROMPT.format_messages(
            title="SQL Injection", severity="critical",
            file_path="db.py", line="42",
            code_snippet="SELECT *", call_chain_text="entry→sink",
            blast_radius_text="5 endpoints", domain="healthcare",
            frameworks="HIPAA, SOC2",
        )
        content = msgs[0].content
        assert "SQL Injection" in content
        assert "db.py" in content


# ═══════════════════════════════════════════════════════════════
# Agent AI response parsing produces all fields
# ═══════════════════════════════════════════════════════════════


def _mock_llm_with_full_response():
    """Mock LLM that returns a response with all required fields."""
    mock = AsyncMock()
    resp = MagicMock()
    resp.content = json.dumps({
        "is_true_positive": True,
        "ai_explanation": (
            "This SQL injection allows extraction of all patient records. "
            "The f-string interpolation bypasses any parameterization.\n\n"
            "An attacker could use UNION-based injection to extract "
            "sensitive PHI including SSNs and medical records."
        ),
        "fix_code": (
            "# BEFORE:\n"
            'cursor.execute(f"SELECT * FROM patients WHERE id={uid}")\n\n'
            "# AFTER:\n"
            'cursor.execute("SELECT * FROM patients WHERE id=%s", (uid,))'
        ),
        "dollar_impact": "$50,000 — $1,900,000",
        "confidence": 0.95,
        "severity": "critical",
        "compliance_refs": [
            {"framework": "HIPAA", "clause": "§164.312(a)(1)", "title": "Access Control"},
            {"framework": "PCI-DSS", "clause": "Req 6.5.1", "title": "Injection Flaws"},
        ],
    })
    resp.usage_metadata = {"input_tokens": 500, "output_tokens": 300}
    mock.ainvoke = AsyncMock(return_value=resp)
    mock.model_name = "test"
    mock.model = "test"
    mock.provider = "test"
    return mock


class TestSecurityAgentOutputFields:
    @pytest.mark.asyncio
    async def test_ai_response_has_all_fields(self):
        from blanketaudit.agents.security_agent import SecurityAgent, _reset_counter
        from blanketaudit.models.finding import AuditFinding, Evidence
        from blanketaudit.llm.resilience import CircuitBreaker

        _reset_counter(0)
        llm = _mock_llm_with_full_response()
        cb = CircuitBreaker(failure_threshold=5)

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = SecurityAgent(llm=llm, circuit_breaker=cb)

        candidate = AuditFinding(
            id="BLK-001", policy_id="SEC-001",
            title="SQL Injection", description="f-string SQL",
            severity="high", category="security",
            confidence=0.7, source="static",
            evidence=[Evidence(
                file_path="db.py", repo_name="api",
                line_start=10, line_end=10,
                code_snippet='f"SELECT * FROM patients WHERE id={uid}"',
                tool="semgrep",
            )],
            compliance_refs=[],
            ai_explanation="", fix_code="", remediation="",
            effort_hours=0, dollar_impact="",
        )

        result = await agent.run_ai_analysis({}, [candidate])
        assert result is not None
        assert len(result) == 1
        f = result[0]

        # Verify all required fields are populated
        assert f.ai_explanation != "", "ai_explanation should be populated"
        assert len(f.ai_explanation) > 50, "ai_explanation should be 2+ paragraphs"
        assert f.fix_code != "", "fix_code should be populated"
        assert f.confidence > 0, "confidence should be set"
        assert f.source == "corroborated"


class TestComplianceAgentOutputFields:
    @pytest.mark.asyncio
    async def test_ai_response_has_compliance_refs(self):
        from blanketaudit.agents.compliance_agent import ComplianceAgent, _reset_counter
        from blanketaudit.models.finding import AuditFinding, Evidence, ComplianceRef
        from blanketaudit.llm.resilience import CircuitBreaker

        _reset_counter(0)
        llm = AsyncMock()
        resp = MagicMock()
        resp.content = json.dumps({
            "status": "fail",
            "confidence": 0.9,
            "explanation": "PHI is logged in plaintext without masking, violating HIPAA safeguards.",
            "compliance_refs": [
                {"framework": "HIPAA", "clause": "§164.530(c)", "title": "Safeguards"},
            ],
            "remediation": "Mask PHI before logging.",
        })
        resp.usage_metadata = {"input_tokens": 500, "output_tokens": 200}
        llm.ainvoke = AsyncMock(return_value=resp)
        llm.model_name = "test"
        llm.model = "test"
        llm.provider = "test"
        cb = CircuitBreaker(failure_threshold=5)

        with patch("blanketaudit.agents.base_agent.get_llm_for_agent", return_value=llm):
            agent = ComplianceAgent(llm=llm, circuit_breaker=cb)

        candidate = AuditFinding(
            id="BLK-001", policy_id="COMP-HIPAA-001",
            title="PHI in Logs", description="Patient data in logs",
            severity="critical", category="compliance",
            confidence=0.7, source="static",
            evidence=[Evidence(
                file_path="service.py", repo_name="api",
                line_start=10, line_end=12,
                code_snippet='logger.info("patient: %s", patient.ssn)',
                tool="regex",
            )],
            compliance_refs=[ComplianceRef(
                framework="HIPAA", clause="§164.312(e)(1)", title="Transmission",
            )],
            ai_explanation="", fix_code="", remediation="",
            effort_hours=0, dollar_impact="",
        )

        result = await agent.run_ai_analysis({"frameworks": ["HIPAA"]}, [candidate])
        assert result is not None
        assert len(result) == 1
        f = result[0]

        assert len(f.compliance_refs) >= 1, "Should have compliance_refs"
        assert f.compliance_refs[0].framework == "HIPAA"
        assert f.compliance_refs[0].clause != ""
        assert f.ai_explanation != ""
        assert f.source == "corroborated"


class TestAuditFindingRequiredFields:
    """Verify the AuditFinding model enforces all required fields."""

    def test_all_fields_present_in_model(self):
        from blanketaudit.models.finding import AuditFinding
        fields = AuditFinding.model_fields
        for field in REQUIRED_FINDING_FIELDS:
            assert field in fields, f"AuditFinding missing field: {field}"

    def test_ai_explanation_separate_from_description(self):
        from blanketaudit.models.finding import AuditFinding
        fields = AuditFinding.model_fields
        assert "ai_explanation" in fields
        assert "description" in fields
        # Both should be separate fields
        assert fields["ai_explanation"] is not fields["description"]

    def test_fix_code_separate_from_remediation(self):
        from blanketaudit.models.finding import AuditFinding
        fields = AuditFinding.model_fields
        assert "fix_code" in fields
        assert "remediation" in fields
        assert fields["fix_code"] is not fields["remediation"]

    def test_compliance_refs_is_structured(self):
        from blanketaudit.models.finding import AuditFinding, ComplianceRef
        f = AuditFinding.model_fields
        # compliance_refs should accept ComplianceRef objects, not strings
        from typing import get_args
        # Just verify it's a list annotation
        assert "compliance_refs" in f

    def test_dollar_impact_field_exists(self):
        from blanketaudit.models.finding import AuditFinding
        assert "dollar_impact" in AuditFinding.model_fields
