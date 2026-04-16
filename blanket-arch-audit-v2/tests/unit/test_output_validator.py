"""Tests for blanketaudit2.llm.output_validator."""

from __future__ import annotations

import json
from typing import Literal
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import BaseModel

from blanketaudit2.llm.output_validator import (
    OutputValidator,
    _extract_json,
    parse_llm_output,
)


# ── Test models ──────────────────────────────────────────────


class SimpleModel(BaseModel):
    name: str
    score: int


class StrictModel(BaseModel):
    id: str
    severity: Literal["critical", "high", "medium", "low"]
    confidence: float


# ── _extract_json ────────────────────────────────────────────


class TestExtractJson:
    def test_bare_object(self):
        raw = '{"name": "test", "score": 42}'
        assert json.loads(_extract_json(raw)) == {"name": "test", "score": 42}

    def test_bare_array(self):
        raw = '[1, 2, 3]'
        assert json.loads(_extract_json(raw)) == [1, 2, 3]

    def test_markdown_fenced_json(self):
        raw = 'Here is the result:\n```json\n{"name": "test", "score": 42}\n```\nDone.'
        assert json.loads(_extract_json(raw)) == {"name": "test", "score": 42}

    def test_markdown_fenced_no_lang(self):
        raw = '```\n{"name": "x", "score": 1}\n```'
        assert json.loads(_extract_json(raw)) == {"name": "x", "score": 1}

    def test_json_embedded_in_prose(self):
        raw = 'The analysis found: {"name": "vuln", "score": 99} which is critical.'
        assert json.loads(_extract_json(raw)) == {"name": "vuln", "score": 99}

    def test_nested_braces(self):
        raw = '{"outer": {"inner": 1}, "list": [1, 2]}'
        parsed = json.loads(_extract_json(raw))
        assert parsed["outer"]["inner"] == 1
        assert parsed["list"] == [1, 2]

    def test_strings_with_braces(self):
        raw = '{"msg": "use {name} placeholder"}'
        parsed = json.loads(_extract_json(raw))
        assert parsed["msg"] == "use {name} placeholder"

    def test_no_json_returns_original(self):
        raw = "No JSON here at all."
        assert _extract_json(raw) == raw


# ── parse_llm_output (sync, no correction) ───────────────────


class TestParseLlmOutput:
    def test_valid_json(self):
        raw = '{"name": "test", "score": 42}'
        result = parse_llm_output(raw, SimpleModel)
        assert result is not None
        assert result.name == "test"
        assert result.score == 42

    def test_json_in_markdown_fence(self):
        raw = '```json\n{"name": "fenced", "score": 7}\n```'
        result = parse_llm_output(raw, SimpleModel)
        assert result is not None
        assert result.name == "fenced"

    def test_invalid_json_returns_none(self):
        result = parse_llm_output("not json at all {{{", SimpleModel)
        assert result is None

    def test_schema_violation_returns_none(self):
        # Missing required field "score".
        result = parse_llm_output('{"name": "oops"}', SimpleModel)
        assert result is None

    def test_strict_enum_validation(self):
        raw = '{"id": "BLK-001", "severity": "critical", "confidence": 0.95}'
        result = parse_llm_output(raw, StrictModel)
        assert result is not None
        assert result.severity == "critical"

    def test_strict_enum_invalid_returns_none(self):
        raw = '{"id": "BLK-001", "severity": "catastrophic", "confidence": 0.95}'
        result = parse_llm_output(raw, StrictModel)
        assert result is None


# ── OutputValidator (async with correction cycle) ────────────


def _make_mock_llm(response_text: str) -> AsyncMock:
    """Create a mock LLM that returns *response_text* from ainvoke."""
    mock_llm = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = response_text
    mock_llm.ainvoke.return_value = mock_response
    return mock_llm


class TestOutputValidator:
    @pytest.mark.asyncio
    async def test_valid_on_first_attempt(self):
        mock_llm = _make_mock_llm("")  # Should not be called.
        validator = OutputValidator(mock_llm)

        raw = '{"name": "pass", "score": 100}'
        result = await validator.validate_and_correct(raw, SimpleModel)

        assert result is not None
        assert result.name == "pass"
        assert result.score == 100
        mock_llm.ainvoke.assert_not_called()

    @pytest.mark.asyncio
    async def test_correction_succeeds_on_retry(self):
        corrected = '{"name": "fixed", "score": 50}'
        mock_llm = _make_mock_llm(corrected)
        validator = OutputValidator(mock_llm)

        # First attempt will fail (invalid JSON), correction returns valid.
        raw = '{"name": "broken", score: INVALID}'
        result = await validator.validate_and_correct(raw, SimpleModel)

        assert result is not None
        assert result.name == "fixed"
        assert result.score == 50
        mock_llm.ainvoke.assert_called_once()

    @pytest.mark.asyncio
    async def test_correction_includes_schema(self):
        corrected = '{"name": "ok", "score": 1}'
        mock_llm = _make_mock_llm(corrected)
        validator = OutputValidator(mock_llm)

        await validator.validate_and_correct("bad json", SimpleModel)

        call_args = mock_llm.ainvoke.call_args[0][0]
        # Second message (HumanMessage) should contain the schema.
        user_msg = call_args[1].content
        assert "name" in user_msg
        assert "score" in user_msg
        assert "validation error" in user_msg.lower() or "Required JSON schema" in user_msg

    @pytest.mark.asyncio
    async def test_returns_none_after_all_retries_exhausted(self):
        # Correction also returns invalid output.
        mock_llm = _make_mock_llm("still broken {{{")
        validator = OutputValidator(mock_llm, max_retries=1)

        result = await validator.validate_and_correct("bad", SimpleModel)

        assert result is None
        assert mock_llm.ainvoke.call_count == 1

    @pytest.mark.asyncio
    async def test_multiple_retries(self):
        # Two retries allowed, both fail.
        mock_llm = _make_mock_llm("nope")
        validator = OutputValidator(mock_llm, max_retries=2)

        result = await validator.validate_and_correct("bad", SimpleModel)

        assert result is None
        assert mock_llm.ainvoke.call_count == 2

    @pytest.mark.asyncio
    async def test_context_included_in_correction(self):
        corrected = '{"name": "ctx", "score": 1}'
        mock_llm = _make_mock_llm(corrected)
        validator = OutputValidator(mock_llm)

        await validator.validate_and_correct(
            "bad json", SimpleModel, context="Analyze security findings."
        )

        user_msg = mock_llm.ainvoke.call_args[0][0][1].content
        assert "Analyze security findings." in user_msg

    @pytest.mark.asyncio
    async def test_fenced_json_in_correction_response(self):
        # LLM wraps correction in markdown fences.
        corrected = '```json\n{"name": "fenced", "score": 77}\n```'
        mock_llm = _make_mock_llm(corrected)
        validator = OutputValidator(mock_llm)

        result = await validator.validate_and_correct("{bad}", SimpleModel)

        assert result is not None
        assert result.name == "fenced"

    @pytest.mark.asyncio
    async def test_schema_error_triggers_correction(self):
        # Valid JSON but wrong schema on first attempt.
        raw = '{"name": "test"}'  # Missing "score".
        corrected = '{"name": "test", "score": 10}'
        mock_llm = _make_mock_llm(corrected)
        validator = OutputValidator(mock_llm)

        result = await validator.validate_and_correct(raw, SimpleModel)

        assert result is not None
        assert result.score == 10
        mock_llm.ainvoke.assert_called_once()

    @pytest.mark.asyncio
    async def test_strict_model_correction(self):
        # Invalid enum on first attempt, corrected on retry.
        raw = '{"id": "BLK-001", "severity": "catastrophic", "confidence": 0.9}'
        corrected = '{"id": "BLK-001", "severity": "critical", "confidence": 0.9}'
        mock_llm = _make_mock_llm(corrected)
        validator = OutputValidator(mock_llm)

        result = await validator.validate_and_correct(raw, StrictModel)

        assert result is not None
        assert result.severity == "critical"

    @pytest.mark.asyncio
    async def test_truncates_long_raw_output(self):
        long_raw = "x" * 20_000
        corrected = '{"name": "ok", "score": 1}'
        mock_llm = _make_mock_llm(corrected)
        validator = OutputValidator(mock_llm)

        await validator.validate_and_correct(long_raw, SimpleModel)

        user_msg = mock_llm.ainvoke.call_args[0][0][1].content
        assert "[truncated]" in user_msg
