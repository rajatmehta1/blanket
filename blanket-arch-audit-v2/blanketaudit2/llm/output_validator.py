"""Pydantic output parsing with a one-shot correction cycle.

Design doc §6.3 flow:
  1. Parse raw LLM text as JSON into a Pydantic model.
  2. On failure → send a correction prompt containing the validation error.
  3. Parse the corrected response.
  4. On second failure → return *None* (caller uses static fallback).
"""

from __future__ import annotations

import json
import re
from typing import Any, TypeVar

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, ValidationError

logger = structlog.get_logger()

T = TypeVar("T", bound=BaseModel)

# Maximum characters of raw output to include in the correction prompt
# to avoid blowing up context on huge responses.
_MAX_RAW_ECHO = 8_000

_CORRECTION_SYSTEM = (
    "You are a JSON repair assistant.  The user will show you a malformed "
    "or schema-invalid JSON response and the validation error.  Return ONLY "
    "the corrected JSON — no explanation, no markdown fences."
)


# ── JSON extraction helpers ──────────────────────────────────

def _extract_json(text: str) -> str:
    """Extract the first JSON object or array from *text*.

    LLMs often wrap JSON in markdown fences or add commentary.
    This strips those wrappers so ``json.loads`` succeeds.
    """
    # Try the raw text first (fast path).
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        return stripped

    # Look for ```json ... ``` fenced blocks.
    match = re.search(r"```(?:json)?\s*\n?([\s\S]*?)```", text)
    if match:
        return match.group(1).strip()

    # Last resort: find first { ... } or [ ... ] in the text.
    for open_ch, close_ch in [("{", "}"), ("[", "]")]:
        start = text.find(open_ch)
        if start == -1:
            continue
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]

    # Nothing found — return original and let the caller fail gracefully.
    return stripped


def _parse_model(raw: str, model_class: type[T]) -> T:
    """Extract JSON from *raw* and parse into *model_class*."""
    json_str = _extract_json(raw)
    data = json.loads(json_str)
    return model_class.model_validate(data)


# ── Synchronous one-shot parser (no LLM needed) ─────────────


def parse_llm_output(raw: str, model_class: type[T]) -> T | None:
    """Parse LLM text into a Pydantic model.

    Returns *None* if parsing fails (caller should fall back to static).
    This is the simple path when no LLM is available for correction.
    """
    try:
        return _parse_model(raw, model_class)
    except (json.JSONDecodeError, ValidationError, Exception) as exc:
        logger.warning(
            "llm_output.parse_failed",
            error=str(exc)[:300],
            model_class=model_class.__name__,
        )
        return None


# ── Async validator with correction cycle ────────────────────


class OutputValidator:
    """Validate and auto-correct LLM output against a Pydantic schema.

    Typical usage::

        validator = OutputValidator(llm)
        finding = await validator.validate_and_correct(raw, AuditFinding)
        if finding is None:
            # fall back to static-only result
    """

    def __init__(self, llm: Any, *, max_retries: int = 1) -> None:
        self.llm = llm
        self.max_retries = max_retries

    # ── public API ───────────────────────────────────────────

    async def validate_and_correct(
        self,
        raw_output: str,
        model_class: type[T],
        *,
        context: str = "",
    ) -> T | None:
        """Try to parse *raw_output*.  On failure, ask the LLM to fix it.

        Parameters
        ----------
        raw_output:
            The raw string returned by the LLM.
        model_class:
            The Pydantic model to parse into.
        context:
            Optional extra context (e.g. the original prompt) included in
            the correction message to help the LLM understand the schema.

        Returns
        -------
        A validated *model_class* instance, or *None* after all retries
        are exhausted.
        """
        # Attempt 1: direct parse
        first_error = ""
        try:
            return _parse_model(raw_output, model_class)
        except (json.JSONDecodeError, ValidationError, Exception) as exc:
            first_error = str(exc)
            logger.warning(
                "llm_output.parse_failed",
                error=first_error[:300],
                model_class=model_class.__name__,
                attempt=1,
            )

        # Correction loop
        current_raw = raw_output
        current_error = first_error

        for attempt in range(2, 2 + self.max_retries):
            corrected_text = await self._request_correction(
                current_raw, current_error, model_class, context
            )
            try:
                result = _parse_model(corrected_text, model_class)
                logger.info(
                    "llm_output.correction_succeeded",
                    model_class=model_class.__name__,
                    attempt=attempt,
                )
                return result
            except (json.JSONDecodeError, ValidationError, Exception) as exc:
                current_error = str(exc)
                current_raw = corrected_text
                logger.warning(
                    "llm_output.correction_failed",
                    error=current_error[:300],
                    model_class=model_class.__name__,
                    attempt=attempt,
                )

        # All retries exhausted — caller must use static fallback.
        logger.error(
            "llm_output.all_retries_exhausted",
            model_class=model_class.__name__,
            retries=self.max_retries,
        )
        return None

    # ── internals ────────────────────────────────────────────

    async def _request_correction(
        self,
        raw_output: str,
        error: str,
        model_class: type[T],
        context: str,
    ) -> str:
        """Send a correction prompt to the LLM and return the response text."""
        schema_json = json.dumps(
            model_class.model_json_schema(), indent=2
        )

        truncated_raw = raw_output[:_MAX_RAW_ECHO]
        if len(raw_output) > _MAX_RAW_ECHO:
            truncated_raw += "\n... [truncated]"

        user_content = (
            "Your previous response had a validation error:\n"
            f"{error}\n\n"
            "Required JSON schema:\n"
            f"```json\n{schema_json}\n```\n\n"
            "Original response (fix this):\n"
            f"```\n{truncated_raw}\n```"
        )
        if context:
            user_content += f"\n\nOriginal task context:\n{context}"

        messages = [
            SystemMessage(content=_CORRECTION_SYSTEM),
            HumanMessage(content=user_content),
        ]

        response = await self.llm.ainvoke(messages)
        return response.content
