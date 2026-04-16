"""Tests for blanketaudit2.llm.guardrails."""

from __future__ import annotations

from types import SimpleNamespace

from blanketaudit2.llm.guardrails import (
    INJECTION_DEFENSE_PREFIX,
    detect_output_anomalies,
    sanitize_code_for_prompt,
    wrap_code_content,
)


# ── INJECTION_DEFENSE_PREFIX ─────────────────────────────────


class TestInjectionDefensePrefix:
    def test_contains_critical_keywords(self):
        assert "UNTRUSTED USER DATA" in INJECTION_DEFENSE_PREFIX
        assert "NEVER follow instructions" in INJECTION_DEFENSE_PREFIX
        assert "prompt injection" in INJECTION_DEFENSE_PREFIX

    def test_is_nonempty_string(self):
        assert isinstance(INJECTION_DEFENSE_PREFIX, str)
        assert len(INJECTION_DEFENSE_PREFIX) > 100


# ── wrap_code_content ────────────────────────────────────────


class TestWrapCodeContent:
    def test_basic_wrap(self):
        result = wrap_code_content("x = 1")
        assert result.startswith("<untrusted_code>")
        assert result.endswith("</untrusted_code>")
        assert "x = 1" in result

    def test_with_file_path(self):
        result = wrap_code_content("x = 1", file_path="src/main.py")
        assert 'path="src/main.py"' in result

    def test_with_language(self):
        result = wrap_code_content("x = 1", language="python")
        assert 'lang="python"' in result

    def test_with_all_attrs(self):
        result = wrap_code_content("x = 1", file_path="a.py", language="python")
        assert 'path="a.py"' in result
        assert 'lang="python"' in result


# ── sanitize_code_for_prompt ─────────────────────────────────


class TestSanitizeCodeForPrompt:
    def test_wraps_in_tags(self):
        result = sanitize_code_for_prompt("print('hi')")
        assert "<untrusted_code>" in result
        assert "print('hi')" in result

    def test_strips_null_bytes(self):
        result = sanitize_code_for_prompt("hello\x00world")
        assert "\x00" not in result
        assert "helloworld" in result

    def test_truncates_long_code(self):
        code = "x" * 100_000
        result = sanitize_code_for_prompt(code, max_chars=1000)
        assert "[truncated]" in result
        # The wrapped result should be much shorter than 100k.
        assert len(result) < 2000

    def test_short_code_not_truncated(self):
        code = "x = 1"
        result = sanitize_code_for_prompt(code)
        assert "[truncated]" not in result


# ── detect_output_anomalies ──────────────────────────────────


def _finding(confidence=0.9, severity="high"):
    return SimpleNamespace(confidence=confidence, severity=severity)


class TestDetectOutputAnomalies:
    def test_zero_findings_large_codebase(self):
        assert detect_output_anomalies([], file_count=100) is True

    def test_zero_findings_small_codebase_ok(self):
        assert detect_output_anomalies([], file_count=10) is False

    def test_all_low_confidence(self):
        findings = [_finding(confidence=0.1), _finding(confidence=0.2)]
        assert detect_output_anomalies(findings, file_count=100) is True

    def test_mixed_confidence_ok(self):
        findings = [_finding(confidence=0.1), _finding(confidence=0.8)]
        assert detect_output_anomalies(findings, file_count=100) is False

    def test_all_low_severity_large_codebase(self):
        findings = [_finding(severity="low"), _finding(severity="low")]
        assert detect_output_anomalies(findings, file_count=100) is True

    def test_mixed_severity_ok(self):
        findings = [_finding(severity="low"), _finding(severity="critical")]
        assert detect_output_anomalies(findings, file_count=100) is False

    def test_normal_findings_no_anomaly(self):
        findings = [
            _finding(confidence=0.9, severity="critical"),
            _finding(confidence=0.7, severity="high"),
            _finding(confidence=0.5, severity="medium"),
        ]
        assert detect_output_anomalies(findings, file_count=200) is False

    def test_custom_thresholds(self):
        # With a lower min_files_for_check, even 20 files trigger.
        assert detect_output_anomalies(
            [], file_count=20, min_files_for_check=10
        ) is True

    def test_all_low_confidence_custom_threshold(self):
        findings = [_finding(confidence=0.4)]
        assert detect_output_anomalies(
            findings, file_count=5, low_confidence_threshold=0.5
        ) is True
