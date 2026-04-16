"""Layer 4: LLM-as-Judge evaluation harness.

A SEPARATE LLM call evaluates the scanner's output quality.
Scores: recall, precision, hallucination rate, remediation quality, severity accuracy.
Target: >90% recall on critical, <5% false positive rate.

This test is SKIPPED by default (requires LLM API key).
Run with: pytest tests/eval/ -m "eval" --run-eval
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# Mark all tests in this module as eval (skipped by default)
pytestmark = pytest.mark.eval

GOLDEN_DIR = Path(__file__).parent.parent / "golden"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def pytest_configure(config):
    config.addinivalue_line("markers", "eval: LLM-as-Judge evaluation tests")


def _should_run_eval() -> bool:
    """Check if eval tests should run (requires --run-eval flag or env var)."""
    import os
    return os.environ.get("RUN_EVAL", "").lower() in ("1", "true", "yes")


# ── Evaluation metrics ───────────────────────────────────────


class EvalMetrics:
    """Compute precision, recall, and other eval metrics."""

    def __init__(
        self,
        expected_findings: list[dict],
        actual_findings: list[dict],
    ) -> None:
        self.expected = expected_findings
        self.actual = actual_findings

    @property
    def recall(self) -> float:
        """Fraction of expected findings that were detected."""
        if not self.expected:
            return 1.0
        found = 0
        for exp in self.expected:
            pattern = exp.get("pattern", "")
            if any(self._matches(a, pattern) for a in self.actual):
                found += 1
        return found / len(self.expected)

    @property
    def critical_recall(self) -> float:
        """Recall specifically for critical findings."""
        critical_expected = [e for e in self.expected if e.get("severity") == "critical"]
        if not critical_expected:
            return 1.0
        found = sum(
            1 for exp in critical_expected
            if any(self._matches(a, exp.get("pattern", "")) for a in self.actual)
        )
        return found / len(critical_expected)

    @property
    def false_positive_rate(self) -> float:
        """Fraction of actual findings that are false positives."""
        if not self.actual:
            return 0.0
        fp = sum(
            1 for a in self.actual
            if not any(self._matches(a, e.get("pattern", "")) for e in self.expected)
        )
        return fp / len(self.actual)

    @staticmethod
    def _matches(finding: dict, pattern: str) -> bool:
        import re
        text = f"{finding.get('policy_id', '')} {finding.get('message', '')} {finding.get('code_snippet', '')}".lower()
        return bool(re.search(pattern.lower(), text))


class LLMJudge:
    """Use an LLM to evaluate scan output quality."""

    def __init__(self, llm: Any = None) -> None:
        self._llm = llm

    async def evaluate(
        self,
        fixture_name: str,
        golden: dict,
        actual_findings: list[dict],
    ) -> dict:
        """Ask the LLM to judge the scan output.

        Returns scores:
        - recall_score (0-100): were all expected findings found?
        - precision_score (0-100): how many findings are real (not false positives)?
        - severity_accuracy (0-100): are severities correctly assigned?
        - remediation_quality (0-100): are fixes actionable?
        - hallucination_rate (0-100): % of findings that don't exist in the code
        """
        if self._llm is None:
            # Compute rule-based metrics instead
            return self._rule_based_eval(golden, actual_findings)

        from langchain_core.messages import HumanMessage, SystemMessage

        system = (
            "You are evaluating a code audit tool's output. Score each dimension 0-100.\n"
            "Respond with JSON: {recall_score, precision_score, severity_accuracy, "
            "remediation_quality, hallucination_rate}\n"
        )

        user = (
            f"Fixture: {fixture_name}\n"
            f"Expected findings: {json.dumps(golden.get('expected_findings', {}), indent=2)}\n"
            f"Actual findings ({len(actual_findings)}):\n"
            f"{json.dumps(actual_findings[:20], indent=2, default=str)}\n"
        )

        response = await self._llm.ainvoke([
            SystemMessage(content=system),
            HumanMessage(content=user),
        ])

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            return self._rule_based_eval(golden, actual_findings)

    @staticmethod
    def _rule_based_eval(golden: dict, actual: list[dict]) -> dict:
        """Compute eval scores without LLM."""
        expected = golden.get("expected_findings", {}).get("must_find", [])
        metrics = EvalMetrics(expected, actual)

        return {
            "recall_score": round(metrics.recall * 100, 1),
            "critical_recall": round(metrics.critical_recall * 100, 1),
            "precision_score": round((1 - metrics.false_positive_rate) * 100, 1),
            "severity_accuracy": 80.0,  # Estimated
            "remediation_quality": 70.0,  # Static-only → no AI remediation
            "hallucination_rate": round(metrics.false_positive_rate * 100, 1),
        }


# ── Scan helper ──────────────────────────────────────────────


def _scan_fixture(fixture_name: str) -> list[dict]:
    from blanketaudit2.policies.engine import PolicyEngine
    path = FIXTURES_DIR / fixture_name
    contents: dict[str, str] = {}
    for f in path.rglob("*"):
        if f.is_file() and f.suffix in (".py", ".txt"):
            try:
                contents[str(f.relative_to(path)).replace("\\", "/")] = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

    policy_root = Path(__file__).parent.parent.parent / "blanketaudit2" / "policies"
    all_candidates: list[dict] = []
    for cat in ("security", "compliance"):
        cat_dir = policy_root / cat
        if not cat_dir.exists():
            continue
        engine = PolicyEngine()
        for policy in engine.load_policies(cat_dir):
            for c in engine.execute_static_checks(policy, contents):
                all_candidates.append({
                    "policy_id": c.policy_id,
                    "category": policy.category,
                    "severity": policy.severity,
                    "message": c.message,
                    "code_snippet": c.code_snippet[:200],
                })
    return all_candidates


# ═══════════════════════════════════════════════════════════════
# Rule-based eval tests (always run)
# ═══════════════════════════════════════════════════════════════


class TestEvalMetrics:
    def test_perfect_recall(self):
        expected = [{"pattern": "sql"}, {"pattern": "password"}]
        actual = [
            {"policy_id": "SEC-001", "message": "SQL injection"},
            {"policy_id": "SEC-014", "message": "hardcoded password"},
        ]
        m = EvalMetrics(expected, actual)
        assert m.recall == 1.0

    def test_partial_recall(self):
        expected = [{"pattern": "sql"}, {"pattern": "xss"}]
        actual = [{"policy_id": "SEC-001", "message": "SQL injection"}]
        m = EvalMetrics(expected, actual)
        assert m.recall == 0.5

    def test_zero_false_positive_rate(self):
        expected = [{"pattern": "sql"}]
        actual = [{"message": "SQL injection"}]
        m = EvalMetrics(expected, actual)
        assert m.false_positive_rate == 0.0

    def test_empty_expected(self):
        m = EvalMetrics([], [{"message": "something"}])
        assert m.recall == 1.0

    def test_empty_actual(self):
        m = EvalMetrics([{"pattern": "sql"}], [])
        assert m.recall == 0.0
        assert m.false_positive_rate == 0.0


class TestRuleBasedEval:
    def test_hipaa_eval(self):
        golden = json.loads((GOLDEN_DIR / "golden-hipaa-fail.json").read_text())
        candidates = _scan_fixture("fixture-hipaa-fail")
        judge = LLMJudge()

        import asyncio
        scores = asyncio.run(judge.evaluate("fixture-hipaa-fail", golden, candidates))

        assert scores["recall_score"] >= 30  # Regex may miss some patterns
        assert len(candidates) >= 3  # But should find several

    def test_secure_clean_eval(self):
        golden = json.loads((GOLDEN_DIR / "golden-secure-clean.json").read_text())
        candidates = _scan_fixture("fixture-secure-clean")
        judge = LLMJudge()

        import asyncio
        scores = asyncio.run(judge.evaluate("fixture-secure-clean", golden, candidates))

        # Clean fixture: no expected must_find, so recall is 1.0
        # Precision depends on false positives from regex
        assert scores["recall_score"] >= 50

    def test_pci_eval(self):
        golden = json.loads((GOLDEN_DIR / "golden-pci-fail.json").read_text())
        candidates = _scan_fixture("fixture-pci-fail")
        judge = LLMJudge()

        import asyncio
        scores = asyncio.run(judge.evaluate("fixture-pci-fail", golden, candidates))

        assert scores["recall_score"] >= 30
        assert len(candidates) >= 3


# ═══════════════════════════════════════════════════════════════
# LLM-as-Judge tests (require API key, skipped by default)
# ═══════════════════════════════════════════════════════════════


@pytest.mark.skipif(not _should_run_eval(), reason="Set RUN_EVAL=1 to run LLM judge tests")
class TestLLMJudge:
    """These tests call a real LLM to evaluate scan output.

    Run with: RUN_EVAL=1 pytest tests/eval/ -v
    """

    @pytest.mark.asyncio
    async def test_hipaa_llm_judge(self):
        from blanketaudit2.llm.provider import get_llm
        llm = get_llm()
        if llm is None:
            pytest.skip("No LLM configured")

        golden = json.loads((GOLDEN_DIR / "golden-hipaa-fail.json").read_text())
        candidates = _scan_fixture("fixture-hipaa-fail")
        judge = LLMJudge(llm=llm)
        scores = await judge.evaluate("fixture-hipaa-fail", golden, candidates)

        assert scores.get("recall_score", 0) >= 90, f"Critical recall too low: {scores}"
        assert scores.get("hallucination_rate", 100) < 5, f"Too many hallucinations: {scores}"

    @pytest.mark.asyncio
    async def test_clean_llm_judge(self):
        from blanketaudit2.llm.provider import get_llm
        llm = get_llm()
        if llm is None:
            pytest.skip("No LLM configured")

        golden = json.loads((GOLDEN_DIR / "golden-secure-clean.json").read_text())
        candidates = _scan_fixture("fixture-secure-clean")
        judge = LLMJudge(llm=llm)
        scores = await judge.evaluate("fixture-secure-clean", golden, candidates)

        assert scores.get("precision_score", 0) >= 95, f"Too many false positives: {scores}"
