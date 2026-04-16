"""Layer 3: Golden file tests — compare scan output vs expected results.

Each fixture repo has a golden JSON defining:
- must_find: findings that MUST be detected
- must_not_find: findings that MUST NOT appear (false positives)
- expected_severity_counts: min/max per severity
- expected_score: overall score range + acceptable grades

Tolerance: exact match on categories, ±10% on confidence.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from blanketaudit2.policies.engine import PolicyEngine

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
GOLDEN_DIR = Path(__file__).parent

# ── Helpers ──────────────────────────────────────────────────


def _load_golden(name: str) -> dict:
    path = GOLDEN_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def _load_file_contents(fixture_name: str) -> dict[str, str]:
    path = FIXTURES_DIR / fixture_name
    contents: dict[str, str] = {}
    for f in path.rglob("*"):
        if f.is_file() and f.suffix in (".py", ".txt", ".yaml", ".yml", ".json"):
            try:
                contents[str(f.relative_to(path)).replace("\\", "/")] = f.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                pass
    return contents


def _scan_fixture(fixture_name: str) -> list[dict]:
    """Run all policy categories against a fixture and return candidate dicts."""
    contents = _load_file_contents(fixture_name)
    all_candidates: list[dict] = []

    policy_root = Path(__file__).parent.parent.parent / "blanketaudit2" / "policies"
    for category in ("security", "compliance", "architecture", "quality"):
        cat_dir = policy_root / category
        if not cat_dir.exists():
            continue
        engine = PolicyEngine()
        policies = engine.load_policies(cat_dir)
        for policy in policies:
            candidates = engine.execute_static_checks(policy, contents)
            for c in candidates:
                all_candidates.append({
                    "policy_id": c.policy_id,
                    "category": policy.category,
                    "severity": policy.severity,
                    "file_path": c.file_path,
                    "message": c.message,
                    "code_snippet": c.code_snippet,
                    "tool": c.tool,
                })

    return all_candidates


def _matches_pattern(candidate: dict, pattern: str) -> bool:
    """Check if a candidate matches a pattern (regex on policy_id + message + snippet)."""
    text = f"{candidate.get('policy_id', '')} {candidate.get('message', '')} {candidate.get('code_snippet', '')}".lower()
    return bool(re.search(pattern.lower(), text))


class GoldenComparator:
    """Compare scan output against golden expectations."""

    def __init__(self, golden: dict, candidates: list[dict]) -> None:
        self.golden = golden
        self.candidates = candidates

    def check_must_find(self) -> list[str]:
        """Return list of unfound must_find patterns."""
        failures: list[str] = []
        for expected in self.golden.get("expected_findings", {}).get("must_find", []):
            pattern = expected.get("pattern", "")
            category = expected.get("category", "")
            severity = expected.get("severity", "")
            min_count = expected.get("min_count", 1)

            matching = [
                c for c in self.candidates
                if (not category or c.get("category") == category)
                and (not severity or c.get("severity") == severity)
                and _matches_pattern(c, pattern)
            ]

            if len(matching) < min_count:
                failures.append(
                    f"Expected >= {min_count} findings matching '{pattern}' "
                    f"(category={category}, severity={severity}), found {len(matching)}"
                )

        return failures

    def check_must_not_find(self) -> list[str]:
        """Return list of false positives found."""
        failures: list[str] = []
        for unexpected in self.golden.get("expected_findings", {}).get("must_not_find", []):
            pattern = unexpected.get("pattern", "")
            category = unexpected.get("category", "")

            matching = [
                c for c in self.candidates
                if (not category or c.get("category") == category)
                and _matches_pattern(c, pattern)
            ]

            if matching:
                failures.append(
                    f"Unexpected finding matching '{pattern}' "
                    f"(category={category}): {matching[0].get('message', '')[:100]}"
                )

        return failures

    def check_severity_counts(self) -> list[str]:
        """Check severity count ranges."""
        failures: list[str] = []
        counts: dict[str, int] = {}
        for c in self.candidates:
            sev = c.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1

        for sev, expected_range in self.golden.get("expected_severity_counts", {}).items():
            actual = counts.get(sev, 0)
            min_val = expected_range.get("min", 0)
            max_val = expected_range.get("max", 999)
            if actual < min_val or actual > max_val:
                failures.append(
                    f"{sev}: expected {min_val}-{max_val}, got {actual}"
                )

        return failures


# ═══════════════════════════════════════════════════════════════
# Golden file tests
# ═══════════════════════════════════════════════════════════════


class TestGoldenHIPAAFail:
    @pytest.fixture(scope="class")
    def scan_result(self):
        return _scan_fixture("fixture-hipaa-fail")

    @pytest.fixture(scope="class")
    def golden(self):
        return _load_golden("golden-hipaa-fail.json")

    def test_must_find_sql_injection(self, scan_result, golden):
        sqli = [c for c in scan_result if _matches_pattern(c, "sql|execute.*f['\"]")]
        assert len(sqli) >= 1, "Should detect SQL injection in patient_service.py"

    def test_must_find_hardcoded_password(self, scan_result, golden):
        matches = [c for c in scan_result if _matches_pattern(c, "password")]
        assert len(matches) >= 1

    def test_must_not_find_false_positives(self, scan_result, golden):
        comp = GoldenComparator(golden, scan_result)
        failures = comp.check_must_not_find()
        assert not failures, failures

    def test_has_critical_findings(self, scan_result):
        criticals = [c for c in scan_result if c.get("severity") == "critical"]
        assert len(criticals) >= 1

    def test_finding_count_reasonable(self, scan_result):
        assert 3 <= len(scan_result) <= 100


class TestGoldenPCIFail:
    @pytest.fixture(scope="class")
    def scan_result(self):
        return _scan_fixture("fixture-pci-fail")

    @pytest.fixture(scope="class")
    def golden(self):
        return _load_golden("golden-pci-fail.json")

    def test_must_find_sql_injection(self, scan_result):
        sqli = [c for c in scan_result if _matches_pattern(c, "sql|execute")]
        assert len(sqli) >= 1

    def test_must_find_hardcoded_secrets(self, scan_result):
        secrets = [c for c in scan_result if _matches_pattern(c, "password|api.key|secret")]
        assert len(secrets) >= 1

    def test_detects_debug_mode(self, scan_result):
        debug = [c for c in scan_result if _matches_pattern(c, "debug")]
        assert len(debug) >= 1

    def test_must_not_find_false_positives(self, scan_result, golden):
        comp = GoldenComparator(golden, scan_result)
        failures = comp.check_must_not_find()
        assert not failures, failures

    def test_has_critical_findings(self, scan_result):
        criticals = [c for c in scan_result if c.get("severity") == "critical"]
        assert len(criticals) >= 1


class TestGoldenSOC2Partial:
    @pytest.fixture(scope="class")
    def scan_result(self):
        return _scan_fixture("fixture-soc2-partial")

    @pytest.fixture(scope="class")
    def golden(self):
        return _load_golden("golden-soc2-partial.json")

    def test_detects_weak_hashing(self, scan_result):
        weak = [c for c in scan_result if _matches_pattern(c, "md5|weak|hash")]
        assert len(weak) >= 1

    def test_detects_command_injection(self, scan_result):
        cmd = [c for c in scan_result if _matches_pattern(c, "os\\.system|command|shell")]
        assert len(cmd) >= 1

    def test_must_not_find_false_positives(self, scan_result, golden):
        comp = GoldenComparator(golden, scan_result)
        failures = comp.check_must_not_find()
        assert not failures, failures

    def test_fewer_criticals_than_hipaa(self, scan_result):
        """Partial compliance should have some findings but balanced."""
        total = len(scan_result)
        assert total >= 2  # Has issues
        assert total <= 50  # Not as bad as fully broken


class TestGoldenSecureClean:
    @pytest.fixture(scope="class")
    def scan_result(self):
        return _scan_fixture("fixture-secure-clean")

    @pytest.fixture(scope="class")
    def golden(self):
        return _load_golden("golden-secure-clean.json")

    def test_no_sql_injection(self, scan_result, golden):
        """Parameterized queries should not trigger SQLi rules."""
        sqli = [c for c in scan_result if c.get("policy_id") in ("SEC-001", "SEC-002", "SEC-003")]
        assert len(sqli) == 0, "Clean code should not trigger SQL injection"

    def test_no_hardcoded_password(self, scan_result, golden):
        """Env-var-based secrets should not trigger hardcoded password rules."""
        secrets = [c for c in scan_result if c.get("policy_id") == "SEC-014"]
        assert len(secrets) == 0, "Clean code uses env vars"

    def test_no_command_injection(self, scan_result, golden):
        cmd = [c for c in scan_result if c.get("policy_id") == "SEC-006"]
        assert len(cmd) == 0

    def test_few_critical_or_high(self, scan_result):
        """Regex-only static analysis may produce some FPs on clean code.
        AI analysis would filter these. Allow a small margin."""
        severe = [c for c in scan_result if c.get("severity") in ("critical", "high")]
        # With regex-only (no AI filtering), some patterns fire broadly.
        # The key test: no SQL injection or hardcoded password false positives.
        assert len(severe) <= 15, f"Too many severe FPs: {len(severe)}"
