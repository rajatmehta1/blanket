"""Tests for blanketaudit.policies — schema, engine, conflict resolver."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from blanketaudit.models.finding import AuditFinding, Evidence
from blanketaudit.policies.conflict_resolver import ConflictResolver, PRIORITY_ORDER
from blanketaudit.policies.engine import PolicyEngine, StaticCandidate
from blanketaudit.policies.schema import (
    AIAnalysis,
    ASTPattern,
    ASTPatternCondition,
    Policy,
    StaticCheck,
    validate_policy_dict,
)


# ── Helpers ──────────────────────────────────────────────────


def _policy_dict(**overrides) -> dict:
    base = dict(
        id="SEC-001",
        name="SQL Injection via String Interpolation",
        category="security",
        severity="critical",
        description="Detect SQL injection via f-strings.",
        frameworks=["PCI-DSS-6.5.1", "HIPAA-164.312-a-1"],
        static_checks=[
            {"tool": "regex", "regex": r"execute\(f['\"]"},
        ],
        ai_analysis={
            "prompt_template": "Analyze: {code_context}",
            "expected_output": "finding_assessment",
            "min_confidence": 0.7,
        },
        remediation_template="Use parameterized queries.",
        effort_hours=2.0,
    )
    base.update(overrides)
    return base


def _finding(
    id: str = "BLK-001",
    policy_id: str = "SEC-001",
    severity: str = "critical",
    category: str = "security",
    file_path: str = "src/main.py",
    line_start: int = 10,
    line_end: int = 12,
) -> AuditFinding:
    return AuditFinding(
        id=id,
        policy_id=policy_id,
        title="Test Finding",
        description="A test finding.",
        severity=severity,
        category=category,
        confidence=0.9,
        source="static",
        evidence=[Evidence(
            file_path=file_path, repo_name="api",
            line_start=line_start, line_end=line_end,
            code_snippet="code here", tool="regex",
        )],
        compliance_refs=[],
        ai_explanation="Explanation.",
        fix_code="fix()",
        remediation="Fix it.",
        effort_hours=1.0,
        dollar_impact="$1,000",
    )


# ═══════════════════════════════════════════════════════════════
# Policy Schema
# ═══════════════════════════════════════════════════════════════


class TestPolicySchema:
    def test_valid_policy(self):
        p = validate_policy_dict(_policy_dict())
        assert p is not None
        assert p.id == "SEC-001"
        assert p.category == "security"
        assert p.severity == "critical"
        assert len(p.static_checks) == 1
        assert p.ai_analysis is not None

    def test_minimal_policy(self):
        p = validate_policy_dict({
            "id": "MIN-001",
            "name": "Minimal",
            "category": "quality",
            "severity": "low",
        })
        assert p is not None
        assert p.static_checks == []
        assert p.ai_analysis is None

    def test_missing_id_rejected(self):
        data = _policy_dict()
        del data["id"]
        assert validate_policy_dict(data) is None

    def test_missing_category_rejected(self):
        data = _policy_dict()
        del data["category"]
        assert validate_policy_dict(data) is None

    def test_invalid_severity_rejected(self):
        assert validate_policy_dict(_policy_dict(severity="catastrophic")) is None

    def test_invalid_category_rejected(self):
        assert validate_policy_dict(_policy_dict(category="performance")) is None

    def test_empty_id_rejected(self):
        assert validate_policy_dict(_policy_dict(id="")) is None

    def test_static_check_regex(self):
        p = validate_policy_dict(_policy_dict(
            static_checks=[{"tool": "regex", "regex": r"password\s*="}],
        ))
        assert p is not None
        assert p.static_checks[0].tool == "regex"
        assert p.static_checks[0].regex == r"password\s*="

    def test_static_check_ast(self):
        p = validate_policy_dict(_policy_dict(
            static_checks=[{
                "tool": "ast",
                "pattern": {
                    "node_type": "binary_expression",
                    "conditions": [{"text_matches": "SELECT"}],
                },
            }],
        ))
        assert p is not None
        assert p.static_checks[0].pattern.node_type == "binary_expression"

    def test_frameworks_list(self):
        p = validate_policy_dict(_policy_dict(
            frameworks=["PCI-DSS-6.5.1", "SOC2-CC6.1"],
        ))
        assert len(p.frameworks) == 2

    def test_conflicts_with(self):
        p = validate_policy_dict(_policy_dict(
            conflicts_with=["ARCH-001"],
            supersedes=["OLD-001"],
        ))
        assert p.conflicts_with == ["ARCH-001"]
        assert p.supersedes == ["OLD-001"]


# ═══════════════════════════════════════════════════════════════
# Policy Engine — Loading
# ═══════════════════════════════════════════════════════════════


class TestPolicyEngineLoading:
    def test_load_from_directory(self, tmp_path):
        (tmp_path / "sec001.yaml").write_text(
            "id: SEC-001\nname: SQLi\ncategory: security\nseverity: critical\n"
            "static_checks:\n  - tool: regex\n    regex: 'execute\\(f'\n",
            encoding="utf-8",
        )
        (tmp_path / "qual001.yaml").write_text(
            "id: QUAL-001\nname: Complexity\ncategory: quality\nseverity: medium\n",
            encoding="utf-8",
        )

        engine = PolicyEngine()
        loaded = engine.load_policies(tmp_path)
        assert len(loaded) == 2
        assert engine.policy_count == 2

    def test_filter_by_category(self, tmp_path):
        (tmp_path / "sec.yaml").write_text(
            "id: SEC-001\nname: S\ncategory: security\nseverity: high\n",
        )
        (tmp_path / "qual.yaml").write_text(
            "id: QUAL-001\nname: Q\ncategory: quality\nseverity: low\n",
        )

        engine = PolicyEngine()
        loaded = engine.load_policies(tmp_path, categories={"security"})
        assert len(loaded) == 1
        assert loaded[0].id == "SEC-001"

    def test_invalid_yaml_skipped(self, tmp_path):
        (tmp_path / "bad.yaml").write_text(":::invalid::yaml")
        (tmp_path / "good.yaml").write_text(
            "id: G-001\nname: Good\ncategory: security\nseverity: low\n",
        )

        engine = PolicyEngine()
        loaded = engine.load_policies(tmp_path)
        assert len(loaded) == 1

    def test_invalid_schema_skipped(self, tmp_path):
        (tmp_path / "nocat.yaml").write_text(
            "id: BAD-001\nname: Missing Category\nseverity: low\n",
        )
        engine = PolicyEngine()
        loaded = engine.load_policies(tmp_path)
        assert len(loaded) == 0

    def test_nonexistent_dir_raises(self):
        engine = PolicyEngine()
        with pytest.raises(Exception):
            engine.load_policies("/nonexistent/path")

    def test_load_from_dict(self):
        engine = PolicyEngine()
        p = engine.load_policy_from_dict(_policy_dict())
        assert p is not None
        assert engine.get_policy("SEC-001") is not None

    def test_recursive_loading(self, tmp_path):
        sub = tmp_path / "security"
        sub.mkdir()
        (sub / "sqli.yaml").write_text(
            "id: SEC-001\nname: SQLi\ncategory: security\nseverity: critical\n",
        )
        engine = PolicyEngine()
        loaded = engine.load_policies(tmp_path)
        assert len(loaded) == 1


# ═══════════════════════════════════════════════════════════════
# Policy Engine — Static Check Execution
# ═══════════════════════════════════════════════════════════════


class TestPolicyEngineStaticChecks:
    def test_regex_check_finds_matches(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-001", name="Hardcoded Password",
            category="security", severity="high",
            static_checks=[StaticCheck(tool="regex", regex=r"password\s*=\s*['\"]")],
        )
        files = {
            "config.py": 'password = "secret123"\nother = 1\n',
            "clean.py": 'x = 1\ny = 2\n',
        }
        candidates = engine.execute_static_checks(policy, files)
        assert len(candidates) == 1
        assert candidates[0].file_path == "config.py"
        assert candidates[0].tool == "regex"

    def test_regex_check_no_match(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-001", name="Test",
            category="security", severity="high",
            static_checks=[StaticCheck(tool="regex", regex=r"password\s*=")],
        )
        files = {"clean.py": "x = 1\n"}
        candidates = engine.execute_static_checks(policy, files)
        assert len(candidates) == 0

    def test_ast_text_matches_fallback(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-002", name="SQL Pattern",
            category="security", severity="critical",
            static_checks=[StaticCheck(
                tool="ast",
                pattern=ASTPattern(
                    node_type="call",
                    conditions=[ASTPatternCondition(text_matches=r"SELECT\s+\*")],
                ),
            )],
        )
        files = {
            "query.py": 'result = db.execute("SELECT * FROM users")\n',
        }
        candidates = engine.execute_static_checks(policy, files)
        assert len(candidates) == 1

    def test_multiple_checks_combined(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-003", name="Multi",
            category="security", severity="high",
            static_checks=[
                StaticCheck(tool="regex", regex=r"password\s*="),
                StaticCheck(tool="regex", regex=r"api_key\s*="),
            ],
        )
        files = {
            "config.py": 'password = "x"\napi_key = "y"\n',
        }
        candidates = engine.execute_static_checks(policy, files)
        assert len(candidates) == 2

    def test_bad_regex_skipped(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-004", name="Bad Regex",
            category="security", severity="high",
            static_checks=[StaticCheck(tool="regex", regex=r"[invalid")],
        )
        candidates = engine.execute_static_checks(policy, {"a.py": "x"})
        assert len(candidates) == 0

    def test_line_number_correct(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-005", name="Line Test",
            category="security", severity="high",
            static_checks=[StaticCheck(tool="regex", regex=r"SECRET")],
        )
        files = {"a.py": "line1\nline2\nSECRET_KEY = 'x'\nline4\n"}
        candidates = engine.execute_static_checks(policy, files)
        assert candidates[0].line_start == 3

    def test_no_static_checks_returns_empty(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-006", name="No Checks",
            category="security", severity="low",
        )
        candidates = engine.execute_static_checks(policy, {"a.py": "x"})
        assert len(candidates) == 0


# ═══════════════════════════════════════════════════════════════
# Policy Engine — AI Analysis
# ═══════════════════════════════════════════════════════════════


class TestPolicyEngineAIAnalysis:
    @pytest.mark.asyncio
    async def test_ai_analysis_calls_llm(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-001", name="Test",
            category="security", severity="high",
            ai_analysis=AIAnalysis(
                prompt_template="Analyze: {code_context}",
            ),
        )
        candidate = StaticCandidate(
            policy_id="SEC-001", file_path="a.py",
            line_start=1, line_end=1,
            code_snippet="password = 'x'", tool="regex",
        )

        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.content = '{"is_vulnerability": true}'
        mock_llm.ainvoke.return_value = mock_response

        results = await engine.execute_ai_analysis(policy, [candidate], mock_llm)
        assert len(results) == 1
        assert "ai_response" in results[0]
        mock_llm.ainvoke.assert_called_once()

    @pytest.mark.asyncio
    async def test_ai_fallback_on_no_llm(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-001", name="Test",
            category="security", severity="high",
            ai_analysis=AIAnalysis(prompt_template="Analyze: {code_context}"),
        )
        candidate = StaticCandidate(
            policy_id="SEC-001", file_path="a.py",
            line_start=1, line_end=1,
            code_snippet="x", tool="regex",
        )

        results = await engine.execute_ai_analysis(policy, [candidate], llm=None)
        assert len(results) == 1
        assert "ai_response" not in results[0]

    @pytest.mark.asyncio
    async def test_ai_graceful_degradation(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-001", name="Test",
            category="security", severity="high",
            ai_analysis=AIAnalysis(prompt_template="Analyze: {code_context}"),
        )
        candidate = StaticCandidate(
            policy_id="SEC-001", file_path="a.py",
            line_start=1, line_end=1,
            code_snippet="x", tool="regex",
        )

        mock_llm = AsyncMock()
        mock_llm.ainvoke.side_effect = RuntimeError("LLM down")

        results = await engine.execute_ai_analysis(policy, [candidate], mock_llm)
        # Should fall back to static candidate
        assert len(results) == 1
        assert "ai_response" not in results[0]


# ═══════════════════════════════════════════════════════════════
# Policy Engine — Full Dual-Layer Execution
# ═══════════════════════════════════════════════════════════════


class TestPolicyEngineDualLayer:
    @pytest.mark.asyncio
    async def test_static_only_when_no_llm(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-001", name="Test",
            category="security", severity="high",
            static_checks=[StaticCheck(tool="regex", regex=r"password\s*=")],
            ai_analysis=AIAnalysis(prompt_template="Analyze: {code_context}"),
        )
        files = {"config.py": 'password = "secret"\n'}
        results = await engine.execute_policy(policy, files, llm=None)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_no_candidates_no_ai(self):
        engine = PolicyEngine()
        policy = Policy(
            id="SEC-001", name="Test",
            category="security", severity="high",
            static_checks=[StaticCheck(tool="regex", regex=r"DOES_NOT_EXIST")],
        )
        results = await engine.execute_policy(policy, {"a.py": "clean"})
        assert len(results) == 0


# ═══════════════════════════════════════════════════════════════
# Conflict Resolver
# ═══════════════════════════════════════════════════════════════


class TestConflictResolver:
    def test_no_conflicts_passthrough(self):
        resolver = ConflictResolver()
        findings = [
            _finding(id="BLK-001", file_path="a.py", line_start=1, line_end=5),
            _finding(id="BLK-002", file_path="b.py", line_start=1, line_end=5),
        ]
        result = resolver.resolve(findings)
        assert len(result) == 2

    def test_security_beats_quality(self):
        resolver = ConflictResolver()
        findings = [
            _finding(id="BLK-001", policy_id="SEC-001",
                     category="security", severity="high",
                     file_path="a.py", line_start=10, line_end=12),
            _finding(id="BLK-002", policy_id="QUAL-001",
                     category="quality", severity="high",
                     file_path="a.py", line_start=10, line_end=12),
        ]
        result = resolver.resolve(findings)
        assert len(result) == 1
        assert result[0].category == "security"

    def test_compliance_beats_architecture(self):
        resolver = ConflictResolver()
        findings = [
            _finding(id="BLK-001", policy_id="COMP-001",
                     category="compliance", severity="medium",
                     file_path="a.py", line_start=10, line_end=12),
            _finding(id="BLK-002", policy_id="ARCH-001",
                     category="architecture", severity="medium",
                     file_path="a.py", line_start=10, line_end=12),
        ]
        result = resolver.resolve(findings)
        assert len(result) == 1
        assert result[0].category == "compliance"

    def test_same_category_higher_severity_wins(self):
        resolver = ConflictResolver()
        findings = [
            _finding(id="BLK-001", policy_id="SEC-001",
                     category="security", severity="critical",
                     file_path="a.py", line_start=10, line_end=12),
            _finding(id="BLK-002", policy_id="SEC-002",
                     category="security", severity="medium",
                     file_path="a.py", line_start=10, line_end=12),
        ]
        result = resolver.resolve(findings)
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_explicit_supersedes(self):
        policies = {
            "NEW-001": Policy(
                id="NEW-001", name="New",
                category="security", severity="high",
                supersedes=["OLD-001"],
            ),
            "OLD-001": Policy(
                id="OLD-001", name="Old",
                category="security", severity="critical",
            ),
        }
        resolver = ConflictResolver(policies=policies)
        findings = [
            _finding(id="BLK-001", policy_id="NEW-001",
                     category="security", severity="high",
                     file_path="a.py", line_start=10, line_end=12),
            _finding(id="BLK-002", policy_id="OLD-001",
                     category="security", severity="critical",
                     file_path="a.py", line_start=10, line_end=12),
        ]
        result = resolver.resolve(findings)
        assert len(result) == 1
        assert result[0].policy_id == "NEW-001"

    def test_different_locations_no_conflict(self):
        resolver = ConflictResolver()
        findings = [
            _finding(id="BLK-001", file_path="a.py", line_start=1, line_end=5),
            _finding(id="BLK-002", file_path="a.py", line_start=50, line_end=55),
        ]
        result = resolver.resolve(findings)
        assert len(result) == 2

    def test_same_severity_same_category_kept_with_conflict_flag(self):
        """When no clear winner, both findings are kept with CONFLICT flag."""
        resolver = ConflictResolver()
        findings = [
            _finding(id="BLK-001", policy_id="SEC-001",
                     category="security", severity="high",
                     file_path="a.py", line_start=10, line_end=12),
            _finding(id="BLK-002", policy_id="SEC-002",
                     category="security", severity="high",
                     file_path="a.py", line_start=10, line_end=12),
        ]
        result = resolver.resolve(findings)
        assert len(result) == 2
        assert all("CONFLICT" in f.ai_explanation for f in result)

    def test_empty_findings(self):
        resolver = ConflictResolver()
        assert resolver.resolve([]) == []

    def test_single_finding(self):
        resolver = ConflictResolver()
        f = _finding()
        assert resolver.resolve([f]) == [f]

    def test_priority_order_constant(self):
        assert PRIORITY_ORDER == ["security", "compliance", "architecture", "quality"]
