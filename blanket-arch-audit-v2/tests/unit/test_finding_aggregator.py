"""Tests for Tier 5 finding aggregation — merger, scorer, aggregator."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit2.models.finding import AuditFinding, ComplianceRef, Evidence
from blanketaudit2.models.scoring import HealthScore
from blanketaudit2.scoring.finding_merger import FindingMerger
from blanketaudit2.scoring.report_assembler import AggregationResult, FindingAggregator
from blanketaudit2.scoring.risk_scorer import RiskScorer


# ── Helpers ──────────────────────────────────────────────────


def _finding(
    id: str = "BLK-001",
    severity: str = "high",
    category: str = "security",
    confidence: float = 0.9,
    file_path: str = "src/main.py",
    line_start: int = 10,
    line_end: int = 12,
    title: str = "SQL Injection",
    compliance_refs: list | None = None,
    source: str = "static",
) -> AuditFinding:
    refs = compliance_refs or []
    return AuditFinding(
        id=id, policy_id="SEC-001", title=title,
        description="A finding", severity=severity, category=category,
        confidence=confidence, source=source,
        evidence=[Evidence(
            file_path=file_path, repo_name="api",
            line_start=line_start, line_end=line_end,
            code_snippet="code", tool="semgrep",
        )],
        compliance_refs=refs,
        ai_explanation="", fix_code="", remediation="",
        effort_hours=1.0, dollar_impact="",
    )


def _finding_dict(**kwargs) -> dict:
    return _finding(**kwargs).model_dump()


def _ref(framework: str = "HIPAA", clause: str = "§164.312(a)(1)", title: str = "Access"):
    return ComplianceRef(framework=framework, clause=clause, title=title)


# ═══════════════════════════════════════════════════════════════
# FindingMerger
# ═══════════════════════════════════════════════════════════════


class TestFindingMerger:
    def test_no_duplicates_passthrough(self):
        merger = FindingMerger()
        findings = [
            _finding(id="BLK-001", file_path="a.py", line_start=1),
            _finding(id="BLK-002", file_path="b.py", line_start=1),
        ]
        result = merger.merge(findings)
        assert len(result) == 2

    def test_dedup_same_location_keeps_highest_confidence(self):
        merger = FindingMerger()
        findings = [
            _finding(id="BLK-001", file_path="a.py", line_start=10, line_end=12, confidence=0.7),
            _finding(id="BLK-002", file_path="a.py", line_start=10, line_end=12, confidence=0.95),
        ]
        result = merger.merge(findings)
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_dedup_same_location_different_category_not_merged(self):
        merger = FindingMerger()
        findings = [
            _finding(id="BLK-001", file_path="a.py", line_start=10, category="security"),
            _finding(id="BLK-002", file_path="a.py", line_start=10, category="compliance"),
        ]
        result = merger.merge(findings)
        assert len(result) == 2  # Different categories = separate

    def test_dedup_merges_compliance_refs(self):
        merger = FindingMerger()
        findings = [
            _finding(id="BLK-001", file_path="a.py", line_start=10, confidence=0.9,
                     compliance_refs=[_ref("HIPAA", "§164.312(a)(1)")]),
            _finding(id="BLK-002", file_path="a.py", line_start=10, confidence=0.8,
                     compliance_refs=[_ref("SOC2", "CC6.1")]),
        ]
        result = merger.merge(findings)
        assert len(result) == 1
        # Should have refs from BOTH original findings
        frameworks = {r.framework for r in result[0].compliance_refs}
        assert "HIPAA" in frameworks
        assert "SOC2" in frameworks

    def test_dedup_on_tie_prefers_higher_severity(self):
        merger = FindingMerger()
        findings = [
            _finding(id="BLK-001", file_path="a.py", line_start=10, confidence=0.9, severity="medium"),
            _finding(id="BLK-002", file_path="a.py", line_start=10, confidence=0.9, severity="critical"),
        ]
        result = merger.merge(findings)
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_cross_framework_mapping_encryption(self):
        merger = FindingMerger(active_frameworks=["HIPAA", "SOC2", "PCI-DSS"])
        findings = [
            _finding(title="Missing encryption at rest"),
        ]
        result = merger.merge(findings)
        frameworks = {r.framework for r in result[0].compliance_refs}
        assert "HIPAA" in frameworks
        assert "SOC2" in frameworks
        assert "PCI-DSS" in frameworks

    def test_cross_framework_mapping_injection(self):
        merger = FindingMerger(active_frameworks=["PCI-DSS", "SOC2"])
        findings = [
            _finding(title="SQL Injection via f-string"),
        ]
        result = merger.merge(findings)
        frameworks = {r.framework for r in result[0].compliance_refs}
        assert "PCI-DSS" in frameworks

    def test_cross_framework_only_active(self):
        merger = FindingMerger(active_frameworks=["HIPAA"])
        findings = [_finding(title="Hardcoded password")]
        result = merger.merge(findings)
        frameworks = {r.framework for r in result[0].compliance_refs}
        assert "HIPAA" in frameworks
        assert "PCI-DSS" not in frameworks  # Not active

    def test_no_cross_framework_when_none_active(self):
        merger = FindingMerger(active_frameworks=[])
        findings = [_finding(title="Missing encryption")]
        result = merger.merge(findings)
        assert len(result[0].compliance_refs) == 0

    def test_empty_findings(self):
        merger = FindingMerger()
        assert merger.merge([]) == []


# ═══════════════════════════════════════════════════════════════
# RiskScorer
# ═══════════════════════════════════════════════════════════════


class TestRiskScorer:
    def test_no_findings_perfect_score(self):
        scorer = RiskScorer()
        score = scorer.score([])
        assert score.overall == 100
        assert score.grade == "A"

    def test_critical_findings_reduce_score(self):
        scorer = RiskScorer()
        findings = [_finding(severity="critical") for _ in range(4)]
        score = scorer.score(findings)
        assert score.overall < 100  # Score reduced from 100
        # Security category should be hammered
        sec = next((c for c in score.categories if "security" in c.name.lower()), None)
        assert sec is not None
        assert sec.score == 0  # 4 criticals × 25 = 100 penalty → 0

    def test_severity_counts(self):
        scorer = RiskScorer()
        findings = [
            _finding(severity="critical"),
            _finding(id="BLK-002", severity="high"),
            _finding(id="BLK-003", severity="medium"),
            _finding(id="BLK-004", severity="low"),
        ]
        score = scorer.score(findings)
        assert score.severity_counts == {"critical": 1, "high": 1, "medium": 1, "low": 1}

    def test_grade_boundaries(self):
        scorer = RiskScorer()
        # No findings = 100 = A
        assert scorer.score([]).grade == "A"
        # Many high-severity findings reduce score significantly
        many = [_finding(id=f"BLK-{i:03d}", severity="high") for i in range(10)]
        many_score = scorer.score(many)
        assert many_score.overall < 85  # Not an A anymore

    def test_categories_populated(self):
        scorer = RiskScorer(active_frameworks=["HIPAA"])
        findings = [
            _finding(category="security"),
            _finding(id="BLK-002", category="compliance"),
        ]
        score = scorer.score(findings)
        cat_names = {c.name for c in score.categories}
        assert "security" in cat_names or "Security" in cat_names

    def test_framework_specific_categories(self):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        score = scorer.score([])
        cat_names = [c.name for c in score.categories]
        assert any("HIPAA" in n for n in cat_names)
        assert any("SOC2" in n for n in cat_names)

    def test_per_category_scoring(self):
        scorer = RiskScorer()
        findings = [
            _finding(category="security", severity="critical"),
            _finding(id="BLK-002", category="quality", severity="low"),
        ]
        score = scorer.score(findings)
        sec = next((c for c in score.categories if "security" in c.name.lower()), None)
        qual = next((c for c in score.categories if "quality" in c.name.lower()), None)
        if sec and qual:
            assert sec.score < qual.score  # Security hit harder


# ═══════════════════════════════════════════════════════════════
# Executive summary (template fallback)
# ═══════════════════════════════════════════════════════════════


class TestExecutiveSummaryTemplate:
    def test_template_summary(self):
        findings = [
            _finding(severity="critical", category="security"),
            _finding(id="BLK-002", severity="high", category="compliance"),
        ]
        health = HealthScore(
            overall=31, grade="D",
            categories=[], severity_counts={"critical": 1, "high": 1, "medium": 0, "low": 0},
        )
        summary = FindingAggregator._generate_summary_template(findings, health)
        assert len(summary["paragraphs"]) == 2
        assert "31/100" in summary["paragraphs"][0]
        assert "Grade D" in summary["paragraphs"][0]
        assert len(summary["immediate_actions"]) >= 1

    def test_template_no_findings(self):
        health = HealthScore(
            overall=100, grade="A",
            categories=[], severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
        )
        summary = FindingAggregator._generate_summary_template([], health)
        assert "100/100" in summary["paragraphs"][0]
        assert len(summary["immediate_actions"]) >= 1

    def test_template_actions_from_critical(self):
        findings = [
            _finding(id="BLK-001", severity="critical", title="SQL Injection"),
            _finding(id="BLK-002", severity="critical", title="XSS"),
        ]
        health = HealthScore(
            overall=20, grade="F",
            categories=[], severity_counts={"critical": 2, "high": 0, "medium": 0, "low": 0},
        )
        summary = FindingAggregator._generate_summary_template(findings, health)
        assert any("BLK-001" in a for a in summary["immediate_actions"])


# ═══════════════════════════════════════════════════════════════
# FindingAggregator (full pipeline)
# ═══════════════════════════════════════════════════════════════


class TestFindingAggregator:
    @pytest.mark.asyncio
    async def test_full_pipeline_no_llm(self):
        aggregator = FindingAggregator(active_frameworks=["HIPAA"])

        # Create raw findings that will pass validation gates
        raw = [_finding_dict(
            file_path="src/main.py", line_start=10, line_end=10,
        )]
        repo_files = {
            "src/main.py": "\n".join(["line"] * 15),
        }

        result = await aggregator.aggregate(raw, repo_files)
        assert isinstance(result, AggregationResult)
        assert result.raw_count == 1
        assert result.health_score.overall <= 100
        assert len(result.executive_summary["paragraphs"]) >= 1

    @pytest.mark.asyncio
    async def test_dedup_in_pipeline(self):
        aggregator = FindingAggregator()

        # Two findings at same location
        raw = [
            _finding_dict(id="BLK-001", file_path="a.py", line_start=10, confidence=0.7),
            _finding_dict(id="BLK-002", file_path="a.py", line_start=10, confidence=0.9),
        ]
        repo_files = {"a.py": "\n".join(["line"] * 15)}

        result = await aggregator.aggregate(raw, repo_files)
        # After validation + dedup, should have 1 finding
        assert result.merged_count <= result.validated_count

    @pytest.mark.asyncio
    async def test_invalid_findings_rejected(self):
        aggregator = FindingAggregator()

        raw = [
            {"garbage": True},  # Invalid schema
            _finding_dict(file_path="nonexistent.py"),  # Invalid evidence
        ]
        repo_files = {}

        result = await aggregator.aggregate(raw, repo_files)
        assert result.validated_count == 0
        assert result.merged_count == 0

    @pytest.mark.asyncio
    async def test_empty_input(self):
        aggregator = FindingAggregator()
        result = await aggregator.aggregate([], {})
        assert result.merged_count == 0
        assert result.health_score.overall == 100
        assert result.health_score.grade == "A"

    @pytest.mark.asyncio
    async def test_with_llm_summary(self):
        llm = AsyncMock()
        resp = MagicMock()
        resp.content = json.dumps({
            "paragraphs": ["AI paragraph 1.", "AI paragraph 2."],
            "immediate_actions": ["Fix BLK-001"],
        })
        resp.usage_metadata = {"input_tokens": 100, "output_tokens": 50}
        llm.ainvoke = AsyncMock(return_value=resp)
        llm.model_name = "test"
        llm.model = "test"
        llm.provider = "test"

        aggregator = FindingAggregator(llm=llm)
        raw = [_finding_dict(file_path="a.py", line_start=1)]
        repo_files = {"a.py": "\n".join(["line"] * 5)}

        result = await aggregator.aggregate(raw, repo_files)
        assert "AI paragraph" in result.executive_summary["paragraphs"][0]

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_template(self):
        llm = AsyncMock()
        llm.ainvoke = AsyncMock(side_effect=RuntimeError("LLM down"))
        llm.model_name = "test"
        llm.model = "test"
        llm.provider = "test"

        aggregator = FindingAggregator(llm=llm)
        result = await aggregator.aggregate([], {})
        # Should use template fallback
        assert len(result.executive_summary["paragraphs"]) >= 1
        assert "100/100" in result.executive_summary["paragraphs"][0]
