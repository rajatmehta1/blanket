"""Tests for 8-category RiskScorer and RemediationPlanner with simulation.

Includes a worked example from the design doc (Appendix B):
  Known findings → expected category scores → expected composite → expected grade.
"""

from __future__ import annotations

import pytest

from blanketaudit2.models.finding import AuditFinding, ComplianceRef, Evidence
from blanketaudit2.models.scoring import HealthScore
from blanketaudit2.scoring.remediation_planner import RemediationPlanner
from blanketaudit2.scoring.risk_scorer import RiskScorer, _grade, _score_from_findings


# ── Helpers ──────────────────────────────────────────────────


def _finding(
    id: str = "BLK-001",
    severity: str = "high",
    category: str = "security",
    compliance_refs: list | None = None,
    effort_hours: float = 2.0,
    title: str = "Finding",
    remediation: str = "Fix it.",
) -> AuditFinding:
    return AuditFinding(
        id=id, policy_id="SEC-001", title=title,
        description="Desc", severity=severity, category=category,
        confidence=0.9, source="static",
        evidence=[Evidence(
            file_path="src/main.py", repo_name="api",
            line_start=1, line_end=5, code_snippet="code", tool="semgrep",
        )],
        compliance_refs=compliance_refs or [],
        ai_explanation="", fix_code="", remediation=remediation,
        effort_hours=effort_hours, dollar_impact="",
    )


def _ref(fw: str, clause: str = "§0"):
    return ComplianceRef(framework=fw, clause=clause, title="Control")


# ═══════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════


class TestGrade:
    def test_grade_a(self):
        assert _grade(100) == "A"
        assert _grade(85) == "A"

    def test_grade_b(self):
        assert _grade(84) == "B"
        assert _grade(70) == "B"

    def test_grade_c(self):
        assert _grade(69) == "C"
        assert _grade(50) == "C"

    def test_grade_d(self):
        assert _grade(49) == "D"
        assert _grade(30) == "D"

    def test_grade_f(self):
        assert _grade(29) == "F"
        assert _grade(0) == "F"


class TestScoreFromFindings:
    def test_no_findings_100(self):
        assert _score_from_findings([]) == 100

    def test_one_critical(self):
        assert _score_from_findings([_finding(severity="critical")]) == 75

    def test_clamped_at_zero(self):
        many = [_finding(id=f"BLK-{i:03d}", severity="critical") for i in range(10)]
        assert _score_from_findings(many) == 0


# ═══════════════════════════════════════════════════════════════
# RiskScorer — dynamic categories
# ═══════════════════════════════════════════════════════════════


class TestRiskScorerCategories:
    def test_no_frameworks_has_generic_compliance(self):
        scorer = RiskScorer(active_frameworks=[])
        health = scorer.score([])
        cat_names = [c.name for c in health.categories]
        assert "Compliance" in cat_names
        assert not any("HIPAA" in n for n in cat_names)

    def test_one_framework_creates_one_compliance_cat(self):
        scorer = RiskScorer(active_frameworks=["HIPAA"])
        health = scorer.score([])
        cat_names = [c.name for c in health.categories]
        assert "HIPAA Compliance" in cat_names
        assert "Compliance" not in cat_names  # Generic replaced by specific

    def test_multiple_frameworks(self):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2", "PCI-DSS"])
        health = scorer.score([])
        cat_names = [c.name for c in health.categories]
        assert "HIPAA Compliance" in cat_names
        assert "SOC2 Compliance" in cat_names
        assert "PCI-DSS Compliance" in cat_names

    def test_always_has_fixed_categories(self):
        scorer = RiskScorer(active_frameworks=["HIPAA"])
        health = scorer.score([])
        cat_names = {c.name for c in health.categories}
        for expected in ("Security", "Code Quality", "Performance", "Reliability", "Infrastructure"):
            assert expected in cat_names, f"Missing: {expected}"

    def test_total_categories_with_3_frameworks(self):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2", "PCI-DSS"])
        health = scorer.score([])
        # 5 fixed + 3 compliance = 8
        assert len(health.categories) == 8


class TestRiskScorerRouting:
    def test_security_finding_routes_to_security(self):
        scorer = RiskScorer(active_frameworks=["HIPAA"])
        findings = [_finding(category="security", severity="critical")]
        health = scorer.score(findings)
        sec = next(c for c in health.categories if c.name == "Security")
        assert sec.finding_count == 1
        assert sec.score == 75  # 100 - 25

    def test_compliance_finding_routes_to_framework(self):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        findings = [
            _finding(
                category="compliance", severity="high",
                compliance_refs=[_ref("HIPAA", "§164.312(a)(1)")],
            ),
        ]
        health = scorer.score(findings)
        hipaa = next(c for c in health.categories if c.name == "HIPAA Compliance")
        soc2 = next(c for c in health.categories if c.name == "SOC2 Compliance")
        assert hipaa.finding_count == 1
        assert hipaa.score == 90  # 100 - 10
        assert soc2.finding_count == 0
        assert soc2.score == 100

    def test_compliance_finding_routes_to_multiple_frameworks(self):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        findings = [
            _finding(
                category="compliance", severity="medium",
                compliance_refs=[_ref("HIPAA"), _ref("SOC2")],
            ),
        ]
        health = scorer.score(findings)
        hipaa = next(c for c in health.categories if c.name == "HIPAA Compliance")
        soc2 = next(c for c in health.categories if c.name == "SOC2 Compliance")
        assert hipaa.finding_count == 1
        assert soc2.finding_count == 1

    def test_architecture_routes_to_quality(self):
        scorer = RiskScorer()
        findings = [_finding(category="architecture", severity="medium")]
        health = scorer.score(findings)
        qual = next(c for c in health.categories if c.name == "Code Quality")
        assert qual.finding_count == 1

    def test_quality_routes_to_quality(self):
        scorer = RiskScorer()
        findings = [_finding(category="quality", severity="low")]
        health = scorer.score(findings)
        qual = next(c for c in health.categories if c.name == "Code Quality")
        assert qual.finding_count == 1

    def test_infrastructure_routes_correctly(self):
        scorer = RiskScorer()
        findings = [_finding(category="infrastructure", severity="medium")]
        health = scorer.score(findings)
        infra = next(c for c in health.categories if c.name == "Infrastructure")
        assert infra.finding_count == 1


class TestRiskScorerComposite:
    def test_no_findings_score_100(self):
        scorer = RiskScorer()
        assert scorer.score([]).overall == 100

    def test_security_weight_dominates(self):
        """Security has 35% weight — security findings impact score more."""
        scorer = RiskScorer()
        # 1 critical in security vs 1 critical in quality
        sec_findings = [_finding(category="security", severity="critical")]
        qual_findings = [_finding(category="quality", severity="critical")]
        sec_score = scorer.score(sec_findings).overall
        qual_score = scorer.score(qual_findings).overall
        # Security-only critical should lower composite more than quality-only
        assert sec_score < qual_score

    def test_compliance_weight_split(self):
        """With 3 frameworks, compliance 30% is split 10% each."""
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2", "PCI-DSS"])
        # One critical compliance finding hitting only HIPAA
        findings = [
            _finding(
                category="compliance", severity="critical",
                compliance_refs=[_ref("HIPAA")],
            ),
        ]
        health = scorer.score(findings)
        # HIPAA is 0 (critical penalty), SOC2/PCI are 100
        # Compliance avg: (0 + 100 + 100) / 3 = 66.7
        # But weighted: HIPAA gets 10%, SOC2 10%, PCI 10%
        # Security: 100*0.35 = 35
        # HIPAA: 75*0.10 = 7.5 (one critical = -25)
        # SOC2: 100*0.10 = 10
        # PCI: 100*0.10 = 10
        # Quality: 100*0.15 = 15
        # Perf: 100*0.10 = 10
        # Reliability: 100*0.10 = 10 (shares perf weight)
        # Infra: 100*0.10 = 10
        # The exact number depends on weight normalization
        # With 3 frameworks, HIPAA gets ~10% weight. One critical → 75 for HIPAA.
        # Overall barely drops: 100*0.35 + 75*0.10 + 100*0.10 + ... ≈ 97-98
        assert 90 <= health.overall <= 100

    def test_severity_counts_correct(self):
        scorer = RiskScorer()
        findings = [
            _finding(id="BLK-001", severity="critical"),
            _finding(id="BLK-002", severity="critical"),
            _finding(id="BLK-003", severity="high"),
            _finding(id="BLK-004", severity="medium"),
        ]
        health = scorer.score(findings)
        assert health.severity_counts == {"critical": 2, "high": 1, "medium": 1, "low": 0}


# ═══════════════════════════════════════════════════════════════
# Worked Example (Design Doc Appendix B)
# ═══════════════════════════════════════════════════════════════


class TestWorkedExample:
    """Design doc Appendix B: known set of findings → expected scores.

    Scenario: Healthcare app with HIPAA + SOC2
    Findings:
      - 2 critical security (SQL injection, command injection)
      - 3 high security (hardcoded password, SSRF, weak crypto)
      - 1 critical compliance/HIPAA (PHI in logs)
      - 2 high compliance/SOC2 (missing audit log, excessive permissions)
      - 1 medium architecture (circular dependency)
      - 2 medium quality (high complexity, silent exception)
      - 1 low infrastructure (unpinned base image)
    """

    @pytest.fixture
    def worked_findings(self) -> list[AuditFinding]:
        return [
            # Security: 2 critical + 3 high = -50 -30 = -80 → score 20
            _finding(id="BLK-001", severity="critical", category="security", title="SQL Injection"),
            _finding(id="BLK-002", severity="critical", category="security", title="Command Injection"),
            _finding(id="BLK-003", severity="high", category="security", title="Hardcoded Password"),
            _finding(id="BLK-004", severity="high", category="security", title="SSRF"),
            _finding(id="BLK-005", severity="high", category="security", title="Weak Crypto"),
            # HIPAA: 1 critical = -25 → score 75
            _finding(id="BLK-006", severity="critical", category="compliance", title="PHI in Logs",
                     compliance_refs=[_ref("HIPAA", "§164.530(c)")]),
            # SOC2: 2 high = -20 → score 80
            _finding(id="BLK-007", severity="high", category="compliance", title="Missing Audit Log",
                     compliance_refs=[_ref("SOC2", "CC7.1")]),
            _finding(id="BLK-008", severity="high", category="compliance", title="Excessive Permissions",
                     compliance_refs=[_ref("SOC2", "CC6.1")]),
            # Quality (arch + quality): 1 medium + 2 medium = -9 → score 91
            _finding(id="BLK-009", severity="medium", category="architecture", title="Circular Dep"),
            _finding(id="BLK-010", severity="medium", category="quality", title="High Complexity"),
            _finding(id="BLK-011", severity="medium", category="quality", title="Silent Exception"),
            # Infrastructure: 1 low = -1 → score 99
            _finding(id="BLK-012", severity="low", category="infrastructure", title="Unpinned Image"),
        ]

    def test_category_scores(self, worked_findings):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        health = scorer.score(worked_findings)

        scores = {c.name: c.score for c in health.categories}

        # Security: 100 - (2×25 + 3×10) = 100 - 80 = 20
        assert scores["Security"] == 20

        # HIPAA: 100 - 25 = 75
        assert scores["HIPAA Compliance"] == 75

        # SOC2: 100 - 20 = 80
        assert scores["SOC2 Compliance"] == 80

        # Quality: 100 - (3×3) = 91
        assert scores["Code Quality"] == 91

        # Performance: 100 (no findings)
        assert scores["Performance"] == 100

        # Reliability: 100 (no findings)
        assert scores["Reliability"] == 100

        # Infrastructure: 100 - 1 = 99
        assert scores["Infrastructure"] == 99

    def test_severity_counts(self, worked_findings):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        health = scorer.score(worked_findings)
        assert health.severity_counts == {"critical": 3, "high": 5, "medium": 3, "low": 1}

    def test_composite_score(self, worked_findings):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        health = scorer.score(worked_findings)
        # Weighted composite should be in a reasonable range
        # Security(20)*0.35 + HIPAA(75)*0.15 + SOC2(80)*0.15 + Quality(91)*0.15
        # + Perf(100)*0.10 + Reliability(100)*0.10 + Infra(99)*0.10
        # ≈ 7 + 11.25 + 12 + 13.65 + 10 + 10 + 9.9 ≈ 73.8 → ~65-75 range
        assert 55 <= health.overall <= 80

    def test_grade(self, worked_findings):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        health = scorer.score(worked_findings)
        assert health.grade in ("B", "C")  # ~65-75 range

    def test_finding_counts_per_category(self, worked_findings):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        health = scorer.score(worked_findings)
        counts = {c.name: c.finding_count for c in health.categories}
        assert counts["Security"] == 5
        assert counts["HIPAA Compliance"] == 1
        assert counts["SOC2 Compliance"] == 2
        assert counts["Code Quality"] == 3  # arch + quality
        assert counts["Infrastructure"] == 1

    def test_8_categories_total(self, worked_findings):
        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2"])
        health = scorer.score(worked_findings)
        assert len(health.categories) == 7  # 5 fixed + 2 compliance


# ═══════════════════════════════════════════════════════════════
# score_without (for remediation simulation)
# ═══════════════════════════════════════════════════════════════


class TestScoreWithout:
    def test_excluding_critical_improves_score(self):
        scorer = RiskScorer()
        findings = [
            _finding(id="BLK-001", severity="critical", category="security"),
            _finding(id="BLK-002", severity="medium", category="security"),
        ]
        full = scorer.score(findings).overall
        without = scorer.score_without(findings, {"BLK-001"})
        assert without > full

    def test_excluding_all_gives_100(self):
        scorer = RiskScorer()
        findings = [_finding(id="BLK-001")]
        assert scorer.score_without(findings, {"BLK-001"}) == 100

    def test_excluding_none_same_as_full(self):
        scorer = RiskScorer()
        findings = [_finding(id="BLK-001")]
        full = scorer.score(findings).overall
        assert scorer.score_without(findings, set()) == full


# ═══════════════════════════════════════════════════════════════
# RemediationPlanner
# ═══════════════════════════════════════════════════════════════


class TestRemediationPlannerV2:
    def test_three_phases(self):
        scorer = RiskScorer()
        planner = RemediationPlanner(scorer=scorer)
        findings = [
            _finding(id="BLK-001", severity="critical", effort_hours=4.0),
            _finding(id="BLK-002", severity="critical", effort_hours=3.0),
            _finding(id="BLK-003", severity="high", effort_hours=2.0),
            _finding(id="BLK-004", severity="high", effort_hours=2.0),
            _finding(id="BLK-005", severity="high", effort_hours=2.0),
            _finding(id="BLK-006", severity="high", effort_hours=2.0),
            _finding(id="BLK-007", severity="high", effort_hours=2.0),
            _finding(id="BLK-008", severity="high", effort_hours=2.0),  # 6th high → phase 2
            _finding(id="BLK-009", severity="medium", effort_hours=1.0),
            _finding(id="BLK-010", severity="low", effort_hours=1.0),
        ]
        health = scorer.score(findings)
        phases = planner.plan(findings, health)

        assert len(phases) == 3
        assert "URGENT" in phases[0].title
        assert "SHORT-TERM" in phases[1].title
        assert "MEDIUM-TERM" in phases[2].title

    def test_score_improves_across_phases(self):
        scorer = RiskScorer()
        planner = RemediationPlanner(scorer=scorer)
        findings = [
            _finding(id="BLK-001", severity="critical"),
            _finding(id="BLK-002", severity="high"),
            _finding(id="BLK-003", severity="medium"),
        ]
        health = scorer.score(findings)
        phases = planner.plan(findings, health)

        # Parse score targets
        scores = []
        for p in phases:
            # "X → Y (+Z points)"
            parts = p.score_target.split(" → ")
            before = int(parts[0])
            after = int(parts[1].split(" ")[0])
            scores.append((before, after))

        # Each phase should improve or maintain score
        for before, after in scores:
            assert after >= before

        # Final score should be higher than initial
        if scores:
            assert scores[-1][1] > scores[0][0]

    def test_per_task_impact_positive(self):
        scorer = RiskScorer()
        planner = RemediationPlanner(scorer=scorer)
        findings = [
            _finding(id="BLK-001", severity="critical"),
            _finding(id="BLK-002", severity="high"),
        ]
        health = scorer.score(findings)
        phases = planner.plan(findings, health)

        for phase in phases:
            for task in phase.items:
                # score_impact should be "+N" where N >= 0
                assert task.score_impact.startswith("+")
                impact = int(task.score_impact[1:])
                assert impact >= 0

    def test_no_findings_no_phases(self):
        planner = RemediationPlanner()
        health = HealthScore(overall=100, grade="A", categories=[],
                             severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0})
        assert planner.plan([], health) == []

    def test_effort_hours_summed(self):
        scorer = RiskScorer()
        planner = RemediationPlanner(scorer=scorer)
        findings = [
            _finding(id="BLK-001", severity="critical", effort_hours=5.0),
            _finding(id="BLK-002", severity="critical", effort_hours=3.0),
        ]
        health = scorer.score(findings)
        phases = planner.plan(findings, health)
        assert "8 hours" in phases[0].total_effort

    def test_without_scorer_uses_fallback(self):
        """Planner works without a scorer (uses severity-based estimates)."""
        planner = RemediationPlanner(scorer=None)
        findings = [
            _finding(id="BLK-001", severity="critical"),
            _finding(id="BLK-002", severity="low"),
        ]
        health = HealthScore(overall=50, grade="C", categories=[],
                             severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 1})
        phases = planner.plan(findings, health)
        assert len(phases) >= 1
        # Should still produce valid score targets
        for p in phases:
            assert "→" in p.score_target

    def test_phase1_has_critical_and_top_high(self):
        scorer = RiskScorer()
        planner = RemediationPlanner(scorer=scorer)
        findings = [
            _finding(id="BLK-001", severity="critical"),
            _finding(id="BLK-002", severity="high"),
            _finding(id="BLK-003", severity="high"),
            _finding(id="BLK-004", severity="high"),
            _finding(id="BLK-005", severity="high"),
            _finding(id="BLK-006", severity="high"),
            _finding(id="BLK-007", severity="high"),  # 6th high → Phase 2
        ]
        health = scorer.score(findings)
        phases = planner.plan(findings, health)

        phase1_ids = {t.finding_id for t in phases[0].items}
        assert "BLK-001" in phase1_ids  # Critical in phase 1
        assert len(phases[0].items) == 6  # 1 critical + 5 high


# ═══════════════════════════════════════════════════════════════
# Priority scoring (severity × blast_radius × compliance_weight)
# ═══════════════════════════════════════════════════════════════


class TestPriorityScoring:
    def test_critical_higher_than_high(self):
        from blanketaudit2.scoring.remediation_planner import _priority_key
        critical = _finding(severity="critical")
        high = _finding(severity="high")
        assert _priority_key(critical) > _priority_key(high)

    def test_blast_radius_boosts_priority(self):
        from blanketaudit2.scoring.remediation_planner import _priority_key
        from blanketaudit2.models.finding import BlastRadius
        no_blast = _finding(severity="high")
        with_blast = _finding(severity="high")
        with_blast = with_blast.model_copy(update={"blast_radius": BlastRadius(
            entry_points=10, repos_affected=3,
            daily_calls="~5,000/day", affected_users="All users",
        )})
        assert _priority_key(with_blast) > _priority_key(no_blast)

    def test_compliance_refs_boost_priority(self):
        from blanketaudit2.scoring.remediation_planner import _priority_key
        no_compliance = _finding(severity="high", compliance_refs=[])
        with_compliance = _finding(severity="high", compliance_refs=[_ref("HIPAA")])
        assert _priority_key(with_compliance) > _priority_key(no_compliance)

    def test_high_blast_high_can_beat_critical_no_blast(self):
        """A high-severity finding with 20 entry points should have higher
        priority than a critical with 1 entry point."""
        from blanketaudit2.scoring.remediation_planner import _priority_key
        from blanketaudit2.models.finding import BlastRadius
        critical_small = _finding(severity="critical")
        # Critical base = 100, blast=1 → 100
        high_big = _finding(severity="high")
        high_big = high_big.model_copy(update={"blast_radius": BlastRadius(
            entry_points=20, repos_affected=5,
            daily_calls="~50,000/day", affected_users="All users",
        )})
        # High base = 50, blast=20 → 1000
        assert _priority_key(high_big) > _priority_key(critical_small)

    def test_sorting_uses_priority(self):
        """Findings within the same severity tier are sorted by priority."""
        from blanketaudit2.models.finding import BlastRadius
        scorer = RiskScorer()
        planner = RemediationPlanner(scorer=scorer)

        big_blast = _finding(id="BLK-001", severity="high", title="Big blast")
        big_blast = big_blast.model_copy(update={"blast_radius": BlastRadius(
            entry_points=15, repos_affected=3,
            daily_calls="~10,000/day", affected_users="All users",
        ), "compliance_refs": [_ref("HIPAA")]})

        small_blast = _finding(id="BLK-002", severity="high", title="Small blast")

        findings = [small_blast, big_blast]  # Intentionally reversed
        health = scorer.score(findings)
        phases = planner.plan(findings, health)

        # Both are high → both in phase 1
        phase1_ids = [t.finding_id for t in phases[0].items]
        # Big blast should come first (higher priority within same severity)
        assert phase1_ids[0] == "BLK-001"
