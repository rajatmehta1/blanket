"""Tests for BlastRadiusComputer, CallChainTracer, DollarImpactEstimator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from blanketaudit.models.finding import AuditFinding, BlastRadius, CallChainStep, ComplianceRef, Evidence
from blanketaudit.scoring.blast_radius import BlastRadiusComputer
from blanketaudit.scoring.call_chain_tracer import CallChainTracer
from blanketaudit.scoring.dollar_impact_estimator import (
    PENALTY_DATA,
    DollarImpactEstimator,
)


# ── Helpers ──────────────────────────────────────────────────


def _finding(
    title: str = "SQL Injection in Patient Search",
    severity: str = "critical",
    file_path: str = "src/service.py",
    repo_name: str = "patient-api",
    line_start: int = 42,
    compliance_refs: list | None = None,
    blast_radius: BlastRadius | None = None,
) -> AuditFinding:
    return AuditFinding(
        id="BLK-001", policy_id="SEC-001",
        title=title, description=f"Finding: {title}",
        severity=severity, category="security",
        confidence=0.9, source="static",
        evidence=[Evidence(
            file_path=file_path, repo_name=repo_name,
            line_start=line_start, line_end=line_start + 3,
            code_snippet='cursor.execute(f"SELECT * FROM patients WHERE id={uid}")',
            tool="semgrep",
        )],
        compliance_refs=compliance_refs or [],
        ai_explanation="", fix_code="", remediation="",
        effort_hours=2.0, dollar_impact="",
        blast_radius=blast_radius,
    )


def _ref(fw: str, clause: str = "§0"):
    return ComplianceRef(framework=fw, clause=clause, title="Control")


def _mock_graph(
    callers: list[dict] | None = None,
    entry_points: list[dict] | None = None,
    call_chains: list[list[str]] | None = None,
):
    store = AsyncMock()
    store.get_callers = AsyncMock(return_value=callers or [])
    store.get_entry_points = AsyncMock(return_value=entry_points or [])
    store.get_call_chain = AsyncMock(return_value=call_chains or [])
    return store


# ═══════════════════════════════════════════════════════════════
# BlastRadiusComputer
# ═══════════════════════════════════════════════════════════════


class TestBlastRadiusComputer:
    @pytest.mark.asyncio
    async def test_computes_with_graph(self):
        graph = _mock_graph(
            callers=[{"name": "handler", "file": "routes.py"}],
            entry_points=[
                {"name": "handler", "file": "routes.py", "repo": "api", "route": "GET /patients"},
                {"name": "admin_handler", "file": "admin.py", "repo": "api"},
            ],
        )
        computer = BlastRadiusComputer(domain="healthcare")
        finding = _finding(title="SQL Injection in patient search")

        br = await computer.compute(finding, graph)
        assert br.entry_points >= 1
        assert br.repos_affected >= 1
        assert br.daily_calls != "unknown"
        assert br.affected_users != "unknown"

    @pytest.mark.asyncio
    async def test_no_graph_returns_default(self):
        computer = BlastRadiusComputer()
        br = await computer.compute(_finding(), None)
        assert br.entry_points == 0
        assert br.repos_affected == 1
        assert br.daily_calls == "unknown"

    @pytest.mark.asyncio
    async def test_no_evidence_returns_default(self):
        computer = BlastRadiusComputer()
        f = _finding()
        f = f.model_copy(update={"evidence": []})
        br = await computer.compute(f, _mock_graph())
        assert br.entry_points == 0

    @pytest.mark.asyncio
    async def test_healthcare_domain_patient_users(self):
        graph = _mock_graph(
            callers=[{"name": "get_patient", "file": "routes.py"}],
            entry_points=[{"name": "get_patient", "route": "/patients/{id}"}],
        )
        computer = BlastRadiusComputer(domain="healthcare")
        br = await computer.compute(_finding(title="SQL in patient endpoint"), graph)
        assert "patient" in br.affected_users.lower()

    @pytest.mark.asyncio
    async def test_finance_domain(self):
        graph = _mock_graph(
            callers=[{"name": "charge", "file": "pay.py"}],
            entry_points=[{"name": "charge", "route": "/payment/charge"}],
        )
        computer = BlastRadiusComputer(domain="finance")
        br = await computer.compute(_finding(title="SQL in payment"), graph)
        assert "cardholder" in br.affected_users.lower() or "user" in br.affected_users.lower()

    @pytest.mark.asyncio
    async def test_graph_error_returns_default(self):
        graph = AsyncMock()
        graph.get_entry_points = AsyncMock(side_effect=RuntimeError("down"))
        computer = BlastRadiusComputer()
        br = await computer.compute(_finding(), graph)
        assert br.entry_points == 0
        assert br.daily_calls == "unknown"


# ═══════════════════════════════════════════════════════════════
# CallChainTracer
# ═══════════════════════════════════════════════════════════════


class TestCallChainTracer:
    @pytest.mark.asyncio
    async def test_traces_chain(self):
        graph = _mock_graph(
            entry_points=[
                {"name": "api::routes.py::handler", "route": "POST /patients", "repo": "api"},
            ],
            call_chains=[["api::routes.py::handler", "api::service.py::search", "api::db.py::query"]],
        )
        tracer = CallChainTracer()
        chain = await tracer.trace(_finding(), graph)

        assert len(chain) == 3
        assert chain[0].step_type == "entry"
        assert chain[-1].step_type == "sink"
        assert all(isinstance(s, CallChainStep) for s in chain)

    @pytest.mark.asyncio
    async def test_no_graph_returns_minimal(self):
        tracer = CallChainTracer()
        chain = await tracer.trace(_finding(), None)
        assert len(chain) == 1
        assert chain[0].step_type == "sink"

    @pytest.mark.asyncio
    async def test_no_entries_returns_minimal(self):
        graph = _mock_graph(entry_points=[])
        tracer = CallChainTracer()
        chain = await tracer.trace(_finding(), graph)
        assert len(chain) == 1

    @pytest.mark.asyncio
    async def test_cross_repo_step_classified(self):
        graph = _mock_graph(
            entry_points=[{"name": "api::routes.py::handler"}],
            call_chains=[[
                "api::routes.py::handler",
                "api::client.py::submit",
                "engine::controller.py::charge",  # Different repo!
                "engine::db.py::execute",          # Same repo as prev → sink
            ]],
        )
        tracer = CallChainTracer()
        chain = await tracer.trace(_finding(), graph)
        assert len(chain) == 4
        step_types = [s.step_type for s in chain]
        assert step_types[0] == "entry"
        assert "cross_repo" in step_types
        assert step_types[-1] == "sink"

    @pytest.mark.asyncio
    async def test_no_evidence_returns_empty(self):
        tracer = CallChainTracer()
        f = _finding()
        f = f.model_copy(update={"evidence": []})
        chain = await tracer.trace(f, _mock_graph())
        assert chain == []

    @pytest.mark.asyncio
    async def test_graph_error_returns_minimal(self):
        graph = AsyncMock()
        graph.get_entry_points = AsyncMock(side_effect=RuntimeError("err"))
        tracer = CallChainTracer()
        chain = await tracer.trace(_finding(), graph)
        assert len(chain) == 1


# ═══════════════════════════════════════════════════════════════
# DollarImpactEstimator
# ═══════════════════════════════════════════════════════════════


class TestDollarImpactEstimator:
    @pytest.mark.asyncio
    async def test_critical_hipaa_finding(self):
        estimator = DollarImpactEstimator(domain="healthcare")
        finding = _finding(
            severity="critical",
            compliance_refs=[_ref("HIPAA", "§164.312(a)(1)")],
        )
        result = await estimator.estimate(finding)
        assert "$" in result
        assert "—" in result  # Range format

    @pytest.mark.asyncio
    async def test_medium_finding_lower_impact(self):
        estimator = DollarImpactEstimator()
        critical = await estimator.estimate(
            _finding(severity="critical", compliance_refs=[_ref("PCI-DSS")])
        )
        medium = await estimator.estimate(
            _finding(severity="medium", compliance_refs=[_ref("PCI-DSS")])
        )
        # Parse the lower bound of each range
        def parse_low(s):
            import re
            m = re.search(r"\$([\d,.]+[MK]?)", s)
            if not m:
                return 0
            v = m.group(1).replace(",", "")
            if v.endswith("M"):
                return float(v[:-1]) * 1_000_000
            if v.endswith("K"):
                return float(v[:-1]) * 1_000
            return float(v)

        assert parse_low(critical) >= parse_low(medium)

    @pytest.mark.asyncio
    async def test_with_blast_radius(self):
        estimator = DollarImpactEstimator(domain="healthcare")
        br = BlastRadius(
            entry_points=5, repos_affected=2,
            daily_calls="~10,000/day", affected_users="All patients",
        )
        finding = _finding(
            severity="critical",
            compliance_refs=[_ref("HIPAA")],
            blast_radius=br,
        )
        result = await estimator.estimate(finding)
        assert "$" in result

    @pytest.mark.asyncio
    async def test_no_compliance_refs_uses_severity_floor(self):
        estimator = DollarImpactEstimator()
        result = await estimator.estimate(_finding(severity="high", compliance_refs=[]))
        assert "$" in result

    @pytest.mark.asyncio
    async def test_low_severity_lower_floor(self):
        estimator = DollarImpactEstimator()
        result = await estimator.estimate(_finding(severity="low", compliance_refs=[]))
        assert "$" in result
        # Should contain relatively small numbers
        assert "100" in result or "1,000" in result or "5,000" in result

    @pytest.mark.asyncio
    async def test_multiple_frameworks_compound(self):
        estimator = DollarImpactEstimator()
        finding = _finding(
            severity="critical",
            compliance_refs=[_ref("HIPAA"), _ref("PCI-DSS"), _ref("GDPR")],
        )
        result = await estimator.estimate(finding)
        assert "$" in result
        # Multiple frameworks should increase the range

    @pytest.mark.asyncio
    async def test_format_range(self):
        assert "$" in DollarImpactEstimator._format_range(5000, 100000)
        assert "—" in DollarImpactEstimator._format_range(5000, 100000)

    @pytest.mark.asyncio
    async def test_format_millions(self):
        result = DollarImpactEstimator._format_range(500_000, 2_000_000)
        assert "M" in result

    def test_penalty_data_covers_major_frameworks(self):
        assert "HIPAA" in PENALTY_DATA
        assert "PCI-DSS" in PENALTY_DATA
        assert "GDPR" in PENALTY_DATA
        assert "SOC2" in PENALTY_DATA

    @pytest.mark.asyncio
    async def test_with_llm(self):
        llm = AsyncMock()
        resp = MagicMock()
        resp.content = "$50,000 — $1,900,000"
        resp.usage_metadata = {"input_tokens": 100, "output_tokens": 50}
        llm.ainvoke = AsyncMock(return_value=resp)
        llm.model_name = "test"
        llm.model = "test"
        llm.provider = "test"

        estimator = DollarImpactEstimator(domain="healthcare", llm=llm)
        result = await estimator.estimate(_finding())
        assert "$50,000" in result

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back(self):
        llm = AsyncMock()
        llm.ainvoke = AsyncMock(side_effect=RuntimeError("LLM down"))
        llm.model_name = "test"
        llm.model = "test"
        llm.provider = "test"

        estimator = DollarImpactEstimator(llm=llm)
        result = await estimator.estimate(_finding(severity="high", compliance_refs=[]))
        assert "$" in result  # Falls back to rules
