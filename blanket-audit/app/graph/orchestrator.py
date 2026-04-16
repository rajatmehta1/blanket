"""LangGraph orchestrator — wires ingestion, parallel agents, and report generation."""
from __future__ import annotations

from langgraph.graph import StateGraph, START, END

from app.agents.architecture_risk_agent import analyze_architecture_risk
from app.agents.cost_optimization_agent import analyze_cost_optimization
from app.agents.scalability_agent import analyze_scalability
from app.agents.security_agent import analyze_security
from app.ingestion.code_parser import parse_repository
from app.models.state import AuditState
from app.reports.generator import generate_report


def build_graph() -> StateGraph:
    """Build and compile the audit pipeline graph."""
    graph = StateGraph(AuditState)

    # nodes
    graph.add_node("parse", parse_repository)
    graph.add_node("arch_risk", analyze_architecture_risk)
    graph.add_node("security", analyze_security)
    graph.add_node("scalability", analyze_scalability)
    graph.add_node("cost_opt", analyze_cost_optimization)
    graph.add_node("report", generate_report)

    # edges: parse first, then fan-out to agents in parallel, then report
    graph.add_edge(START, "parse")
    graph.add_edge("parse", "arch_risk")
    graph.add_edge("parse", "security")
    graph.add_edge("parse", "scalability")
    graph.add_edge("parse", "cost_opt")
    graph.add_edge("arch_risk", "report")
    graph.add_edge("security", "report")
    graph.add_edge("scalability", "report")
    graph.add_edge("cost_opt", "report")
    graph.add_edge("report", END)

    return graph.compile()
