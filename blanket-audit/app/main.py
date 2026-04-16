"""Blanket Audit — CLI entry point.

Usage:
    python -m app.main <repo_path_or_url> [--profile saas|startup|ai_team]

Examples:
    python -m app.main .
    python -m app.main /path/to/repo --profile saas
    python -m app.main https://github.com/user/repo.git --profile ai_team
"""
import argparse
import asyncio
import logging
import sys

from app.graph.orchestrator import build_graph
from app.models.common import CustomerProfile


def main():
    parser = argparse.ArgumentParser(description="Blanket Audit — architecture audit for git repositories")
    parser.add_argument("repo", help="Local path or git URL of the repository to audit")
    parser.add_argument(
        "--profile",
        choices=[p.value for p in CustomerProfile],
        default=CustomerProfile.STARTUP.value,
        help="Customer profile (default: startup)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    initial_state = {
        "repo_url": args.repo,
        "customer_profile": CustomerProfile(args.profile),
        "repo_metadata": None,
        "parsed_files": [],
        "graph_populated": False,
        "embeddings_populated": False,
        "architecture_findings": [],
        "scalability_findings": [],
        "security_findings": [],
        "cost_findings": [],
        "domain_findings": [],
        "detected_domains": [],
        "errors": [],
        "agent_logs": [],
    }

    graph = build_graph()
    result = asyncio.run(graph.ainvoke(initial_state))

    # exit with non-zero if critical findings
    all_findings = (
        result.get("architecture_findings", [])
        + result.get("security_findings", [])
        + result.get("scalability_findings", [])
        + result.get("cost_findings", [])
    )
    criticals = [f for f in all_findings if f.get("severity") == "critical"]
    if criticals:
        sys.exit(1)


if __name__ == "__main__":
    main()
