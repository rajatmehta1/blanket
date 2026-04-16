"""Compute BlastRadius per finding from the call graph.

Queries the graph store (Neo4j or InMemoryGraph) to determine how many
entry points can reach the vulnerable method, which repos are affected,
and estimates daily call volume and affected user groups.
"""

from __future__ import annotations

from collections import deque
from typing import Any

import structlog

from blanketaudit2.models.finding import AuditFinding, BlastRadius

logger = structlog.get_logger()

# Daily call volume estimates by entry point type
_CALL_ESTIMATES: dict[str, str] = {
    "GET": "~5,000/day",
    "POST": "~2,000/day",
    "PUT": "~500/day",
    "DELETE": "~200/day",
    "PATCH": "~300/day",
    "": "~1,000/day",  # Unknown method
}

# Domain → affected user inference
_DOMAIN_USER_MAP: dict[str, dict[str, str]] = {
    "healthcare": {
        "patient": "All patients",
        "claim": "Insurance claimants",
        "provider": "Healthcare providers",
        "default": "Healthcare users",
    },
    "finance": {
        "payment": "All cardholders",
        "account": "Account holders",
        "transaction": "Transaction participants",
        "default": "Financial service users",
    },
    "general": {
        "user": "All users",
        "auth": "All authenticated users",
        "admin": "System administrators",
        "default": "Application users",
    },
}


class BlastRadiusComputer:
    """Compute BlastRadius for each finding using the call graph."""

    def __init__(self, domain: str = "general") -> None:
        self._domain = domain

    async def compute(
        self,
        finding: AuditFinding,
        graph_store: Any,
    ) -> BlastRadius:
        """Compute blast radius for a finding.

        Parameters
        ----------
        finding:
            The finding to compute blast radius for.
        graph_store:
            A graph store (Neo4jStore or InMemoryGraph) with
            ``get_callers``, ``get_entry_points`` methods.

        Returns
        -------
        BlastRadius with entry_points, repos_affected, daily_calls,
        affected_users.
        """
        if graph_store is None:
            return self._default_blast_radius(finding)

        method_id = self._find_method_id(finding)
        if not method_id:
            return self._default_blast_radius(finding)

        try:
            # Reverse BFS to find reaching entry points
            reaching_entries, repos = await self._reverse_bfs(method_id, graph_store)

            daily_calls = self._estimate_daily_calls(reaching_entries)
            affected_users = self._infer_affected_users(finding, reaching_entries)

            return BlastRadius(
                entry_points=len(reaching_entries),
                repos_affected=len(repos),
                daily_calls=daily_calls,
                affected_users=affected_users,
            )
        except Exception as exc:
            logger.warning("blast_radius.compute_failed", error=str(exc)[:200])
            return self._default_blast_radius(finding)

    async def _reverse_bfs(
        self,
        method_id: str,
        graph_store: Any,
    ) -> tuple[list[dict], set[str]]:
        """Reverse BFS from method to find all reaching entry points."""
        all_entries = await graph_store.get_entry_points()
        entry_names = {e.get("name", "") for e in all_entries}

        visited: set[str] = set()
        queue: deque[str] = deque([method_id])
        reaching: list[dict] = []
        repos: set[str] = set()

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            # Extract repo from qualified ID
            parts = current.split("::")
            if parts:
                repos.add(parts[0])

            if current in entry_names:
                entry = next((e for e in all_entries if e.get("name") == current), {})
                reaching.append(entry)

            callers = await graph_store.get_callers(current)
            for caller in callers:
                caller_name = caller.get("name", "")
                if caller_name and caller_name not in visited:
                    queue.append(caller_name)

        return reaching, repos

    @staticmethod
    def _find_method_id(finding: AuditFinding) -> str:
        """Extract the likely method ID from a finding's evidence."""
        if not finding.evidence:
            return ""
        ev = finding.evidence[0]
        return f"{ev.repo_name}::{ev.file_path}::line{ev.line_start}"

    def _estimate_daily_calls(self, entries: list[dict]) -> str:
        """Estimate daily call volume from entry point types."""
        if not entries:
            return "unknown"
        # Sum estimates from all reaching entry points
        total = 0
        for entry in entries:
            route = entry.get("route", "") or entry.get("name", "")
            # Infer HTTP method from route name
            method = ""
            for m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                if m.lower() in route.lower():
                    method = m
                    break
            estimate_str = _CALL_ESTIMATES.get(method, _CALL_ESTIMATES[""])
            # Parse the number
            import re
            match = re.search(r"~?([\d,]+)", estimate_str)
            if match:
                total += int(match.group(1).replace(",", ""))
        return f"~{total:,}/day" if total > 0 else "~1,000/day"

    def _infer_affected_users(
        self,
        finding: AuditFinding,
        entries: list[dict],
    ) -> str:
        """Infer affected user group from domain + endpoint context."""
        domain_map = _DOMAIN_USER_MAP.get(self._domain, _DOMAIN_USER_MAP["general"])
        context = finding.title.lower()
        if finding.evidence:
            context += " " + finding.evidence[0].file_path.lower()

        for keyword, user_group in domain_map.items():
            if keyword != "default" and keyword in context:
                return user_group

        # Check entry point routes
        for entry in entries:
            route = (entry.get("route", "") or entry.get("name", "")).lower()
            for keyword, user_group in domain_map.items():
                if keyword != "default" and keyword in route:
                    return user_group

        return domain_map.get("default", "Application users")

    @staticmethod
    def _default_blast_radius(finding: AuditFinding) -> BlastRadius:
        """Default when graph is unavailable."""
        return BlastRadius(
            entry_points=0,
            repos_affected=1,
            daily_calls="unknown",
            affected_users="unknown",
        )
