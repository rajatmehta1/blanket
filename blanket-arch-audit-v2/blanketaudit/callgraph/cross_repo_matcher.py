"""Match HTTP client calls <-> endpoint handlers across repos.

Design doc Tier 2.5: cross-repo call graph matching.
Matches HTTP client library calls (requests, httpx, axios, fetch, RestTemplate, WebClient)
to server-side endpoint handlers detected by the entry point detector.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import structlog

from blanketaudit.callgraph.static_builder import CallEdge, CallGraph
from blanketaudit.ingestion.models import AnalysisContext, CallInfo, EntryPointInfo

logger = structlog.get_logger()


@dataclass
class CrossRepoMatch:
    """A matched HTTP client call -> endpoint handler pair."""
    client_method: str       # Qualified caller in the client repo
    client_repo: str
    server_method: str       # Qualified handler in the server repo
    server_repo: str
    http_method: str         # GET, POST, etc.
    route: str               # Normalized path
    client_file: str
    client_line: int


# -- HTTP client detection patterns ----------------------------------------

# Pattern: (library/object).(method) -> HTTP method
# Python
_PYTHON_HTTP_PATTERNS: dict[str, str] = {
    "requests.get": "GET", "requests.post": "POST", "requests.put": "PUT",
    "requests.delete": "DELETE", "requests.patch": "PATCH",
    "httpx.get": "GET", "httpx.post": "POST", "httpx.put": "PUT",
    "httpx.delete": "DELETE", "httpx.patch": "PATCH",
    # Instance methods: client.get, session.get, etc.
    ".get(": "GET", ".post(": "POST", ".put(": "PUT",
    ".delete(": "DELETE", ".patch(": "PATCH",
}

# Java
_JAVA_HTTP_PATTERNS: dict[str, str] = {
    "restTemplate.getForObject": "GET", "restTemplate.getForEntity": "GET",
    "restTemplate.postForObject": "POST", "restTemplate.postForEntity": "POST",
    "restTemplate.put": "PUT", "restTemplate.delete": "DELETE",
    "restTemplate.exchange": "",  # Method determined by HttpMethod param
    "webClient.get": "GET", "webClient.post": "POST",
    "webClient.put": "PUT", "webClient.delete": "DELETE",
}

# TypeScript / JavaScript
_TS_HTTP_PATTERNS: dict[str, str] = {
    "fetch": "",  # Method in options object
    "axios.get": "GET", "axios.post": "POST", "axios.put": "PUT",
    "axios.delete": "DELETE", "axios.patch": "PATCH",
    "axios(": "",  # Method in config object
}

# Combine all patterns
_ALL_HTTP_PATTERNS: dict[str, str] = {
    **_PYTHON_HTTP_PATTERNS,
    **_JAVA_HTTP_PATTERNS,
    **_TS_HTTP_PATTERNS,
}

# Regex to extract URL paths from call arguments
# Matches quoted strings that look like URL paths: "/api/...", "http://host/api/..."
_URL_PATH_RE = re.compile(
    r"""['"`](?:https?://[^/'"]+)?(/[a-zA-Z0-9_/{}\-:.*]+)['"`]"""
)


def _normalize_path(path: str) -> str:
    """Normalize a URL path for matching.

    - Strip trailing slashes
    - Replace path parameters: {id}, :id, {user_id} -> {param}
    - Lowercase
    """
    path = path.rstrip("/")
    # Replace {xxx} and :xxx style params
    path = re.sub(r"\{[^}]+\}", "{param}", path)
    path = re.sub(r":([a-zA-Z_]\w*)", "{param}", path)
    # Replace ** glob patterns
    path = re.sub(r"\*\*", "{glob}", path)
    return path.lower()


def _detect_http_call(call: CallInfo) -> tuple[str, str] | None:
    """Check if a CallInfo represents an HTTP client call.

    Returns (http_method, raw_url_hint) or None.
    """
    callee_lower = call.callee.lower()

    for pattern, method in _ALL_HTTP_PATTERNS.items():
        if pattern.lower() in callee_lower:
            return (method or "GET", "")  # URL extracted separately
    return None


class CrossRepoMatcher:
    """Match HTTP client calls to endpoint handlers across repositories.

    Usage::

        matcher = CrossRepoMatcher()
        matches = matcher.match(
            contexts=[ctx_api, ctx_engine],
            entry_points=all_entry_points,
        )
    """

    def match(
        self,
        contexts: list[AnalysisContext],
        entry_points: list[EntryPointInfo],
    ) -> list[CrossRepoMatch]:
        """Find cross-repo HTTP call -> handler matches.

        Parameters
        ----------
        contexts:
            AnalysisContext per repo (contains calls with callee names).
        entry_points:
            All detected entry points across all repos.
        """
        # Build endpoint index: normalized_path -> list of EntryPointInfo
        endpoint_index = self._build_endpoint_index(entry_points)

        matches: list[CrossRepoMatch] = []

        for ctx in contexts:
            for call in ctx.calls:
                http_info = _detect_http_call(call)
                if http_info is None:
                    continue

                http_method, _ = http_info

                # Try to extract URL path from callee text
                url_match = _URL_PATH_RE.search(call.callee)
                if url_match is None:
                    continue

                raw_path = url_match.group(1)
                norm_path = _normalize_path(raw_path)

                # Look up in endpoint index
                candidates = endpoint_index.get(norm_path, [])
                for ep in candidates:
                    # Skip same-repo matches (those are intra-repo calls)
                    if ep.repo_name == ctx.repo_name:
                        continue
                    # Match HTTP method if both are specified
                    if http_method and ep.http_method and http_method != ep.http_method:
                        continue

                    matches.append(CrossRepoMatch(
                        client_method=call.caller,
                        client_repo=ctx.repo_name,
                        server_method=ep.method_name,
                        server_repo=ep.repo_name,
                        http_method=http_method or ep.http_method,
                        route=ep.route,
                        client_file=call.file_path,
                        client_line=call.line_number,
                    ))

        logger.info("cross_repo.matched", match_count=len(matches))
        return matches

    def add_to_graph(
        self,
        graph: CallGraph,
        matches: list[CrossRepoMatch],
    ) -> None:
        """Add cross-repo matches as edges in the call graph."""
        for m in matches:
            edge = CallEdge(
                caller=f"{m.client_repo}::??::{m.client_method}",
                callee=f"{m.server_repo}::??::{m.server_method}",
                caller_repo=m.client_repo,
                callee_repo=m.server_repo,
                file_path=m.client_file,
                line_number=m.client_line,
                call_type="http",
                resolved=True,
            )
            graph.add_edge(edge)

    @staticmethod
    def _build_endpoint_index(
        entry_points: list[EntryPointInfo],
    ) -> dict[str, list[EntryPointInfo]]:
        """Index entry points by normalized route path."""
        index: dict[str, list[EntryPointInfo]] = {}
        for ep in entry_points:
            if not ep.route:
                continue
            norm = _normalize_path(ep.route)
            index.setdefault(norm, []).append(ep)
        return index
