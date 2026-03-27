"""Tests for cross_repo_matcher and graph_analyzer."""
from __future__ import annotations

import pytest
from collections import defaultdict

from blanketaudit.callgraph.static_builder import CallGraph, CallEdge
from blanketaudit.callgraph.cross_repo_matcher import (
    CrossRepoMatcher, CrossRepoMatch, _normalize_path, _detect_http_call,
)
from blanketaudit.callgraph.graph_analyzer import GraphAnalyzer, TaintPath
from blanketaudit.ingestion.models import (
    AnalysisContext, CallInfo, EntryPointInfo, MethodInfo,
)


# ── Helpers ──────────────────────────────────────────────────

def _method(name, qualified_name=None, file_path="main.py", repo="api",
            line_start=1, line_end=10, is_entry_point=False, loc=10):
    return MethodInfo(
        name=name, qualified_name=qualified_name or name,
        file_path=file_path, repo_name=repo,
        line_start=line_start, line_end=line_end,
        is_entry_point=is_entry_point, loc=loc,
    )


def _call(caller, callee, file_path="main.py", line=1, call_type="direct"):
    return CallInfo(
        caller=caller, callee=callee,
        file_path=file_path, line_number=line, call_type=call_type,
    )


def _entry_point(method_name, file_path, repo, http_method="GET", route="/"):
    return EntryPointInfo(
        method_name=method_name, file_path=file_path, repo_name=repo,
        http_method=http_method, route=route, framework="fastapi",
    )


def _context(repo="api", methods=None, calls=None, entry_points=None):
    return AnalysisContext(
        repo_name=repo, root_path=f"/tmp/{repo}",
        methods=methods or [], calls=calls or [],
        entry_points=entry_points or [],
    )


def _build_graph(method_specs):
    """Build a CallGraph from a dict of method specs.

    method_specs = {
        "A": {"repo": "api", "file": "a.py", "entry": True, "loc": 10},
        "B": {"repo": "api", "file": "b.py", "entry": False, "loc": 5},
    }
    """
    g = CallGraph()
    for qid, spec in method_specs.items():
        m = _method(
            name=qid.split("::")[-1] if "::" in qid else qid,
            qualified_name=qid.split("::")[-1] if "::" in qid else qid,
            file_path=spec.get("file", "main.py"),
            repo=spec.get("repo", "api"),
            is_entry_point=spec.get("entry", False),
            loc=spec.get("loc", 10),
        )
        g.add_method(qid, m)
    return g


def _add_edges(g, edges):
    for caller, callee in edges:
        # Derive repos from the method registry if available, else default
        caller_repo = "api"
        callee_repo = "api"
        if caller in g.methods:
            caller_repo = g.methods[caller].repo_name
        if callee in g.methods:
            callee_repo = g.methods[callee].repo_name
        g.add_edge(CallEdge(
            caller=caller, callee=callee,
            caller_repo=caller_repo, callee_repo=callee_repo,
            file_path="main.py", line_number=1,
        ))


# ── _normalize_path ──────────────────────────────────────────

class TestNormalizePath:
    def test_strips_trailing_slash(self):
        assert _normalize_path("/api/users/") == "/api/users"

    def test_replaces_path_params_braces(self):
        assert _normalize_path("/users/{user_id}") == "/users/{param}"

    def test_replaces_path_params_colon(self):
        assert _normalize_path("/users/:id") == "/users/{param}"

    def test_lowercase(self):
        assert _normalize_path("/API/Users") == "/api/users"

    def test_multiple_params(self):
        result = _normalize_path("/users/{id}/claims/{claim_id}")
        assert result == "/users/{param}/claims/{param}"

    def test_no_change_needed(self):
        assert _normalize_path("/api/health") == "/api/health"

    def test_glob_pattern(self):
        result = _normalize_path("/api/**")
        assert result == "/api/{glob}"


# ── _detect_http_call ────────────────────────────────────────

class TestDetectHttpCall:
    def test_requests_get(self):
        call = _call("foo", 'requests.get("/api/users")')
        result = _detect_http_call(call)
        assert result is not None
        assert result[0] == "GET"

    def test_httpx_post(self):
        call = _call("foo", 'httpx.post("/api/data")')
        result = _detect_http_call(call)
        assert result is not None
        assert result[0] == "POST"

    def test_axios_delete(self):
        call = _call("foo", 'axios.delete("/api/items")')
        result = _detect_http_call(call)
        assert result is not None
        assert result[0] == "DELETE"

    def test_non_http_call(self):
        call = _call("foo", "db.query")
        result = _detect_http_call(call)
        assert result is None

    def test_java_rest_template(self):
        call = _call("foo", 'restTemplate.getForObject("http://host/api/users")')
        result = _detect_http_call(call)
        assert result is not None
        assert result[0] == "GET"

    def test_requests_patch(self):
        call = _call("foo", 'requests.patch("/api/items/1")')
        result = _detect_http_call(call)
        assert result is not None
        assert result[0] == "PATCH"

    def test_webclient_put(self):
        call = _call("foo", 'webClient.put("/api/resource")')
        result = _detect_http_call(call)
        assert result is not None
        assert result[0] == "PUT"

    def test_returns_empty_url_hint(self):
        """The second element of the returned tuple is always empty string."""
        call = _call("foo", 'requests.get("/x")')
        result = _detect_http_call(call)
        assert result is not None
        assert result[1] == ""


# ── CrossRepoMatcher ────────────────────────────────────────

class TestCrossRepoMatcher:
    def test_matches_python_to_python(self):
        """requests.post in repo A matches @router.post in repo B."""
        ctx_client = _context(
            repo="client",
            calls=[_call("submit", 'requests.post("/api/payments/charge")',
                          file_path="client.py", call_type="method")],
        )
        entry_points = [
            _entry_point("charge", "routes.py", "server", "POST", "/api/payments/charge"),
        ]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx_client], entry_points)
        assert len(matches) == 1
        assert matches[0].server_repo == "server"
        assert matches[0].http_method == "POST"

    def test_no_match_same_repo(self):
        """Same-repo HTTP calls should not produce cross-repo matches."""
        ctx = _context(
            repo="api",
            calls=[_call("foo", 'requests.get("/api/health")',
                          file_path="main.py")],
        )
        entry_points = [
            _entry_point("health", "routes.py", "api", "GET", "/api/health"),
        ]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx], entry_points)
        assert len(matches) == 0

    def test_path_normalization_matches(self):
        """Different param styles should match: {id} vs :id."""
        ctx_client = _context(
            repo="client",
            calls=[_call("get", 'httpx.get("/users/:user_id")',
                          file_path="client.py")],
        )
        entry_points = [
            _entry_point("get_user", "routes.py", "server", "GET", "/users/{user_id}"),
        ]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx_client], entry_points)
        assert len(matches) == 1

    def test_http_method_mismatch_no_match(self):
        ctx_client = _context(
            repo="client",
            calls=[_call("do", 'requests.get("/api/data")', file_path="c.py")],
        )
        entry_points = [
            _entry_point("post_data", "routes.py", "server", "POST", "/api/data"),
        ]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx_client], entry_points)
        assert len(matches) == 0

    def test_no_url_no_match(self):
        """HTTP call without a URL path shouldn't match."""
        ctx_client = _context(
            repo="client",
            calls=[_call("do", "requests.get(url_var)", file_path="c.py")],
        )
        entry_points = [_entry_point("h", "r.py", "server", "GET", "/api")]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx_client], entry_points)
        assert len(matches) == 0

    def test_add_to_graph(self):
        graph = CallGraph()
        match = CrossRepoMatch(
            client_method="submit", client_repo="client",
            server_method="charge", server_repo="server",
            http_method="POST", route="/pay",
            client_file="c.py", client_line=10,
        )
        matcher = CrossRepoMatcher()
        matcher.add_to_graph(graph, [match])
        assert graph.edge_count == 1
        assert graph.edges[0].call_type == "http"

    def test_add_to_graph_edge_format(self):
        """Edges added to graph use repo::??::method format."""
        graph = CallGraph()
        match = CrossRepoMatch(
            client_method="submit", client_repo="client",
            server_method="charge", server_repo="server",
            http_method="POST", route="/pay",
            client_file="c.py", client_line=10,
        )
        matcher = CrossRepoMatcher()
        matcher.add_to_graph(graph, [match])
        edge = graph.edges[0]
        assert edge.caller == "client::??::submit"
        assert edge.callee == "server::??::charge"
        assert edge.caller_repo == "client"
        assert edge.callee_repo == "server"

    def test_multiple_repos(self):
        """Client calls two different server repos."""
        ctx_client = _context(
            repo="frontend",
            calls=[
                _call("fetch_users", 'axios.get("/api/users")', file_path="app.js"),
                _call("fetch_orders", 'axios.get("/api/orders")', file_path="app.js"),
            ],
        )
        entry_points = [
            _entry_point("list_users", "users.py", "user-svc", "GET", "/api/users"),
            _entry_point("list_orders", "orders.py", "order-svc", "GET", "/api/orders"),
        ]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx_client], entry_points)
        assert len(matches) == 2
        repos = {m.server_repo for m in matches}
        assert repos == {"user-svc", "order-svc"}

    def test_entry_point_without_route_skipped(self):
        """Entry points with empty route are excluded from the index."""
        ctx_client = _context(
            repo="client",
            calls=[_call("do", 'requests.get("/api/test")', file_path="c.py")],
        )
        entry_points = [
            _entry_point("handler", "main.py", "server", "GET", ""),  # no route
        ]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx_client], entry_points)
        assert len(matches) == 0

    def test_multiple_contexts(self):
        """Match works across multiple client contexts."""
        ctx1 = _context(
            repo="svc-a",
            calls=[_call("call_b", 'requests.post("/api/b")', file_path="a.py")],
        )
        ctx2 = _context(
            repo="svc-b",
            calls=[_call("call_c", 'requests.post("/api/c")', file_path="b.py")],
        )
        entry_points = [
            _entry_point("handle_b", "b.py", "svc-b", "POST", "/api/b"),
            _entry_point("handle_c", "c.py", "svc-c", "POST", "/api/c"),
        ]
        matcher = CrossRepoMatcher()
        matches = matcher.match([ctx1, ctx2], entry_points)
        assert len(matches) == 2


# ── GraphAnalyzer ────────────────────────────────────────────

class TestBlastRadius:
    def test_direct_entry_point(self):
        """Entry point calling a method -- blast radius = 1 entry."""
        g = _build_graph({
            "entry": {"entry": True},
            "target": {},
        })
        _add_edges(g, [("entry", "target")])
        analyzer = GraphAnalyzer(g)
        br = analyzer.blast_radius("target")
        assert br.entry_points == 1

    def test_no_entry_points(self):
        g = _build_graph({"A": {}, "B": {}})
        _add_edges(g, [("A", "B")])
        analyzer = GraphAnalyzer(g)
        br = analyzer.blast_radius("B")
        assert br.entry_points == 0

    def test_multiple_entry_points(self):
        g = _build_graph({
            "ep1": {"entry": True},
            "ep2": {"entry": True},
            "mid": {},
            "target": {},
        })
        _add_edges(g, [("ep1", "mid"), ("ep2", "mid"), ("mid", "target")])
        analyzer = GraphAnalyzer(g)
        br = analyzer.blast_radius("target")
        assert br.entry_points == 2

    def test_repos_affected(self):
        """Method in repo2 called from repo1 entry point affects 2 repos."""
        g = CallGraph()
        m1 = _method("a", repo="repo1", is_entry_point=True)
        m2 = _method("b", repo="repo2")
        g.add_method("repo1::a.py::a", m1)
        g.add_method("repo2::b.py::b", m2)
        g.add_edge(CallEdge(
            caller="repo1::a.py::a", callee="repo2::b.py::b",
            caller_repo="repo1", callee_repo="repo2",
            file_path="a.py", line_number=1,
        ))
        analyzer = GraphAnalyzer(g)
        br = analyzer.blast_radius("repo2::b.py::b")
        assert br.repos_affected >= 2

    def test_blast_radius_defaults(self):
        """daily_calls and affected_users default to 'unknown'."""
        g = _build_graph({"entry": {"entry": True}, "target": {}})
        _add_edges(g, [("entry", "target")])
        analyzer = GraphAnalyzer(g)
        br = analyzer.blast_radius("target")
        assert br.daily_calls == "unknown"
        assert br.affected_users == "unknown"

    def test_blast_radius_self(self):
        """Entry point's blast radius includes itself."""
        g = _build_graph({"entry": {"entry": True}})
        analyzer = GraphAnalyzer(g)
        br = analyzer.blast_radius("entry")
        assert br.entry_points == 1

    def test_deep_chain_blast_radius(self):
        """Blast radius traverses through deep chains."""
        g = _build_graph({
            "ep": {"entry": True},
            "A": {}, "B": {}, "C": {}, "sink": {},
        })
        _add_edges(g, [("ep", "A"), ("A", "B"), ("B", "C"), ("C", "sink")])
        analyzer = GraphAnalyzer(g)
        br = analyzer.blast_radius("sink")
        assert br.entry_points == 1


class TestTaintPaths:
    def test_direct_path(self):
        g = _build_graph({"A": {}, "B": {}, "C": {}})
        _add_edges(g, [("A", "B"), ("B", "C")])
        analyzer = GraphAnalyzer(g)
        paths = analyzer.taint_paths("A", "C")
        assert len(paths) == 1
        assert paths[0].length == 2
        assert paths[0].path == ["A", "B", "C"]

    def test_no_path(self):
        g = _build_graph({"A": {}, "B": {}})
        analyzer = GraphAnalyzer(g)
        paths = analyzer.taint_paths("A", "B")
        assert len(paths) == 0

    def test_multiple_paths(self):
        g = _build_graph({"A": {}, "B": {}, "C": {}, "D": {}})
        _add_edges(g, [("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")])
        analyzer = GraphAnalyzer(g)
        paths = analyzer.taint_paths("A", "D")
        assert len(paths) == 2

    def test_depth_limit(self):
        """Very long chain should be limited by max_depth."""
        methods = {f"M{i}": {} for i in range(25)}
        g = _build_graph(methods)
        _add_edges(g, [(f"M{i}", f"M{i+1}") for i in range(24)])
        analyzer = GraphAnalyzer(g)
        paths = analyzer.taint_paths("M0", "M24", max_depth=10)
        assert len(paths) == 0  # Path is 24 hops, limit is 10

    def test_single_hop(self):
        g = _build_graph({"A": {}, "B": {}})
        _add_edges(g, [("A", "B")])
        analyzer = GraphAnalyzer(g)
        paths = analyzer.taint_paths("A", "B")
        assert len(paths) == 1
        assert paths[0].length == 1

    def test_source_and_sink_attributes(self):
        g = _build_graph({"X": {}, "Y": {}, "Z": {}})
        _add_edges(g, [("X", "Y"), ("Y", "Z")])
        analyzer = GraphAnalyzer(g)
        paths = analyzer.taint_paths("X", "Z")
        assert paths[0].source == "X"
        assert paths[0].sink == "Z"


class TestFindCycles:
    def test_simple_cycle(self):
        g = _build_graph({"A": {}, "B": {}, "C": {}})
        _add_edges(g, [("A", "B"), ("B", "C"), ("C", "A")])
        analyzer = GraphAnalyzer(g)
        cycles = analyzer.find_cycles()
        assert len(cycles) >= 1

    def test_no_cycles(self):
        g = _build_graph({"A": {}, "B": {}, "C": {}})
        _add_edges(g, [("A", "B"), ("B", "C")])
        analyzer = GraphAnalyzer(g)
        cycles = analyzer.find_cycles()
        assert len(cycles) == 0

    def test_self_loop(self):
        g = _build_graph({"A": {}})
        _add_edges(g, [("A", "A")])
        analyzer = GraphAnalyzer(g)
        cycles = analyzer.find_cycles()
        assert len(cycles) >= 1

    def test_max_cycles_limit(self):
        # Create many independent 2-node cycles
        g = _build_graph({f"X{i}": {} for i in range(20)})
        for i in range(0, 20, 2):
            _add_edges(g, [(f"X{i}", f"X{i+1}"), (f"X{i+1}", f"X{i}")])
        analyzer = GraphAnalyzer(g)
        cycles = analyzer.find_cycles(max_cycles=3)
        assert len(cycles) <= 3

    def test_cycle_contains_loop_members(self):
        """Each cycle should contain nodes forming the loop."""
        g = _build_graph({"A": {}, "B": {}, "C": {}})
        _add_edges(g, [("A", "B"), ("B", "C"), ("C", "A")])
        analyzer = GraphAnalyzer(g)
        cycles = analyzer.find_cycles()
        # At least one cycle should contain all three nodes
        found = False
        for cycle in cycles:
            if "A" in cycle and "B" in cycle and "C" in cycle:
                found = True
                break
        assert found


class TestFindDeadCode:
    def test_reachable_from_entry(self):
        g = _build_graph({
            "entry": {"entry": True},
            "live": {},
        })
        _add_edges(g, [("entry", "live")])
        analyzer = GraphAnalyzer(g)
        dead = analyzer.find_dead_code()
        assert "live" not in dead

    def test_unreachable_is_dead(self):
        g = _build_graph({
            "entry": {"entry": True},
            "live": {},
            "dead": {},
        })
        _add_edges(g, [("entry", "live")])
        analyzer = GraphAnalyzer(g)
        dead = analyzer.find_dead_code()
        assert "dead" in dead
        assert "live" not in dead
        assert "entry" not in dead

    def test_no_entry_points_all_dead(self):
        g = _build_graph({"A": {}, "B": {}, "C": {}})
        _add_edges(g, [("A", "B"), ("B", "C")])
        analyzer = GraphAnalyzer(g)
        dead = analyzer.find_dead_code()
        assert len(dead) == 3

    def test_dead_code_returns_sorted(self):
        g = _build_graph({"entry": {"entry": True}, "Z": {}, "A": {}, "M": {}})
        analyzer = GraphAnalyzer(g)
        dead = analyzer.find_dead_code()
        assert dead == sorted(dead)

    def test_transitively_reachable_is_live(self):
        """Methods reachable through chain from entry are not dead."""
        g = _build_graph({
            "entry": {"entry": True},
            "mid": {},
            "leaf": {},
        })
        _add_edges(g, [("entry", "mid"), ("mid", "leaf")])
        analyzer = GraphAnalyzer(g)
        dead = analyzer.find_dead_code()
        assert len(dead) == 0


class TestSinglePointsOfFailure:
    def test_detects_spof(self):
        g = _build_graph({
            "entry": {"entry": True},
            "bridge": {},
            "leaf": {},
        })
        _add_edges(g, [("entry", "bridge"), ("bridge", "leaf")])
        analyzer = GraphAnalyzer(g)
        spofs = analyzer.find_single_points_of_failure()
        assert "bridge" in spofs

    def test_no_spof_with_multiple_callers(self):
        g = _build_graph({
            "ep1": {"entry": True},
            "ep2": {"entry": True},
            "node": {},
            "leaf": {},
        })
        _add_edges(g, [("ep1", "node"), ("ep2", "node"), ("node", "leaf")])
        analyzer = GraphAnalyzer(g)
        spofs = analyzer.find_single_points_of_failure()
        # node has 2 callers, so not a SPOF
        assert "node" not in spofs

    def test_entry_point_not_spof(self):
        """Entry points themselves are excluded from SPOF detection."""
        g = _build_graph({
            "entry": {"entry": True},
            "leaf": {},
        })
        _add_edges(g, [("entry", "leaf")])
        analyzer = GraphAnalyzer(g)
        spofs = analyzer.find_single_points_of_failure()
        assert "entry" not in spofs

    def test_leaf_with_single_caller_not_spof(self):
        """Leaf nodes (no callees) are NOT SPOFs even with one caller."""
        g = _build_graph({
            "entry": {"entry": True},
            "leaf": {},
        })
        _add_edges(g, [("entry", "leaf")])
        analyzer = GraphAnalyzer(g)
        spofs = analyzer.find_single_points_of_failure()
        # leaf has no callees, so it doesn't connect to anything downstream
        assert "leaf" not in spofs

    def test_unreachable_not_spof(self):
        """Methods not reachable from entry points are not SPOFs."""
        g = _build_graph({
            "entry": {"entry": True},
            "live": {},
            "isolated_bridge": {},
            "isolated_leaf": {},
        })
        _add_edges(g, [
            ("entry", "live"),
            ("isolated_bridge", "isolated_leaf"),
        ])
        analyzer = GraphAnalyzer(g)
        spofs = analyzer.find_single_points_of_failure()
        assert "isolated_bridge" not in spofs


class TestMaxCallDepth:
    def test_chain_depth(self):
        g = _build_graph({
            "entry": {"entry": True},
            "A": {}, "B": {}, "C": {},
        })
        _add_edges(g, [("entry", "A"), ("A", "B"), ("B", "C")])
        analyzer = GraphAnalyzer(g)
        assert analyzer.max_call_depth() == 3

    def test_empty_graph_depth_zero(self):
        g = CallGraph()
        analyzer = GraphAnalyzer(g)
        assert analyzer.max_call_depth() == 0

    def test_single_entry_no_callees(self):
        g = _build_graph({"entry": {"entry": True}})
        analyzer = GraphAnalyzer(g)
        assert analyzer.max_call_depth() == 0

    def test_branching_takes_max(self):
        """Max depth picks the longest branch."""
        g = _build_graph({
            "entry": {"entry": True},
            "short": {},
            "A": {}, "B": {}, "C": {},
        })
        _add_edges(g, [
            ("entry", "short"),           # depth 1
            ("entry", "A"), ("A", "B"), ("B", "C"),  # depth 3
        ])
        analyzer = GraphAnalyzer(g)
        assert analyzer.max_call_depth() == 3

    def test_multiple_entries_takes_global_max(self):
        g = _build_graph({
            "ep1": {"entry": True},
            "ep2": {"entry": True},
            "A": {}, "B": {}, "C": {},
        })
        _add_edges(g, [
            ("ep1", "A"),                    # depth 1
            ("ep2", "B"), ("B", "C"),        # depth 2
        ])
        analyzer = GraphAnalyzer(g)
        assert analyzer.max_call_depth() == 2


class TestCriticalPaths:
    def test_entry_to_leaf(self):
        g = _build_graph({
            "entry": {"entry": True},
            "mid": {},
            "leaf": {},
        })
        _add_edges(g, [("entry", "mid"), ("mid", "leaf")])
        analyzer = GraphAnalyzer(g)
        paths = analyzer.find_critical_paths()
        assert len(paths) >= 1
        # At least one path should be entry -> mid -> leaf
        found = any(p == ["entry", "mid", "leaf"] for p in paths)
        assert found

    def test_explicit_sinks(self):
        g = _build_graph({
            "entry": {"entry": True},
            "A": {}, "B": {}, "C": {},
        })
        _add_edges(g, [("entry", "A"), ("A", "B"), ("A", "C")])
        analyzer = GraphAnalyzer(g)
        paths = analyzer.find_critical_paths(sinks={"B"})
        assert len(paths) == 1
        assert paths[0][-1] == "B"


class TestBuildSummary:
    def test_produces_valid_summary(self):
        g = _build_graph({
            "entry": {"entry": True, "loc": 20},
            "live": {"loc": 15},
            "dead": {"loc": 10},
        })
        _add_edges(g, [("entry", "live")])
        analyzer = GraphAnalyzer(g)
        summary = analyzer.build_summary()
        assert len(summary.entry_points) == 1
        assert summary.dead_methods.count == 1  # "dead" is unreachable
        assert summary.dead_methods.total_lines == 10

    def test_with_cross_repo_matches(self):
        g = _build_graph({"entry": {"entry": True}})
        analyzer = GraphAnalyzer(g)
        match = CrossRepoMatch(
            client_method="submit", client_repo="client",
            server_method="charge", server_repo="server",
            http_method="POST", route="/pay",
            client_file="c.py", client_line=10,
        )
        summary = analyzer.build_summary(cross_repo_matches=[match])
        assert len(summary.cross_repo_edges) == 1
        assert "POST" in summary.cross_repo_edges[0].via

    def test_summary_spofs(self):
        g = _build_graph({
            "entry": {"entry": True},
            "bridge": {},
            "leaf": {},
        })
        _add_edges(g, [("entry", "bridge"), ("bridge", "leaf")])
        analyzer = GraphAnalyzer(g)
        summary = analyzer.build_summary()
        assert "bridge" in summary.single_points_of_failure

    def test_summary_no_cross_repo_by_default(self):
        g = _build_graph({"entry": {"entry": True}})
        analyzer = GraphAnalyzer(g)
        summary = analyzer.build_summary()
        assert summary.cross_repo_edges == []

    def test_summary_cycles(self):
        g = _build_graph({"A": {"entry": True}, "B": {}})
        _add_edges(g, [("A", "B"), ("B", "A")])
        analyzer = GraphAnalyzer(g)
        summary = analyzer.build_summary()
        assert len(summary.circular_dependencies) >= 1

    def test_entry_point_depth_in_summary(self):
        g = _build_graph({
            "entry": {"entry": True},
            "A": {}, "B": {},
        })
        _add_edges(g, [("entry", "A"), ("A", "B")])
        analyzer = GraphAnalyzer(g)
        summary = analyzer.build_summary()
        assert summary.entry_points[0].depth == 2

    def test_cross_repo_edge_format(self):
        """Cross-repo edges in summary use repo::method format."""
        g = _build_graph({"entry": {"entry": True}})
        analyzer = GraphAnalyzer(g)
        match = CrossRepoMatch(
            client_method="submit", client_repo="client",
            server_method="charge", server_repo="server",
            http_method="POST", route="/pay",
            client_file="c.py", client_line=10,
        )
        summary = analyzer.build_summary(cross_repo_matches=[match])
        edge = summary.cross_repo_edges[0]
        assert edge.from_method == "client::submit"
        assert edge.to_method == "server::charge"
        assert edge.via == "POST /pay"

    def test_dead_methods_top_files(self):
        """Dead methods summary tracks which files have the most dead code."""
        g = _build_graph({
            "entry": {"entry": True},
            "dead1": {"file": "utils.py", "loc": 5},
            "dead2": {"file": "utils.py", "loc": 10},
            "dead3": {"file": "helpers.py", "loc": 3},
        })
        analyzer = GraphAnalyzer(g)
        summary = analyzer.build_summary()
        assert summary.dead_methods.count == 3
        # utils.py has 2 dead methods, should appear first
        assert summary.dead_methods.top_files[0] == "utils.py"
