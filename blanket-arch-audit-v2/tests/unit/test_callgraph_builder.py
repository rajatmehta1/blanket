"""Tests for callgraph static_builder and entry_point_detector."""
from __future__ import annotations
import pytest
from blanketaudit2.callgraph.static_builder import (
    CallGraph, CallEdge, StaticCallGraphBuilder, SymbolTable, _build_import_map,
)
from blanketaudit2.callgraph.entry_point_detector import EntryPointDetector
from blanketaudit2.ingestion.models import (
    AnalysisContext, CallInfo, EntryPointInfo, ImportInfo, MethodInfo,
)


# -- Helpers -------------------------------------------------------------------

def _method(name, qualified_name=None, file_path="main.py", repo="api",
            line_start=1, line_end=10, is_entry_point=False, decorators=None,
            parameters=None, loc=10):
    return MethodInfo(
        name=name,
        qualified_name=qualified_name or name,
        file_path=file_path,
        repo_name=repo,
        line_start=line_start,
        line_end=line_end,
        is_entry_point=is_entry_point,
        decorators=decorators or [],
        parameters=parameters or [],
        loc=loc,
    )

def _call(caller, callee, file_path="main.py", line=1, call_type="direct"):
    return CallInfo(
        caller=caller, callee=callee,
        file_path=file_path, line_number=line, call_type=call_type,
    )

def _import(source_file, module, names=None, is_relative=False, line=1):
    return ImportInfo(
        source_file=source_file,
        imported_module=module,
        imported_names=names or [],
        line_number=line,
        is_relative=is_relative,
    )

def _entry_point(method_name, file_path, repo, http_method="GET", route="/", framework="fastapi"):
    return EntryPointInfo(
        method_name=method_name,
        file_path=file_path,
        repo_name=repo,
        http_method=http_method,
        route=route,
        framework=framework,
    )

def _context(repo="api", root="/tmp/api", methods=None, calls=None, imports=None,
             entry_points=None, classes=None):
    return AnalysisContext(
        repo_name=repo,
        root_path=root,
        methods=methods or [],
        calls=calls or [],
        imports=imports or [],
        entry_points=entry_points or [],
        classes=classes or [],
    )


# -- CallGraph dataclass -------------------------------------------------------

class TestCallGraph:
    def test_empty_graph(self):
        g = CallGraph()
        assert g.method_count == 0
        assert g.edge_count == 0

    def test_add_method(self):
        g = CallGraph()
        m = _method("foo")
        g.add_method("api::main.py::foo", m)
        assert g.method_count == 1
        assert "api::main.py::foo" in g.methods

    def test_add_edge(self):
        g = CallGraph()
        edge = CallEdge(
            caller="api::main.py::foo", callee="api::main.py::bar",
            caller_repo="api", callee_repo="api",
            file_path="main.py", line_number=5,
        )
        g.add_edge(edge)
        assert g.edge_count == 1
        assert "api::main.py::bar" in g.callees["api::main.py::foo"]
        assert "api::main.py::foo" in g.callers["api::main.py::bar"]

    def test_entry_points_tracked(self):
        g = CallGraph()
        m = _method("handler", is_entry_point=True)
        g.add_method("api::routes.py::handler", m)
        assert "api::routes.py::handler" in g.entry_points

    def test_non_entry_method_not_in_entry_points(self):
        g = CallGraph()
        m = _method("helper", is_entry_point=False)
        g.add_method("api::utils.py::helper", m)
        assert "api::utils.py::helper" not in g.entry_points

    def test_multiple_edges(self):
        g = CallGraph()
        for i in range(5):
            edge = CallEdge(
                caller=f"api::main.py::caller{i}", callee="api::main.py::target",
                caller_repo="api", callee_repo="api",
                file_path="main.py", line_number=i,
            )
            g.add_edge(edge)
        assert g.edge_count == 5
        assert len(g.callers["api::main.py::target"]) == 5


# -- SymbolTable ---------------------------------------------------------------

class TestSymbolTable:
    def test_register_and_resolve_same_file(self):
        st = SymbolTable()
        m = _method("foo", qualified_name="foo", file_path="main.py", repo="api")
        qid = st.register("api", m)
        assert qid == "api::main.py::foo"
        resolved = st.resolve("foo", "main.py", "api", {})
        assert resolved == qid

    def test_resolve_qualified_name(self):
        st = SymbolTable()
        m = _method("search", qualified_name="UserService.search",
                     file_path="service.py", repo="api")
        qid = st.register("api", m)
        resolved = st.resolve("UserService.search", "routes.py", "api", {})
        assert resolved == qid

    def test_resolve_via_import_map(self):
        st = SymbolTable()
        m = _method("save", qualified_name="save", file_path="repo.py", repo="api")
        qid = st.register("api", m)
        # import_map: alias "repo" -> module "repo"
        import_map = {"repo": "repo"}
        resolved = st.resolve("repo.save", "service.py", "api", import_map)
        assert resolved == qid

    def test_unresolved_returns_none(self):
        st = SymbolTable()
        resolved = st.resolve("nonexistent", "main.py", "api", {})
        assert resolved is None

    def test_short_name_fallback(self):
        st = SymbolTable()
        m = _method("helper", file_path="utils.py", repo="api")
        qid = st.register("api", m)
        resolved = st.resolve("helper", "main.py", "api", {})
        assert resolved == qid

    def test_same_repo_preferred_over_cross_repo(self):
        st = SymbolTable()
        m1 = _method("process", file_path="core.py", repo="api")
        m2 = _method("process", file_path="core.py", repo="engine")
        qid1 = st.register("api", m1)
        qid2 = st.register("engine", m2)
        resolved = st.resolve("process", "handler.py", "api", {})
        assert resolved == qid1

    def test_register_returns_qualified_id(self):
        st = SymbolTable()
        m = _method("run", qualified_name="TaskRunner.run",
                     file_path="runner.py", repo="worker")
        qid = st.register("worker", m)
        assert qid == "worker::runner.py::TaskRunner.run"


# -- _build_import_map ---------------------------------------------------------

class TestBuildImportMap:
    def test_plain_import(self):
        imports = [_import("main.py", "os")]
        result = _build_import_map(imports, "main.py")
        assert result["os"] == "os"

    def test_from_import(self):
        imports = [_import("main.py", "pathlib", names=["Path"])]
        result = _build_import_map(imports, "main.py")
        assert result["Path"] == "pathlib"

    def test_filters_by_file(self):
        imports = [
            _import("main.py", "os"),
            _import("other.py", "sys"),
        ]
        result = _build_import_map(imports, "main.py")
        assert "os" in result
        assert "sys" not in result

    def test_dotted_module_alias(self):
        imports = [_import("main.py", "blanketaudit2.config")]
        result = _build_import_map(imports, "main.py")
        assert result["config"] == "blanketaudit2.config"

    def test_multiple_names_from_one_module(self):
        imports = [_import("main.py", "typing", names=["List", "Dict", "Optional"])]
        result = _build_import_map(imports, "main.py")
        assert result["List"] == "typing"
        assert result["Dict"] == "typing"
        assert result["Optional"] == "typing"

    def test_aliased_import_uses_alias(self):
        """'from foo import bar as baz' should map baz -> foo."""
        imports = [_import("main.py", "numpy", names=["array as np_array"])]
        result = _build_import_map(imports, "main.py")
        assert result["np_array"] == "numpy"

    def test_empty_imports(self):
        result = _build_import_map([], "main.py")
        assert result == {}


# -- StaticCallGraphBuilder ----------------------------------------------------

class TestStaticCallGraphBuilder:
    def test_single_file_simple(self):
        """Two methods in one file, one calls the other."""
        ctx = _context(
            repo="api",
            methods=[
                _method("foo", file_path="main.py"),
                _method("bar", file_path="main.py"),
            ],
            calls=[_call("foo", "bar", file_path="main.py")],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert graph.method_count == 2
        assert graph.edge_count == 1
        assert graph.edges[0].resolved is True

    def test_cross_file_resolution(self):
        """Method in file A calls method in file B via 'import db'."""
        ctx = _context(
            repo="api",
            methods=[
                _method("handler", file_path="routes.py"),
                _method("query", file_path="db.py"),
            ],
            calls=[_call("handler", "db.query", file_path="routes.py", call_type="method")],
            # Plain 'import db' -> import_map: {"db": "db"}
            imports=[_import("routes.py", "db")],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert graph.edge_count == 1
        assert graph.edges[0].resolved is True

    def test_unresolved_call_does_not_crash(self):
        """Calling a method that doesn't exist should produce an unresolved edge."""
        ctx = _context(
            repo="api",
            methods=[_method("foo", file_path="main.py")],
            calls=[_call("foo", "nonexistent_lib.do_stuff", file_path="main.py")],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert graph.edge_count == 1
        assert graph.edges[0].resolved is False
        assert "<unresolved>" in graph.edges[0].callee

    def test_entry_points_registered(self):
        ctx = _context(
            repo="api",
            methods=[
                _method("get_user", is_entry_point=True, file_path="routes.py"),
                _method("helper", file_path="utils.py"),
            ],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert len(graph.entry_points) == 1

    def test_multi_repo_build(self):
        ctx1 = _context(
            repo="api",
            methods=[_method("handler", file_path="routes.py", repo="api")],
            calls=[],
        )
        ctx2 = _context(
            repo="engine",
            root="/tmp/engine",
            methods=[_method("process", file_path="core.py", repo="engine")],
            calls=[],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build([ctx1, ctx2])
        assert graph.method_count == 2

    def test_qualified_name_resolution(self):
        """Class.method calls should resolve when qualified name matches."""
        ctx = _context(
            repo="api",
            methods=[
                _method("search", qualified_name="UserService.search", file_path="service.py"),
                _method("handler", qualified_name="handler", file_path="routes.py"),
            ],
            calls=[_call("handler", "UserService.search", file_path="routes.py")],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert graph.edges[0].resolved is True

    def test_call_type_preserved(self):
        """The call_type from CallInfo should propagate to the edge."""
        ctx = _context(
            repo="api",
            methods=[
                _method("foo", file_path="main.py"),
                _method("bar", file_path="main.py"),
            ],
            calls=[_call("foo", "bar", file_path="main.py", call_type="async")],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert graph.edges[0].call_type == "async"

    def test_no_methods_no_crash(self):
        """Empty context should produce an empty graph."""
        ctx = _context(repo="api", methods=[], calls=[])
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert graph.method_count == 0
        assert graph.edge_count == 0

    def test_multi_repo_methods_isolated(self):
        """Methods from different repos with the same name stay separate."""
        ctx1 = _context(
            repo="api",
            methods=[_method("process", file_path="core.py", repo="api")],
        )
        ctx2 = _context(
            repo="engine",
            root="/tmp/engine",
            methods=[_method("process", file_path="core.py", repo="engine")],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build([ctx1, ctx2])
        assert graph.method_count == 2
        assert "api::core.py::process" in graph.methods
        assert "engine::core.py::process" in graph.methods

    def test_realistic_three_file_scenario(self):
        """Simulate routes.py -> service.py -> db.py call chain."""
        ctx = _context(
            repo="api",
            methods=[
                _method("get_user", qualified_name="get_user",
                        file_path="routes.py", is_entry_point=True),
                _method("find_user", qualified_name="UserService.find_user",
                        file_path="service.py"),
                _method("query", qualified_name="query",
                        file_path="db.py"),
            ],
            calls=[
                _call("get_user", "UserService.find_user",
                      file_path="routes.py", line=10),
                _call("UserService.find_user", "query",
                      file_path="service.py", line=20),
            ],
            imports=[
                _import("routes.py", "service", names=["UserService"]),
                _import("service.py", "db", names=["query"]),
            ],
        )
        builder = StaticCallGraphBuilder()
        graph = builder.build_single(ctx)
        assert graph.method_count == 3
        assert graph.edge_count == 2
        assert len(graph.entry_points) == 1
        # Both edges should be resolved
        assert all(e.resolved for e in graph.edges)

    def test_build_single_delegates_to_build(self):
        """build_single wraps build with a single-element list."""
        ctx = _context(
            repo="api",
            methods=[_method("foo", file_path="main.py")],
        )
        builder = StaticCallGraphBuilder()
        g1 = builder.build_single(ctx)
        g2 = builder.build([ctx])
        assert g1.method_count == g2.method_count


# -- EntryPointDetector --------------------------------------------------------

class TestEntryPointDetector:
    def test_detects_existing_entry_points(self):
        ctx = _context(
            repo="api",
            entry_points=[
                _entry_point("get_user", "routes.py", "api", "GET", "/users/{id}"),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) == 1
        assert eps[0].http_method == "GET"

    def test_detects_from_decorators(self):
        ctx = _context(
            repo="api",
            methods=[
                _method("create_user", qualified_name="create_user",
                        file_path="routes.py", repo="api",
                        decorators=['router.post("/users")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) >= 1
        assert any(ep.http_method == "POST" for ep in eps)

    def test_detects_main_function(self):
        ctx = _context(
            repo="cli",
            methods=[_method("main", file_path="app.py", repo="cli")],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert any(ep.framework == "main" for ep in eps)

    def test_deduplication(self):
        """Same entry point from extractor + decorator scan should not duplicate."""
        ep = _entry_point("handler", "routes.py", "api", "GET", "/")
        ctx = _context(
            repo="api",
            entry_points=[ep],
            methods=[
                # is_entry_point=False so Pass 2 scans its decorators too
                _method("handler", qualified_name="handler",
                        file_path="routes.py", repo="api",
                        is_entry_point=False,
                        decorators=['app.get("/")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        # The extractor entry point has GET, and the decorator also produces GET.
        # Dedup key matches, so no duplicates.
        keys = [f"{e.file_path}::{e.method_name}::{e.http_method}" for e in eps]
        assert len(keys) == len(set(keys))

    def test_spring_annotation_detection(self):
        ctx = _context(
            repo="api",
            methods=[
                _method("getUser", qualified_name="UserController.getUser",
                        file_path="UserController.java", repo="api",
                        decorators=['GetMapping("/users/{id}")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) >= 1
        assert any(ep.http_method == "GET" for ep in eps)

    def test_no_false_positives(self):
        """Regular methods without decorators should not be detected."""
        ctx = _context(
            repo="api",
            methods=[
                _method("helper", file_path="utils.py", repo="api"),
                _method("process", file_path="core.py", repo="api"),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) == 0

    def test_multiple_http_methods(self):
        """Multiple route handlers in the same file."""
        ctx = _context(
            repo="api",
            methods=[
                _method("list_users", qualified_name="list_users",
                        file_path="routes.py", repo="api",
                        decorators=['router.get("/users")']),
                _method("create_user", qualified_name="create_user",
                        file_path="routes.py", repo="api",
                        decorators=['router.post("/users")']),
                _method("delete_user", qualified_name="delete_user",
                        file_path="routes.py", repo="api",
                        decorators=['router.delete("/users/{id}")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) == 3
        methods = {ep.http_method for ep in eps}
        assert methods == {"GET", "POST", "DELETE"}

    def test_route_extraction(self):
        """Route path should be extracted from the decorator."""
        ctx = _context(
            repo="api",
            methods=[
                _method("get_item", qualified_name="get_item",
                        file_path="routes.py", repo="api",
                        decorators=['app.get("/items/{item_id}")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) == 1
        assert eps[0].route == "/items/{item_id}"

    def test_framework_detection_fastapi(self):
        ctx = _context(
            repo="api",
            methods=[
                _method("endpoint", qualified_name="endpoint",
                        file_path="app.py", repo="api",
                        decorators=['app.post("/submit")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) == 1
        assert eps[0].framework == "fastapi"

    def test_framework_detection_spring(self):
        ctx = _context(
            repo="api",
            methods=[
                _method("save", qualified_name="Controller.save",
                        file_path="Controller.java", repo="api",
                        decorators=['PostMapping("/save")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) == 1
        assert eps[0].framework == "spring"

    def test_main_not_detected_when_is_entry_point_true(self):
        """Pass 3 skips methods with name 'main' if is_entry_point is already True."""
        ctx = _context(
            repo="cli",
            methods=[_method("main", file_path="app.py", repo="cli",
                             is_entry_point=True)],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        # is_entry_point=True but no entry_points in context, and Pass 2 checks
        # decorators (none here). Pass 3 skips because is_entry_point=True.
        assert len(eps) == 0

    def test_express_endpoint_detection(self):
        ctx = _context(
            repo="web",
            methods=[
                _method("getUsers", qualified_name="getUsers",
                        file_path="routes.ts", repo="web",
                        decorators=['app.get("/api/users")']),
            ],
        )
        detector = EntryPointDetector()
        eps = detector.detect(ctx)
        assert len(eps) >= 1
        assert eps[0].framework == "express"
