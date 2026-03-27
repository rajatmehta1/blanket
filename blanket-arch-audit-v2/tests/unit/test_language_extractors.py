"""Tests for language extractors (Python, Java, TypeScript).

These tests require tree-sitter and language grammars to be installed.
Tests are skipped if tree-sitter is not available.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from blanketaudit.ingestion.extractors.base_extractor import BaseExtractor, ExtractionResult


# ── Helper parsers (skip if tree-sitter unavailable) ─────────


def _parse_python(code: str):
    """Parse Python code with tree-sitter. Returns (tree, source_bytes)."""
    ts = pytest.importorskip("tree_sitter")
    ts_python = pytest.importorskip("tree_sitter_python")
    lang = ts.Language(ts_python.language())
    parser = ts.Parser(lang)
    source = code.encode("utf-8")
    tree = parser.parse(source)
    return tree, source


def _parse_java(code: str):
    """Parse Java code with tree-sitter. Returns (tree, source_bytes)."""
    ts = pytest.importorskip("tree_sitter")
    ts_java = pytest.importorskip("tree_sitter_java")
    lang = ts.Language(ts_java.language())
    parser = ts.Parser(lang)
    source = code.encode("utf-8")
    return parser.parse(source), source


def _parse_typescript(code: str):
    """Parse TypeScript code with tree-sitter. Returns (tree, source_bytes)."""
    ts = pytest.importorskip("tree_sitter")
    ts_ts = pytest.importorskip("tree_sitter_typescript")
    # tree_sitter_typescript exposes language_typescript() or language()
    lang_fn = getattr(ts_ts, "language_typescript", None) or getattr(ts_ts, "language", None)
    lang = ts.Language(lang_fn())
    parser = ts.Parser(lang)
    source = code.encode("utf-8")
    return parser.parse(source), source


# ══════════════════════════════════════════════════════════════
# Base extractor helpers (no tree-sitter needed)
# ══════════════════════════════════════════════════════════════


class TestExtractionResult:
    def test_empty_result(self):
        r = ExtractionResult("test.py", "repo")
        assert r.file_path == "test.py"
        assert r.repo_name == "repo"
        assert r.classes == []
        assert r.methods == []
        assert r.calls == []
        assert r.imports == []
        assert r.entry_points == []

    def test_multiple_results_independent(self):
        r1 = ExtractionResult("a.py", "repo1")
        r2 = ExtractionResult("b.py", "repo2")
        # Ensure lists are not shared between instances
        r1.classes.append(MagicMock())
        assert len(r2.classes) == 0


class TestBaseExtractorHelpers:
    """Test tree-sitter helper methods using mock nodes."""

    def _make_node(self, type_name="identifier", text=b"foo", children=None,
                   start_point=(0, 0), end_point=(0, 3), start_byte=0, end_byte=3):
        node = MagicMock()
        node.type = type_name
        node.children = children or []
        node.start_point = start_point
        node.end_point = end_point
        node.start_byte = start_byte
        node.end_byte = end_byte
        return node

    def test_node_text(self):
        node = self._make_node(start_byte=0, end_byte=3)
        assert BaseExtractor.node_text(node, b"foo bar") == "foo"

    def test_node_text_utf8(self):
        node = self._make_node(start_byte=0, end_byte=6)
        assert BaseExtractor.node_text(node, "hel\u00e4lo".encode("utf-8")) == "hel\u00e4l"

    def test_find_children(self):
        child1 = self._make_node(type_name="identifier")
        child2 = self._make_node(type_name="string")
        child3 = self._make_node(type_name="identifier")
        parent = self._make_node(children=[child1, child2, child3])
        assert BaseExtractor.find_children(parent, "identifier") == [child1, child3]

    def test_find_children_no_match(self):
        child = self._make_node(type_name="string")
        parent = self._make_node(children=[child])
        assert BaseExtractor.find_children(parent, "identifier") == []

    def test_find_first_child(self):
        child1 = self._make_node(type_name="string")
        child2 = self._make_node(type_name="identifier")
        parent = self._make_node(children=[child1, child2])
        assert BaseExtractor.find_first_child(parent, "identifier") is child2
        assert BaseExtractor.find_first_child(parent, "number") is None

    def test_node_line_is_1_based(self):
        node = self._make_node(start_point=(0, 0))
        assert BaseExtractor.node_line(node) == 1
        node2 = self._make_node(start_point=(9, 5))
        assert BaseExtractor.node_line(node2) == 10

    def test_node_end_line_is_1_based(self):
        node = self._make_node(end_point=(4, 0))
        assert BaseExtractor.node_end_line(node) == 5

    def test_walk_descendants(self):
        leaf1 = self._make_node(type_name="call", children=[])
        leaf2 = self._make_node(type_name="identifier", children=[])
        leaf3 = self._make_node(type_name="call", children=[])
        mid = self._make_node(type_name="block", children=[leaf1, leaf2])
        root = self._make_node(type_name="module", children=[mid, leaf3])
        calls = BaseExtractor.walk_descendants(root, "call")
        assert len(calls) == 2
        assert leaf1 in calls
        assert leaf3 in calls

    def test_walk_descendants_includes_root_if_matching(self):
        root = self._make_node(type_name="call", children=[])
        calls = BaseExtractor.walk_descendants(root, "call")
        assert len(calls) == 1

    def test_walk_descendants_empty(self):
        root = self._make_node(type_name="module", children=[])
        assert BaseExtractor.walk_descendants(root, "call") == []


# ══════════════════════════════════════════════════════════════
# Python extractor tests (with real tree-sitter)
# ══════════════════════════════════════════════════════════════


SAMPLE_PYTHON = '''
import os
from pathlib import Path
from flask import Flask, request

class UserService:
    """Manages users."""

    def __init__(self, db):
        self.db = db

    def get_user(self, user_id: int) -> dict:
        if user_id <= 0:
            raise ValueError("Invalid ID")
        return self.db.query(user_id)

def helper_func(x, y):
    return x + y
'''

SAMPLE_PYTHON_FASTAPI = '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"id": user_id}

@router.post("/users")
async def create_user(data: dict):
    return data
'''


class TestPythonExtractor:
    def _get_extractor(self):
        from blanketaudit.ingestion.extractors.python_extractor import PythonExtractor
        return PythonExtractor(repo_name="test")

    def test_extracts_imports(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        modules = [i.imported_module for i in result.imports]
        assert "os" in modules
        # Check from...import (pathlib and flask)
        assert any("pathlib" in m for m in modules)
        assert any("flask" in m for m in modules)

    def test_import_names_extracted(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        flask_import = next(i for i in result.imports if "flask" in i.imported_module)
        assert "Flask" in flask_import.imported_names
        assert "request" in flask_import.imported_names

    def test_extracts_class(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        assert len(result.classes) == 1
        cls = result.classes[0]
        assert cls.name == "UserService"
        assert "__init__" in cls.methods
        assert "get_user" in cls.methods

    def test_class_metadata(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        cls = result.classes[0]
        assert cls.file_path == "service.py"
        assert cls.repo_name == "test"
        assert cls.line_start > 0
        assert cls.line_end >= cls.line_start
        assert cls.loc > 0

    def test_extracts_methods(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        names = [m.qualified_name for m in result.methods]
        assert "UserService.__init__" in names
        assert "UserService.get_user" in names
        assert "helper_func" in names

    def test_method_parameters(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        get_user = next(m for m in result.methods if m.name == "get_user")
        # Parameters should include self and user_id (with type annotation)
        assert len(get_user.parameters) >= 2

    def test_method_return_type(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        get_user = next(m for m in result.methods if m.name == "get_user")
        assert get_user.return_type == "dict"

    def test_extracts_calls(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        callees = [c.callee for c in result.calls]
        assert any("db.query" in c for c in callees)
        assert any("ValueError" in c for c in callees)

    def test_call_has_caller(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        query_call = next(c for c in result.calls if "db.query" in c.callee)
        assert query_call.caller == "UserService.get_user"

    def test_call_types(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        query_call = next(c for c in result.calls if "db.query" in c.callee)
        assert query_call.call_type == "method"
        val_call = next(c for c in result.calls if "ValueError" in c.callee)
        assert val_call.call_type == "constructor"

    def test_fastapi_entry_points(self):
        tree, source = _parse_python(SAMPLE_PYTHON_FASTAPI)
        ext = self._get_extractor()
        result = ext.extract("routes.py", tree, source)
        assert len(result.entry_points) >= 2
        routes = [ep.route for ep in result.entry_points]
        http_methods = [ep.http_method for ep in result.entry_points]
        assert "/users/{user_id}" in routes
        assert "/users" in routes
        assert "GET" in http_methods
        assert "POST" in http_methods

    def test_entry_point_framework(self):
        tree, source = _parse_python(SAMPLE_PYTHON_FASTAPI)
        ext = self._get_extractor()
        result = ext.extract("routes.py", tree, source)
        for ep in result.entry_points:
            assert ep.framework == "fastapi"
            assert ep.repo_name == "test"

    def test_entry_point_methods_flagged(self):
        tree, source = _parse_python(SAMPLE_PYTHON_FASTAPI)
        ext = self._get_extractor()
        result = ext.extract("routes.py", tree, source)
        entry_methods = [m for m in result.methods if m.is_entry_point]
        assert len(entry_methods) >= 2

    def test_complexity_counted(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        get_user = next(m for m in result.methods if m.name == "get_user")
        # Has an if statement, so complexity > 1
        assert get_user.complexity >= 2

    def test_simple_function_complexity_is_1(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        helper = next(m for m in result.methods if m.name == "helper_func")
        assert helper.complexity == 1

    def test_no_entry_points_in_plain_module(self):
        tree, source = _parse_python(SAMPLE_PYTHON)
        ext = self._get_extractor()
        result = ext.extract("service.py", tree, source)
        assert len(result.entry_points) == 0

    def test_class_with_bases(self):
        code = '''
class Child(Parent):
    def do_thing(self):
        pass
'''
        tree, source = _parse_python(code)
        ext = self._get_extractor()
        result = ext.extract("child.py", tree, source)
        assert len(result.classes) == 1
        assert "Parent" in result.classes[0].bases


# ══════════════════════════════════════════════════════════════
# Java extractor tests (with real tree-sitter)
# ══════════════════════════════════════════════════════════════


SAMPLE_JAVA = '''
import org.springframework.web.bind.annotation.*;
import com.example.service.UserService;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService service) {
        this.userService = service;
    }

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        if (id <= 0) {
            throw new IllegalArgumentException("Bad id");
        }
        return userService.findById(id);
    }

    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        return userService.save(user);
    }
}
'''

SAMPLE_JAVA_INTERFACE = '''
public interface UserRepository {
    User findById(Long id);
    User save(User user);
}
'''


class TestJavaExtractor:
    def _get_extractor(self):
        from blanketaudit.ingestion.extractors.java_extractor import JavaExtractor
        return JavaExtractor(repo_name="test")

    def test_extracts_imports(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        modules = [i.imported_module for i in result.imports]
        assert any("springframework" in m for m in modules)
        assert any("UserService" in m for m in modules)

    def test_extracts_class(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        class_names = [c.name for c in result.classes]
        assert "UserController" in class_names

    def test_class_annotations(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        cls = next(c for c in result.classes if c.name == "UserController")
        # Should have RestController and RequestMapping annotations
        joined = " ".join(cls.decorators)
        assert "RestController" in joined

    def test_class_methods_list(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        cls = next(c for c in result.classes if c.name == "UserController")
        assert "getUser" in cls.methods
        assert "createUser" in cls.methods

    def test_extracts_methods(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        qualified_names = [m.qualified_name for m in result.methods]
        assert "UserController.getUser" in qualified_names
        assert "UserController.createUser" in qualified_names

    def test_constructor_extracted(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        qualified_names = [m.qualified_name for m in result.methods]
        assert "UserController.UserController" in qualified_names

    def test_method_parameters(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        get_user = next(m for m in result.methods if m.name == "getUser")
        assert len(get_user.parameters) >= 1
        # Should contain the @PathVariable Long id parameter
        assert any("id" in p for p in get_user.parameters)

    def test_method_return_type(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        get_user = next(m for m in result.methods if m.name == "getUser")
        assert get_user.return_type == "User"

    def test_spring_entry_points(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        assert len(result.entry_points) >= 2
        routes = [ep.route for ep in result.entry_points]
        http_methods = [ep.http_method for ep in result.entry_points]
        assert "/users/{id}" in routes
        assert "/users" in routes
        assert "GET" in http_methods
        assert "POST" in http_methods

    def test_entry_point_framework_is_spring(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        for ep in result.entry_points:
            assert ep.framework == "spring"

    def test_entry_point_methods_flagged(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        entry_methods = [m for m in result.methods if m.is_entry_point]
        assert len(entry_methods) >= 2

    def test_extracts_calls(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        callees = [c.callee for c in result.calls]
        assert any("findById" in c for c in callees)
        assert any("save" in c for c in callees)

    def test_constructor_call_detected(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        ctor_calls = [c for c in result.calls if c.call_type == "constructor"]
        callees = [c.callee for c in ctor_calls]
        assert any("IllegalArgumentException" in c for c in callees)

    def test_complexity_with_if(self):
        tree, source = _parse_java(SAMPLE_JAVA)
        ext = self._get_extractor()
        result = ext.extract("UserController.java", tree, source)
        get_user = next(m for m in result.methods if m.name == "getUser")
        # Has an if statement, complexity > 1
        assert get_user.complexity >= 2

    def test_interface_extraction(self):
        tree, source = _parse_java(SAMPLE_JAVA_INTERFACE)
        ext = self._get_extractor()
        result = ext.extract("UserRepository.java", tree, source)
        assert len(result.classes) >= 1
        iface = next(c for c in result.classes if c.name == "UserRepository")
        assert iface.line_start > 0

    def test_no_entry_points_in_plain_class(self):
        code = '''
public class Util {
    public static int add(int a, int b) {
        return a + b;
    }
}
'''
        tree, source = _parse_java(code)
        ext = self._get_extractor()
        result = ext.extract("Util.java", tree, source)
        assert len(result.entry_points) == 0


# ══════════════════════════════════════════════════════════════
# TypeScript extractor tests (with real tree-sitter)
# ══════════════════════════════════════════════════════════════


SAMPLE_TS = """
import { Router, Request, Response } from 'express';
const db = require('./database');

class UserController {
    private router: Router;

    constructor() {
        this.router = Router();
    }

    getUser(req: Request, res: Response) {
        const user = db.findUser(req.params.id);
        res.json(user);
    }
}

export function setupRoutes(app: any) {
    app.get('/api/users/:id', (req, res) => res.json({}));
    app.post('/api/users', (req, res) => res.json({}));
}
"""

SAMPLE_TS_SIMPLE = """
function noop() {
    return;
}

function complexFn(x: number) {
    if (x > 0) {
        return x;
    } else if (x < 0) {
        return -x;
    }
    return 0;
}
"""


class TestTypeScriptExtractor:
    def _get_extractor(self):
        from blanketaudit.ingestion.extractors.typescript_extractor import TypeScriptExtractor
        return TypeScriptExtractor(repo_name="test")

    def test_extracts_es6_imports(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        modules = [i.imported_module for i in result.imports]
        assert "express" in modules

    def test_import_names_extracted(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        express_import = next(i for i in result.imports if i.imported_module == "express")
        assert "Router" in express_import.imported_names
        assert "Request" in express_import.imported_names
        assert "Response" in express_import.imported_names

    def test_extracts_require_import(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        modules = [i.imported_module for i in result.imports]
        assert "./database" in modules

    def test_require_import_is_relative(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        db_import = next(i for i in result.imports if i.imported_module == "./database")
        assert db_import.is_relative is True

    def test_es6_import_not_relative(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        express_import = next(i for i in result.imports if i.imported_module == "express")
        assert express_import.is_relative is False

    def test_extracts_class(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        class_names = [c.name for c in result.classes]
        assert "UserController" in class_names

    def test_class_methods_list(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        cls = next(c for c in result.classes if c.name == "UserController")
        assert "constructor" in cls.methods
        assert "getUser" in cls.methods

    def test_extracts_class_methods(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        qualified_names = [m.qualified_name for m in result.methods]
        assert "UserController.constructor" in qualified_names
        assert "UserController.getUser" in qualified_names

    def test_extracts_top_level_function(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        names = [m.qualified_name for m in result.methods]
        assert "setupRoutes" in names

    def test_method_parameters(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        get_user = next(m for m in result.methods if m.name == "getUser")
        assert len(get_user.parameters) >= 2

    def test_extracts_calls(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        callees = [c.callee for c in result.calls]
        assert any("db.findUser" in c for c in callees)
        assert any("res.json" in c for c in callees)

    def test_express_entry_points(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        assert len(result.entry_points) >= 2
        routes = [ep.route for ep in result.entry_points]
        http_methods = [ep.http_method for ep in result.entry_points]
        assert "/api/users/:id" in routes
        assert "/api/users" in routes
        assert "GET" in http_methods
        assert "POST" in http_methods

    def test_entry_point_framework_is_express(self):
        tree, source = _parse_typescript(SAMPLE_TS)
        ext = self._get_extractor()
        result = ext.extract("controller.ts", tree, source)
        for ep in result.entry_points:
            assert ep.framework == "express"

    def test_complexity_simple_function(self):
        tree, source = _parse_typescript(SAMPLE_TS_SIMPLE)
        ext = self._get_extractor()
        result = ext.extract("utils.ts", tree, source)
        noop = next(m for m in result.methods if m.name == "noop")
        assert noop.complexity == 1

    def test_complexity_with_branches(self):
        tree, source = _parse_typescript(SAMPLE_TS_SIMPLE)
        ext = self._get_extractor()
        result = ext.extract("utils.ts", tree, source)
        complex_fn = next(m for m in result.methods if m.name == "complexFn")
        # Has if and else-if, complexity > 1
        assert complex_fn.complexity >= 2

    def test_no_entry_points_in_plain_module(self):
        tree, source = _parse_typescript(SAMPLE_TS_SIMPLE)
        ext = self._get_extractor()
        result = ext.extract("utils.ts", tree, source)
        assert len(result.entry_points) == 0

    def test_class_with_heritage(self):
        code = """
class AdminController extends BaseController {
    handle() {
        return true;
    }
}
"""
        tree, source = _parse_typescript(code)
        ext = self._get_extractor()
        result = ext.extract("admin.ts", tree, source)
        cls = next(c for c in result.classes if c.name == "AdminController")
        assert "BaseController" in cls.bases

    def test_export_function_extracted(self):
        code = """
export function greet(name: string) {
    return "hello " + name;
}
"""
        tree, source = _parse_typescript(code)
        ext = self._get_extractor()
        result = ext.extract("greet.ts", tree, source)
        names = [m.name for m in result.methods]
        assert "greet" in names
