"""Tests for LangGraph agent tools — neo4j, milvus, ast, coverage."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit.agents.tools.ast_tools import (
    get_class_info,
    get_file_methods,
    get_imports,
    get_method_info,
    inspect_node,
    read_file_content,
    set_analysis_contexts,
)
from blanketaudit.agents.tools.coverage_tool import (
    CoverageResult,
    CoverageSummary,
    find_coverage_reports,
    parse_coverage_report,
    parse_coverage_xml,
    parse_lcov,
    parse_jacoco_xml,
)
from blanketaudit.agents.tools.milvus_tools import (
    add_code_chunk,
    compliance_rag,
    search_vuln_patterns,
    semantic_search,
    set_vector_store,
)
from blanketaudit.agents.tools.neo4j_tools import (
    find_call_chain,
    get_blast_radius,
    get_entry_points,
    query_call_graph,
    query_dependencies,
    set_graph_store,
)


# ═══════════════════════════════════════════════════════════════
# Neo4j tools
# ═══════════════════════════════════════════════════════════════


class TestNeo4jTools:
    def _mock_store(self):
        store = AsyncMock()
        store.get_callers = AsyncMock(return_value=[
            {"name": "handler", "file": "routes.py"},
        ])
        store.get_callees = AsyncMock(return_value=[
            {"name": "db.query", "file": "db.py"},
        ])
        store.get_entry_points = AsyncMock(return_value=[
            {"name": "handler", "file": "routes.py", "repo": "api"},
        ])
        store.get_call_chain = AsyncMock(return_value=[
            ["handler", "service", "db"],
        ])
        store.query = AsyncMock(return_value=[])
        return store

    @pytest.mark.asyncio
    async def test_query_call_graph(self):
        store = self._mock_store()
        set_graph_store(store)
        result = json.loads(await query_call_graph("Service.get"))
        assert result["caller_count"] == 1
        assert result["callee_count"] == 1
        assert result["callers"][0]["name"] == "handler"

    @pytest.mark.asyncio
    async def test_query_call_graph_no_store(self):
        set_graph_store(None)
        result = json.loads(await query_call_graph("x"))
        assert "error" in result
        assert result["callers"] == []

    @pytest.mark.asyncio
    async def test_get_entry_points(self):
        set_graph_store(self._mock_store())
        result = json.loads(await get_entry_points())
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_find_call_chain(self):
        set_graph_store(self._mock_store())
        result = json.loads(await find_call_chain("handler", "db"))
        assert result["count"] == 1
        assert result["chains"][0] == ["handler", "service", "db"]

    @pytest.mark.asyncio
    async def test_get_blast_radius(self):
        set_graph_store(self._mock_store())
        result = json.loads(await get_blast_radius("Service.get"))
        assert result["direct_callers"] == 1

    @pytest.mark.asyncio
    async def test_query_dependencies(self):
        set_graph_store(self._mock_store())
        result = json.loads(await query_dependencies("service.py"))
        assert "methods" in result

    @pytest.mark.asyncio
    async def test_handles_store_error(self):
        store = AsyncMock()
        store.get_callers = AsyncMock(side_effect=RuntimeError("down"))
        store.get_callees = AsyncMock(side_effect=RuntimeError("down"))
        set_graph_store(store)
        result = json.loads(await query_call_graph("x"))
        assert "error" in result


# ═══════════════════════════════════════════════════════════════
# Milvus tools
# ═══════════════════════════════════════════════════════════════


class TestMilvusTools:
    def _mock_store(self):
        store = AsyncMock()
        store.search_code = AsyncMock(return_value=[
            {"content": "SQL query code", "metadata": {"file": "db.py"}, "score": 0.95},
        ])
        store.search_compliance = AsyncMock(return_value=[
            {"content": "HIPAA access control", "metadata": {"framework": "HIPAA", "clause": "§164.312", "title": "Access"}, "score": 0.9},
        ])
        store.search_vuln_patterns = AsyncMock(return_value=[
            {"content": "SQL injection via f-string", "metadata": {"cwe": "CWE-89"}, "score": 0.85},
        ])
        store.add_code_chunks = AsyncMock(return_value=["id1"])
        return store

    @pytest.mark.asyncio
    async def test_semantic_search(self):
        set_vector_store(self._mock_store())
        result = json.loads(await semantic_search("SQL injection"))
        assert result["count"] == 1
        assert result["results"][0]["content"] == "SQL query code"

    @pytest.mark.asyncio
    async def test_semantic_search_no_store(self):
        set_vector_store(None)
        result = json.loads(await semantic_search("x"))
        assert "error" in result

    @pytest.mark.asyncio
    async def test_compliance_rag(self):
        set_vector_store(self._mock_store())
        result = json.loads(await compliance_rag("access control for PHI"))
        assert result["count"] == 1
        assert result["clauses"][0]["framework"] == "HIPAA"

    @pytest.mark.asyncio
    async def test_search_vuln_patterns(self):
        set_vector_store(self._mock_store())
        result = json.loads(await search_vuln_patterns("SQL injection"))
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_add_code_chunk(self):
        set_vector_store(self._mock_store())
        result = json.loads(await add_code_chunk("code", "a.py", "api"))
        assert result["status"] == "added"

    @pytest.mark.asyncio
    async def test_handles_store_error(self):
        store = AsyncMock()
        store.search_code = AsyncMock(side_effect=RuntimeError("down"))
        set_vector_store(store)
        result = json.loads(await semantic_search("x"))
        assert "error" in result


# ═══════════════════════════════════════════════════════════════
# AST tools
# ═══════════════════════════════════════════════════════════════


class TestASTTools:
    @pytest.fixture(autouse=True)
    def setup_contexts(self):
        from blanketaudit.ingestion.models import (
            AnalysisContext, ClassInfo, ImportInfo, MethodInfo,
        )
        ctx = AnalysisContext(
            repo_name="api", root_path="/tmp/api",
            methods=[
                MethodInfo(
                    name="get_user", qualified_name="UserService.get_user",
                    file_path="service.py", repo_name="api",
                    line_start=10, line_end=25,
                    parameters=["self", "uid: int"], return_type="dict",
                    decorators=[], complexity=3, is_entry_point=False, loc=15,
                ),
                MethodInfo(
                    name="handler", qualified_name="handler",
                    file_path="routes.py", repo_name="api",
                    line_start=5, line_end=15,
                    is_entry_point=True, complexity=1, loc=10,
                ),
            ],
            classes=[
                ClassInfo(
                    name="UserService", file_path="service.py", repo_name="api",
                    line_start=5, line_end=30,
                    methods=["get_user", "save_user"], bases=["BaseService"],
                    loc=25,
                ),
            ],
            imports=[
                ImportInfo(
                    source_file="service.py", imported_module="models",
                    imported_names=["User"], line_number=1,
                ),
            ],
        )
        set_analysis_contexts([ctx])

    def test_inspect_node_finds_method(self):
        result = json.loads(inspect_node("service.py", 15))
        assert result["type"] == "method"
        assert result["name"] == "UserService.get_user"
        assert result["complexity"] == 3

    def test_inspect_node_finds_class(self):
        result = json.loads(inspect_node("service.py", 5))
        assert result["type"] == "class"
        assert result["name"] == "UserService"

    def test_inspect_node_not_found(self):
        result = json.loads(inspect_node("service.py", 100))
        assert "error" in result

    def test_get_method_info(self):
        result = json.loads(get_method_info("UserService.get_user"))
        assert result["complexity"] == 3
        assert result["return_type"] == "dict"
        assert len(result["parameters"]) == 2

    def test_get_method_info_not_found(self):
        result = json.loads(get_method_info("Nonexistent.method"))
        assert "error" in result

    def test_get_class_info(self):
        result = json.loads(get_class_info("UserService"))
        assert result["bases"] == ["BaseService"]
        assert "get_user" in result["methods"]

    def test_get_class_info_not_found(self):
        result = json.loads(get_class_info("FakeClass"))
        assert "error" in result

    def test_get_file_methods(self):
        result = json.loads(get_file_methods("service.py"))
        assert result["count"] == 1
        assert result["methods"][0]["qualified_name"] == "UserService.get_user"

    def test_get_file_methods_empty(self):
        result = json.loads(get_file_methods("nonexistent.py"))
        assert result["count"] == 0

    def test_get_imports(self):
        result = json.loads(get_imports("service.py"))
        assert result["count"] == 1
        assert result["imports"][0]["module"] == "models"

    def test_read_file_content(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("line1\nline2\nline3\nline4\n")
        result = json.loads(read_file_content("test.py", str(tmp_path), 2, 3))
        assert result["content"] == "line2\nline3"
        assert result["start_line"] == 2
        assert result["end_line"] == 3

    def test_read_file_content_not_found(self, tmp_path):
        result = json.loads(read_file_content("nope.py", str(tmp_path)))
        assert "error" in result


# ═══════════════════════════════════════════════════════════════
# Coverage tool
# ═══════════════════════════════════════════════════════════════


class TestCoverageResult:
    def test_to_dict(self):
        r = CoverageResult("a.py", 0.85, 85, 100)
        d = r.to_dict()
        assert d["percent"] == 85.0
        assert d["lines_covered"] == 85

    def test_summary_overall(self):
        files = [
            CoverageResult("a.py", 0.8, 80, 100),
            CoverageResult("b.py", 0.6, 30, 50),
        ]
        s = CoverageSummary(files)
        assert round(s.overall_rate, 3) == 0.733  # 110/150
        assert s.file_count == 2

    def test_uncovered_files(self):
        files = [
            CoverageResult("good.py", 0.9, 90, 100),
            CoverageResult("bad.py", 0.3, 30, 100),
        ]
        s = CoverageSummary(files)
        uncovered = s.uncovered_files(threshold=0.5)
        assert len(uncovered) == 1
        assert uncovered[0]["file_path"] == "bad.py"


SAMPLE_COVERAGE_XML = """<?xml version="1.0" ?>
<coverage version="5.5" timestamp="1234" lines-valid="200" lines-covered="150" line-rate="0.75">
  <packages>
    <package name="src">
      <classes>
        <class name="main.py" filename="src/main.py" line-rate="0.8">
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="1"/>
            <line number="3" hits="0"/>
            <line number="4" hits="1"/>
            <line number="5" hits="1"/>
          </lines>
        </class>
        <class name="utils.py" filename="src/utils.py" line-rate="0.5">
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="0"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
"""

SAMPLE_LCOV = """SF:src/main.ts
LF:20
LH:18
end_of_record
SF:src/utils.ts
LF:10
LH:3
end_of_record
"""

SAMPLE_JACOCO_XML = """<?xml version="1.0" encoding="UTF-8"?>
<report name="test">
  <package name="com/example">
    <sourcefile name="Main.java">
      <counter type="LINE" missed="5" covered="15"/>
    </sourcefile>
    <sourcefile name="Utils.java">
      <counter type="LINE" missed="10" covered="10"/>
    </sourcefile>
  </package>
</report>
"""


class TestParseCoverageXML:
    def test_parse(self, tmp_path):
        f = tmp_path / "coverage.xml"
        f.write_text(SAMPLE_COVERAGE_XML)
        summary = parse_coverage_xml(f)
        assert summary.file_count == 2
        assert summary.files[0].file_path == "src/main.py"
        assert summary.files[0].lines_covered == 4
        assert summary.files[0].lines_total == 5

    def test_missing_file(self, tmp_path):
        summary = parse_coverage_xml(tmp_path / "nope.xml")
        assert summary.file_count == 0


class TestParseLcov:
    def test_parse(self, tmp_path):
        f = tmp_path / "lcov.info"
        f.write_text(SAMPLE_LCOV)
        summary = parse_lcov(f)
        assert summary.file_count == 2
        assert summary.files[0].file_path == "src/main.ts"
        assert summary.files[0].lines_covered == 18
        assert summary.files[0].lines_total == 20

    def test_missing_file(self, tmp_path):
        summary = parse_lcov(tmp_path / "nope.info")
        assert summary.file_count == 0


class TestParseJacocoXML:
    def test_parse(self, tmp_path):
        f = tmp_path / "jacoco.xml"
        f.write_text(SAMPLE_JACOCO_XML)
        summary = parse_jacoco_xml(f)
        assert summary.file_count == 2
        assert summary.files[0].lines_covered == 15
        assert summary.files[0].lines_total == 20

    def test_missing_file(self, tmp_path):
        summary = parse_jacoco_xml(tmp_path / "nope.xml")
        assert summary.file_count == 0


class TestFindCoverageReports:
    def test_finds_coverage_xml(self, tmp_path):
        (tmp_path / "coverage.xml").write_text("<coverage/>")
        reports = find_coverage_reports(tmp_path)
        assert len(reports) == 1
        assert reports[0][0] == "coverage_xml"

    def test_finds_lcov(self, tmp_path):
        (tmp_path / "lcov.info").write_text("SF:a\nend_of_record\n")
        reports = find_coverage_reports(tmp_path)
        assert len(reports) == 1
        assert reports[0][0] == "lcov"

    def test_empty_dir(self, tmp_path):
        assert find_coverage_reports(tmp_path) == []


class TestParseCoverageReport:
    def test_auto_detect_coverage_xml(self, tmp_path):
        (tmp_path / "coverage.xml").write_text(SAMPLE_COVERAGE_XML)
        result = json.loads(parse_coverage_report(str(tmp_path)))
        assert "overall_percent" in result
        assert result["file_count"] == 2

    def test_no_report_found(self, tmp_path):
        result = json.loads(parse_coverage_report(str(tmp_path)))
        assert "error" in result

    def test_nonexistent_path(self):
        result = json.loads(parse_coverage_report("/nonexistent"))
        assert "error" in result
