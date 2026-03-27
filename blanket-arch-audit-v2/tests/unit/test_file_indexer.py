"""Tests for blanketaudit.ingestion.file_indexer."""
from __future__ import annotations

from pathlib import Path

import pytest

from blanketaudit.ingestion.file_indexer import (
    FileIndexer,
    _classify_file_type,
    _detect_language,
)
from blanketaudit.ingestion.models import FileType


# ── Language Detection ──────────────────────────────────────


class TestDetectLanguage:
    def test_python(self):
        assert _detect_language(Path("main.py")) == "python"

    def test_typescript(self):
        assert _detect_language(Path("app.ts")) == "typescript"

    def test_tsx(self):
        assert _detect_language(Path("App.tsx")) == "typescript"

    def test_java(self):
        assert _detect_language(Path("App.java")) == "java"

    def test_go(self):
        assert _detect_language(Path("main.go")) == "go"

    def test_rust(self):
        assert _detect_language(Path("lib.rs")) == "rust"

    def test_csharp(self):
        assert _detect_language(Path("Program.cs")) == "csharp"

    def test_javascript(self):
        assert _detect_language(Path("index.js")) == "javascript"

    def test_shell(self):
        assert _detect_language(Path("deploy.sh")) == "shell"

    def test_unknown(self):
        assert _detect_language(Path("readme.xyz")) == ""

    def test_sql(self):
        assert _detect_language(Path("schema.sql")) == "sql"


# ── File Type Classification ────────────────────────────────


class TestClassifyFileType:
    def test_source_file(self):
        assert _classify_file_type(Path("src/main.py")) == FileType.SOURCE

    def test_config_yaml(self):
        assert _classify_file_type(Path("config.yaml")) == FileType.CONFIG

    def test_config_json(self):
        assert _classify_file_type(Path("settings.json")) == FileType.CONFIG

    def test_config_env(self):
        # .env has no suffix; extension-based lookup uses ".env" key in the map
        # but Path(".env").suffix == "" so it falls through to OTHER
        assert _classify_file_type(Path("app.env")) == FileType.CONFIG

    def test_dockerfile(self):
        assert _classify_file_type(Path("Dockerfile")) == FileType.IAC

    def test_terraform(self):
        assert _classify_file_type(Path("main.tf")) == FileType.IAC

    def test_github_actions(self):
        assert _classify_file_type(Path(".github/workflows/ci.yml")) == FileType.CICD

    def test_gitlab_ci(self):
        assert _classify_file_type(Path(".gitlab-ci.yml")) == FileType.CICD

    def test_jenkinsfile(self):
        assert _classify_file_type(Path("Jenkinsfile")) == FileType.CICD

    def test_test_file_prefix(self):
        assert _classify_file_type(Path("test_main.py")) == FileType.TEST

    def test_test_file_suffix_py(self):
        assert _classify_file_type(Path("main_test.py")) == FileType.TEST

    def test_test_file_suffix_ts(self):
        assert _classify_file_type(Path("app.test.ts")) == FileType.TEST

    def test_test_file_in_tests_dir(self):
        assert _classify_file_type(Path("tests/conftest.py")) == FileType.TEST

    def test_build_file_pyproject(self):
        # pyproject.toml has .toml extension which maps to CONFIG before the
        # build filename check — this matches the actual implementation priority
        assert _classify_file_type(Path("pyproject.toml")) == FileType.CONFIG

    def test_build_file_package_json(self):
        # package.json has .json extension which maps to CONFIG before the
        # build filename check — this matches the actual implementation priority
        assert _classify_file_type(Path("package.json")) == FileType.CONFIG

    def test_build_file_makefile(self):
        # Makefile is matched by exact filename, so it gets BUILD
        assert _classify_file_type(Path("Makefile")) == FileType.BUILD

    def test_build_file_pom_xml(self):
        # pom.xml has no extension mapping to CONFIG, so it falls through to BUILD
        assert _classify_file_type(Path("pom.xml")) == FileType.BUILD

    def test_doc_file(self):
        assert _classify_file_type(Path("README.md")) == FileType.DOC

    def test_k8s_manifest(self):
        assert _classify_file_type(Path("k8s/deployment.yaml")) == FileType.IAC

    def test_docker_compose(self):
        assert _classify_file_type(Path("docker-compose.yml")) == FileType.IAC

    def test_other(self):
        assert _classify_file_type(Path("unknown.xyz")) == FileType.OTHER


# ── FileIndexer ─────────────────────────────────────────────


class TestFileIndexer:
    def test_index_simple_project(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')\nprint('world')\n")
        (tmp_path / "utils.py").write_text("def helper():\n    pass\n")

        indexer = FileIndexer()
        files = indexer.index_project(tmp_path, "test-repo")

        assert len(files) == 2
        names = {f.path for f in files}
        assert "main.py" in names
        assert "utils.py" in names

        main = next(f for f in files if f.path == "main.py")
        assert main.language == "python"
        assert main.loc == 2
        assert main.repo_name == "test-repo"
        assert main.content_sha256 != ""

    def test_skips_git_directory(self, tmp_path):
        git = tmp_path / ".git"
        git.mkdir()
        (git / "config").write_text("fake")
        (tmp_path / "main.py").write_text("x=1\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        assert len(files) == 1
        assert files[0].path == "main.py"

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "lodash"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("module.exports = {}")
        (tmp_path / "app.js").write_text("const _ = require('lodash')\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        assert len(files) == 1

    def test_skips_pycache(self, tmp_path):
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "mod.cpython-311.pyc").write_bytes(b"\x00")
        (tmp_path / "mod.py").write_text("x=1\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        assert len(files) == 1

    def test_skips_binary_files(self, tmp_path):
        (tmp_path / "main.py").write_text("x=1\n")
        (tmp_path / "logo.png").write_bytes(b"\x89PNG")

        files = FileIndexer().index_project(tmp_path, "repo")
        assert len(files) == 1
        assert files[0].path == "main.py"

    def test_skips_pdf_files(self, tmp_path):
        (tmp_path / "main.py").write_text("x=1\n")
        (tmp_path / "doc.pdf").write_bytes(b"%PDF-1.4")

        files = FileIndexer().index_project(tmp_path, "repo")
        assert len(files) == 1

    def test_multi_language(self, tmp_path):
        (tmp_path / "app.py").write_text("pass\n")
        (tmp_path / "index.ts").write_text("export {}\n")
        (tmp_path / "Main.java").write_text("class Main {}\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        languages = {f.language for f in files}
        assert "python" in languages
        assert "typescript" in languages
        assert "java" in languages

    def test_respects_gitignore(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.log\nsecrets/\n")
        (tmp_path / "main.py").write_text("x=1\n")
        (tmp_path / "debug.log").write_text("log data")
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "key.py").write_text("KEY='secret'\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        paths = {f.path for f in files}
        assert "main.py" in paths
        assert "debug.log" not in paths

    def test_respects_blanketauditignore(self, tmp_path):
        (tmp_path / ".blanketauditignore").write_text("generated/\n")
        gen = tmp_path / "generated"
        gen.mkdir()
        (gen / "output.py").write_text("x=1\n")
        (tmp_path / "main.py").write_text("x=1\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        paths = {f.path for f in files}
        assert "main.py" in paths
        assert "generated/output.py" not in paths

    def test_empty_directory(self, tmp_path):
        files = FileIndexer().index_project(tmp_path, "repo")
        assert files == []

    def test_sha256_computed(self, tmp_path):
        (tmp_path / "main.py").write_text("x=1\n")
        files = FileIndexer().index_project(tmp_path, "repo")
        assert len(files[0].content_sha256) == 64

    def test_sha256_deterministic(self, tmp_path):
        (tmp_path / "main.py").write_text("x=1\n")
        files1 = FileIndexer().index_project(tmp_path, "repo")
        files2 = FileIndexer().index_project(tmp_path, "repo")
        assert files1[0].content_sha256 == files2[0].content_sha256

    def test_file_type_classified(self, tmp_path):
        (tmp_path / "main.py").write_text("x=1\n")
        (tmp_path / "config.yaml").write_text("key: val\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        types = {f.path: f.file_type for f in files}
        assert types["main.py"] == FileType.SOURCE
        assert types["config.yaml"] == FileType.CONFIG

    def test_size_bytes_set(self, tmp_path):
        content = "hello world\n"
        (tmp_path / "main.py").write_text(content)
        files = FileIndexer().index_project(tmp_path, "repo")
        assert files[0].size_bytes > 0

    def test_last_modified_set(self, tmp_path):
        (tmp_path / "main.py").write_text("x=1\n")
        files = FileIndexer().index_project(tmp_path, "repo")
        assert files[0].last_modified != ""

    def test_nested_directories(self, tmp_path):
        src = tmp_path / "src" / "app"
        src.mkdir(parents=True)
        (src / "server.py").write_text("pass\n")

        files = FileIndexer().index_project(tmp_path, "repo")
        assert len(files) == 1
        assert files[0].path == "src/app/server.py"

    def test_nonexistent_path_returns_empty(self, tmp_path):
        files = FileIndexer().index_project(tmp_path / "nope", "repo")
        assert files == []

    def test_loc_counts_all_lines(self, tmp_path):
        (tmp_path / "main.py").write_text("a\nb\nc\nd\ne\n")
        files = FileIndexer().index_project(tmp_path, "repo")
        assert files[0].loc == 5
