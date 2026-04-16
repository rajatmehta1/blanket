"""Tests for external tool integrations — Semgrep, Gitleaks, OSV-scanner.

These tests mock the subprocess calls since the actual tools may not be
installed in the test environment.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit2.agents.tools.semgrep_tool import (
    SemgrepFinding,
    _map_sarif_level,
    _parse_sarif,
    check_semgrep_installed,
    run_semgrep,
)
from blanketaudit2.agents.tools.gitleaks_tool import (
    GitleaksFinding,
    _parse_gitleaks_json,
    check_gitleaks_installed,
    run_gitleaks,
)
from blanketaudit2.agents.tools.osv_tool import (
    OSVFinding,
    _parse_osv_json,
    check_osv_installed,
    find_manifests,
    run_osv_scan,
)


# ═══════════════════════════════════════════════════════════════
# Semgrep
# ═══════════════════════════════════════════════════════════════


SAMPLE_SARIF = {
    "runs": [{
        "results": [
            {
                "ruleId": "python.lang.security.audit.formatted-sql-query",
                "message": {"text": "SQL injection via f-string"},
                "level": "error",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/db.py"},
                        "region": {
                            "startLine": 15,
                            "endLine": 15,
                            "snippet": {"text": 'f"SELECT * FROM users WHERE id={uid}"'},
                        },
                    }
                }],
            },
            {
                "ruleId": "python.lang.security.insecure-hash",
                "message": {"text": "Use of MD5"},
                "level": "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/auth.py"},
                        "region": {
                            "startLine": 8,
                            "endLine": 8,
                            "snippet": {"text": "hashlib.md5(pw)"},
                        },
                    }
                }],
            },
        ]
    }]
}


class TestSemgrepParsing:
    def test_parse_sarif_extracts_findings(self):
        findings = _parse_sarif(SAMPLE_SARIF, "/tmp/repo")
        assert len(findings) == 2
        assert findings[0].rule_id == "python.lang.security.audit.formatted-sql-query"
        assert findings[0].file_path == "src/db.py"
        assert findings[0].line_start == 15
        assert findings[0].severity == "high"

    def test_parse_sarif_second_finding(self):
        findings = _parse_sarif(SAMPLE_SARIF, "/tmp/repo")
        assert findings[1].rule_id == "python.lang.security.insecure-hash"
        assert findings[1].severity == "medium"

    def test_parse_sarif_empty_runs(self):
        assert _parse_sarif({"runs": []}, "/tmp") == []

    def test_parse_sarif_no_runs(self):
        assert _parse_sarif({}, "/tmp") == []

    def test_map_sarif_level(self):
        assert _map_sarif_level("error") == "high"
        assert _map_sarif_level("warning") == "medium"
        assert _map_sarif_level("note") == "low"
        assert _map_sarif_level("unknown") == "medium"

    def test_finding_to_dict(self):
        f = SemgrepFinding(
            rule_id="test", file_path="a.py",
            line_start=1, line_end=2,
            message="msg", severity="high",
            code_snippet="code",
        )
        d = f.to_dict()
        assert d["tool"] == "semgrep"
        assert d["rule_id"] == "test"
        assert d["severity"] == "high"

    def test_parse_sarif_already_relative(self):
        sarif = {
            "runs": [{"results": [{
                "ruleId": "r1",
                "message": {"text": "msg"},
                "level": "error",
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/main.py"},
                    "region": {"startLine": 1, "endLine": 1},
                }}],
            }]}]
        }
        findings = _parse_sarif(sarif, "/tmp/repo")
        assert findings[0].file_path == "src/main.py"


class TestSemgrepExecution:
    @pytest.mark.asyncio
    async def test_not_installed_returns_empty(self):
        with patch("blanketaudit2.agents.tools.semgrep_tool.check_semgrep_installed",
                    return_value=False):
            result = await run_semgrep("/tmp/repo")
        assert result == []

    @pytest.mark.asyncio
    async def test_check_installed_false(self):
        with patch("blanketaudit2.agents.tools.semgrep_tool.asyncio.create_subprocess_exec",
                    side_effect=FileNotFoundError):
            assert await check_semgrep_installed() is False

    @pytest.mark.asyncio
    async def test_error_exit_code_returns_empty(self):
        mock_proc = AsyncMock()
        mock_proc.returncode = 2  # Error (not 0 or 1)
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch("blanketaudit2.agents.tools.semgrep_tool.check_semgrep_installed",
                    return_value=True), \
             patch("blanketaudit2.agents.tools.semgrep_tool.asyncio.create_subprocess_exec",
                    return_value=mock_proc), \
             patch("blanketaudit2.agents.tools.semgrep_tool.asyncio.wait_for",
                    return_value=(b"", b"error")):
            mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
            result = await run_semgrep("/tmp/repo")
        assert result == []

    @pytest.mark.asyncio
    async def test_timeout_returns_empty(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()

        with patch("blanketaudit2.agents.tools.semgrep_tool.check_semgrep_installed",
                    return_value=True), \
             patch("blanketaudit2.agents.tools.semgrep_tool.asyncio.create_subprocess_exec",
                    return_value=mock_proc), \
             patch("blanketaudit2.agents.tools.semgrep_tool.asyncio.wait_for",
                    side_effect=asyncio.TimeoutError):
            result = await run_semgrep("/tmp/repo", timeout=1)
        assert result == []


# ═══════════════════════════════════════════════════════════════
# Gitleaks
# ═══════════════════════════════════════════════════════════════


SAMPLE_GITLEAKS = [
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "src/config.py",
        "StartLine": 5,
        "Match": 'API_KEY = "sk-1234567890abcdef"',
        "Secret": "sk-1234567890abcdef",
        "Commit": "abc123",
    },
    {
        "RuleID": "aws-access-key-id",
        "Description": "AWS Access Key ID",
        "File": "deploy.sh",
        "StartLine": 12,
        "Match": "export AWS_ACCESS_KEY_ID=AKIA1234567890",
        "Secret": "AKIA1234567890",
        "Commit": "def456",
    },
]


class TestGitleaksParsing:
    def test_parse_json(self):
        findings = _parse_gitleaks_json(SAMPLE_GITLEAKS, "/tmp/repo")
        assert len(findings) == 2
        assert findings[0].rule_id == "generic-api-key"
        assert findings[0].file_path == "src/config.py"
        assert findings[0].line_number == 5

    def test_secret_masking(self):
        f = GitleaksFinding(
            rule_id="test", description="test",
            file_path="a.py", line_number=1,
            match="x", secret="sk-1234567890abcdef",
        )
        assert "1234567890" not in f.secret
        assert f.secret.startswith("sk-1")
        assert f.secret.endswith("cdef")
        assert "***" in f.secret

    def test_short_secret_fully_masked(self):
        f = GitleaksFinding(
            rule_id="test", description="test",
            file_path="a.py", line_number=1,
            match="x", secret="short",
        )
        assert f.secret == "***"

    def test_finding_to_dict(self):
        findings = _parse_gitleaks_json(SAMPLE_GITLEAKS, "/tmp/repo")
        d = findings[0].to_dict()
        assert d["tool"] == "gitleaks"
        assert d["severity"] == "high"
        assert d["line_start"] == 5

    def test_empty_input(self):
        assert _parse_gitleaks_json([], "/tmp") == []


class TestGitleaksExecution:
    @pytest.mark.asyncio
    async def test_not_installed_returns_empty(self):
        with patch("blanketaudit2.agents.tools.gitleaks_tool.check_gitleaks_installed",
                    return_value=False):
            result = await run_gitleaks("/tmp/repo")
        assert result == []

    @pytest.mark.asyncio
    async def test_check_installed_false(self):
        with patch("blanketaudit2.agents.tools.gitleaks_tool.asyncio.create_subprocess_exec",
                    side_effect=FileNotFoundError):
            assert await check_gitleaks_installed() is False

    @pytest.mark.asyncio
    async def test_timeout_returns_empty(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()

        with patch("blanketaudit2.agents.tools.gitleaks_tool.check_gitleaks_installed",
                    return_value=True), \
             patch("blanketaudit2.agents.tools.gitleaks_tool.asyncio.create_subprocess_exec",
                    return_value=mock_proc), \
             patch("blanketaudit2.agents.tools.gitleaks_tool.asyncio.wait_for",
                    side_effect=asyncio.TimeoutError):
            result = await run_gitleaks("/tmp/repo", timeout=1)
        assert result == []


# ═══════════════════════════════════════════════════════════════
# OSV-scanner
# ═══════════════════════════════════════════════════════════════


SAMPLE_OSV = {
    "results": [{
        "source": {"path": "/tmp/repo/requirements.txt"},
        "packages": [{
            "package": {"name": "flask", "version": "2.0.0"},
            "vulnerabilities": [{
                "id": "GHSA-abcd-1234-efgh",
                "summary": "XSS vulnerability in Flask debugger",
                "aliases": ["CVE-2023-12345"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{
                    "ranges": [{"events": [{"fixed": "2.3.1"}]}],
                }],
            }],
            "groups": [],
        }, {
            "package": {"name": "requests", "version": "2.28.0"},
            "vulnerabilities": [{
                "id": "GHSA-wxyz-5678-ijkl",
                "summary": "SSRF in requests library",
                "aliases": ["CVE-2023-67890"],
                "database_specific": {"severity": "MEDIUM"},
                "affected": [{
                    "ranges": [{"events": [{"fixed": "2.31.0"}]}],
                }],
            }],
            "groups": [],
        }],
    }]
}


class TestOSVParsing:
    def test_parse_json(self):
        findings = _parse_osv_json(SAMPLE_OSV, "/tmp/repo")
        assert len(findings) == 2

    def test_first_finding_fields(self):
        findings = _parse_osv_json(SAMPLE_OSV, "/tmp/repo")
        f = findings[0]
        assert f.vuln_id == "GHSA-abcd-1234-efgh"
        assert f.package_name == "flask"
        assert f.package_version == "2.0.0"
        assert f.severity == "high"
        assert f.fixed_version == "2.3.1"
        assert "CVE-2023-12345" in f.aliases

    def test_manifest_path_preserved(self):
        """On different platforms the path may or may not be relative."""
        findings = _parse_osv_json(SAMPLE_OSV, "/tmp/repo")
        assert "requirements.txt" in findings[0].manifest_file

    def test_finding_to_dict(self):
        findings = _parse_osv_json(SAMPLE_OSV, "/tmp/repo")
        d = findings[0].to_dict()
        assert d["tool"] == "osv"
        assert d["vuln_id"] == "GHSA-abcd-1234-efgh"
        assert d["package_name"] == "flask"
        assert d["fixed_version"] == "2.3.1"

    def test_empty_results(self):
        assert _parse_osv_json({"results": []}, "/tmp") == []

    def test_empty_packages(self):
        data = {"results": [{"source": {"path": "x"}, "packages": []}]}
        assert _parse_osv_json(data, "/tmp") == []

    def test_severity_mapping(self):
        findings = _parse_osv_json(SAMPLE_OSV, "/tmp/repo")
        assert findings[0].severity == "high"
        assert findings[1].severity == "medium"


class TestOSVExecution:
    @pytest.mark.asyncio
    async def test_not_installed_returns_empty(self):
        with patch("blanketaudit2.agents.tools.osv_tool.check_osv_installed",
                    return_value=False):
            result = await run_osv_scan("/tmp/repo")
        assert result == []

    @pytest.mark.asyncio
    async def test_check_installed_false(self):
        with patch("blanketaudit2.agents.tools.osv_tool.asyncio.create_subprocess_exec",
                    side_effect=FileNotFoundError):
            assert await check_osv_installed() is False

    @pytest.mark.asyncio
    async def test_timeout_returns_empty(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()

        with patch("blanketaudit2.agents.tools.osv_tool.check_osv_installed",
                    return_value=True), \
             patch("blanketaudit2.agents.tools.osv_tool.asyncio.create_subprocess_exec",
                    return_value=mock_proc), \
             patch("blanketaudit2.agents.tools.osv_tool.asyncio.wait_for",
                    side_effect=asyncio.TimeoutError):
            result = await run_osv_scan("/tmp/repo", timeout=1)
        assert result == []


class TestFindManifests:
    def test_finds_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0\n")
        manifests = find_manifests(tmp_path)
        names = [m.name for m in manifests]
        assert "requirements.txt" in names

    def test_finds_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "app"}')
        manifests = find_manifests(tmp_path)
        names = [m.name for m in manifests]
        assert "package.json" in names

    def test_finds_nested_manifests(self, tmp_path):
        sub = tmp_path / "services" / "api"
        sub.mkdir(parents=True)
        (sub / "requirements.txt").write_text("flask\n")
        (tmp_path / "package.json").write_text("{}")
        manifests = find_manifests(tmp_path)
        assert len(manifests) == 2

    def test_skips_node_modules(self, tmp_path):
        """Verify node_modules is pruned from the walk."""
        import tempfile, os
        # Use our own temp dir to avoid pytest fixture caching issues
        base = Path(tempfile.mkdtemp())
        try:
            nm = base / "node_modules" / "lodash"
            nm.mkdir(parents=True)
            (nm / "package.json").write_text("{}")
            src = base / "src"
            src.mkdir()
            (src / "requirements.txt").write_text("flask\n")
            manifests = find_manifests(base)
            manifest_strs = [str(m) for m in manifests]
            # node_modules should be excluded
            assert not any("node_modules" in s for s in manifest_strs), manifest_strs
            # requirements.txt should be found
            assert any("requirements.txt" in s for s in manifest_strs), manifest_strs
        finally:
            import shutil
            shutil.rmtree(base, ignore_errors=True)

    def test_empty_dir(self, tmp_path):
        assert find_manifests(tmp_path) == []
