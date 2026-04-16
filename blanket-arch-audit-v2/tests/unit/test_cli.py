"""Tests for the CLI — scan, report, policies, providers commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

typer = pytest.importorskip("typer")
from typer.testing import CliRunner

from blanketaudit2.cli.main import app, EXIT_OK, EXIT_ERROR, EXIT_FINDINGS, _is_ci

runner = CliRunner()


# ═══════════════════════════════════════════════════════════════
# Version / help
# ═══════════════════════════════════════════════════════════════


class TestVersionHelp:
    def test_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "blanketaudit2" in result.output
        assert "0.1.0" in result.output

    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "report" in result.output
        assert "policies" in result.output
        assert "providers" in result.output

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.output
        assert "--domain" in result.output
        assert "--framework" in result.output
        assert "--format" in result.output


# ═══════════════════════════════════════════════════════════════
# scan command
# ═══════════════════════════════════════════════════════════════


class TestScanCommand:
    def test_scan_no_args_shows_error(self):
        with patch("blanketaudit2.cli.config_loader.load_config") as mock_load, \
             patch("blanketaudit2.metrics.setup_observability"):
            mock_load.return_value = MagicMock(
                log_level="INFO", log_json=False, domain="general",
                active_frameworks=[], model_dump=MagicMock(return_value={}),
            )
            result = runner.invoke(app, ["scan"])
        assert result.exit_code == EXIT_ERROR

    def test_scan_dry_run(self, tmp_path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')\n")

        mock_result = {
            "status": "aborted",
            "cost_estimate": {
                "total_estimated_usd": 2.50,
                "per_agent": [],
                "total_estimated_tokens": 50000,
                "file_tier_breakdown": {"tier1": 1, "tier2": 0, "tier3": 0},
                "model_routing": {},
                "within_budget": True,
                "total_files": 1,
                "total_loc": 1,
                "recommendation": "Within budget",
            },
            "health_score": {"overall": 100, "grade": "A", "severity_counts": {}},
        }

        with patch("blanketaudit2.cli.config_loader.load_config") as mock_load, \
             patch("blanketaudit2.metrics.setup_observability"), \
             patch("blanketaudit2.cli.main._run_scan", return_value=mock_result):
            mock_load.return_value = MagicMock(
                log_level="INFO", log_json=False, domain="general",
                active_frameworks=[], model_dump=MagicMock(return_value={}),
            )
            result = runner.invoke(app, ["scan", str(repo), "--dry-run"])

        assert result.exit_code == EXIT_OK

    def test_scan_json_output(self, tmp_path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / "main.py").write_text("x=1\n")

        mock_result = {
            "status": "completed",
            "health_score": {
                "overall": 80, "grade": "B",
                "severity_counts": {"critical": 0, "high": 1, "medium": 2, "low": 0},
                "categories": [],
            },
            "findings": [],
            "validated_findings": [],
            "report": {"project_name": "test", "findings": [], "infra_findings": [],
                        "health_score": {"overall": 80, "grade": "B", "categories": [],
                                          "severity_counts": {"critical": 0, "high": 1, "medium": 2, "low": 0}},
                        "remediation_phases": [], "active_frameworks": [],
                        "scan_manifest": {"scan_id": "s1"}},
        }

        with patch("blanketaudit2.cli.config_loader.load_config") as mock_load, \
             patch("blanketaudit2.metrics.setup_observability"), \
             patch("blanketaudit2.cli.main._run_scan", return_value=mock_result):
            mock_load.return_value = MagicMock(
                log_level="INFO", log_json=False, domain="general",
                active_frameworks=[], model_dump=MagicMock(return_value={}),
            )
            result = runner.invoke(app, ["scan", str(repo), "--json"])

        assert result.exit_code == EXIT_OK
        # Should contain JSON summary
        import json
        output = result.output.strip()
        # Find the JSON part
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("{"):
                data = json.loads(line + output[output.index(line) + len(line):])
                assert "gate" in data
                break

    def test_scan_exit_code_findings(self, tmp_path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / "main.py").write_text("x=1\n")

        mock_result = {
            "status": "completed",
            "health_score": {
                "overall": 30, "grade": "D",
                "severity_counts": {"critical": 2, "high": 3, "medium": 0, "low": 0},
                "categories": [],
            },
            "findings": [],
            "validated_findings": [],
            "report": {},
        }

        with patch("blanketaudit2.cli.config_loader.load_config") as mock_load, \
             patch("blanketaudit2.metrics.setup_observability"), \
             patch("blanketaudit2.cli.main._run_scan", return_value=mock_result):
            mock_load.return_value = MagicMock(
                log_level="INFO", log_json=False, domain="general",
                active_frameworks=[], model_dump=MagicMock(return_value={}),
            )
            result = runner.invoke(app, ["scan", str(repo)])

        # Critical findings → exit code 1
        assert result.exit_code == EXIT_FINDINGS


# ═══════════════════════════════════════════════════════════════
# policies command
# ═══════════════════════════════════════════════════════════════


class TestPoliciesCommand:
    def test_policies_list(self):
        result = runner.invoke(app, ["policies", "--list"])
        assert result.exit_code == 0
        assert "Policies" in result.output

    def test_policies_validate(self):
        result = runner.invoke(app, ["policies", "--validate"])
        assert result.exit_code == 0
        assert "validated" in result.output.lower()

    def test_policies_filter_category(self):
        result = runner.invoke(app, ["policies", "--list", "--category", "security"])
        assert result.exit_code == 0

    def test_policies_shows_count(self):
        result = runner.invoke(app, ["policies", "--list"])
        assert result.exit_code == 0
        # Should show policy table with IDs
        assert "SEC-" in result.output or "QUAL-" in result.output or "ARCH-" in result.output or "COMP-" in result.output


# ═══════════════════════════════════════════════════════════════
# providers command
# ═══════════════════════════════════════════════════════════════


class TestProvidersCommand:
    def test_providers_shows_config(self):
        result = runner.invoke(app, ["providers"])
        assert result.exit_code == 0
        assert "Provider" in result.output
        assert "LLM" in result.output

    def test_providers_shows_status(self):
        result = runner.invoke(app, ["providers"])
        assert "configured" in result.output or "disabled" in result.output


# ═══════════════════════════════════════════════════════════════
# CI detection
# ═══════════════════════════════════════════════════════════════


class TestCIDetection:
    def test_is_ci_in_test(self):
        # In pytest, stdout may or may not be a tty
        assert isinstance(_is_ci(), bool)


# ═══════════════════════════════════════════════════════════════
# Exit codes
# ═══════════════════════════════════════════════════════════════


class TestExitCodes:
    def test_exit_codes_defined(self):
        assert EXIT_OK == 0
        assert EXIT_FINDINGS == 1
        assert EXIT_ERROR == 2
