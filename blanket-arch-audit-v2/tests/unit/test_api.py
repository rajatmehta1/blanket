"""Tests for FastAPI endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from blanketaudit.api.app import app
from blanketaudit.config import Settings, get_settings


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(llm={"provider": "none"}, embedding={"provider": "none"})


client = TestClient(app)


# ═══════════════════════════════════════════════════════════════
# Health endpoint
# ═══════════════════════════════════════════════════════════════


class TestHealthEndpoint:
    def test_health_returns_200(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_has_version(self):
        data = client.get("/health").json()
        assert "version" in data
        assert data["version"] == "0.1.0"

    def test_health_has_llm_config(self):
        data = client.get("/health").json()
        assert "llm" in data
        assert "provider" in data["llm"]

    def test_health_has_embeddings_config(self):
        data = client.get("/health").json()
        assert "embeddings" in data

    def test_health_has_circuit_breaker(self):
        data = client.get("/health").json()
        assert "circuit_breaker" in data

    def test_health_has_cost_config(self):
        data = client.get("/health").json()
        assert "cost" in data
        assert "max_scan_cost_usd" in data["cost"]


# ═══════════════════════════════════════════════════════════════
# Scan endpoints
# ═══════════════════════════════════════════════════════════════


class TestScanEndpoints:
    def test_start_scan(self):
        resp = client.post("/api/v1/scan", json={
            "project_name": "test",
            "repos": [{"local_path": "/tmp/test"}],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "queued"

    def test_get_scan_not_found(self):
        resp = client.get("/api/v1/scan/nonexistent")
        assert resp.status_code == 404

    def test_list_scans(self):
        # Start a scan first
        client.post("/api/v1/scan", json={
            "project_name": "list-test",
            "repos": [],
        })
        resp = client.get("/api/v1/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_scan_status_after_start(self):
        resp = client.post("/api/v1/scan", json={
            "project_name": "status-test",
            "repos": [],
        })
        scan_id = resp.json()["scan_id"]
        status_resp = client.get(f"/api/v1/scan/{scan_id}")
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["scan_id"] == scan_id
        assert data["status"] in ("queued", "running", "completed", "failed")

    def test_get_report_not_completed(self):
        resp = client.post("/api/v1/scan", json={
            "project_name": "report-test",
            "repos": [],
        })
        scan_id = resp.json()["scan_id"]
        report_resp = client.get(f"/api/v1/scan/{scan_id}/report")
        # May be 409 (not completed) or 200 (if background task finished)
        assert report_resp.status_code in (200, 409)


class TestCostEstimate:
    def test_cost_estimate_endpoint(self):
        resp = client.post("/api/v1/scan/cost-estimate", json={
            "project_name": "dry-run",
            "repos": [],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert "cost_estimate" in data

    def test_cost_estimate_with_frameworks(self):
        resp = client.post("/api/v1/scan/cost-estimate", json={
            "project_name": "dry-run",
            "frameworks": ["HIPAA", "SOC2"],
            "repos": [],
        })
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════
# Policies endpoint
# ═══════════════════════════════════════════════════════════════


class TestPoliciesEndpoint:
    def test_list_all_policies(self):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 80  # We have 88 policies

    def test_filter_by_category(self):
        resp = client.get("/api/v1/policies?category=security")
        assert resp.status_code == 200
        data = resp.json()
        assert all(p["category"] == "security" for p in data)
        assert len(data) >= 20

    def test_policy_structure(self):
        resp = client.get("/api/v1/policies")
        data = resp.json()
        p = data[0]
        assert "id" in p
        assert "name" in p
        assert "category" in p
        assert "severity" in p
        assert "has_static_checks" in p
        assert "has_ai_analysis" in p


# ═══════════════════════════════════════════════════════════════
# OpenAPI docs
# ═══════════════════════════════════════════════════════════════


class TestDocs:
    def test_openapi_available(self):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["info"]["title"] == "BlanketAudit API"
        assert "/health" in data["paths"]
        assert "/api/v1/scan" in data["paths"]
        assert "/api/v1/scan/cost-estimate" in data["paths"]
        assert "/api/v1/policies" in data["paths"]
