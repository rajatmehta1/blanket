"""Tests for compliance knowledge base loading and seeding."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit2.config import Settings, get_settings
from blanketaudit2.policies.knowledge_base.seeder import (
    ComplianceClause,
    KnowledgeBaseSeeder,
    load_all_clauses,
    load_clauses_from_yaml,
)
from blanketaudit2.storage.milvus_store import MilvusStore

KB_DIR = Path(__file__).parent.parent.parent / "blanketaudit2" / "policies" / "knowledge_base"


# ── Helpers ──────────────────────────────────────────────────


def _settings() -> Settings:
    get_settings.cache_clear()
    return Settings(llm={"provider": "none"}, embedding={"provider": "none"})


def _mock_store():
    """Mock MilvusStore with working add_texts."""
    store = MagicMock(spec=MilvusStore)
    store.add_texts = AsyncMock(return_value=["id1", "id2"])
    store.add_vuln_patterns = AsyncMock(return_value=["id1"])
    return store


# ═══════════════════════════════════════════════════════════════
# YAML loading — all 4 files parse correctly
# ═══════════════════════════════════════════════════════════════


class TestLoadClausesFromYaml:
    def test_hipaa_loads(self):
        clauses = load_clauses_from_yaml(KB_DIR / "hipaa_clauses.yaml")
        assert len(clauses) >= 12
        assert all(c.framework == "HIPAA" for c in clauses)

    def test_soc2_loads(self):
        clauses = load_clauses_from_yaml(KB_DIR / "soc2_criteria.yaml")
        assert len(clauses) >= 10
        assert all(c.framework == "SOC2" for c in clauses)

    def test_pci_dss_loads(self):
        clauses = load_clauses_from_yaml(KB_DIR / "pci_dss_requirements.yaml")
        assert len(clauses) >= 10
        assert all(c.framework == "PCI-DSS" for c in clauses)

    def test_gdpr_loads(self):
        clauses = load_clauses_from_yaml(KB_DIR / "gdpr_articles.yaml")
        assert len(clauses) >= 8
        assert all(c.framework == "GDPR" for c in clauses)

    def test_nonexistent_file_returns_empty(self, tmp_path):
        clauses = load_clauses_from_yaml(tmp_path / "nonexistent.yaml")
        assert clauses == []

    def test_invalid_yaml_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(":::bad::yaml")
        clauses = load_clauses_from_yaml(bad)
        assert clauses == []

    def test_no_clauses_key_returns_empty(self, tmp_path):
        f = tmp_path / "no_clauses.yaml"
        f.write_text("something_else: true\n")
        clauses = load_clauses_from_yaml(f)
        assert clauses == []


class TestLoadAllClauses:
    def test_loads_all_frameworks(self):
        all_clauses = load_all_clauses(KB_DIR)
        assert "hipaa" in all_clauses
        assert "soc2" in all_clauses
        assert "pci_dss" in all_clauses
        assert "gdpr" in all_clauses

    def test_total_clause_count(self):
        all_clauses = load_all_clauses(KB_DIR)
        total = sum(len(c) for c in all_clauses.values())
        assert total >= 45  # At least 12+10+10+8 = 40

    def test_missing_dir_returns_partial(self, tmp_path):
        # Empty dir — no files found
        all_clauses = load_all_clauses(tmp_path)
        assert all(len(v) == 0 for v in all_clauses.values()) or len(all_clauses) == 0


# ═══════════════════════════════════════════════════════════════
# Clause quality — verify all fields are populated
# ═══════════════════════════════════════════════════════════════


class TestClauseQuality:
    @pytest.fixture
    def all_clauses(self):
        all_c = load_all_clauses(KB_DIR)
        return [c for clauses in all_c.values() for c in clauses]

    def test_all_have_id(self, all_clauses):
        for c in all_clauses:
            assert c.id, f"Missing id for clause: {c.title}"

    def test_all_have_framework(self, all_clauses):
        for c in all_clauses:
            assert c.framework in ("HIPAA", "SOC2", "PCI-DSS", "GDPR"), \
                f"Bad framework for {c.id}: {c.framework}"

    def test_all_have_clause(self, all_clauses):
        for c in all_clauses:
            assert c.clause, f"Missing clause ref for {c.id}"

    def test_all_have_title(self, all_clauses):
        for c in all_clauses:
            assert c.title, f"Missing title for {c.id}"

    def test_all_have_text(self, all_clauses):
        for c in all_clauses:
            assert len(c.text) > 20, f"Text too short for {c.id}: {c.text[:50]}"

    def test_all_have_technical_requirements(self, all_clauses):
        for c in all_clauses:
            assert len(c.technical_requirements) >= 1, \
                f"Missing technical_requirements for {c.id}"

    def test_all_have_code_indicators(self, all_clauses):
        for c in all_clauses:
            assert len(c.code_indicators) >= 1, \
                f"Missing code_indicators for {c.id}"

    def test_unique_ids(self, all_clauses):
        ids = [c.id for c in all_clauses]
        assert len(ids) == len(set(ids)), \
            f"Duplicate IDs: {[i for i in ids if ids.count(i) > 1]}"


# ═══════════════════════════════════════════════════════════════
# ComplianceClause object
# ═══════════════════════════════════════════════════════════════


class TestComplianceClause:
    def test_embedding_text(self):
        c = ComplianceClause(
            id="TEST-001", framework="HIPAA", clause="§164.312(a)(1)",
            title="Access Control",
            text="Implement access control for ePHI.",
            technical_requirements=["Auth required", "RBAC enforced"],
            code_indicators=["auth middleware", "permission checks"],
        )
        text = c.embedding_text
        assert "HIPAA" in text
        assert "Access Control" in text
        assert "Auth required" in text
        assert "auth middleware" in text

    def test_to_metadata(self):
        c = ComplianceClause(
            id="TEST-001", framework="HIPAA", clause="§164.312(a)(1)",
            title="Access Control", text="Text here.",
            technical_requirements=["req1", "req2"],
            code_indicators=["ind1"],
        )
        meta = c.to_metadata()
        assert meta["id"] == "TEST-001"
        assert meta["framework"] == "HIPAA"
        assert "req1" in meta["technical_requirements"]
        assert "ind1" in meta["code_indicators"]


# ═══════════════════════════════════════════════════════════════
# KnowledgeBaseSeeder
# ═══════════════════════════════════════════════════════════════


class TestKnowledgeBaseSeeder:
    @pytest.mark.asyncio
    async def test_seed_calls_add_texts(self):
        store = _mock_store()
        seeder = KnowledgeBaseSeeder(store, kb_dir=KB_DIR)
        seeder.clear_seed_marker()

        try:
            stats = await seeder.seed()
            assert len(stats) >= 4
            assert all(v > 0 for v in stats.values())
            store.add_texts.assert_called()
        finally:
            seeder.clear_seed_marker()

    @pytest.mark.asyncio
    async def test_seed_skips_if_already_seeded(self):
        store = _mock_store()
        seeder = KnowledgeBaseSeeder(store, kb_dir=KB_DIR)
        seeder.clear_seed_marker()

        try:
            # First seed
            await seeder.seed()
            call_count_after_first = store.add_texts.call_count

            # Second seed — should skip
            stats = await seeder.seed()
            assert stats == {}
            assert store.add_texts.call_count == call_count_after_first
        finally:
            seeder.clear_seed_marker()

    @pytest.mark.asyncio
    async def test_seed_force_reseeds(self):
        store = _mock_store()
        seeder = KnowledgeBaseSeeder(store, kb_dir=KB_DIR)
        seeder.clear_seed_marker()

        try:
            await seeder.seed()
            call_count = store.add_texts.call_count

            # Force reseed
            stats = await seeder.seed(force=True)
            assert len(stats) >= 4
            assert store.add_texts.call_count > call_count
        finally:
            seeder.clear_seed_marker()

    @pytest.mark.asyncio
    async def test_seed_empty_dir(self, tmp_path):
        store = _mock_store()
        seeder = KnowledgeBaseSeeder(store, kb_dir=tmp_path)
        stats = await seeder.seed()
        assert stats == {}

    @pytest.mark.asyncio
    async def test_seed_vuln_patterns(self):
        store = _mock_store()
        seeder = KnowledgeBaseSeeder(store, kb_dir=KB_DIR)
        patterns = [
            {"description": "SQL injection via f-string", "cwe": "CWE-89"},
            {"description": "XSS via innerHTML", "cwe": "CWE-79"},
        ]
        count = await seeder.seed_vuln_patterns(patterns)
        assert count >= 1
        store.add_vuln_patterns.assert_called_once()

    @pytest.mark.asyncio
    async def test_seed_vuln_patterns_empty(self):
        store = _mock_store()
        seeder = KnowledgeBaseSeeder(store, kb_dir=KB_DIR)
        count = await seeder.seed_vuln_patterns([])
        assert count == 0

    def test_clear_seed_marker(self, tmp_path):
        seeder = KnowledgeBaseSeeder(MagicMock(), kb_dir=tmp_path)
        # Create marker
        (tmp_path / ".seeded").write_text("done")
        assert seeder._is_seeded()
        # Clear it
        seeder.clear_seed_marker()
        assert not seeder._is_seeded()


# ═══════════════════════════════════════════════════════════════
# Specific framework content checks
# ═══════════════════════════════════════════════════════════════


class TestFrameworkContent:
    def test_hipaa_has_access_control(self):
        clauses = load_clauses_from_yaml(KB_DIR / "hipaa_clauses.yaml")
        access = [c for c in clauses if "access" in c.title.lower() or "access" in c.text.lower()]
        assert len(access) >= 1

    def test_hipaa_has_encryption(self):
        clauses = load_clauses_from_yaml(KB_DIR / "hipaa_clauses.yaml")
        enc = [c for c in clauses if "encrypt" in c.title.lower() or "encrypt" in c.text.lower()]
        assert len(enc) >= 1

    def test_soc2_has_change_management(self):
        clauses = load_clauses_from_yaml(KB_DIR / "soc2_criteria.yaml")
        change = [c for c in clauses if "change" in c.title.lower()]
        assert len(change) >= 1

    def test_pci_has_injection_requirement(self):
        clauses = load_clauses_from_yaml(KB_DIR / "pci_dss_requirements.yaml")
        injection = [c for c in clauses if "injection" in c.title.lower() or "injection" in c.text.lower()]
        assert len(injection) >= 1

    def test_gdpr_has_right_to_erasure(self):
        clauses = load_clauses_from_yaml(KB_DIR / "gdpr_articles.yaml")
        erasure = [c for c in clauses if "erasure" in c.title.lower() or "erasure" in c.text.lower()]
        assert len(erasure) >= 1

    def test_gdpr_has_data_protection_by_design(self):
        clauses = load_clauses_from_yaml(KB_DIR / "gdpr_articles.yaml")
        dpbd = [c for c in clauses if "design" in c.title.lower()]
        assert len(dpbd) >= 1
