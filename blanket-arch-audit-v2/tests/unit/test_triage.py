"""Tests for blanketaudit2.triage — file scoring, tier assignment, batch assembly."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from blanketaudit2.config import Settings, get_settings
from blanketaudit2.ingestion.models import FileMetadata, FileType
from blanketaudit2.triage.batch_assembler import BatchAssembler, estimate_tokens
from blanketaudit2.triage.file_scorer import FileScorer
from blanketaudit2.triage.tier_assigner import TierAssigner


# ── Helpers ──────────────────────────────────────────────────

_NOW = datetime(2026, 3, 23, tzinfo=timezone.utc)
_RECENT = (_NOW - timedelta(days=5)).isoformat()
_OLD = (_NOW - timedelta(days=120)).isoformat()


def _file(
    path: str = "src/main.py",
    repo: str = "api",
    language: str = "python",
    loc: int = 200,
    file_type: FileType = FileType.SOURCE,
    size_bytes: int = 8000,
    last_modified: str = "",
) -> FileMetadata:
    return FileMetadata(
        path=path, repo_name=repo, language=language,
        loc=loc, file_type=file_type,
        size_bytes=size_bytes, last_modified=last_modified,
    )


def _settings(**triage_overrides) -> Settings:
    get_settings.cache_clear()
    triage = {"tier1_threshold": 60, "tier2_threshold": 30, **triage_overrides}
    return Settings(llm={"provider": "none"}, triage=triage)


# ═══════════════════════════════════════════════════════════════
# FileScorer
# ═══════════════════════════════════════════════════════════════


class TestFileScorer:
    def _scorer(self, import_counts=None):
        return FileScorer(import_counts=import_counts or {}, now=_NOW)

    # ── Language scoring ─────────────────────────────────────

    def test_python_source_gets_language_bonus(self):
        s = self._scorer()
        score = s.score(_file(language="python"))
        assert score > 0

    def test_unknown_language_lower(self):
        s = self._scorer()
        py = s.score(_file(language="python"))
        unk = s.score(_file(language="", file_type=FileType.OTHER))
        assert py > unk

    # ── File type scoring ────────────────────────────────────

    def test_source_scores_higher_than_config(self):
        s = self._scorer()
        src = s.score(_file(file_type=FileType.SOURCE))
        cfg = s.score(_file(file_type=FileType.CONFIG, language=""))
        assert src > cfg

    def test_iac_scores_between_source_and_doc(self):
        s = self._scorer()
        src = s.score(_file(file_type=FileType.SOURCE))
        iac = s.score(_file(file_type=FileType.IAC, path="infra/main.tf", language=""))
        doc = s.score(_file(file_type=FileType.DOC, path="README.md", language=""))
        assert src > iac > doc

    # ── Path patterns ────────────────────────────────────────

    def test_auth_path_gets_bonus(self):
        s = self._scorer()
        auth = s.score(_file(path="src/auth/login_handler.py"))
        util = s.score(_file(path="src/utils/helpers.py"))
        assert auth > util

    def test_payment_path_gets_bonus(self):
        s = self._scorer()
        pay = s.score(_file(path="src/payments/charge.py"))
        util = s.score(_file(path="src/utils/format.py"))
        assert pay > util

    def test_route_handler_path_bonus(self):
        s = self._scorer()
        route = s.score(_file(path="src/routes/users.py"))
        other = s.score(_file(path="src/lib/math.py"))
        assert route > other

    def test_controller_path_bonus(self):
        s = self._scorer()
        ctrl = s.score(_file(path="src/controllers/UserController.java", language="java"))
        other = s.score(_file(path="src/utils/StringUtils.java", language="java"))
        assert ctrl > other

    def test_service_path_bonus(self):
        s = self._scorer()
        svc = s.score(_file(path="src/services/payment_service.py"))
        util = s.score(_file(path="src/lib/cache.py"))
        assert svc > util

    # ── Recency ──────────────────────────────────────────────

    def test_recent_file_gets_bonus(self):
        s = self._scorer()
        recent = s.score(_file(last_modified=_RECENT))
        old = s.score(_file(last_modified=_OLD))
        assert recent > old

    def test_moderately_recent_partial_bonus(self):
        s = self._scorer()
        mid = (_NOW - timedelta(days=60)).isoformat()
        recent = s.score(_file(last_modified=_RECENT))
        moderate = s.score(_file(last_modified=mid))
        old = s.score(_file(last_modified=_OLD))
        assert recent > moderate >= old

    # ── Import count (fan-out) ───────────────────────────────

    def test_high_import_count_bonus(self):
        s = self._scorer(import_counts={"src/main.py": 15})
        high = s.score(_file(path="src/main.py"))
        s2 = FileScorer(import_counts={}, now=_NOW)
        low = s2.score(_file(path="src/main.py"))
        assert high > low

    def test_moderate_import_count(self):
        s = self._scorer(import_counts={"a.py": 5, "b.py": 1})
        a = s.score(_file(path="a.py"))
        b = s.score(_file(path="b.py"))
        assert a > b

    # ── File size ────────────────────────────────────────────

    def test_sweet_spot_size_bonus(self):
        s = self._scorer()
        sweet = s.score(_file(loc=300))
        tiny = s.score(_file(loc=5))
        assert sweet > tiny

    def test_huge_file_diminishing_returns(self):
        s = self._scorer()
        sweet = s.score(_file(loc=300))
        huge = s.score(_file(loc=2000))
        assert sweet > huge  # 300 LOC gets more than 2000

    # ── Test file penalty ────────────────────────────────────

    def test_test_file_penalized(self):
        s = self._scorer()
        src = s.score(_file(path="src/service.py", file_type=FileType.SOURCE))
        test = s.score(_file(path="tests/test_service.py", file_type=FileType.TEST))
        assert src > test

    def test_test_file_low_score(self):
        s = self._scorer()
        test = s.score(_file(
            path="tests/test_auth.py", file_type=FileType.TEST,
            language="python", loc=50,
        ))
        # Even with python + auth in path, test penalty should keep it low
        assert test < 40

    # ── Generated code penalty ───────────────────────────────

    def test_protobuf_generated_penalized(self):
        s = self._scorer()
        gen = s.score(_file(path="proto/user_pb2.py"))
        src = s.score(_file(path="src/user.py"))
        assert src > gen

    def test_migration_penalized(self):
        s = self._scorer()
        mig = s.score(_file(path="alembic/versions/001_initial.py"))
        src = s.score(_file(path="src/models.py"))
        assert src > mig

    def test_minified_js_penalized(self):
        s = self._scorer()
        mini = s.score(_file(path="dist/bundle.min.js", language="javascript"))
        src = s.score(_file(path="src/app.js", language="javascript"))
        assert src > mini

    # ── Clamping ─────────────────────────────────────────────

    def test_score_never_below_zero(self):
        s = self._scorer()
        # Generated test file with no language
        score = s.score(_file(
            path="codegen/test_generated_pb2.py",
            file_type=FileType.TEST, language="", loc=0,
        ))
        assert score >= 0

    def test_score_never_above_100(self):
        s = self._scorer(import_counts={"src/routes/auth_controller.py": 20})
        score = s.score(_file(
            path="src/routes/auth_controller.py",
            language="python", loc=300,
            last_modified=_RECENT,
        ))
        assert score <= 100

    # ── score_all ────────────────────────────────────────────

    def test_score_all(self):
        files = [_file(path="a.py"), _file(path="b.py")]
        s = self._scorer()
        scores = s.score_all(files)
        assert len(scores) == 2
        assert "a.py" in scores
        assert all(0 <= v <= 100 for v in scores.values())


# ═══════════════════════════════════════════════════════════════
# TierAssigner
# ═══════════════════════════════════════════════════════════════


class TestTierAssigner:
    def _assigner(self, t1=60, t2=30):
        with patch("blanketaudit2.triage.tier_assigner.get_settings") as mock_gs:
            mock_gs.return_value = _settings(tier1_threshold=t1, tier2_threshold=t2)
            return TierAssigner(tier1_threshold=t1, tier2_threshold=t2)

    def test_high_score_tier1(self):
        a = self._assigner()
        assert a.assign_one(80) == 1

    def test_medium_score_tier2(self):
        a = self._assigner()
        assert a.assign_one(45) == 2

    def test_low_score_tier3(self):
        a = self._assigner()
        assert a.assign_one(15) == 3

    def test_boundary_tier1(self):
        a = self._assigner()
        assert a.assign_one(61) == 1
        assert a.assign_one(60) == 2  # Not > 60

    def test_boundary_tier2(self):
        a = self._assigner()
        assert a.assign_one(31) == 2
        assert a.assign_one(30) == 3  # Not > 30

    def test_zero_score_tier3(self):
        a = self._assigner()
        assert a.assign_one(0) == 3

    def test_max_score_tier1(self):
        a = self._assigner()
        assert a.assign_one(100) == 1

    def test_assign_batch(self):
        a = self._assigner()
        files = [_file(path="a.py"), _file(path="b.py"), _file(path="c.py")]
        scores = {"a.py": 80, "b.py": 45, "c.py": 10}
        tiers = a.assign(files, scores)
        assert tiers["a.py"] == 1
        assert tiers["b.py"] == 2
        assert tiers["c.py"] == 3

    def test_missing_score_defaults_to_tier3(self):
        a = self._assigner()
        files = [_file(path="unknown.py")]
        tiers = a.assign(files, {})
        assert tiers["unknown.py"] == 3

    def test_summary(self):
        a = self._assigner()
        tiers = {"a": 1, "b": 1, "c": 2, "d": 3, "e": 3, "f": 3}
        s = a.summary(tiers)
        assert s == {1: 2, 2: 1, 3: 3}

    def test_custom_thresholds(self):
        a = self._assigner(t1=80, t2=50)
        assert a.assign_one(85) == 1
        assert a.assign_one(65) == 2
        assert a.assign_one(40) == 3


# ═══════════════════════════════════════════════════════════════
# BatchAssembler
# ═══════════════════════════════════════════════════════════════


class TestEstimateTokens:
    def test_from_size_bytes(self):
        f = _file(size_bytes=4000, loc=0)
        assert estimate_tokens(f) == 1000  # 4000 / 4

    def test_from_loc_fallback(self):
        f = _file(size_bytes=0, loc=100)
        assert estimate_tokens(f) == 1000  # 100 * 40 / 4

    def test_minimum_default(self):
        f = _file(size_bytes=0, loc=0)
        assert estimate_tokens(f) == 100


class TestBatchAssembler:
    def _assembler(self, max_tokens=1000, reserve=200):
        with patch("blanketaudit2.triage.batch_assembler.get_settings") as mock_gs:
            mock_gs.return_value = _settings()
            return BatchAssembler(max_batch_tokens=max_tokens, response_reserve=reserve)

    def test_single_batch_fits(self):
        ba = self._assembler(max_tokens=100_000, reserve=10_000)
        files = [_file(path="a.py", size_bytes=1000), _file(path="b.py", size_bytes=1000)]
        tiers = {"a.py": 1, "b.py": 1}
        batches = ba.assemble(files, tiers)
        assert len(batches) == 1
        assert len(batches[0]) == 2

    def test_splits_when_exceeds_limit(self):
        ba = self._assembler(max_tokens=1000, reserve=200)
        # Effective limit = 800 tokens. Each file ~250 tokens (1000 bytes / 4).
        files = [
            _file(path="a.py", size_bytes=1000),
            _file(path="b.py", size_bytes=1000),
            _file(path="c.py", size_bytes=1000),
            _file(path="d.py", size_bytes=1000),
        ]
        tiers = {"a.py": 1, "b.py": 1, "c.py": 1, "d.py": 1}
        batches = ba.assemble(files, tiers)
        assert len(batches) >= 2

    def test_tier3_files_excluded(self):
        ba = self._assembler(max_tokens=100_000, reserve=10_000)
        files = [_file(path="a.py"), _file(path="b.py"), _file(path="c.py")]
        tiers = {"a.py": 1, "b.py": 3, "c.py": 2}
        batches = ba.assemble(files, tiers)
        all_paths = [f.path for batch in batches for f in batch]
        assert "a.py" in all_paths
        assert "c.py" in all_paths
        assert "b.py" not in all_paths

    def test_empty_files_returns_empty(self):
        ba = self._assembler()
        batches = ba.assemble([], {})
        assert batches == []

    def test_all_tier3_returns_empty(self):
        ba = self._assembler()
        files = [_file(path="a.py"), _file(path="b.py")]
        tiers = {"a.py": 3, "b.py": 3}
        batches = ba.assemble(files, tiers)
        assert batches == []

    def test_oversized_file_gets_own_batch(self):
        ba = self._assembler(max_tokens=1000, reserve=200)
        # File with 4000 bytes = 1000 tokens, exceeds effective limit (800)
        files = [
            _file(path="huge.py", size_bytes=4000),
            _file(path="small.py", size_bytes=100),
        ]
        tiers = {"huge.py": 1, "small.py": 1}
        batches = ba.assemble(files, tiers)
        assert len(batches) == 2
        # The huge file should be alone
        huge_batch = [b for b in batches if any(f.path == "huge.py" for f in b)]
        assert len(huge_batch[0]) == 1

    def test_same_directory_grouped(self):
        ba = self._assembler(max_tokens=100_000, reserve=10_000)
        files = [
            _file(path="src/api/routes.py", size_bytes=1000),
            _file(path="src/api/handlers.py", size_bytes=1000),
            _file(path="src/db/models.py", size_bytes=1000),
        ]
        tiers = {f.path: 1 for f in files}
        batches = ba.assemble(files, tiers)
        # All should fit in one batch, but same-dir files should be adjacent
        if len(batches) == 1:
            paths = [f.path for f in batches[0]]
            api_indices = [i for i, p in enumerate(paths) if "api" in p]
            # The two api files should be adjacent
            if len(api_indices) == 2:
                assert abs(api_indices[0] - api_indices[1]) == 1

    def test_batch_token_counts(self):
        ba = self._assembler(max_tokens=100_000, reserve=10_000)
        files = [_file(path="a.py", size_bytes=2000), _file(path="b.py", size_bytes=4000)]
        tiers = {"a.py": 1, "b.py": 1}
        batches = ba.assemble(files, tiers)
        counts = ba.batch_token_counts(batches)
        assert len(counts) == len(batches)
        assert all(c > 0 for c in counts)
        assert sum(counts) == estimate_tokens(files[0]) + estimate_tokens(files[1])

    def test_custom_tier_filter(self):
        ba = self._assembler(max_tokens=100_000, reserve=10_000)
        files = [_file(path="a.py"), _file(path="b.py"), _file(path="c.py")]
        tiers = {"a.py": 1, "b.py": 2, "c.py": 3}
        # Only tier 1
        batches = ba.assemble(files, tiers, tier_filter={1})
        all_paths = [f.path for batch in batches for f in batch]
        assert "a.py" in all_paths
        assert "b.py" not in all_paths
        assert "c.py" not in all_paths

    def test_no_batch_exceeds_limit(self):
        ba = self._assembler(max_tokens=2000, reserve=500)
        # Effective limit = 1500 tokens
        files = [_file(path=f"f{i}.py", size_bytes=2000) for i in range(10)]
        tiers = {f.path: 1 for f in files}
        batches = ba.assemble(files, tiers)
        counts = ba.batch_token_counts(batches)
        for c in counts:
            # Allow oversized files in their own batch, but grouped batches
            # should respect the limit (within tolerance of one file)
            batch_idx = counts.index(c)
            if len(batches[batch_idx]) > 1:
                assert c <= 1500
