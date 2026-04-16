"""Tests for blanketaudit2.metrics — logging, tracing, Prometheus."""

from __future__ import annotations

import asyncio
import io
import json
from unittest.mock import MagicMock, patch

import pytest
import structlog

from blanketaudit2.metrics import (
    _NoOpSpan,
    _NoOpTracer,
    _add_scan_context,
    _ensure_metrics,
    clear_scan_context,
    get_metric,
    get_tracer,
    record_cache,
    record_finding,
    record_llm_call,
    record_triage,
    set_scan_context,
    setup_logging,
    setup_observability,
    timed_span,
)


# ═══════════════════════════════════════════════════════════════
# 1.  Structured Logging
# ═══════════════════════════════════════════════════════════════


class TestSetupLogging:
    def test_json_mode_produces_json(self, capsys):
        setup_logging(log_level="DEBUG", json=True)
        log = structlog.get_logger()
        log.info("test_event", key="value")
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        assert data["event"] == "test_event"
        assert data["key"] == "value"
        assert "level" in data
        assert "timestamp" in data

    def test_console_mode(self, capsys):
        setup_logging(log_level="DEBUG", json=False)
        log = structlog.get_logger()
        log.info("hello")
        captured = capsys.readouterr().out
        assert "hello" in captured

    def test_log_level_filtering(self, capsys):
        setup_logging(log_level="WARNING", json=True)
        log = structlog.get_logger()
        log.info("should_be_filtered")
        log.warning("should_appear")
        captured = capsys.readouterr().out.strip()
        # Only the warning should be in output
        assert "should_be_filtered" not in captured
        assert "should_appear" in captured


class TestScanContext:
    def test_set_and_clear(self, capsys):
        setup_logging(log_level="DEBUG", json=True)
        set_scan_context(scan_id="scan-123", agent="security", step="static_scan")
        log = structlog.get_logger()
        log.info("with_context")
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        assert data["scan_id"] == "scan-123"
        assert data["agent"] == "security"
        assert data["step"] == "static_scan"

        clear_scan_context()
        log.info("after_clear")
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        assert "scan_id" not in data

    def test_partial_context(self, capsys):
        setup_logging(log_level="DEBUG", json=True)
        clear_scan_context()
        set_scan_context(scan_id="scan-456")
        log = structlog.get_logger()
        log.info("partial")
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        assert data["scan_id"] == "scan-456"
        assert "agent" not in data
        clear_scan_context()

    def test_add_scan_context_processor(self):
        clear_scan_context()
        set_scan_context(scan_id="s1", agent="a1", step="st1")
        event_dict: dict = {"event": "test"}
        result = _add_scan_context(None, "info", event_dict)
        assert result["scan_id"] == "s1"
        assert result["agent"] == "a1"
        assert result["step"] == "st1"
        clear_scan_context()


class TestLogFieldsDesignDoc:
    """Verify the design doc §14.1 fields appear when expected."""

    def test_llm_call_log_fields(self, capsys):
        setup_logging(log_level="DEBUG", json=True)
        set_scan_context(scan_id="scan-x", agent="security", step="ai_analysis")
        record_llm_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            input_tokens=1500,
            output_tokens=800,
            cost_usd=0.0165,
            duration_seconds=2.3,
        )
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        # Design doc §14.1 required fields
        assert data["scan_id"] == "scan-x"
        assert data["agent"] == "security"
        assert data["step"] == "ai_analysis"
        assert data["input_tokens"] == 1500
        assert data["output_tokens"] == 800
        assert data["cost_usd"] == 0.0165
        assert data["duration_ms"] == 2300.0
        assert data["provider"] == "anthropic"
        assert data["model"] == "claude-sonnet-4-20250514"
        clear_scan_context()


# ═══════════════════════════════════════════════════════════════
# 2.  OpenTelemetry Tracing
# ═══════════════════════════════════════════════════════════════


class TestNoOpTracer:
    def test_noop_span_context_manager(self):
        span = _NoOpSpan()
        with span as s:
            s.set_attribute("key", "value")
            s.set_status("OK")
            s.record_exception(RuntimeError("test"))
        # No crash

    def test_noop_tracer_returns_span(self):
        tracer = _NoOpTracer()
        span = tracer.start_as_current_span("test.span")
        assert isinstance(span, _NoOpSpan)


class TestGetTracer:
    def test_returns_tracer(self):
        # Should return either an OTel tracer or a NoOpTracer
        tracer = get_tracer()
        assert tracer is not None
        span = tracer.start_as_current_span("test")
        assert span is not None


class TestTimedSpan:
    @pytest.mark.asyncio
    async def test_timed_span_decorator(self, capsys):
        setup_logging(log_level="DEBUG", json=True)

        @timed_span("test.operation")
        async def my_operation():
            return 42

        result = await my_operation()
        assert result == 42
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        assert data["event"] == "test.operation.completed"
        assert "duration_ms" in data
        assert data["duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_timed_span_records_exception(self, capsys):
        setup_logging(log_level="DEBUG", json=True)

        @timed_span("test.failing")
        async def failing_op():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            await failing_op()
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        assert data["event"] == "test.failing.failed"
        assert "boom" in data["error"]


class TestSetupTracing:
    def test_no_op_when_endpoint_empty(self):
        # Should not raise even if OTel SDK is not fully configured
        from blanketaudit2.metrics import setup_tracing
        setup_tracing(endpoint="")  # No-op


# ═══════════════════════════════════════════════════════════════
# 3.  Prometheus Metrics
# ═══════════════════════════════════════════════════════════════


class TestPrometheusMetrics:
    def test_ensure_metrics_creates_all(self):
        """All expected metric names should be present."""
        pytest.importorskip("prometheus_client")
        from blanketaudit2.metrics import _metrics
        _metrics.clear()
        m = _ensure_metrics()
        expected = {
            "scans_total", "scan_duration_seconds", "findings_total",
            "llm_calls_total", "llm_latency_seconds", "llm_tokens_total",
            "llm_cost_usd_total", "cache_hits_total", "cache_misses_total",
            "triage_files_total", "agent_duration_seconds",
        }
        assert expected.issubset(set(m.keys())), f"Missing: {expected - set(m.keys())}"

    def test_get_metric_existing(self):
        pytest.importorskip("prometheus_client")
        _ensure_metrics()
        assert get_metric("scans_total") is not None
        assert get_metric("llm_calls_total") is not None

    def test_get_metric_unknown(self):
        assert get_metric("nonexistent_metric") is None


class TestRecordFinding:
    def test_increments_counter(self):
        _ensure_metrics()
        findings = get_metric("findings_total")
        if findings is None:
            pytest.skip("prometheus_client not installed")
        before = findings.labels(severity="critical", category="security")._value.get()
        record_finding("critical", "security")
        after = findings.labels(severity="critical", category="security")._value.get()
        assert after == before + 1


class TestRecordCache:
    def test_hit(self):
        _ensure_metrics()
        hits = get_metric("cache_hits_total")
        if hits is None:
            pytest.skip("prometheus_client not installed")
        before = hits._value.get()
        record_cache(hit=True)
        assert hits._value.get() == before + 1

    def test_miss(self):
        _ensure_metrics()
        misses = get_metric("cache_misses_total")
        if misses is None:
            pytest.skip("prometheus_client not installed")
        before = misses._value.get()
        record_cache(hit=False)
        assert misses._value.get() == before + 1


class TestRecordTriage:
    def test_tier_counter(self):
        _ensure_metrics()
        triage = get_metric("triage_files_total")
        if triage is None:
            pytest.skip("prometheus_client not installed")
        before = triage.labels(tier="1")._value.get()
        record_triage(tier=1, count=5)
        assert triage.labels(tier="1")._value.get() == before + 5


class TestRecordLlmCall:
    def test_increments_all_llm_metrics(self):
        _ensure_metrics()
        calls = get_metric("llm_calls_total")
        tokens = get_metric("llm_tokens_total")
        cost = get_metric("llm_cost_usd_total")
        if calls is None:
            pytest.skip("prometheus_client not installed")

        record_llm_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            cost_usd=0.01,
            duration_seconds=1.5,
        )
        assert calls.labels(
            provider="anthropic", model="claude-sonnet-4-20250514", status="success"
        )._value.get() >= 1


# ═══════════════════════════════════════════════════════════════
# 4.  Top-level setup
# ═══════════════════════════════════════════════════════════════


class TestSetupObservability:
    def test_setup_does_not_raise(self, capsys):
        setup_observability(
            log_level="INFO", log_json=True,
            otel_endpoint="", prometheus_port=0,
        )
        captured = capsys.readouterr().out.strip()
        data = json.loads(captured)
        assert data["event"] == "observability.ready"

    def test_setup_with_console_logging(self, capsys):
        setup_observability(log_level="DEBUG", log_json=False)
        captured = capsys.readouterr().out
        assert "observability.ready" in captured
