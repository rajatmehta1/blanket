"""Observability stack — structured logging, OpenTelemetry traces, Prometheus metrics.

Design doc §14: every I/O function logs scan_id, agent, step, duration_ms,
tokens, cost_usd.  Traces follow the pipeline hierarchy.  Prometheus
counters/histograms track scans, findings, LLM calls, cache, and agents.

Call ``setup_observability()`` once at startup.
"""

from __future__ import annotations

import functools
import logging
import time
from contextvars import ContextVar
from typing import Any, Callable

import structlog

# Map string level names to numeric values (structlog removed get_level_from_name).
_LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def _level_number(name: str) -> int:
    return _LEVEL_MAP.get(name.upper(), logging.INFO)

# ── Context variables for structured log fields ──────────────
# These are set by the orchestrator and automatically merged into every log line.

_scan_id: ContextVar[str] = ContextVar("scan_id", default="")
_agent_name: ContextVar[str] = ContextVar("agent_name", default="")
_step_name: ContextVar[str] = ContextVar("step_name", default="")


def set_scan_context(
    scan_id: str = "",
    agent: str = "",
    step: str = "",
) -> None:
    """Set context variables that auto-attach to every structlog message."""
    if scan_id:
        _scan_id.set(scan_id)
    if agent:
        _agent_name.set(agent)
    if step:
        _step_name.set(step)


def clear_scan_context() -> None:
    """Reset all context variables."""
    _scan_id.set("")
    _agent_name.set("")
    _step_name.set("")


def _add_scan_context(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor that injects scan context into every log event."""
    sid = _scan_id.get()
    if sid:
        event_dict["scan_id"] = sid
    agent = _agent_name.get()
    if agent:
        event_dict["agent"] = agent
    step = _step_name.get()
    if step:
        event_dict["step"] = step
    return event_dict


# ═══════════════════════════════════════════════════════════════
# 1.  Structured Logging  (design doc §14.1)
# ═══════════════════════════════════════════════════════════════


def setup_logging(log_level: str = "INFO", json: bool = True) -> None:
    """Configure structlog for JSON output with scan context injection.

    Fields automatically attached to every log line:
    - scan_id, agent, step  (from context vars)
    - level, timestamp       (from processors)
    """
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        _add_scan_context,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json:
        shared_processors.append(structlog.processors.JSONRenderer())
    else:
        shared_processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=shared_processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            _level_number(log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


# ═══════════════════════════════════════════════════════════════
# 2.  OpenTelemetry Tracing  (design doc §14.2)
# ═══════════════════════════════════════════════════════════════

# Trace hierarchy:
#   scan.ingest  →  scan.triage  →  scan.estimate  →
#   scan.agent.{name}  →  scan.merge  →  scan.report

# The tracer is initialised lazily so imports never fail.
_tracer: Any = None


def get_tracer() -> Any:
    """Return the OTel tracer, or a no-op proxy if OTel is not configured."""
    global _tracer
    if _tracer is not None:
        return _tracer
    try:
        from opentelemetry import trace
        _tracer = trace.get_tracer("blanketaudit")
    except ImportError:
        _tracer = _NoOpTracer()
    return _tracer


class _NoOpSpan:
    """Minimal stand-in when OpenTelemetry is not installed."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_exception(self, exc: BaseException) -> None:
        pass

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _NoOpTracer:
    """Returns _NoOpSpan for every ``start_as_current_span`` call."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()


def setup_tracing(endpoint: str = "") -> None:
    """Configure OpenTelemetry OTLP exporter.

    No-op if *endpoint* is empty or if ``opentelemetry-sdk`` is not installed.
    """
    global _tracer
    if not endpoint:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({"service.name": "blanketaudit"})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("blanketaudit")
        structlog.get_logger().info("tracing.configured", endpoint=endpoint)
    except ImportError:
        structlog.get_logger().warning(
            "tracing.skipped",
            reason="opentelemetry-sdk or OTLP exporter not installed",
        )


# ═══════════════════════════════════════════════════════════════
# 3.  Prometheus Metrics  (design doc §14.3)
# ═══════════════════════════════════════════════════════════════

# Lazy singletons — created on first access so the module imports even
# when prometheus_client is not installed.

_metrics: dict[str, Any] = {}


def _ensure_metrics() -> dict[str, Any]:
    """Create Prometheus metric objects once."""
    if _metrics:
        return _metrics

    try:
        from prometheus_client import Counter, Histogram, Gauge

        _metrics.update(
            # ── Scan-level ───────────────────────────────────
            scans_total=Counter(
                "blanketaudit_scans_total",
                "Total number of scans started",
                ["status"],  # started, completed, failed
            ),
            scan_duration_seconds=Histogram(
                "blanketaudit_scan_duration_seconds",
                "End-to-end scan duration",
                buckets=[10, 30, 60, 120, 300, 600, 1200],
            ),
            findings_total=Counter(
                "blanketaudit_findings_total",
                "Total findings produced",
                ["severity", "category"],
            ),
            # ── LLM ─────────────────────────────────────────
            llm_calls_total=Counter(
                "blanketaudit_llm_calls_total",
                "Total LLM API calls",
                ["provider", "model", "status"],  # status: success, error, timeout
            ),
            llm_latency_seconds=Histogram(
                "blanketaudit_llm_latency_seconds",
                "LLM call latency",
                ["provider", "model"],
                buckets=[0.5, 1, 2, 5, 10, 30, 60],
            ),
            llm_tokens_total=Counter(
                "blanketaudit_llm_tokens_total",
                "Total LLM tokens consumed",
                ["direction", "model"],  # direction: input, output
            ),
            llm_cost_usd_total=Counter(
                "blanketaudit_llm_cost_usd_total",
                "Cumulative LLM spend in USD",
                ["model"],
            ),
            # ── Cache ────────────────────────────────────────
            cache_hits_total=Counter(
                "blanketaudit_cache_hits_total",
                "Cache hit count",
            ),
            cache_misses_total=Counter(
                "blanketaudit_cache_misses_total",
                "Cache miss count",
            ),
            # ── Triage ───────────────────────────────────────
            triage_files_total=Counter(
                "blanketaudit_triage_files_total",
                "Files triaged by tier",
                ["tier"],  # 1, 2, 3
            ),
            # ── Agent ────────────────────────────────────────
            agent_duration_seconds=Histogram(
                "blanketaudit_agent_duration_seconds",
                "Agent execution time",
                ["agent"],
                buckets=[1, 5, 10, 30, 60, 120, 300],
            ),
        )
    except ImportError:
        pass  # Prometheus not installed — metrics silently disabled

    return _metrics


def get_metric(name: str) -> Any | None:
    """Return a Prometheus metric by name, or *None* if unavailable."""
    m = _ensure_metrics()
    return m.get(name)


def setup_prometheus(port: int = 0) -> None:
    """Initialise Prometheus metrics and optionally start the HTTP server.

    If *port* is > 0, ``prometheus_client.start_http_server`` is called.
    """
    _ensure_metrics()
    if port > 0:
        try:
            from prometheus_client import start_http_server
            start_http_server(port)
            structlog.get_logger().info("prometheus.server_started", port=port)
        except ImportError:
            structlog.get_logger().warning(
                "prometheus.skipped", reason="prometheus_client not installed"
            )


# ═══════════════════════════════════════════════════════════════
# 4.  Convenience helpers
# ═══════════════════════════════════════════════════════════════


def record_llm_call(
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
    duration_seconds: float,
    status: str = "success",
) -> None:
    """Record a single LLM call across all observability layers."""
    log = structlog.get_logger()
    log.info(
        "llm.call",
        provider=provider,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=round(cost_usd, 6),
        duration_ms=round(duration_seconds * 1000, 1),
        status=status,
    )

    m = _ensure_metrics()
    if m:
        calls = m.get("llm_calls_total")
        if calls:
            calls.labels(provider=provider, model=model, status=status).inc()
        latency = m.get("llm_latency_seconds")
        if latency:
            latency.labels(provider=provider, model=model).observe(duration_seconds)
        tokens = m.get("llm_tokens_total")
        if tokens:
            tokens.labels(direction="input", model=model).inc(input_tokens)
            tokens.labels(direction="output", model=model).inc(output_tokens)
        cost = m.get("llm_cost_usd_total")
        if cost:
            cost.labels(model=model).inc(cost_usd)


def record_finding(severity: str, category: str) -> None:
    """Increment the findings counter."""
    m = _ensure_metrics()
    findings = m.get("findings_total") if m else None
    if findings:
        findings.labels(severity=severity, category=category).inc()


def record_cache(hit: bool) -> None:
    """Record a cache hit or miss."""
    m = _ensure_metrics()
    if not m:
        return
    if hit:
        counter = m.get("cache_hits_total")
    else:
        counter = m.get("cache_misses_total")
    if counter:
        counter.inc()


def record_triage(tier: int, count: int = 1) -> None:
    """Record files assigned to a triage tier."""
    m = _ensure_metrics()
    triage = m.get("triage_files_total") if m else None
    if triage:
        triage.labels(tier=str(tier)).inc(count)


def timed_span(span_name: str) -> Callable:
    """Decorator: wrap an async function in an OTel span + duration log."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            log = structlog.get_logger()
            start = time.perf_counter()
            with tracer.start_as_current_span(span_name) as span:
                try:
                    result = await func(*args, **kwargs)
                    elapsed = time.perf_counter() - start
                    span.set_attribute("duration_ms", round(elapsed * 1000, 1))
                    log.info(
                        f"{span_name}.completed",
                        duration_ms=round(elapsed * 1000, 1),
                    )
                    return result
                except Exception as exc:
                    elapsed = time.perf_counter() - start
                    span.record_exception(exc)
                    log.error(
                        f"{span_name}.failed",
                        duration_ms=round(elapsed * 1000, 1),
                        error=str(exc)[:300],
                    )
                    raise

        return wrapper

    return decorator


# ═══════════════════════════════════════════════════════════════
# 5.  Top-level setup
# ═══════════════════════════════════════════════════════════════


def setup_observability(
    log_level: str = "INFO",
    log_json: bool = True,
    otel_endpoint: str = "",
    prometheus_port: int = 0,
) -> None:
    """One-call initialisation of the full observability stack.

    Called once at startup by the CLI or API entrypoint.
    """
    setup_logging(log_level=log_level, json=log_json)
    setup_tracing(endpoint=otel_endpoint)
    setup_prometheus(port=prometheus_port)
    structlog.get_logger().info(
        "observability.ready",
        log_level=log_level,
        log_json=log_json,
        otel=bool(otel_endpoint),
        prometheus=prometheus_port > 0,
    )
