"""Retry, circuit breaker, rate limiter, and the unified safe LLM call wrapper.

Design doc §6 (error handling) and §15 (rate limiting).

All agents call ``safe_llm_call`` — the ONE function that combines:
  rate limiter → circuit breaker → retry → cost tracking → logging.
"""

from __future__ import annotations

import asyncio
import enum
import time
from typing import Any, Callable, Coroutine

import structlog
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from blanketaudit2.config import get_settings
from blanketaudit2.exceptions import BudgetExceededError, CircuitOpenError, LLMError
from blanketaudit2.metrics import record_llm_call

logger = structlog.get_logger()


# ═══════════════════════════════════════════════════════════════
# 1.  Retry strategy  (design doc §6.1)
# ═══════════════════════════════════════════════════════════════

# Exception types that are safe to retry (transient errors).
_RETRYABLE = (
    TimeoutError,
    ConnectionError,
    OSError,
)


def _before_sleep(retry_state: RetryCallState) -> None:
    """Log each retry attempt."""
    logger.warning(
        "llm.retry",
        attempt=retry_state.attempt_number,
        wait=round(retry_state.upcoming_sleep, 2) if retry_state.upcoming_sleep else 0,
        error=str(retry_state.outcome.exception())[:200] if retry_state.outcome else "",
    )


def make_retry_decorator(max_attempts: int = 3):
    """Build a tenacity retry decorator for LLM calls."""
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(_RETRYABLE),
        before_sleep=_before_sleep,
        reraise=True,
    )


llm_retry = make_retry_decorator(3)


# ═══════════════════════════════════════════════════════════════
# 2.  Circuit breaker  (design doc §6.2)
# ═══════════════════════════════════════════════════════════════


class CircuitState(str, enum.Enum):
    CLOSED = "closed"          # Normal — calls go through
    OPEN = "open"              # Tripped — all calls fail fast
    HALF_OPEN = "half_open"    # Recovery probe — allow 1 test call


class CircuitBreaker:
    """Trip after *failure_threshold* failures within *window_seconds*.

    When open, raises ``CircuitOpenError`` immediately (static fallback).
    After *recovery_seconds*, allows one probe call (half-open).
    If the probe succeeds → close.  If it fails → re-open.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        window_seconds: float = 60.0,
        recovery_seconds: float = 120.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.recovery_seconds = recovery_seconds

        self._state = CircuitState.CLOSED
        self._failures: list[float] = []  # timestamps of recent failures
        self._opened_at: float = 0.0
        self._lock = asyncio.Lock()

    # ── Properties ───────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        if self._state is CircuitState.OPEN:
            if time.monotonic() - self._opened_at >= self.recovery_seconds:
                return CircuitState.HALF_OPEN
        return self._state

    @property
    def is_open(self) -> bool:
        return self.state is CircuitState.OPEN

    @property
    def failure_count(self) -> int:
        """Number of failures within the current window."""
        cutoff = time.monotonic() - self.window_seconds
        return sum(1 for t in self._failures if t > cutoff)

    # ── Core ─────────────────────────────────────────────────

    async def call(self, func: Callable[..., Coroutine], *args: Any, **kwargs: Any) -> Any:
        """Execute *func* through the circuit breaker.

        Raises ``CircuitOpenError`` when the circuit is open.
        """
        current = self.state

        if current is CircuitState.OPEN:
            raise CircuitOpenError(
                "Circuit breaker is open — using static fallback",
                details={
                    "failure_count": self.failure_count,
                    "recovery_in_seconds": round(
                        self.recovery_seconds - (time.monotonic() - self._opened_at), 1
                    ),
                },
            )

        try:
            result = await func(*args, **kwargs)
            await self._record_success()
            return result
        except Exception as exc:
            await self._record_failure()
            raise

    async def _record_success(self) -> None:
        async with self._lock:
            if self._state in (CircuitState.HALF_OPEN, CircuitState.OPEN):
                logger.info("circuit_breaker.closed", previous=self._state.value)
            self._state = CircuitState.CLOSED
            self._failures.clear()

    async def _record_failure(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._failures.append(now)

            # Prune old failures outside window
            cutoff = now - self.window_seconds
            self._failures = [t for t in self._failures if t > cutoff]

            if self._state is CircuitState.HALF_OPEN:
                # Probe failed → re-open
                self._state = CircuitState.OPEN
                self._opened_at = now
                logger.warning("circuit_breaker.reopened")
            elif len(self._failures) >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = now
                logger.warning(
                    "circuit_breaker.opened",
                    failures=len(self._failures),
                    threshold=self.failure_threshold,
                )

    def reset(self) -> None:
        """Force-reset to closed (for testing)."""
        self._state = CircuitState.CLOSED
        self._failures.clear()
        self._opened_at = 0.0

    @classmethod
    def from_settings(cls) -> CircuitBreaker:
        cfg = get_settings().circuit_breaker
        return cls(
            failure_threshold=cfg.failure_threshold,
            window_seconds=cfg.window_seconds,
            recovery_seconds=cfg.recovery_timeout_seconds,
        )


# ═══════════════════════════════════════════════════════════════
# 3.  Global API rate limiter  (design doc §15.1)
# ═══════════════════════════════════════════════════════════════


class APIRateLimiter:
    """Shared ``asyncio.Semaphore`` limiting concurrent LLM API calls.

    Prevents exceeding provider rate limits when 4 agents run in parallel.
    """

    def __init__(self, max_concurrent: int = 5) -> None:
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active: int = 0

    @property
    def active_calls(self) -> int:
        return self._active

    @property
    def available_slots(self) -> int:
        return self.max_concurrent - self._active

    async def call(self, func: Callable[..., Coroutine], *args: Any, **kwargs: Any) -> Any:
        """Execute *func* after acquiring a rate-limit slot."""
        async with self._semaphore:
            self._active += 1
            try:
                return await func(*args, **kwargs)
            finally:
                self._active -= 1

    @classmethod
    def from_settings(cls) -> APIRateLimiter:
        cfg = get_settings().rate_limiter
        return cls(max_concurrent=cfg.max_concurrent_api_calls)


# ═══════════════════════════════════════════════════════════════
# 4.  Unified safe LLM call  (combines all of the above)
# ═══════════════════════════════════════════════════════════════

# Module-level singletons — initialised lazily.
_circuit_breaker: CircuitBreaker | None = None
_rate_limiter: APIRateLimiter | None = None


def get_circuit_breaker() -> CircuitBreaker:
    global _circuit_breaker
    if _circuit_breaker is None:
        _circuit_breaker = CircuitBreaker.from_settings()
    return _circuit_breaker


def get_rate_limiter() -> APIRateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = APIRateLimiter.from_settings()
    return _rate_limiter


async def safe_llm_call(
    llm: Any,
    messages: list,
    *,
    agent_name: str = "",
    cost_tracker: Any | None = None,
    circuit_breaker: CircuitBreaker | None = None,
    rate_limiter: APIRateLimiter | None = None,
    max_retries: int = 3,
) -> Any:
    """The ONE function all agents use for LLM calls.

    Applies (in order):
    1. Rate limiter — wait for a semaphore slot
    2. Circuit breaker — fail-fast if circuit is open
    3. Retry — tenacity exponential backoff on transient errors
    4. Cost tracking — record tokens and cost
    5. Metrics — log the call

    Parameters
    ----------
    llm : BaseChatModel
        The LangChain chat model.
    messages : list
        Messages to send (LangChain message objects).
    agent_name : str
        Name of the calling agent (for logging and cost tracking).
    cost_tracker : CostTracker | None
        If provided, tokens and cost are recorded.
    circuit_breaker : CircuitBreaker | None
        Override the global circuit breaker (useful for testing).
    rate_limiter : APIRateLimiter | None
        Override the global rate limiter (useful for testing).
    max_retries : int
        Number of retry attempts for transient failures.

    Returns
    -------
    The LLM response (BaseMessage).

    Raises
    ------
    CircuitOpenError
        If the circuit breaker is open.
    BudgetExceededError
        If cost tracking detects budget overrun.
    LLMError
        If the call fails after all retries.
    """
    cb = circuit_breaker or get_circuit_breaker()
    rl = rate_limiter or get_rate_limiter()
    retry_decorator = make_retry_decorator(max_retries)

    @retry_decorator
    async def _invoke() -> Any:
        return await llm.ainvoke(messages)

    start = time.perf_counter()
    status = "success"

    try:
        # Rate limiter wraps circuit breaker wraps retry
        response = await rl.call(cb.call, _invoke)
        return response
    except CircuitOpenError:
        status = "circuit_open"
        raise
    except BudgetExceededError:
        status = "budget_exceeded"
        raise
    except Exception as exc:
        status = "error"
        raise LLMError(
            f"LLM call failed for agent '{agent_name}': {exc}",
            details={"agent": agent_name},
        ) from exc
    finally:
        elapsed = time.perf_counter() - start

        # Extract token usage from response metadata if available
        input_tokens = 0
        output_tokens = 0
        model_name = getattr(llm, "model_name", "") or getattr(llm, "model", "") or ""

        if status == "success":
            try:
                usage = getattr(response, "usage_metadata", None) or {}
                if isinstance(usage, dict):
                    input_tokens = usage.get("input_tokens", 0)
                    output_tokens = usage.get("output_tokens", 0)
            except Exception:
                pass

            # Fallback: if provider didn't report tokens (e.g. Ollama),
            # estimate from message text and response content.
            if not input_tokens and not output_tokens:
                try:
                    from blanketaudit2.llm.cost_tracker import count_tokens
                    # Estimate input tokens from messages
                    input_text = " ".join(
                        getattr(m, "content", "") or "" for m in messages
                    )
                    if input_text:
                        input_tokens = count_tokens(input_text, model_name)
                    # Estimate output tokens from response
                    resp_text = getattr(response, "content", "") or ""
                    if resp_text:
                        output_tokens = count_tokens(resp_text, model_name)
                except Exception:
                    pass

        # Cost tracking
        if cost_tracker is not None and (input_tokens or output_tokens):
            try:
                cost_tracker.record_call(
                    agent_name=agent_name,
                    model=model_name,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                )
            except BudgetExceededError:
                raise
            except Exception:
                pass  # Don't let tracking failures kill the call

        # Metrics
        from blanketaudit2.llm.cost_tracker import _get_pricing
        inp_price, out_price = _get_pricing(model_name)
        cost_usd = (input_tokens * inp_price + output_tokens * out_price) / 1_000_000

        # Detect provider — ChatOllama doesn't expose a .provider attribute
        _provider = getattr(llm, "provider", None)
        if not _provider:
            _cls_name = type(llm).__name__.lower()
            if "ollama" in _cls_name:
                _provider = "ollama"
            elif "anthropic" in _cls_name:
                _provider = "anthropic"
            elif "openai" in _cls_name or "azure" in _cls_name:
                _provider = "openai"
            elif "groq" in _cls_name:
                _provider = "groq"
            elif "google" in _cls_name or "genai" in _cls_name:
                _provider = "google"
            else:
                _provider = "unknown"

        record_llm_call(
            provider=_provider,
            model=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            duration_seconds=elapsed,
            status=status,
        )
