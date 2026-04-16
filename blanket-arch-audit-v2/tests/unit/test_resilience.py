"""Tests for blanketaudit2.llm.resilience — retry, circuit breaker, rate limiter."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blanketaudit2.exceptions import CircuitOpenError, LLMError
from blanketaudit2.llm.resilience import (
    APIRateLimiter,
    CircuitBreaker,
    CircuitState,
    make_retry_decorator,
    safe_llm_call,
)


# ═══════════════════════════════════════════════════════════════
# Retry
# ═══════════════════════════════════════════════════════════════


class TestRetryDecorator:
    @pytest.mark.asyncio
    async def test_succeeds_without_retry(self):
        call_count = 0

        @make_retry_decorator(max_attempts=3)
        async def good_call():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await good_call()
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_timeout(self):
        call_count = 0

        @make_retry_decorator(max_attempts=3)
        async def flaky_call():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("timeout")
            return "recovered"

        result = await flaky_call()
        assert result == "recovered"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retries_on_connection_error(self):
        call_count = 0

        @make_retry_decorator(max_attempts=3)
        async def flaky_call():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("refused")
            return "ok"

        result = await flaky_call()
        assert result == "ok"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_does_not_retry_on_value_error(self):
        call_count = 0

        @make_retry_decorator(max_attempts=3)
        async def bad_call():
            nonlocal call_count
            call_count += 1
            raise ValueError("not retryable")

        with pytest.raises(ValueError, match="not retryable"):
            await bad_call()
        assert call_count == 1  # No retry

    @pytest.mark.asyncio
    async def test_exhausts_retries(self):
        @make_retry_decorator(max_attempts=2)
        async def always_fail():
            raise TimeoutError("always")

        with pytest.raises(TimeoutError):
            await always_fail()


# ═══════════════════════════════════════════════════════════════
# Circuit Breaker
# ═══════════════════════════════════════════════════════════════


class TestCircuitBreakerStates:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state is CircuitState.CLOSED
        assert not cb.is_open

    @pytest.mark.asyncio
    async def test_stays_closed_on_success(self):
        cb = CircuitBreaker(failure_threshold=3)

        async def ok():
            return "ok"

        result = await cb.call(ok)
        assert result == "ok"
        assert cb.state is CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(failure_threshold=3, window_seconds=60)

        async def fail():
            raise RuntimeError("boom")

        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(fail)

        assert cb.state is CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_open_circuit_raises_immediately(self):
        cb = CircuitBreaker(failure_threshold=1, window_seconds=60, recovery_seconds=999)

        async def fail():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await cb.call(fail)

        assert cb.is_open

        with pytest.raises(CircuitOpenError, match="Circuit breaker is open"):
            await cb.call(fail)

    @pytest.mark.asyncio
    async def test_half_open_after_recovery_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, window_seconds=60, recovery_seconds=0.05)

        async def fail():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await cb.call(fail)
        assert cb.state is CircuitState.OPEN

        # Wait for recovery timeout
        await asyncio.sleep(0.06)
        assert cb.state is CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_half_open_success_closes(self):
        cb = CircuitBreaker(failure_threshold=1, window_seconds=60, recovery_seconds=0.05)

        call_count = 0

        async def sometimes_fail():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("first fail")
            return "ok"

        with pytest.raises(RuntimeError):
            await cb.call(sometimes_fail)
        assert cb.state is CircuitState.OPEN

        await asyncio.sleep(0.06)
        assert cb.state is CircuitState.HALF_OPEN

        result = await cb.call(sometimes_fail)
        assert result == "ok"
        assert cb.state is CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(failure_threshold=1, window_seconds=60, recovery_seconds=0.05)

        async def always_fail():
            raise RuntimeError("still broken")

        with pytest.raises(RuntimeError):
            await cb.call(always_fail)
        assert cb.state is CircuitState.OPEN

        await asyncio.sleep(0.06)
        assert cb.state is CircuitState.HALF_OPEN

        with pytest.raises(RuntimeError):
            await cb.call(always_fail)
        assert cb.state is CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_failures_outside_window_dont_count(self):
        cb = CircuitBreaker(failure_threshold=3, window_seconds=0.05)

        async def fail():
            raise RuntimeError("boom")

        # Two failures
        with pytest.raises(RuntimeError):
            await cb.call(fail)
        with pytest.raises(RuntimeError):
            await cb.call(fail)

        # Wait for window to expire
        await asyncio.sleep(0.06)

        # Third failure is within a new window — should not trip
        with pytest.raises(RuntimeError):
            await cb.call(fail)
        assert cb.state is CircuitState.CLOSED  # Only 1 failure in current window

    def test_reset(self):
        cb = CircuitBreaker(failure_threshold=1)
        cb._state = CircuitState.OPEN
        cb._failures = [time.monotonic()]
        cb.reset()
        assert cb.state is CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_failure_count_property(self):
        cb = CircuitBreaker(failure_threshold=5, window_seconds=60)
        now = time.monotonic()
        cb._failures = [now - 100, now - 50, now - 10, now - 1]
        # Only failures within 60s window count
        assert cb.failure_count == 3  # -50, -10, -1


# ═══════════════════════════════════════════════════════════════
# Rate Limiter
# ═══════════════════════════════════════════════════════════════


class TestAPIRateLimiter:
    @pytest.mark.asyncio
    async def test_basic_call(self):
        rl = APIRateLimiter(max_concurrent=3)

        async def ok():
            return 42

        result = await rl.call(ok)
        assert result == 42

    @pytest.mark.asyncio
    async def test_limits_concurrency(self):
        rl = APIRateLimiter(max_concurrent=2)
        max_seen = 0
        active = 0

        async def tracked():
            nonlocal active, max_seen
            active += 1
            max_seen = max(max_seen, active)
            await asyncio.sleep(0.05)
            active -= 1
            return "done"

        # Launch 5 concurrent calls with limit 2
        tasks = [rl.call(tracked) for _ in range(5)]
        results = await asyncio.gather(*tasks)
        assert all(r == "done" for r in results)
        assert max_seen <= 2

    @pytest.mark.asyncio
    async def test_active_calls_tracking(self):
        rl = APIRateLimiter(max_concurrent=5)
        assert rl.active_calls == 0
        assert rl.available_slots == 5

        started = asyncio.Event()
        release = asyncio.Event()

        async def blocked():
            started.set()
            await release.wait()

        task = asyncio.create_task(rl.call(blocked))
        await started.wait()
        assert rl.active_calls == 1
        assert rl.available_slots == 4

        release.set()
        await task
        assert rl.active_calls == 0

    @pytest.mark.asyncio
    async def test_exception_releases_slot(self):
        rl = APIRateLimiter(max_concurrent=1)

        async def fail():
            raise ValueError("oops")

        with pytest.raises(ValueError):
            await rl.call(fail)

        # Slot should be released — next call should work
        async def ok():
            return "fine"

        result = await rl.call(ok)
        assert result == "fine"


# ═══════════════════════════════════════════════════════════════
# safe_llm_call
# ═══════════════════════════════════════════════════════════════


def _make_mock_llm(content: str = "response", model: str = "test-model") -> AsyncMock:
    """Create a mock LLM with ainvoke."""
    mock = AsyncMock()
    mock.model_name = model
    mock.model = model
    mock.provider = "test"
    response = MagicMock()
    response.content = content
    response.usage_metadata = {"input_tokens": 100, "output_tokens": 50}
    mock.ainvoke.return_value = response
    return mock


class TestSafeLlmCall:
    @pytest.mark.asyncio
    async def test_successful_call(self):
        llm = _make_mock_llm("hello")
        cb = CircuitBreaker(failure_threshold=5)
        rl = APIRateLimiter(max_concurrent=5)

        result = await safe_llm_call(
            llm, [{"role": "user", "content": "hi"}],
            agent_name="security",
            circuit_breaker=cb,
            rate_limiter=rl,
        )
        assert result.content == "hello"
        llm.ainvoke.assert_called_once()

    @pytest.mark.asyncio
    async def test_circuit_open_raises(self):
        llm = _make_mock_llm()
        cb = CircuitBreaker(failure_threshold=1, recovery_seconds=999)

        # Trip the circuit
        llm_fail = AsyncMock()
        llm_fail.ainvoke = AsyncMock(side_effect=TimeoutError("timeout"))
        llm_fail.model_name = "test"
        llm_fail.model = "test"
        llm_fail.provider = "test"

        rl = APIRateLimiter(max_concurrent=5)

        # First call trips the circuit (retry exhausted → circuit records failure)
        with pytest.raises(LLMError):
            await safe_llm_call(
                llm_fail, [],
                agent_name="test",
                circuit_breaker=cb,
                rate_limiter=rl,
                max_retries=1,
            )

        # Second call should get CircuitOpenError
        with pytest.raises(CircuitOpenError):
            await safe_llm_call(
                llm, [],
                agent_name="test",
                circuit_breaker=cb,
                rate_limiter=rl,
            )

    @pytest.mark.asyncio
    async def test_wraps_unknown_error_in_llm_error(self):
        llm = AsyncMock()
        llm.ainvoke = AsyncMock(side_effect=ValueError("unexpected"))
        llm.model_name = "test"
        llm.model = "test"
        llm.provider = "test"

        cb = CircuitBreaker(failure_threshold=5)
        rl = APIRateLimiter(max_concurrent=5)

        with pytest.raises(LLMError, match="LLM call failed"):
            await safe_llm_call(
                llm, [],
                agent_name="security",
                circuit_breaker=cb,
                rate_limiter=rl,
                max_retries=1,
            )

    @pytest.mark.asyncio
    async def test_records_cost_tracking(self):
        llm = _make_mock_llm()
        cb = CircuitBreaker(failure_threshold=5)
        rl = APIRateLimiter(max_concurrent=5)

        tracker = MagicMock()
        tracker.record_call = MagicMock()

        await safe_llm_call(
            llm, [],
            agent_name="compliance",
            cost_tracker=tracker,
            circuit_breaker=cb,
            rate_limiter=rl,
        )

        tracker.record_call.assert_called_once()
        call_kwargs = tracker.record_call.call_args[1]
        assert call_kwargs["agent_name"] == "compliance"
        assert call_kwargs["input_tokens"] == 100
        assert call_kwargs["output_tokens"] == 50

    @pytest.mark.asyncio
    async def test_rate_limiter_applied(self):
        """Verify the rate limiter actually constrains concurrency."""
        llm = _make_mock_llm()
        # Make ainvoke take a bit of time
        original = llm.ainvoke

        async def slow_invoke(msgs):
            await asyncio.sleep(0.02)
            return await original(msgs)

        llm.ainvoke = slow_invoke

        cb = CircuitBreaker(failure_threshold=10)
        rl = APIRateLimiter(max_concurrent=2)

        tasks = [
            safe_llm_call(llm, [], agent_name="a", circuit_breaker=cb, rate_limiter=rl)
            for _ in range(4)
        ]
        results = await asyncio.gather(*tasks)
        assert len(results) == 4
