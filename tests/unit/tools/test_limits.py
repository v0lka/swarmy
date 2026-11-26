"""Tests of ``tools.limits`` — the session-global ResourceLimiter (arch §6.4, T2.1.2).

Covers the roadmap acceptance criteria: rps-per-host spacing under parallel
calls (interval measurement), the global concurrency ceiling via an active-
request counter, budget exhaustion refusing with ``invariant:budget``, and
event-loop responsiveness while waits are pending. Plus the cancel-refund
contract and the client-facing limit exposure.
"""

from __future__ import annotations

import asyncio
import itertools
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from swarmy.tools.limits import (
    BUDGET_RULE_ID,
    BudgetExhausted,
    ResourceLimiter,
    ResourceLimits,
)

if TYPE_CHECKING:
    from collections.abc import Coroutine


def _limits(**overrides: float | int) -> ResourceLimits:
    """Build a limits config with the arch §12.1 example as the baseline."""
    values: dict[str, float | int] = {
        "rate_limit": 10,
        "max_concurrent_requests": 4,
        "max_body_bytes": 5_242_880,
        "max_redirect_depth": 5,
        "total_request_budget": 1000,
        "connect_timeout_s": 10,
        "read_timeout_s": 30,
    }
    values.update(overrides)
    return ResourceLimits(**values)


async def _run(coros: list[Coroutine[object, object, object]]) -> list[object]:
    """Gather tasks, returning their results in completion-tolerant order."""
    return list(await asyncio.gather(*coros))


def _ticker_ticks(duration_s: float, step_s: float = 0.005) -> int:
    """Return a coroutine counting loop wakeups over ``duration_s``.

    Used as the event-loop heartbeat: a blocked loop would produce far
    fewer ticks than the requested duration allows.
    """

    async def tick() -> int:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration_s
        ticks = 0
        while loop.time() < deadline:
            await asyncio.sleep(step_s)
            ticks += 1
        return ticks

    return tick()  # type: ignore[return-value]


# ---- config validation (fail-fast, arch §4.5) ----


def test_limits_config_requires_every_field() -> None:
    """A partially specified limits section is a ValidationError (arch §12.1)."""
    with pytest.raises(ValidationError):
        ResourceLimits(rate_limit=5)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "overrides",
    [
        {"rate_limit": 0},
        {"rate_limit": -1},
        {"max_concurrent_requests": 0},
        {"max_body_bytes": 0},
        {"max_redirect_depth": 0},
        {"total_request_budget": 0},
        {"connect_timeout_s": 0},
        {"read_timeout_s": -5},
    ],
    ids=[
        "rate-zero", "rate-negative", "concurrency-zero", "body-zero",
        "redirect-zero", "budget-zero", "connect-zero", "read-negative",
    ],
)
def test_limits_config_rejects_non_positive_values(overrides: dict[str, float | int]) -> None:
    """Every limit is an invariant: zero/negative values cannot weaken it."""
    with pytest.raises(ValidationError):
        _limits(**overrides)


# ---- rps per host (token bucket) ----


async def test_rps_per_host_respected_under_parallel_calls() -> None:
    """Consecutive starts on one host are spaced >= 1/rate apart (AC)."""
    limiter = ResourceLimiter(_limits(rate_limit=5))  # interval 0.2 s
    loop = asyncio.get_running_loop()
    starts: dict[str, list[float]] = {"crowded": [], "other": []}

    async def request(host: str) -> None:
        async with limiter.acquire(host, "GET"):
            starts[host].append(loop.time())

    t0 = loop.time()
    await _run([request("crowded") for _ in range(4)] + [request("other") for _ in range(2)])

    crowded = starts["crowded"]
    assert len(crowded) == 4
    gaps = [later - earlier for earlier, later in itertools.pairwise(crowded)]
    assert all(gap >= 0.15 for gap in gaps), f"rps violated on host: {gaps}"  # 0.2 - slack
    assert crowded[0] - t0 < 0.15, "first slot must be immediate"
    # a different host is not throttled by the crowded one
    assert starts["other"][0] - t0 < 0.15
    assert limiter.budget_used == 6


async def test_rate_bucket_keys_per_host() -> None:
    """Two hosts get independent buckets; case differences fold to one."""
    limiter = ResourceLimiter(_limits(rate_limit=2))  # interval 0.5 s
    loop = asyncio.get_running_loop()

    async def request(host: str) -> float:
        async with limiter.acquire(host, "GET"):
            return loop.time()

    _, first = await _run([request("Host.Example.Com"), request("host.example.com")])
    # normalized to the same bucket: the second start waits one interval
    second_wait = await request("host.example.com")
    assert second_wait - first >= 0.45
    assert len(limiter._buckets) == 1  # white-box: per-host bucket keying


# ---- global concurrency ceiling ----


async def test_concurrent_requests_never_exceed_max() -> None:
    """Summed in-flight requests stay <= max_concurrent_requests (AC)."""
    limiter = ResourceLimiter(_limits(max_concurrent_requests=3, rate_limit=1000))
    active = 0
    peak = 0
    completed = 0

    async def request() -> None:
        nonlocal active, peak, completed
        async with limiter.acquire("h", "GET"):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.05)
            active -= 1
            completed += 1

    await _run([request() for _ in range(10)])
    assert peak <= 3, f"concurrency ceiling broken: {peak}"
    assert peak >= 2, "test must have exercised actual contention"
    assert completed == 10
    assert limiter.requests_in_flight == 0


# ---- session request budget ----


async def test_budget_exhaustion_blocks_with_invariant_budget_reason() -> None:
    """A spent budget refuses new calls with the budget rule id (AC)."""
    limiter = ResourceLimiter(_limits(total_request_budget=2))

    async with limiter.acquire("h", "GET"):
        pass
    async with limiter.acquire("h", "POST"):
        pass
    assert limiter.budget_used == 2
    assert limiter.budget_remaining == 0
    assert limiter.budget_exhausted is True

    with pytest.raises(BudgetExhausted) as excinfo:
        async with limiter.acquire("h", "GET"):
            pass
    assert excinfo.value.rule_id == BUDGET_RULE_ID == "invariant:budget"
    assert "invariant:budget" in str(excinfo.value)
    assert (limiter.budget_block_reason() or "").startswith("invariant:budget")
    assert limiter.budget_used == 2  # the refused call consumed nothing


def test_budget_block_reason_is_none_while_budget_last() -> None:
    """The pre-check reason exists only after exhaustion (invariant wiring)."""
    limiter = ResourceLimiter(_limits(total_request_budget=7))
    assert limiter.budget_block_reason() is None
    assert limiter.budget_exhausted is False


async def test_cancelled_wait_refunds_budget_and_releases_slot() -> None:
    """A task cancelled while waiting never counted as a request (arch §6.4)."""
    limiter = ResourceLimiter(_limits(max_concurrent_requests=1, total_request_budget=2))

    async def hold() -> None:
        async with limiter.acquire("h", "GET"):
            await asyncio.sleep(0.3)

    async def wait_for_slot() -> None:
        async with limiter.acquire("h", "GET"):
            pass

    holder = asyncio.create_task(hold())
    await asyncio.sleep(0.02)
    waiter = asyncio.create_task(wait_for_slot())
    await asyncio.sleep(0.02)
    assert limiter.budget_used == 2  # both reserved their slot...
    assert limiter.requests_in_flight == 1  # ...but only the holder is in flight

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert limiter.budget_used == 1, "cancelled wait must refund the budget"
    assert limiter.requests_in_flight == 1  # semaphore slot not leaked

    await holder
    assert limiter.requests_in_flight == 0
    assert limiter.budget_used == 1  # only the executed request counts


# ---- event-loop responsiveness ----


async def test_waiting_never_blocks_the_event_loop() -> None:
    """Ticker keeps ticking while tasks wait on the semaphore and on rate (AC)."""
    limiter = ResourceLimiter(
        _limits(max_concurrent_requests=1, rate_limit=2)  # rate interval 0.5 s
    )

    async def hold_semaphore() -> None:
        async with limiter.acquire("h", "GET"):
            await asyncio.sleep(0.2)

    async def wait_for_slot() -> None:
        async with limiter.acquire("h", "GET"):
            pass  # waits for the semaphore, then for the rate slot

    holder = asyncio.create_task(hold_semaphore())
    waiter = asyncio.create_task(wait_for_slot())
    heartbeat = asyncio.create_task(_ticker_ticks(0.4))
    ticks = await heartbeat
    await holder
    await waiter
    assert ticks >= 25, f"event loop starved during waits: {ticks} ticks"
    assert limiter.budget_used == 2


# ---- client-facing exposure (P2.2 consumer contract) ----


def test_limits_exposed_for_the_http_client() -> None:
    """The client reads its cut-offs (body, redirects, timeouts) from here."""
    limits = _limits(max_body_bytes=4096, max_redirect_depth=7)
    limiter = ResourceLimiter(limits)
    assert limiter.limits is limits
    assert limiter.limits.max_body_bytes == 4096
    assert limiter.limits.max_redirect_depth == 7
    assert limiter.limits.connect_timeout_s == 10
    assert limiter.limits.read_timeout_s == 30


async def test_lease_carries_normalized_host_and_method() -> None:
    """The lease normalizes its key inputs (bucket key and diagnostics)."""
    limiter = ResourceLimiter(_limits())
    async with limiter.acquire("  Target.Example.Com  ", "get") as lease:
        assert lease.host == "target.example.com"
        assert lease.method == "GET"
