"""``ResourceLimiter``: global session resource limits (arch §6.4, T2.1.2).

All limits are session-global invariants (arch §6.4, spec §7.3, D19, arch
§16 invariant 7): under parallel ``task()`` delegations the *summed* swarm
pressure on the target never exceeds one agent's worth of limits — the
limiter therefore knows nothing about subagents, owners, or risk classes;
its API is just ``(host, method)``.

Mechanisms (arch §6.4 table):

* ``rate_limit`` (rps per host) — a token bucket per host with strict
  spacing (capacity 1 slot, refilled every ``1/rate`` seconds): any two
  consecutive request starts on one host are at least ``1/rate`` apart;
* ``max_concurrent_requests`` — one global ``asyncio.Semaphore``;
* ``total_request_budget`` — an atomic counter consumed once per
  ``acquire()`` (per request, redirect hops included); exhaustion refuses
  every further network call with the ``invariant:budget`` rule;
* ``max_body_bytes`` / ``max_redirect_depth`` / ``connect_timeout_s`` /
  ``read_timeout_s`` — cut-off values *exposed* here; the HTTP client
  (P2.2) enforces them while reading responses, counting redirect hops and
  configuring its timeouts.

``acquire(host, method)`` is the single entry point: it returns an async
context manager (release happens on context exit). Waiting never blocks
the event loop — the semaphore and the rate bucket are awaited — and
cancelling the awaiting task (HITL reject, session close) refunds the
budget slot, because a cancelled wait never became a request.
"""

from __future__ import annotations

import asyncio
from typing import Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

#: The rule id of the budget-exhaustion denial (arch §6.4, roadmap T2.1.2).
BUDGET_RULE_ID: Final[str] = "invariant:budget"


class ResourceLimits(BaseModel):
    """The ``limits`` section of the session config (arch §12.1, §6.4).

    All fields are required and strictly positive — a partially specified
    limits section is a session-start failure (fail-fast, arch §4.5), never
    a silent default that weakens an invariant.
    """

    model_config = ConfigDict(extra="forbid")

    rate_limit: float = Field(gt=0)  # requests per second, per host
    max_concurrent_requests: int = Field(gt=0)  # global, all hosts summed
    # both directions (client-side, Issue #31): outgoing request bodies
    # above it are denied pre-connect; response reads are cut off at it.
    max_body_bytes: int = Field(gt=0)
    max_redirect_depth: int = Field(ge=1)  # hop counter in the client pipeline
    total_request_budget: int = Field(gt=0)  # requests per session, atomic
    connect_timeout_s: float = Field(gt=0)
    read_timeout_s: float = Field(gt=0)


class LimitLease(NamedTuple):
    """What one acquired request slot carries (diagnostics of the holder)."""

    host: str
    method: str


class BudgetExhausted(Exception):
    """The session request budget is spent; every network call is refused.

    The platform contour (HTTP client, P2.2) converts this into a
    ``GuardrailBlocked`` journal event carrying :data:`BUDGET_RULE_ID`
    (arch §6.4); the exception is the in-process signal until then.
    """

    rule_id: Final[str] = BUDGET_RULE_ID

    def __init__(self, reason: str) -> None:
        """Build the refusal from its agent-facing reason."""
        super().__init__(reason)
        self.reason = reason


class _HostRateBucket:
    """Token bucket of one host: strict spacing of request starts.

    Capacity is one slot refilled every ``1/rate`` seconds, so consecutive
    slot reservations are always at least one interval apart — the property
    the rps test measures. Waiting happens on ``asyncio.sleep`` (never a
    busy loop), with the lock held only while reserving, so cancellations
    and interleavings stay clean; FIFO order of waiters is not promised,
    only the spacing invariant.
    """

    __slots__ = ("_interval", "_lock", "_next_slot_at")

    def __init__(self, rate_limit: float) -> None:
        """Build the bucket for one normalized host key."""
        self._interval: Final[float] = 1.0 / rate_limit
        self._lock = asyncio.Lock()
        self._next_slot_at = 0.0

    async def wait_slot(self) -> None:
        """Reserve the next start slot, sleeping until it opens."""
        loop = asyncio.get_running_loop()
        while True:
            async with self._lock:
                delay = self._next_slot_at - loop.time()
                if delay <= 0:
                    self._next_slot_at = loop.time() + self._interval
                    return
            await asyncio.sleep(delay)


class ResourceLimiter:
    """Session-global limiter behind every platform HTTP call (arch §6.4).

    One instance per session, shared by all parallel delegations (D19).
    Budget consumption is atomic with respect to the event loop: the
    check-and-decrement sequence contains no ``await``. The limiter never
    touches the bus, the journal, or the memory store.
    """

    __slots__ = ("_buckets", "_budget_used", "_in_flight", "_limits", "_semaphore")

    def __init__(self, limits: ResourceLimits) -> None:
        """Bind the config and create the session-wide primitives."""
        self._limits = limits
        self._semaphore = asyncio.Semaphore(limits.max_concurrent_requests)
        self._buckets: dict[str, _HostRateBucket] = {}
        self._budget_used = 0
        self._in_flight = 0

    # ---- introspection (invariant pre-checks, client wiring, tests) ----

    @property
    def limits(self) -> ResourceLimits:
        """The configured limits (the client reads its cut-offs here)."""
        return self._limits

    @property
    def budget_used(self) -> int:
        """Requests consumed from the session budget so far."""
        return self._budget_used

    @property
    def budget_remaining(self) -> int:
        """Requests the session may still start."""
        return self._limits.total_request_budget - self._budget_used

    @property
    def budget_exhausted(self) -> bool:
        """True once no further request can start (arch §6.4)."""
        return self.budget_remaining <= 0

    @property
    def requests_in_flight(self) -> int:
        """Requests currently holding the global semaphore."""
        return self._in_flight

    def budget_block_reason(self) -> str | None:
        """The ``invariant:budget`` denial reason, or ``None`` while budget lasts.

        Used by the layer-1 ``invariant: limits`` pre-check so a spent
        budget denies *before* the limiter's async waits even begin
        (pipeline order arch §6.2: guardrails → limiter → httpx).
        """
        if not self.budget_exhausted:
            return None
        return (
            f"{BUDGET_RULE_ID}: the session request budget is exhausted "
            f"({self._budget_used}/{self._limits.total_request_budget} requests used); "
            "no further network calls will be made this session"
        )

    # ---- the single entry point (arch §6.4) ----

    def acquire(self, host: str, method: str) -> Acquire:
        """Acquire one request slot: budget → semaphore → rate bucket.

        Returns an async context manager; the slot is released on context
        exit. Raises :class:`BudgetExhausted` (on ``__aenter__``) once the
        budget is spent; the budget slot is refunded when the caller is
        cancelled while still waiting (the request never started). Each
        redirect hop the client makes acquires again — the budget counts
        requests, hops included (arch §6.2).

        Args:
            host: the target host of the request (rate bucket key).
            method: the HTTP method (carried on the lease for diagnostics).

        Returns:
            The async context manager yielding a :class:`LimitLease`.
        """
        return Acquire(self, host, method)

    # ---- internals shared with Acquire (same module, one lifecycle) ----

    def _bucket_for(self, host: str) -> _HostRateBucket:
        """Return (creating on first use) the rate bucket of ``host``."""
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _HostRateBucket(self._limits.rate_limit)
            self._buckets[host] = bucket
        return bucket


class Acquire:
    """The async context manager returned by :meth:`ResourceLimiter.acquire`.

    A plain class (not ``@asynccontextmanager``) so the acquire/release
    bookkeeping is explicit: refund-on-cancel must not depend on generator
    finalization details.
    """

    __slots__ = ("_entered", "_lease", "_limiter")

    def __init__(self, limiter: ResourceLimiter, host: str, method: str) -> None:
        """Bind limiter and target; nothing runs until ``__aenter__``."""
        self._limiter = limiter
        self._lease = LimitLease(host=host.strip().lower(), method=method.upper())
        self._entered = False

    async def __aenter__(self) -> LimitLease:
        """Consume budget, then wait for the semaphore and the rate slot."""
        limiter = self._limiter
        if limiter.budget_exhausted:
            reason = limiter.budget_block_reason()
            raise BudgetExhausted(reason if reason is not None else BUDGET_RULE_ID)
        limiter._budget_used += 1  # atomic: no await between check and decrement
        try:
            await limiter._semaphore.acquire()
            try:
                limiter._in_flight += 1
                await limiter._bucket_for(self._lease.host).wait_slot()
            except BaseException:
                limiter._in_flight -= 1
                limiter._semaphore.release()
                raise
        except BaseException:
            # Cancelled (or otherwise failed) before becoming a request:
            # the budget slot is refunded (arch §6.4 semantics).
            limiter._budget_used -= 1
            raise
        self._entered = True
        return self._lease

    async def __aexit__(self, *exc_info: object) -> None:
        """Release the semaphore slot (the budget stays spent)."""
        if self._entered:
            self._entered = False
            self._limiter._in_flight -= 1
            self._limiter._semaphore.release()


__all__ = [
    "BUDGET_RULE_ID",
    "Acquire",
    "BudgetExhausted",
    "LimitLease",
    "ResourceLimiter",
    "ResourceLimits",
]
