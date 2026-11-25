"""Tests of guardrail layer 1 — the platform invariants (arch §6.5, T1.4.3/T2.1.3).

Invariants are non-configurable code constants with ``invariant:``-prefixed
ids; the ``platform-http`` invariant must catch network-shaped calls on any
tool outside the platform HTTP set, and the T2.1.3 slots stay inert until
real checks are injected. The wired half (T2.1.3) proves the real scope /
limits / timeout / out-of-scope-target checks: out-of-scope requests are
denied with ``layer="invariant"`` *before* any connection, and the
invariants evaluate before ``ResourceLimiter.acquire`` (pipeline order
arch §6.2: guardrails → limiter → httpx).
"""

from __future__ import annotations

import pytest

from swarmy.guardrails.invariants import (
    INVARIANT_PREFIX,
    Invariant,
    InvariantLayer,
    default_invariants,
    platform_http_check,
    session_invariants,
)
from swarmy.guardrails.models import Verdict
from swarmy.guardrails.pipeline import GuardrailPipeline
from swarmy.tools.limits import ResourceLimiter, ResourceLimits
from swarmy.tools.scope import (
    OutOfScopeEndpoint,
    ScopeEntries,
    ScopeRegistry,
)


def _session_scope() -> ScopeRegistry:
    """A small realistic allowlist (arch §12.1 shape) for the wired tests."""
    return ScopeRegistry(
        ScopeEntries(
            domains=["target.example.com"],
            ip_subnets=["203.0.113.0/24"],
            ports=[80, 443],
            schemes=["http", "https"],
        )
    )


def _session_limiter(total_request_budget: int = 5000) -> ResourceLimiter:
    """A limiter with the arch §12.1 example limits and a large budget."""
    return ResourceLimiter(
        ResourceLimits(
            rate_limit=5,
            max_concurrent_requests=8,
            max_body_bytes=5_242_880,
            max_redirect_depth=5,
            total_request_budget=total_request_budget,
            connect_timeout_s=10,
            read_timeout_s=30,
        )
    )


def _wired_layer(scope: ScopeRegistry, limiter: ResourceLimiter) -> InvariantLayer:
    """Build the layer-1 set with every T2.1.3 slot filled for real."""
    return InvariantLayer(session_invariants(scope, limiter))


def _evaluate(
    tool_name: str, tool_args: dict[str, object]
) -> tuple[str, str] | None:
    """Evaluate the default invariant layer, returning (rule_id, layer)."""
    layer = InvariantLayer(default_invariants())
    feedback = layer.evaluate(tool_name, tool_args)
    if feedback is None:
        return None
    return feedback.rule_id, feedback.layer


def test_platform_http_fires_on_fake_network_tool() -> None:
    """A non-platform tool with a network argument is denied (AC)."""
    denied = _evaluate("raw_fetch", {"url": "http://target.example.com/"})
    assert denied is not None
    rule_id, layer = denied
    assert rule_id == "invariant:platform-http"
    assert layer == "invariant"


@pytest.mark.parametrize(
    ("tool_name", "tool_args"),
    [
        ("raw_fetch", {"url": "http://target.example.com/"}),
        ("ssh_probe", {"host": "target.example.com", "port": 22}),
        ("dns_lookup", {"hostname": "target.example.com"}),
        ("webhook_post", {"endpoint_url": "http://target.example.com/hook"}),
    ],
    ids=["url", "host", "hostname", "endpoint_url"],
)
def test_platform_http_catches_every_network_hint_key(
    tool_name: str, tool_args: dict[str, object]
) -> None:
    """Each network-shaped argument key triggers the invariant."""
    denied = _evaluate(tool_name, tool_args)
    assert denied is not None
    assert denied[0] == "invariant:platform-http"


@pytest.mark.parametrize(
    ("tool_name", "tool_args"),
    [
        ("http_get", {"url": "http://target.example.com/"}),  # platform tool
        ("http_post", {"url": "http://target.example.com/", "body": "x"}),
        ("memory_add_note", {"text": "harmless observation"}),  # no network args
        ("emit_event", {"type": "OperatorMessage", "payload": {}}),
    ],
    ids=["http_get", "http_post", "memory-tool", "emit-tool"],
)
def test_platform_http_allows_platform_and_offline_tools(
    tool_name: str, tool_args: dict[str, object]
) -> None:
    """Platform HTTP tools and offline tools pass layer 1."""
    assert _evaluate(tool_name, tool_args) is None


def test_check_function_returns_none_for_platform_tool() -> None:
    """The bare check callable agrees with the layer evaluator."""
    assert platform_http_check("http_get", {"url": "http://x/"}) is None
    reason = platform_http_check("raw_fetch", {"url": "http://x/"})
    assert reason is not None
    assert "platform HTTP" in reason


def test_all_invariant_ids_have_the_invariant_prefix() -> None:
    """Every layer-1 rule id is ``invariant:<name>`` (AC)."""
    layer = InvariantLayer(default_invariants())
    assert layer.ids == (
        "invariant:platform-http",
        "invariant:scope",
        "invariant:limits",
        "invariant:timeout",
        "invariant:out-of-scope-target",
    )
    assert all(item.invariant_id.startswith(INVARIANT_PREFIX) for item in layer)


def test_placeholder_slots_are_inert_by_default() -> None:
    """Uninjected scope/limits/timeout/target slots always allow."""
    layer = InvariantLayer(default_invariants())
    assert layer.evaluate("any_tool_at_all", {"anything": "goes"}) is None


def test_placeholder_slots_accept_injected_checks() -> None:
    """The T2.1.3 real checks plug in as callables and start denying."""

    def scope_check(tool_name: str, tool_args: dict[str, object]) -> str | None:
        """Toy scope rule: deny everything for the test."""
        return f"tool {tool_name!r} is outside the scope allowlist"

    layer = InvariantLayer(
        default_invariants(scope_check=scope_check, limits_check=None)
    )
    feedback = layer.evaluate("http_get", {"url": "http://x/"})
    assert feedback is not None
    assert feedback.rule_id == "invariant:scope"
    assert feedback.layer == "invariant"
    assert "outside the scope allowlist" in feedback.reason


def test_invariant_layer_rejects_unprefixed_ids() -> None:
    """Building a layer with an unprefixed id fails fast."""
    rogue = Invariant(
        invariant_id="not-prefixed", description="rogue", check=lambda _n, _a: None
    )
    with pytest.raises(ValueError, match="invariant:"):
        InvariantLayer([rogue])


# ---- T2.1.3: the wired real checks (session_invariants) ----


def test_wired_scope_blocks_out_of_scope_request_with_layer_invariant() -> None:
    """An out-of-scope request is denied, layer=invariant, with reason (AC)."""
    layer = _wired_layer(_session_scope(), _session_limiter())
    feedback = layer.evaluate("http_get", {"url": "https://evil.example.net/login"})
    assert feedback is not None
    assert feedback.rule_id == "invariant:scope"
    assert feedback.layer == "invariant"
    assert "outside the session scope allowlist" in feedback.reason


def test_wired_scope_allows_in_scope_request() -> None:
    """An allowlisted target passes the whole layer (all five slots wired)."""
    layer = _wired_layer(_session_scope(), _session_limiter())
    assert layer.evaluate("http_get", {"url": "https://target.example.com/login"}) is None
    assert layer.evaluate("http_get", {"url": "http://203.0.113.9/x"}) is None


def test_wired_out_of_scope_target_blocks_marked_endpoint() -> None:
    """A marked record denies its endpoint even inside the allowlist (AC)."""
    scope = _session_scope()
    scope.mark_out_of_scope(
        [OutOfScopeEndpoint(host="target.example.com:443", method="POST", path="/logout")]
    )
    layer = _wired_layer(scope, _session_limiter())
    feedback = layer.evaluate("http_post", {"url": "https://target.example.com/logout"})
    assert feedback is not None
    assert feedback.rule_id == "invariant:out-of-scope-target"
    assert feedback.layer == "invariant"
    # the same URL under a different method is not the marked record
    assert layer.evaluate("http_get", {"url": "https://target.example.com/logout"}) is None


async def test_wired_limits_blocks_after_budget_exhausted() -> None:
    """A spent budget denies with rule invariant:limits, reason invariant:budget."""
    limiter = _session_limiter(total_request_budget=1)
    layer = _wired_layer(_session_scope(), limiter)
    async with limiter.acquire("target.example.com", "GET"):
        pass
    feedback = layer.evaluate("http_get", {"url": "https://target.example.com/x"})
    assert feedback is not None
    assert feedback.rule_id == "invariant:limits"
    assert feedback.layer == "invariant"
    assert "invariant: budget" in feedback.reason


def test_wired_timeout_blocks_overwide_timeout_argument() -> None:
    """An explicit timeout wider than the session budget is denied pre-call."""
    layer = _wired_layer(_session_scope(), _session_limiter())
    feedback = layer.evaluate(
        "http_post", {"url": "https://target.example.com/x", "read_timeout_s": 999}
    )
    assert feedback is not None
    assert feedback.rule_id == "invariant:timeout"
    assert feedback.layer == "invariant"
    # within the budget (or absent) — allowed
    assert layer.evaluate("http_post", {"url": "https://target.example.com/x"}) is None
    assert layer.evaluate(
        "http_post", {"url": "https://target.example.com/x", "read_timeout_s": 5}
    ) is None


def test_wired_layer_keeps_evaluation_order_and_first_denial() -> None:
    """Order is canonical; the first denial wins (scope before target rule)."""
    scope = _session_scope()
    scope.mark_out_of_scope(
        [OutOfScopeEndpoint(host="evil.example.net:443", method="GET", path="/")]
    )
    layer = _wired_layer(scope, _session_limiter())
    assert layer.ids == (
        "invariant:platform-http",
        "invariant:scope",
        "invariant:limits",
        "invariant:timeout",
        "invariant:out-of-scope-target",
    )
    # out-of-allowlist AND marked: invariant:scope fires first (fixed order)
    feedback = layer.evaluate("http_get", {"url": "https://evil.example.net/"})
    assert feedback is not None
    assert feedback.rule_id == "invariant:scope"


async def test_pipeline_denies_before_limiter_acquire_is_reached() -> None:
    """Guardrails run strictly before ResourceLimiter.acquire (AC, arch §6.2)."""

    class LimiterSpy:
        """Recording facade over the real limiter (ordering probe)."""

        def __init__(self, inner: ResourceLimiter) -> None:
            self._inner = inner
            self.acquire_calls: list[tuple[str, str]] = []

        @property
        def limits(self) -> ResourceLimits:
            """Mirror the inner limiter's config (timeout pre-check reads it)."""
            return self._inner.limits

        def budget_block_reason(self) -> str | None:
            """Mirror the inner limiter's budget state."""
            return self._inner.budget_block_reason()

        def acquire(self, host: str, method: str) -> object:
            """Record the attempt, then delegate to the real limiter."""
            self.acquire_calls.append((host, method))
            return self._inner.acquire(host, method)

    limiter = _session_limiter()
    spy = LimiterSpy(limiter)
    pipeline = GuardrailPipeline(invariants=_wired_layer(_session_scope(), spy), engine_rules=[])

    # out-of-scope: the guardrail stage blocks — the limiter is never touched
    blocked = pipeline.evaluate("http_get", {"url": "https://evil.example.net/"})
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.feedback is not None
    assert blocked.feedback.rule_id == "invariant:scope"
    assert spy.acquire_calls == []

    # in-scope: the pipeline allows, and only then the client stage acquires
    allowed = pipeline.evaluate("http_get", {"url": "https://target.example.com/login"})
    assert allowed.verdict is Verdict.ALLOW
    async with spy.acquire("target.example.com", "GET"):  # the arch §6.2 next stage
        pass
    assert spy.acquire_calls == [("target.example.com", "GET")]
