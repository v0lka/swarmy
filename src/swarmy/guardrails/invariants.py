"""Layer 1 — platform invariants: non-configurable code constants (arch §6.5, T1.4.3).

Invariants are the innermost, *unturn-offable* guardrail layer: their rules
live here as code, they never appear in any config schema, and a deny from
any of them denies the operation (spec §8.2, D11). Rule ids are prefixed
``invariant:`` (the ``GuardrailBlockedPayload.rule_id`` convention, arch
§5.1).

v0.1 carries one active invariant — ``invariant:platform-http`` (every
network call goes through the platform HTTP client, arch §6.5) — plus four
*placeholder slots* for the checks that arrive with the execution perimeter
in P2.1 (T2.1.3): scope, resource limits, timeout and out-of-scope-target.
Each slot is an injectable check callable (so T2.1.3 plugs real checks in
without touching the pipeline); until injected the slots are inert and
always allow.

Evaluation happens from the tool name + arguments alone, before any network
activity can start (arch §6.5): the checks are pure, synchronous functions.
T2.1.3 adds the *factories* that plug the real scope/limits checks into the
slots (:func:`scope_invariant_check`, :func:`limits_invariant_check`,
:func:`timeout_invariant_check`, :func:`out_of_scope_target_invariant_check`,
and the wiring one-stop :func:`session_invariants`); the bare
``default_invariants()`` set stays inert so tests and M1 code paths are
unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Final, NamedTuple

from swarmy.guardrails.models import BlockedFeedback

if TYPE_CHECKING:
    from swarmy.tools.limits import ResourceLimiter
    from swarmy.tools.scope import ScopeRegistry

#: Prefix of every layer-1 rule id (arch §5.1: "invariant:<name>").
INVARIANT_PREFIX = "invariant:"

#: Platform HTTP tools of the execution perimeter (arch §6.1, §6.2, T2.2.3):
#: the four named wrappers of ``tools/http/tools.py``. HEAD/PATCH stay
#: client-reachable without a dedicated wrapper (arch §6.2 Literal).
PLATFORM_HTTP_TOOLS: frozenset[str] = frozenset(
    {"http_get", "http_post", "http_put", "http_delete"}
)

#: Platform tools that legitimately carry host-shaped arguments without
#: performing network I/O: the memory wrappers record host facts in the
#: session store (they cannot open a connection — arch §2.5 forbids direct
#: network paths outside the HTTP client). Exempting them keeps the
#: invariant's intent (no network bypass) without blocking the platform's
#: own record-keeping contract (T1.2.6).
PLATFORM_MEMORY_TOOLS: frozenset[str] = frozenset(
    {
        "memory_search",
        "memory_get",
        "memory_upsert_endpoint",
        "memory_save_finding",
        "memory_link_attack_node",
        "memory_add_fact",
        "memory_add_note",
        "update_finding_status",
    }
)

#: Argument keys whose presence implies the tool is about to perform a
#: network call. Deliberately narrow (a filesystem ``path`` is not network):
#: false negatives widen layer-2/3 coverage, false positives would block
#: innocent tools.
NETWORK_ARG_HINTS: frozenset[str] = frozenset(
    {"url", "base_url", "host", "hostname", "endpoint_url"}
)

#: An invariant check: pure (tool_name, tool_args) -> denial reason, or
#: ``None`` when the call is allowed. No I/O, no clock, no randomness.
InvariantCheck = Callable[[str, Mapping[str, object]], str | None]


def platform_http_check(tool_name: str, tool_args: Mapping[str, object]) -> str | None:
    """Deny network-bearing calls on tools outside the platform HTTP set.

    The one active invariant of v0.1 (arch §6.5): a tool call that carries a
    network-shaped argument (``NETWORK_ARG_HINTS``) must go through a
    platform HTTP tool; anything else would bypass ``SwarmyHttpClient`` and
    the guardrails/limiters that wrap it.

    Args:
        tool_name: name of the tool being called.
        tool_args: arguments of the call (untrusted LLM-authored values).

    Returns:
        Denial reason, or ``None`` when the call may proceed to layer 2.
    """
    if tool_name in PLATFORM_HTTP_TOOLS or tool_name in PLATFORM_MEMORY_TOOLS:
        return None
    if any(key in tool_args for key in NETWORK_ARG_HINTS):
        return (
            f"tool {tool_name!r} looks like a network call but is not a platform "
            f"HTTP tool {sorted(PLATFORM_HTTP_TOOLS)}; all network access must go "
            "through the platform HTTP client (arch §6.5)"
        )
    return None


def _inert_check(_tool_name: str, _tool_args: Mapping[str, object]) -> str | None:
    """Placeholder check that always allows (filled by T2.1.3)."""
    return None


#: Argument keys carrying a request URL on the platform HTTP tools
#: (arch §6.2 ``RequestSpec``; ``endpoint_url`` covers webhook-style args).
#: Host-shaped keys (``host``/``hostname``) are deliberately excluded — a
#: bare hostname carries no scheme/port to check, and a tool carrying them
#: is already denied by :func:`platform_http_check` unless it is a platform
#: HTTP tool, which speaks in URLs.
URL_ARG_KEYS: frozenset[str] = frozenset({"url", "base_url", "endpoint_url"})

#: HTTP method implied by each platform HTTP tool name (arch §6.2).
_TOOL_METHODS: Final = {
    "http_get": "GET",
    "http_post": "POST",
    "http_put": "PUT",
    "http_delete": "DELETE",
}


def _string_leaves(value: object) -> Iterator[str]:
    """Yield every string leaf of an (untrusted) argument tree."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _string_leaves(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _string_leaves(item)


def _url_candidates(tool_args: Mapping[str, object]) -> list[str]:
    """Every URL-shaped string under the URL argument keys (stable order)."""
    found: list[str] = []
    for key in sorted(URL_ARG_KEYS):
        value = tool_args.get(key)
        if value is not None:
            found.extend(_string_leaves(value))
    return found


def _method_of_call(tool_name: str, tool_args: Mapping[str, object]) -> str | None:
    """HTTP method of the call: explicit argument, else the tool-name map.

    ``None`` means "method unknown" — the out-of-scope-target check treats
    that as fail-closed (matches any marked record).
    """
    explicit = tool_args.get("method")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().upper()
    return _TOOL_METHODS.get(tool_name)


def scope_invariant_check(scope: ScopeRegistry) -> InvariantCheck:
    """Build the ``invariant: scope`` check from a :class:`ScopeRegistry`.

    Every URL-shaped argument of the call must pass
    ``ScopeRegistry.check`` (arch §6.3: the check runs before each network
    hop); the first denial becomes the reason. Non-network tools and calls
    without URL arguments allow.

    Args:
        scope: the session allowlist (arch §6.3).

    Returns:
        The layer-1 check callable for :func:`default_invariants`.
    """

    def check(tool_name: str, tool_args: Mapping[str, object]) -> str | None:
        """Deny when any URL argument fails the allowlist."""
        del tool_name  # the rule keys on the URL arguments alone
        for url in _url_candidates(tool_args):
            verdict = scope.check(url)
            if not verdict.allowed and verdict.reason is not None:
                return (
                    f"URL {url!r} is outside the session scope allowlist: {verdict.reason} "
                    "(invariant: scope); out-of-scope requests are never executed — "
                    "re-plan inside the allowlisted target"
                )
        return None

    return check


def limits_invariant_check(limiter: ResourceLimiter) -> InvariantCheck:
    """Build the ``invariant: limits`` check from a :class:`ResourceLimiter`.

    The synchronous layer-1 share of the limiter contract (arch §6.4/§6.2):
    a spent session request budget denies the call *here*, before the
    limiter's async waits — the reason carries the ``invariant: budget``
    rule id. Concurrency/rate waits remain in ``ResourceLimiter.acquire``,
    which the client calls only after the whole pipeline allowed (arch
    §6.2 order: guardrails → limiter → httpx).

    Args:
        limiter: the session-global limiter (arch §6.4).

    Returns:
        The layer-1 check callable for :func:`default_invariants`.
    """

    def check(tool_name: str, tool_args: Mapping[str, object]) -> str | None:
        """Deny network-shaped calls once the budget is exhausted."""
        if not (tool_name in PLATFORM_HTTP_TOOLS or any(k in tool_args for k in NETWORK_ARG_HINTS)):
            return None
        return limiter.budget_block_reason()

    return check


def timeout_invariant_check(limiter: ResourceLimiter) -> InvariantCheck:
    """Build the ``invariant: timeout`` check from a :class:`ResourceLimiter`.

    Defense-in-depth pre-check: when a call *explicitly* requests timeouts
    wider than the session budget (``connect_timeout_s``/``read_timeout_s``
    and whole-call ``timeout``/``timeout_s``), it is denied here. The
    runtime half of the rule stays with the client: a timeout surfacing
    from httpx is published as ``GuardrailBlocked(layer="invariant",
    rule_id="timeout")`` (arch §6.2). The platform ``RequestSpec`` carries
    no timeout field, so ordinary calls pass untouched.

    Args:
        limiter: the session-global limiter owning the timeout budgets.

    Returns:
        The layer-1 check callable for :func:`default_invariants`.
    """

    def check(tool_name: str, tool_args: Mapping[str, object]) -> str | None:
        """Deny explicit timeout arguments exceeding the session budgets."""
        del tool_name
        limits = limiter.limits
        budgets: dict[str, float] = {
            "connect_timeout_s": limits.connect_timeout_s,
            "read_timeout_s": limits.read_timeout_s,
            "timeout": limits.connect_timeout_s + limits.read_timeout_s,
            "timeout_s": limits.connect_timeout_s + limits.read_timeout_s,
        }
        for key, budget in budgets.items():
            requested = tool_args.get(key)
            if isinstance(requested, (int, float)) and requested > budget:
                return (
                    f"invariant: timeout: requested {key}={requested}s exceeds the session "
                    f"timeout budget of {budget}s; the platform applies its own timeouts"
                )
        return None

    return check


def out_of_scope_target_invariant_check(scope: ScopeRegistry) -> InvariantCheck:
    """Build the ``invariant: out-of-scope-target`` check from the registry.

    Memory ``Endpoint`` records flagged ``out_of_scope=True`` are never
    served by the network tools (arch §6.3): the check consults the
    marked records the platform contour fed via
    ``ScopeRegistry.mark_out_of_scope`` and denies an exact host+path
    match (method-aware when the call carries one). A URL inside the
    domain allowlist can still be denied here — that is the point of the
    rule (e.g. an operator excluded one endpoint of an allowed host).

    Args:
        scope: the session registry holding the marked records.

    Returns:
        The layer-1 check callable for :func:`default_invariants`.
    """

    def check(tool_name: str, tool_args: Mapping[str, object]) -> str | None:
        """Deny requests to marked out-of-scope endpoint records."""
        method = _method_of_call(tool_name, tool_args)
        for url in _url_candidates(tool_args):
            reason = scope.out_of_scope_reason(url, method)
            if reason is not None:
                return reason
        return None

    return check


def session_invariants(
    scope: ScopeRegistry, limiter: ResourceLimiter
) -> tuple[Invariant, ...]:
    """Assemble the full layer-1 set with the real P2.1 checks (T2.1.3).

    The engine wiring one-stop: equivalent to :func:`default_invariants`
    with every slot filled from ``scope``/``limiter``. Evaluation order
    stays the canonical one (platform-http → scope → limits → timeout →
    out-of-scope-target), and every denial reports ``layer="invariant"``.

    Args:
        scope: the session allowlist (arch §6.3).
        limiter: the session-global limiter (arch §6.4).

    Returns:
        The invariant rules for :class:`InvariantLayer`.
    """
    return default_invariants(
        scope_check=scope_invariant_check(scope),
        limits_check=limits_invariant_check(limiter),
        timeout_check=timeout_invariant_check(limiter),
        out_of_scope_target_check=out_of_scope_target_invariant_check(scope),
    )


class Invariant(NamedTuple):
    """One layer-1 rule: a prefixed id plus its check callable."""

    invariant_id: str  # always INVARIANT_PREFIX + short name
    description: str
    check: InvariantCheck


def _prefixed(name: str) -> str:
    """Build the canonical ``invariant:<name>`` id (arch §5.1)."""
    return f"{INVARIANT_PREFIX}{name}"


def default_invariants(
    *,
    scope_check: InvariantCheck | None = None,
    limits_check: InvariantCheck | None = None,
    timeout_check: InvariantCheck | None = None,
    out_of_scope_target_check: InvariantCheck | None = None,
) -> tuple[Invariant, ...]:
    """Assemble the layer-1 invariant set (arch §6.5, T2.1.3 slots).

    ``platform-http`` is active from M1. The other four slots are injected
    callables — pass the real checks from ``tools.scope``/``tools.limits``
    in P2.1; until then they default to inert (always-allow) placeholders.
    The set is built by the engine wiring and is never user-configurable.

    Args:
        scope_check: scope allowlist check (slot, T2.1.3).
        limits_check: resource-limiter check (slot, T2.1.3).
        timeout_check: per-call timeout budget check (slot, T2.1.3).
        out_of_scope_target_check: session-target allowlist check (slot, T2.1.3).

    Returns:
        The invariant rules in evaluation order (platform-http first).
    """
    return (
        Invariant(
            invariant_id=_prefixed("platform-http"),
            description="network calls only via the platform HTTP client",
            check=platform_http_check,
        ),
        Invariant(
            invariant_id=_prefixed("scope"),
            description="target allowlist (slot, real check lands in T2.1.3)",
            check=scope_check if scope_check is not None else _inert_check,
        ),
        Invariant(
            invariant_id=_prefixed("limits"),
            description="resource limiters (slot, real check lands in T2.1.3)",
            check=limits_check if limits_check is not None else _inert_check,
        ),
        Invariant(
            invariant_id=_prefixed("timeout"),
            description="call timeout budget (slot, real check lands in T2.1.3)",
            check=timeout_check if timeout_check is not None else _inert_check,
        ),
        Invariant(
            invariant_id=_prefixed("out-of-scope-target"),
            description="session-target allowlist (slot, real check lands in T2.1.3)",
            check=out_of_scope_target_check
            if out_of_scope_target_check is not None
            else _inert_check,
        ),
    )


class InvariantLayer:
    """Evaluator of the layer-1 invariant set (arch §6.5).

    Iterates the invariants in their fixed order and returns the feedback of
    the first denial; an invariant deny is final — no other layer can unblock
    it (D11).
    """

    __slots__ = ("_invariants",)

    def __init__(self, invariants: Sequence[Invariant]) -> None:
        """Bind the invariant rules (see :func:`default_invariants`)."""
        for invariant in invariants:
            if not invariant.invariant_id.startswith(INVARIANT_PREFIX):
                msg = f"invariant id must be prefixed {INVARIANT_PREFIX!r}: {invariant.invariant_id!r}"
                raise ValueError(msg)
        self._invariants = tuple(invariants)

    @property
    def ids(self) -> tuple[str, ...]:
        """All invariant ids in evaluation order (diagnostics/tests)."""
        return tuple(invariant.invariant_id for invariant in self._invariants)

    def evaluate(self, tool_name: str, tool_args: Mapping[str, object]) -> BlockedFeedback | None:
        """Run every invariant; first denial becomes the layer-1 feedback.

        Args:
            tool_name: name of the tool being called.
            tool_args: arguments of the call.

        Returns:
            ``BlockedFeedback`` with the invariant id and reason, or ``None``
            when every invariant allows the call.
        """
        for invariant in self._invariants:
            reason = invariant.check(tool_name, tool_args)
            if reason is not None:
                return BlockedFeedback(
                    rule_id=invariant.invariant_id, layer="invariant", reason=reason
                )
        return None

    def __iter__(self) -> Iterator[Invariant]:
        """Iterate the invariant rules (diagnostics)."""
        return iter(self._invariants)


__all__ = [
    "INVARIANT_PREFIX",
    "NETWORK_ARG_HINTS",
    "PLATFORM_HTTP_TOOLS",
    "URL_ARG_KEYS",
    "Invariant",
    "InvariantCheck",
    "InvariantLayer",
    "default_invariants",
    "limits_invariant_check",
    "out_of_scope_target_invariant_check",
    "platform_http_check",
    "scope_invariant_check",
    "session_invariants",
    "timeout_invariant_check",
]
