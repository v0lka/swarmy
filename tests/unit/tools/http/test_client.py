"""``SwarmyHttpClient`` pipeline tests on ``httpx.MockTransport`` (T2.2.2).

Every roadmap AC of the client: per-hop scope/limits re-checks (redirect
spy + budget counter), timeout → agent feedback + ``invariant:timeout``
journal event (through a **real** ``JournalWriter``), outbound-secret warn
(non-blocking, masked preview), out-of-scope calls never opening a
connection, manual redirect depth limit, and the cross-domain out-of-scope
redirect block.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import httpx
import pytest
from tests.unit.tools.http.conftest import LIMITS, EventSpy, make_scope

from swarmy.core.config import SecretsConfig
from swarmy.guardrails.invariants import InvariantLayer, session_invariants
from swarmy.guardrails.models import (
    GuardrailBlocked,
    GuardrailRule,
    ModuleGuardrails,
    RuleCondition,
)
from swarmy.guardrails.pipeline import GuardrailPipeline
from swarmy.tools.http.client import SwarmyHttpClient
from swarmy.tools.http.models import RequestSpec
from swarmy.tools.limits import ResourceLimiter
from swarmy.tools.projector import ContextProjector
from swarmy.tools.scope import ScopeEntries, ScopeRegistry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from tests.unit.tools.http.conftest import EvidenceSpy, JournalBlockedEvents

    from swarmy.events.journal import JournalReader

    ClientFactory = Callable[..., SwarmyHttpClient]
    TransportFactory = Callable[..., httpx.MockTransport]
    RedirectFactory = Callable[[int, str], httpx.Response]


def timeout_transport(base_url: str) -> httpx.MockTransport:
    """Transport whose handler always raises a read timeout."""
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        raise httpx.ReadTimeout("read timed out", request=httpx.Request("GET", base_url))

    return httpx.MockTransport(handler)


async def test_out_of_scope_call_never_opens_connection(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    default_limits: object,
    event_spy: EventSpy,
    evidence_spy: EvidenceSpy,
) -> None:
    """A pipeline deny happens before the transport: no call, no budget spent."""
    calls: list[httpx.Request] = []
    limiter = ResourceLimiter(default_limits)  # type: ignore[arg-type]
    client = make_client(transport=make_transport({}, calls), limiter_override=limiter)
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(
            RequestSpec(method="GET", url="http://other.example.org/"), tool_name="http_get"
        )
    assert excinfo.value.feedback.rule_id == "invariant:scope"  # layer-1 slot id (arch §6.5)
    assert calls == []  # no connection was ever attempted
    assert limiter.budget_used == 0  # invariants fire before ResourceLimiter.acquire
    assert event_spy.blocked
    assert event_spy.blocked[0].rule_id == "invariant:scope"
    assert event_spy.blocked[0].layer == "invariant"
    assert evidence_spy.calls == []  # a blocked call leaves no evidence


async def test_redirect_chain_rechecks_scope_and_limits_per_hop(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
    default_limits: object,
    evidence_spy: EvidenceSpy,
) -> None:
    """Every hop passes scope + limiter again (budget counts hops, not calls)."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {
            "/": redirect_response(302, "/step2"),
            "/step2": redirect_response(302, "/step3"),
            "/step3": httpx.Response(200, text="final-body"),
        },
        calls,
    )
    limiter = ResourceLimiter(default_limits)  # type: ignore[arg-type]
    client = make_client(transport=transport, limiter_override=limiter)
    record = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
    )
    assert not isinstance(record, str)
    assert record.status == 200
    assert record.redirects == [f"{base_url}/step2", f"{base_url}/step3"]
    assert "final-body" in record.body_preview
    assert [str(call.url) for call in calls] == [
        f"{base_url}/",
        f"{base_url}/step2",
        f"{base_url}/step3",
    ]
    assert limiter.budget_used == 3  # each hop acquired its own slot (arch §6.4)
    # Evidence: one unit for the call; request head + final response recorded.
    assert len(evidence_spy.calls) == 1
    first = evidence_spy.calls[0]
    assert first["tool"] == "http_get"
    assert first["include_response"] is True
    assert b"GET / HTTP/1.1" in first["request_head"]
    assert first["response_body"] == b"final-body"
    assert record.evidence_id == 1
    assert record.request_id


async def test_cross_domain_redirect_out_of_scope_is_blocked(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
    default_limits: object,
    event_spy: EventSpy,
) -> None:
    """A redirect leaving the allowlist is a scope block, never contacted."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {"/": redirect_response(302, "http://evil.example.org/next")}, calls
    )
    limiter = ResourceLimiter(default_limits)  # type: ignore[arg-type]
    client = make_client(transport=transport, limiter_override=limiter)
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(
            RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
        )
    assert excinfo.value.feedback.rule_id == "invariant:scope"
    assert [str(call.url) for call in calls] == [f"{base_url}/"]  # evil host never called
    assert limiter.budget_used == 1  # the blocked hop consumed no budget
    assert event_spy.blocked[0].rule_id == "invariant:scope"


async def test_manual_redirect_depth_limit(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
    default_limits: object,
) -> None:
    """Exceeding ``max_redirect_depth`` blocks before the next hop is sent."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {
            "/a": redirect_response(302, "/b"),
            "/b": redirect_response(302, "/c"),
            "/c": httpx.Response(200, text="never"),
        },
        calls,
    )
    shallow_limits = default_limits.model_copy(update={"max_redirect_depth": 1})
    shallow = ResourceLimiter(shallow_limits)
    client = make_client(transport=transport, limiter_override=shallow)
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(
            RequestSpec(method="GET", url=f"{base_url}/a"), tool_name="http_get"
        )
    assert excinfo.value.feedback.rule_id == "invariant:limits"
    assert "max_redirect_depth" in excinfo.value.feedback.reason
    assert [call.url.path for call in calls] == ["/a", "/b"]  # /c was never sent
    assert shallow.budget_used == 2


async def test_timeout_returns_feedback_and_journals_invariant_timeout(
    make_client: ClientFactory,
    base_url: str,
    journal_events: JournalBlockedEvents,
    journal_env: tuple[object, object, JournalReader],
) -> None:
    """Timeout: textual feedback to the agent + ``invariant:timeout`` in the journal."""
    client = make_client(transport=timeout_transport(base_url), events=journal_events)
    outcome = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/slow"), tool_name="http_get"
    )
    assert isinstance(outcome, str)  # textual feedback; no raw exception escapes
    assert "invariant:timeout" in outcome
    assert "NOT executed" in outcome
    _database, _writer, reader = journal_env
    envelopes = await reader.tail(10)
    payloads = [envelope.payload for envelope in envelopes if envelope.type == "GuardrailBlocked"]
    assert payloads, "the timeout must be journaled as GuardrailBlocked"
    assert payloads[-1].rule_id == "invariant:timeout"
    assert payloads[-1].layer == "invariant"
    assert payloads[-1].tool_name == "http_get"


async def test_outbound_secret_warns_but_proceeds_and_masks(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    event_spy: EventSpy,
) -> None:
    """A secret in outgoing headers: warn event, call proceeds, preview masked."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {"/": httpx.Response(200, text="echo token sekret-value-123 echoed")}, calls
    )
    client = make_client(transport=transport)
    spec = RequestSpec(
        method="GET", url=f"{base_url}/", headers={"Authorization": "Bearer sekret-value-123"}
    )
    record = await client.request(spec, tool_name="http_get")
    assert not isinstance(record, str)
    assert record.status == 200
    assert len(calls) == 1  # the warn never blocks the call
    assert len(event_spy.warns) == 1
    warn = event_spy.warns[0]
    assert warn.secret_names == ["api_key"]
    assert "header:authorization" in warn.locations
    assert "<masked:api_key>" in record.body_preview
    assert "sekret-value-123" not in record.body_preview


async def test_outbound_secret_in_body_also_warns(
    make_client: ClientFactory, make_transport: TransportFactory, base_url: str, event_spy: EventSpy
) -> None:
    """A secret inside the request body is detected the same way."""
    calls: list[httpx.Request] = []
    transport = make_transport({"/login": httpx.Response(200, text="ok")}, calls)
    client = make_client(transport=transport)
    spec = RequestSpec(method="POST", url=f"{base_url}/login", body="password=sekret-value-123")
    record = await client.request(spec, tool_name="http_post")
    assert not isinstance(record, str)
    assert len(event_spy.warns) == 1
    assert event_spy.warns[0].locations == ["body"]
    assert len(calls) == 1


async def test_evidence_disabled_keeps_no_evidence(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    evidence_spy: EvidenceSpy,
) -> None:
    """``evidence=False`` records nothing and links no evidence id."""
    calls: list[httpx.Request] = []
    transport = make_transport({"/": httpx.Response(200, text="fine")}, calls)
    client = make_client(transport=transport)
    spec = RequestSpec(method="GET", url=f"{base_url}/", evidence=False)
    record = await client.request(spec, tool_name="http_get")
    assert not isinstance(record, str)
    assert evidence_spy.calls == []
    assert record.evidence_id is None


async def test_budget_exhaustion_becomes_guardrail_block(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    default_limits: object,
    event_spy: EventSpy,
) -> None:
    """A spent budget refuses the call with the ``invariant:budget`` rule."""
    calls: list[httpx.Request] = []
    transport = make_transport({"/": httpx.Response(200, text="ok")}, calls)
    tiny = ResourceLimiter(default_limits.model_copy(update={"total_request_budget": 1}))
    client = make_client(transport=transport, limiter_override=tiny)
    first = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
    )
    assert not isinstance(first, str)
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(
            RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
        )
    assert excinfo.value.feedback.rule_id == "invariant:limits"  # layer-1 slot id
    assert "invariant:budget" in excinfo.value.feedback.reason  # the budget rule inside
    assert len(calls) == 1
    assert event_spy.blocked[0].rule_id == "invariant:limits"  # journal-first publish


async def test_evidence_head_carries_single_http_prefix(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    evidence_spy: EvidenceSpy,
) -> None:
    """httpx reports versions pre-prefixed ('HTTP/1.1') — the head must not double it."""
    calls: list[httpx.Request] = []
    transport = make_transport({"/": httpx.Response(200, text="ok")}, calls)
    client = make_client(transport=transport)
    record = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
    )
    assert not isinstance(record, str)
    head = evidence_spy.calls[0]["response_head"]
    assert isinstance(head, bytes)
    assert head.startswith(b"HTTP/1.1 200 ")
    assert b"HTTP/HTTP/" not in head


async def test_reader_cutoff_reports_exact_dropped_bytes_when_declared(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    default_limits: object,
    evidence_spy: EvidenceSpy,
) -> None:
    """A declared Content-Length gives the §6.4 cutoff an exact dropped count."""
    calls: list[httpx.Request] = []
    body = b"A" * 100
    transport = make_transport(
        {"/": httpx.Response(200, content=body, headers={"Content-Length": "100"})}, calls
    )
    tiny = ResourceLimiter(default_limits.model_copy(update={"max_body_bytes": 16}))
    client = make_client(transport=transport, limiter_override=tiny)
    record = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
    )
    assert not isinstance(record, str)
    assert record.body_bytes == 100  # declared size, not the kept prefix
    first = evidence_spy.calls[0]
    assert first["response_truncated"] is True
    assert first["response_dropped_bytes"] == 84
    assert first["response_body"] == b"A" * 16


async def test_reader_cutoff_unknown_total_size_reports_none(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    default_limits: object,
    evidence_spy: EvidenceSpy,
) -> None:
    """A streaming body has no total size — dropped stays None, never invented."""
    calls: list[httpx.Request] = []

    async def stream() -> AsyncIterator[bytes]:
        yield b"x" * 10
        yield b"y" * 10

    transport = make_transport({"/": httpx.Response(200, content=stream())}, calls)
    tiny = ResourceLimiter(default_limits.model_copy(update={"max_body_bytes": 16}))
    client = make_client(transport=transport, limiter_override=tiny)
    record = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
    )
    assert not isinstance(record, str)
    first = evidence_spy.calls[0]
    assert first["response_truncated"] is True
    assert first["response_dropped_bytes"] is None
    assert first["response_body"] == b"x" * 10 + b"y" * 6


# ---- Issue #10 ↔ F-16: blocked/timeout digests are masked ----


async def test_blocked_digest_masks_operator_secret(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
    event_spy: EventSpy,
) -> None:
    """A deny of a credentialed call journals a masked digest, never the secret.

    The redirect leaves the allowlist — a routine deny of exactly the call
    that carries the credential in its headers. Before the fix the raw
    ``Authorization`` value landed verbatim in the journal event.
    """
    calls: list[httpx.Request] = []
    transport = make_transport({"/": redirect_response(302, "http://evil.example.org/next")}, calls)
    client = make_client(transport=transport)
    spec = RequestSpec(
        method="GET",
        url=f"{base_url}/",
        headers={"Authorization": "Bearer sekret-value-123"},
        query={"token": "sekret-value-123"},
    )
    with pytest.raises(GuardrailBlocked):
        await client.request(spec, tool_name="http_get")
    assert len(event_spy.blocked) == 1
    digest = event_spy.blocked[0].tool_args_digest
    assert "sekret-value-123" not in digest
    assert "<masked:api_key>" in digest


async def test_timeout_digest_masks_operator_secret(
    make_client: ClientFactory,
    base_url: str,
    journal_events: JournalBlockedEvents,
    journal_env: tuple[object, object, JournalReader],
) -> None:
    """A timeout of a credentialed call journals the masked digest too."""
    client = make_client(transport=timeout_transport(base_url), events=journal_events)
    spec = RequestSpec(
        method="GET",
        url=f"{base_url}/slow",
        headers={"Authorization": "Bearer sekret-value-123"},
    )
    outcome = await client.request(spec, tool_name="http_get")
    assert isinstance(outcome, str)
    _database, _writer, reader = journal_env
    envelopes = await reader.tail(10)
    payloads = [envelope.payload for envelope in envelopes if envelope.type == "GuardrailBlocked"]
    assert payloads, "the timeout must be journaled as GuardrailBlocked"
    digest = payloads[-1].tool_args_digest
    assert "sekret-value-123" not in digest
    assert "<masked:api_key>" in digest


def transport_error_transport(base_url: str) -> httpx.MockTransport:
    """Transport whose handler always fails at the connection layer."""
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        # The message deliberately embeds a credential-looking string: the
        # structured feedback must carry only the exception *type* name, so
        # no part of the raw exception text can reach journal or agent.
        raise httpx.ConnectError(
            "connection refused while dialing with sekret-value-123",
            request=httpx.Request("GET", base_url),
        )

    return httpx.MockTransport(handler)


async def test_transport_error_journals_invariant_transport(
    make_client: ClientFactory,
    base_url: str,
    journal_events: JournalBlockedEvents,
    journal_env: tuple[object, object, JournalReader],
) -> None:
    """Entry #34: a non-timeout transport failure takes the timeout contour.

    ``ConnectError`` (an ``httpx.HTTPError`` that is not a
    ``TimeoutException``) returns the structured feedback text and journals
    ``GuardrailBlocked`` under ``invariant:transport`` with the masked
    digest — and no raw exception text (with its embedded secret) escapes.
    """
    client = make_client(transport=transport_error_transport(base_url), events=journal_events)
    outcome = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/refused"), tool_name="http_get"
    )
    assert isinstance(outcome, str)  # textual feedback; no raw exception escapes
    assert "invariant:transport" in outcome
    assert "NOT executed" in outcome
    assert "sekret-value-123" not in outcome  # exception message never rendered
    _database, _writer, reader = journal_env
    envelopes = await reader.tail(10)
    payloads = [envelope.payload for envelope in envelopes if envelope.type == "GuardrailBlocked"]
    assert payloads, "the transport failure must be journaled as GuardrailBlocked"
    assert payloads[-1].rule_id == "invariant:transport"
    assert payloads[-1].layer == "invariant"
    assert payloads[-1].tool_name == "http_get"
    assert "sekret-value-123" not in payloads[-1].reason
    assert "sekret-value-123" not in payloads[-1].tool_args_digest


async def test_transport_error_of_credentialed_call_masks_digest(
    make_client: ClientFactory,
    base_url: str,
    journal_events: JournalBlockedEvents,
    journal_env: tuple[object, object, JournalReader],
) -> None:
    """A transport failure of a credentialed call journals the masked digest."""
    client = make_client(transport=transport_error_transport(base_url), events=journal_events)
    spec = RequestSpec(
        method="GET",
        url=f"{base_url}/refused",
        headers={"Authorization": "Bearer sekret-value-123"},
        query={"token": "sekret-value-123"},
    )
    outcome = await client.request(spec, tool_name="http_get")
    assert isinstance(outcome, str)
    _database, _writer, reader = journal_env
    envelopes = await reader.tail(10)
    payloads = [envelope.payload for envelope in envelopes if envelope.type == "GuardrailBlocked"]
    assert payloads, "the transport failure must be journaled as GuardrailBlocked"
    digest = payloads[-1].tool_args_digest
    assert "sekret-value-123" not in digest
    assert "<masked:api_key>" in digest


async def test_outbound_secret_in_query_warns(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    event_spy: EventSpy,
) -> None:
    """A credential pasted into a query parameter fires the hygiene warn."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {"/": httpx.Response(200, text="echo sekret-value-123 done")}, calls
    )
    client = make_client(transport=transport)
    spec = RequestSpec(method="GET", url=f"{base_url}/", query={"token": "sekret-value-123"})
    record = await client.request(spec, tool_name="http_get")
    assert not isinstance(record, str)
    assert len(calls) == 1  # warn-not-block: the call proceeds
    assert len(event_spy.warns) == 1
    warn = event_spy.warns[0]
    assert warn.secret_names == ["api_key"]
    assert warn.locations == ["query:token"]
    assert "<masked:api_key>" in record.body_preview  # preview masks the reflected value


# ---- Issue #31: request bodies are capped before the first hop ----


async def test_oversized_request_body_is_denied_before_the_network(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    base_url: str,
    default_limits: object,
    event_spy: EventSpy,
    evidence_spy: EvidenceSpy,
) -> None:
    """A body beyond ``max_body_bytes`` is a limiter deny, not a flood."""
    calls: list[httpx.Request] = []
    limiter = ResourceLimiter(default_limits)  # type: ignore[arg-type]
    client = make_client(transport=make_transport({}, calls), limiter_override=limiter)
    spec = RequestSpec(method="POST", url=f"{base_url}/upload", body="B" * 2048)
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(spec, tool_name="http_post")
    assert excinfo.value.feedback.rule_id == "invariant:limits"
    assert "max_body_bytes" in excinfo.value.feedback.reason
    assert calls == []  # no byte reached the transport
    assert limiter.budget_used == 0  # the denied call spent nothing
    assert evidence_spy.calls == []  # a blocked call leaves no evidence


async def test_request_body_at_the_limit_is_sent(
    make_client: ClientFactory, make_transport: TransportFactory, base_url: str
) -> None:
    """A body exactly at the threshold passes (deny is strictly ``>``)."""
    calls: list[httpx.Request] = []
    transport = make_transport({"/upload": httpx.Response(200, text="ok")}, calls)
    client = make_client(transport=transport)
    body = "B" * 1024  # == max_body_bytes of the test limits
    record = await client.request(
        RequestSpec(method="POST", url=f"{base_url}/upload", body=body), tool_name="http_post"
    )
    assert not isinstance(record, str)
    assert record.status == 200
    assert calls[0].read() == body.encode()


# ---- F-7: engine/module rules are re-evaluated on redirect hops ----


def _legacy_deny_rule() -> GuardrailRule:
    """Operator-style rule denying any URL carrying ``legacy-api``."""
    return GuardrailRule(
        id="deny-legacy-api",
        applies_to=["http_get", "http_post"],
        condition=RuleCondition(url_matches="legacy-api"),
        action="block",
        severity="high",
        message="the legacy API is outside this engagement's mandate",
    )


async def test_redirect_hop_reevaluates_engine_rules(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
    event_spy: EventSpy,
) -> None:
    """A target-controlled hop into a rule-denied path is blocked, not followed."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {"/": redirect_response(302, f"{base_url}/legacy-api/export"), "/legacy-api/export": httpx.Response(200, text="x")},
        calls,
    )
    pipeline = GuardrailPipeline(
        invariants=InvariantLayer(session_invariants(make_scope(), ResourceLimiter(LIMITS))),
        engine_rules=[_legacy_deny_rule()],
    )
    client = make_client(transport=transport, pipeline_override=pipeline)
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get")
    assert excinfo.value.feedback.rule_id == "deny-legacy-api"
    assert excinfo.value.feedback.layer == "engine"
    assert [call.url.path for call in calls] == ["/"]  # the denied hop was never sent
    assert event_spy.blocked[0].rule_id == "deny-legacy-api"


async def test_redirect_hop_rules_follow_the_rewritten_method(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
) -> None:
    """A 303 rewrite POST→GET re-evaluates the hop under ``http_get`` rules.

    The rule denies the landing URL for ``http_post`` only: if the hop were
    still judged under the original tool name, the rewritten GET would be
    denied — the hop must be evaluated under its own implied tool.
    """
    calls: list[httpx.Request] = []
    transport = make_transport(
        {"/form": redirect_response(303, f"{base_url}/done"), "/done": httpx.Response(200, text="done")}, calls
    )
    post_only_rule = GuardrailRule(
        id="deny-post-landing",
        applies_to=["http_post"],
        condition=RuleCondition(url_matches="done"),
        action="block",
        severity="high",
        message="landing pages are read-only (GET)",
    )
    pipeline = GuardrailPipeline(
        invariants=InvariantLayer(session_invariants(make_scope(), ResourceLimiter(LIMITS))),
        engine_rules=[post_only_rule],
    )
    client = make_client(transport=transport, pipeline_override=pipeline)
    record = await client.request(
        RequestSpec(method="POST", url=f"{base_url}/form", body="a=1"), tool_name="http_post"
    )
    assert not isinstance(record, str)
    assert record.status == 200
    assert [call.method for call in calls] == ["POST", "GET"]  # the rewrite happened


async def test_redirect_hop_module_rules_fire_per_hop(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
) -> None:
    """Module-level rules (layer 3) are part of the per-hop re-evaluation."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {"/": redirect_response(302, f"{base_url}/legacy-api/x"), "/legacy-api/x": httpx.Response(200, text="x")}, calls
    )
    module_rule = GuardrailRule(
        id="module-no-legacy",
        applies_to=["http_get"],
        condition=RuleCondition(url_matches="legacy-api"),
        action="block",
        severity="medium",
        message="module rules out the legacy surface",
    )
    pipeline = GuardrailPipeline(
        invariants=InvariantLayer(session_invariants(make_scope(), ResourceLimiter(LIMITS))),
        module_guardrails=ModuleGuardrails(rules=[module_rule]),
    )
    client = make_client(transport=transport, pipeline_override=pipeline)
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get")
    assert excinfo.value.feedback.rule_id == "module-no-legacy"
    assert excinfo.value.feedback.layer == "module"


# ---- Issue #42: per-hop raw traffic in evidence ----


async def test_redirect_chain_records_every_hop_pair(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    redirect_response: RedirectFactory,
    base_url: str,
    evidence_spy: EvidenceSpy,
) -> None:
    """Each hop's exchanged request/response pair rides the evidence record."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {
            "/": redirect_response(302, "/step2"),
            "/step2": redirect_response(302, "/step3"),
            "/step3": httpx.Response(200, text="final-body"),
        },
        calls,
    )
    client = make_client(transport=transport)
    record = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/"), tool_name="http_get"
    )
    assert not isinstance(record, str)
    assert len(evidence_spy.calls) == 1  # one evidence unit for the call
    hops = evidence_spy.calls[0]["hops"]
    assert isinstance(hops, list)
    assert len(hops) == 3  # every hop, redirecting ones and the final one
    hop1, hop2, hop3 = hops  # type: ignore[misc]
    assert hop1.hop == 1
    assert b"GET / HTTP/1.1" in hop1.request_head
    assert b"HTTP/1.1 302" in hop1.response_head
    assert hop2.hop == 2
    assert b"GET /step2" in hop2.request_head
    assert b"HTTP/1.1 302" in hop2.response_head
    assert hop3.hop == 3
    assert b"GET /step3" in hop3.request_head  # the final hop's rewritten request line
    assert b"HTTP/1.1 200" in hop3.response_head
    assert hop3.response_body == b"final-body"
    # The call summary semantics of the top-level files are unchanged.
    first = evidence_spy.calls[0]
    assert b"GET / HTTP/1.1" in first["request_head"]  # type: ignore[operator]
    assert first["response_body"] == b"final-body"


# ---- DNS-rebinding guard (F-11): resolved-IP verification + session pin ----


class _ScriptedResolver:
    """Structural ``HostResolver`` with scripted per-host resolutions (F-11).

    Mirrors the ``HostResolver`` protocol of ``tools.http.client``; tests
    inject it instead of the production ``GetaddrinfoHostResolver`` so the
    pin semantics are deterministic (no real DNS in unit tests).
    """

    def __init__(self, resolutions: dict[str, tuple[str, ...]]) -> None:
        self._resolutions = resolutions
        self.calls: list[str] = []

    def rebind(self, host: str, addresses: tuple[str, ...]) -> None:
        """Swap the resolution of ``host`` mid-test (the rebinding event)."""
        self._resolutions[host] = addresses

    async def resolve(self, host: str) -> tuple[str, ...]:
        """Return the scripted addresses of ``host`` (empty = unresolvable)."""
        self.calls.append(host)
        return self._resolutions.get(host, ())


def _pin_client(
    make_transport: TransportFactory,
    default_limits: object,
    resolver: _ScriptedResolver | None,
    evidence_spy: EvidenceSpy,
    scope: ScopeRegistry | None = None,
    calls: list[httpx.Request] | None = None,
    events: EventSpy | None = None,
) -> SwarmyHttpClient:
    """Build a client with the rebinding guard wired (F-11 test seam).

    Standalone construction (not the ``make_client`` fixture): the guard is
    opt-in via ``host_resolver``, mirroring the production wiring in
    ``core.session`` which passes :class:`GetaddrinfoHostResolver`.
    """
    effective_scope = scope if scope is not None else make_scope()
    limiter = ResourceLimiter(default_limits)  # type: ignore[arg-type]
    return SwarmyHttpClient(
        scope=effective_scope,
        limiter=limiter,
        pipeline=GuardrailPipeline(
            invariants=InvariantLayer(session_invariants(effective_scope, limiter))
        ),
        projector=ContextProjector(),
        secrets=SecretsConfig(),
        evidence=evidence_spy,
        events=events if events is not None else EventSpy(),
        transport=make_transport(
            {"/": httpx.Response(200, text="ok")}, calls if calls is not None else []
        ),
        host_resolver=resolver,
    )


async def test_resolved_ip_outside_subnets_blocks_the_hop(
    make_transport: TransportFactory,
    event_spy: EventSpy,
    evidence_spy: EvidenceSpy,
    default_limits: object,
) -> None:
    """An allowlisted name resolving outside ``ip_subnets`` is denied (F-11).

    CWE-350: the scope matched the *name*, but the address the resolver
    returns belongs to nobody's allowlist — the hop dies pre-connect under
    ``invariant: host-pin``.
    """
    calls: list[httpx.Request] = []
    resolver = _ScriptedResolver({"app.example.com": ("198.51.100.9",)})
    client = _pin_client(
        make_transport,
        default_limits,
        resolver,
        scope=ScopeRegistry(
            ScopeEntries(domains=["example.com"], ip_subnets=["203.0.113.0/24"])
        ),
        calls=calls,
        events=event_spy,
        evidence_spy=evidence_spy,
    )
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert excinfo.value.feedback.rule_id == "invariant:host-pin"
    assert "198.51.100.9" in excinfo.value.feedback.reason
    assert "203.0.113.0/24" in excinfo.value.feedback.reason
    assert calls == []  # denied before the transport: no byte was sent
    assert event_spy.blocked[0].rule_id == "invariant:host-pin"


async def test_first_resolution_is_pinned_and_rebinding_denied(
    make_transport: TransportFactory,
    event_spy: EventSpy,
    evidence_spy: EvidenceSpy,
    default_limits: object,
) -> None:
    """A name that stops resolving to its pinned address is denied (F-11).

    The first successful resolution pins the address for the session; the
    second request must still see it among the records — a swapped record
    set (the rebinding attack) denies the hop pre-connect.
    """
    calls: list[httpx.Request] = []
    resolver = _ScriptedResolver({"app.example.com": ("203.0.113.7",)})
    client = _pin_client(
        make_transport,
        default_limits,
        resolver,
        evidence_spy,
        calls=calls,
        events=event_spy,
    )
    record = await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert not isinstance(record, str)
    assert len(calls) == 1  # the pinned first call went through
    # mid-session rebinding: the allowlisted name now answers elsewhere
    resolver.rebind("app.example.com", ("198.51.100.9",))
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert excinfo.value.feedback.rule_id == "invariant:host-pin"
    assert "203.0.113.7" in excinfo.value.feedback.reason  # the pinned address
    assert "198.51.100.9" in excinfo.value.feedback.reason  # the rebound answer
    assert len(calls) == 1  # the rebound hop never reached the transport
    assert event_spy.blocked[0].rule_id == "invariant:host-pin"


async def test_stable_resolution_and_ip_literals_pass_the_guard(
    make_transport: TransportFactory,
    evidence_spy: EvidenceSpy,
    default_limits: object,
) -> None:
    """Stable multi-record resolution stays allowed; IP literals skip DNS.

    Round-robin/CDN names that keep the pinned address among their records
    are normal rotation, not rebinding; a literal host carries no resolution
    to pin (and does not even consult the resolver).
    """
    calls: list[httpx.Request] = []
    resolver = _ScriptedResolver({"app.example.com": ("203.0.113.7", "203.0.113.8")})
    client = _pin_client(
        make_transport,
        default_limits,
        resolver,
        evidence_spy,
        scope=ScopeRegistry(
            ScopeEntries(domains=["example.com"], ip_subnets=["203.0.113.0/24"])
        ),
        calls=calls,
    )
    first = await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    second = await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert not isinstance(first, str)
    assert not isinstance(second, str)
    assert len(calls) == 2
    literal = await client.request(RequestSpec(method="GET", url="http://203.0.113.7/"))
    assert not isinstance(literal, str)
    assert len(calls) == 3
    assert resolver.calls == ["app.example.com", "app.example.com"]  # literal skipped


async def test_unresolvable_and_disabled_guard_skip_the_pin(
    make_transport: TransportFactory,
    evidence_spy: EvidenceSpy,
    default_limits: object,
) -> None:
    """Unresolvable names and ``host_resolver=None`` skip the guard.

    Fail-open only toward *no connection*: an unresolvable name cannot be
    contacted anyway (the mock transport stands in for the failing connect
    here); a client built without a resolver (the injected-transport test
    seam) never resolves at all.
    """
    calls: list[httpx.Request] = []
    resolver = _ScriptedResolver({})  # nothing resolves
    client = _pin_client(
        make_transport,
        default_limits,
        resolver,
        evidence_spy,
        scope=ScopeRegistry(
            ScopeEntries(domains=["example.com"], ip_subnets=["203.0.113.0/24"])
        ),
        calls=calls,
    )
    record = await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert not isinstance(record, str)
    assert resolver.calls == ["app.example.com"]
    # a client without a resolver (test seam) never consults DNS
    bare = _pin_client(make_transport, default_limits, None, evidence_spy, calls=calls)
    bare_record = await bare.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert not isinstance(bare_record, str)
    assert resolver.calls == ["app.example.com"]  # unchanged: no resolution happened


async def test_resolver_timeout_denies_the_hop(
    make_transport: TransportFactory,
    event_spy: EventSpy,
    evidence_spy: EvidenceSpy,
    default_limits: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hung resolver denies the hop — fail closed (review follow-up, F-11).

    A resolution that never returns must not silently skip the rebinding
    guard while the hop proceeds: the timeout is a ``invariant: host-pin``
    deny, not a pass. Only an *unresolvable* name proceeds (nothing can be
    contacted anyway).
    """
    monkeypatch.setattr("swarmy.tools.http.client._RESOLVE_TIMEOUT_S", 0.05)

    class _HangingResolver:
        """Resolver that never answers (the hung-getaddrinfo case)."""

        async def resolve(self, host: str) -> tuple[str, ...]:
            del host
            await asyncio.sleep(30)
            return ()

    calls: list[httpx.Request] = []
    client = _pin_client(
        make_transport,
        default_limits,
        _HangingResolver(),
        evidence_spy,
        calls=calls,
        events=event_spy,
    )
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert excinfo.value.feedback.rule_id == "invariant:host-pin"
    assert "could not verify" in excinfo.value.feedback.reason
    assert calls == []  # denied before the transport: no byte was sent
    assert event_spy.blocked[0].rule_id == "invariant:host-pin"


async def test_connection_targets_the_verified_address(
    make_transport: TransportFactory,
    evidence_spy: EvidenceSpy,
    default_limits: object,
) -> None:
    """The verified address is what the connection actually targets (F-11).

    The check-then-connect gap is closed by pinning: the request URL
    carries the verified IP for the socket while ``Host`` and the
    ``sni_hostname`` extension keep the original name — SNI and
    certificate verification continue to validate the *name*.
    """
    calls: list[httpx.Request] = []
    resolver = _ScriptedResolver({"app.example.com": ("203.0.113.7",)})
    client = _pin_client(
        make_transport,
        default_limits,
        resolver,
        evidence_spy,
        scope=ScopeRegistry(
            ScopeEntries(domains=["example.com"], ip_subnets=["203.0.113.0/24"])
        ),
        calls=calls,
    )
    record = await client.request(
        RequestSpec(method="GET", url="http://app.example.com/a", query={"b": "1"})
    )
    assert not isinstance(record, str)
    assert len(calls) == 1
    assert calls[0].url.host == "203.0.113.7"  # socket destination = verified IP
    assert calls[0].url.path == "/a"  # path preserved
    assert dict(calls[0].url.params) == {"b": "1"}  # query preserved
    assert calls[0].headers["host"] == "app.example.com"  # wire Host = the name
    assert calls[0].extensions["sni_hostname"] == "app.example.com"  # SNI/cert = the name


async def test_pinning_preserves_an_explicit_host_header(
    make_transport: TransportFactory,
    evidence_spy: EvidenceSpy,
    default_limits: object,
) -> None:
    """An operator-authored ``Host`` header survives the pinned hop.

    Header-injection probes must reach the target verbatim: pinning
    changes the socket destination, never the request the operator (or
    the agent) authored — no implicit ``Host`` is injected over it.
    """
    calls: list[httpx.Request] = []
    resolver = _ScriptedResolver({"app.example.com": ("203.0.113.7",)})
    client = _pin_client(
        make_transport,
        default_limits,
        resolver,
        evidence_spy,
        calls=calls,
    )
    record = await client.request(
        RequestSpec(
            method="GET",
            url="http://app.example.com/",
            headers={"Host": "internal.target", "X-Probe": "1"},
        )
    )
    assert not isinstance(record, str)
    assert calls[0].url.host == "203.0.113.7"
    assert calls[0].headers["host"] == "internal.target"  # preserved verbatim
    assert calls[0].extensions["sni_hostname"] == "app.example.com"  # URL name


async def test_failed_connect_falls_through_to_the_next_verified_address(
    make_transport: TransportFactory,
    evidence_spy: EvidenceSpy,
    default_limits: object,
) -> None:
    """A refused connect on one verified address tries the next one.

    Multi-record names (CDN rotation, dual families) stay reachable: every
    address the resolver returned was verified by the guard, so the hop
    may walk the candidate list in resolver order. A refused *connect*
    advances; a timeout would not (the target stalled).
    """
    attempts: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.host)
        if len(attempts) == 1:
            raise httpx.ConnectError("first address refused", request=request)
        return httpx.Response(200, text="ok")

    def factory(routes: object, calls: list[httpx.Request]) -> httpx.MockTransport:
        del routes, calls
        return httpx.MockTransport(handler)

    calls: list[httpx.Request] = []
    resolver = _ScriptedResolver({"app.example.com": ("203.0.113.7", "203.0.113.8")})
    client = _pin_client(factory, default_limits, resolver, evidence_spy, calls=calls)
    record = await client.request(RequestSpec(method="GET", url="http://app.example.com/"))
    assert not isinstance(record, str)
    assert attempts == ["203.0.113.7", "203.0.113.8"]  # both verified candidates tried
    assert "ok" in record.body_preview  # the hop completed on the verified address
