"""``SwarmyHttpClient`` pipeline tests on ``httpx.MockTransport`` (T2.2.2).

Every roadmap AC of the client: per-hop scope/limits re-checks (redirect
spy + budget counter), timeout → agent feedback + ``invariant: timeout``
journal event (through a **real** ``JournalWriter``), outbound-secret warn
(non-blocking, masked preview), out-of-scope calls never opening a
connection, manual redirect depth limit, and the cross-domain out-of-scope
redirect block.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest

from swarmy.guardrails.models import GuardrailBlocked
from swarmy.tools.http.models import RequestSpec
from swarmy.tools.limits import ResourceLimiter

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from tests.unit.tools.http.conftest import EventSpy, EvidenceSpy, JournalBlockedEvents

    from swarmy.events.journal import JournalReader
    from swarmy.tools.http.client import SwarmyHttpClient

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
    assert excinfo.value.feedback.rule_id == "invariant: scope"
    assert [str(call.url) for call in calls] == [f"{base_url}/"]  # evil host never called
    assert limiter.budget_used == 1  # the blocked hop consumed no budget
    assert event_spy.blocked[0].rule_id == "invariant: scope"


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
    assert excinfo.value.feedback.rule_id == "invariant: limits"
    assert "max_redirect_depth" in excinfo.value.feedback.reason
    assert [call.url.path for call in calls] == ["/a", "/b"]  # /c was never sent
    assert shallow.budget_used == 2


async def test_timeout_returns_feedback_and_journals_invariant_timeout(
    make_client: ClientFactory,
    base_url: str,
    journal_events: JournalBlockedEvents,
    journal_env: tuple[object, object, JournalReader],
) -> None:
    """Timeout: textual feedback to the agent + ``invariant: timeout`` in the journal."""
    client = make_client(transport=timeout_transport(base_url), events=journal_events)
    outcome = await client.request(
        RequestSpec(method="GET", url=f"{base_url}/slow"), tool_name="http_get"
    )
    assert isinstance(outcome, str)  # textual feedback; no raw exception escapes
    assert "invariant: timeout" in outcome
    assert "NOT executed" in outcome
    _database, _writer, reader = journal_env
    envelopes = await reader.tail(10)
    payloads = [envelope.payload for envelope in envelopes if envelope.type == "GuardrailBlocked"]
    assert payloads, "the timeout must be journaled as GuardrailBlocked"
    assert payloads[-1].rule_id == "invariant: timeout"
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
    """A spent budget refuses the call with the ``invariant: budget`` rule."""
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
    assert "invariant: budget" in excinfo.value.feedback.reason  # the budget rule inside
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
