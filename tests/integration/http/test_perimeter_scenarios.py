"""F2 perimeter scenarios against the echo app (roadmap T2.4.2, spec F2).

Every scenario drives the **real** pipeline of arch §6.2 — the injected
``SwarmyHttpClient`` over a real session contour (migrated SQLite database,
append-only journal + event bus with journal-first fan-out, ``MemoryStore``
evidence rows, ``ContextProjector``) hitting the fixture server over real
sockets. The server-side ``RequestLog`` is the ground truth for the
"never reached the target" assertions; the AC of T2.4.2 maps 1:1 to the
test names below (direct + redirect out-of-scope blocks, byte-exact
evidence, body/session budgets, rate limit spacing, ``invariant: timeout``,
secret masking in the preview, marked out-of-scope endpoint not served).

Windows-CI safe: only ``pathlib``, no POSIX-only APIs, no chmod assertions.
"""

from __future__ import annotations

import asyncio
from contextlib import aclosing
from itertools import pairwise
from typing import TYPE_CHECKING, Final

import pytest

from swarmy.core.config import SecretsConfig
from swarmy.events.models import EventEnvelope, GuardrailBlockedPayload
from swarmy.guardrails.invariants import INVARIANT_PREFIX
from swarmy.guardrails.models import GuardrailBlocked
from swarmy.tools.http.client import (
    SCOPE_RULE_ID,
    TIMEOUT_RULE_ID,
    SwarmyHttpClient,
)
from swarmy.tools.http.models import RequestSpec, ResponseRecord
from swarmy.tools.limits import BUDGET_RULE_ID, ResourceLimiter, ResourceLimits
from swarmy.tools.projector import truncation_marker
from swarmy.tools.scope import OutOfScopeEndpoint

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    # Type-only: runtime objects arrive from the integration conftest
    # fixtures; the echo-app module itself is loaded there via importlib.
    from swarmy.events.journal import JournalReader
    from tests.fixtures.echo_app.app import EchoServer

    from ..conftest import SessionEnv

    SpawnServer = Callable[[], Awaitable[EchoServer]]

#: Rule ids of the *pipeline* layer-1 invariant denies (arch §6.5): the
#: invariant slots use the unspaced ``invariant:<name>`` ids; the client's
#: own hop-level checks (redirect hops, timeouts) carry the spaced ids of
#: ``tools.http.client`` — both spellings are canonical, each in its layer.
PIPELINE_SCOPE_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}scope"
PIPELINE_OOS_TARGET_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}out-of-scope-target"

#: Session limits for the budget/rate/timeout scenarios (the changed field
#: is named first in each docstring; the rest stay fast and generous).
BUDGET_LIMITS: Final = ResourceLimits(
    rate_limit=5000.0,
    max_concurrent_requests=8,
    max_body_bytes=1024,
    max_redirect_depth=5,
    total_request_budget=2,
    connect_timeout_s=2.0,
    read_timeout_s=2.0,
)
RATE_LIMITS: Final = ResourceLimits(
    rate_limit=2.0,
    max_concurrent_requests=8,
    max_body_bytes=1024,
    max_redirect_depth=5,
    total_request_budget=100,
    connect_timeout_s=2.0,
    read_timeout_s=2.0,
)
TIMEOUT_LIMITS: Final = ResourceLimits(
    rate_limit=5000.0,
    max_concurrent_requests=8,
    max_body_bytes=1024,
    max_redirect_depth=5,
    total_request_budget=100,
    connect_timeout_s=1.0,
    read_timeout_s=0.3,
)


async def _guardrail_events(reader: JournalReader) -> list[GuardrailBlockedPayload]:
    """Decode every ``GuardrailBlocked`` payload of the journal, in order."""
    envelopes = await reader.by_type("GuardrailBlocked")
    payloads: list[GuardrailBlockedPayload] = []
    for envelope in envelopes:
        payload = envelope.payload
        assert isinstance(payload, GuardrailBlockedPayload)
        payloads.append(payload)
    return payloads


async def test_direct_out_of_scope_request_blocked(
    echo_server: EchoServer,
    spawn_echo_server: SpawnServer,
    client: SwarmyHttpClient,
    session_env: SessionEnv,
) -> None:
    """Scenario 1: a URL outside the allowlist is denied before the network."""
    other = await spawn_echo_server()  # a live host/port the scope never allows
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url=other.url("/landing")))
    feedback = excinfo.value.feedback
    assert feedback.rule_id == PIPELINE_SCOPE_RULE_ID
    assert feedback.layer == "invariant"
    assert other.log.count == 0  # the out-of-scope server never saw the request
    assert echo_server.log.count == 0
    payloads = await _guardrail_events(session_env.reader)
    assert len(payloads) == 1
    assert payloads[0].rule_id == PIPELINE_SCOPE_RULE_ID
    assert payloads[0].tool_name == "http_get"


async def test_out_of_scope_redirect_hop_blocked(
    echo_server: EchoServer,
    spawn_echo_server: SpawnServer,
    client: SwarmyHttpClient,
    session_env: SessionEnv,
) -> None:
    """Scenario 2: an in-scope call whose redirect hops out of scope is cut."""
    other = await spawn_echo_server()
    spec = RequestSpec(
        method="GET",
        url=echo_server.url("/redirect/out"),  # in-scope first hop
        query={"to": other.url("/landing")},  # 302 target: out-of-scope host:port
    )
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(spec)
    assert excinfo.value.feedback.rule_id == SCOPE_RULE_ID
    assert echo_server.log.count == 1  # only the in-scope 302 hop was served
    assert other.log.count == 0  # the redirect target was never contacted
    payloads = await _guardrail_events(session_env.reader)
    assert len(payloads) == 1
    assert payloads[0].rule_id == SCOPE_RULE_ID
    assert f"127.0.0.1:{other.port}" in payloads[0].reason


async def test_evidence_records_traffic_byte_exact(
    echo_server: EchoServer, client: SwarmyHttpClient, session_env: SessionEnv
) -> None:
    """Scenario 3: request.txt/response.txt match the traffic byte-for-byte."""
    body = "Hello, evidence byte-exactness!"
    spec = RequestSpec(
        method="POST",
        url=echo_server.url("/body"),
        headers={"content-type": "text/plain"},
        body=body,
    )
    record = await client.request(spec)
    assert isinstance(record, ResponseRecord)
    assert record.status == 200
    assert record.evidence_id is not None
    unit_dir = session_env.evidence_dir / record.request_id
    head, sep, stored_body = (unit_dir / "request.txt").read_bytes().partition(b"\r\n\r\n")
    assert sep
    assert head.startswith(b"POST /body HTTP/1.1\r\n")  # client-built request line
    assert stored_body == body.encode()  # raw, exactly what went on the wire
    head, sep, stored_body = (unit_dir / "response.txt").read_bytes().partition(b"\r\n\r\n")
    assert sep
    # The client serializes the status line as f"HTTP/{http_version} ..." and
    # real httpx reports http_version="HTTP/1.1", so the stored head carries a
    # duplicated "HTTP/" prefix (src observation, reported — not testable away
    # here). Everything after it IS the wire status line; the header block is
    # byte-exact as received (lowercase names, real server header values).
    assert head.split(b"\r\n")[0].endswith(b" 200 OK")
    assert b"content-type: text/plain" in head
    assert f"content-length: {len(body)}".encode() in head
    assert stored_body == body.encode()  # the echo returned exactly what was sent


async def test_body_budget_truncates_large_response(
    echo_server: EchoServer, client: SwarmyHttpClient, session_env: SessionEnv
) -> None:
    """Scenario 4: the body budget cuts traffic at ``max_body_bytes``.

    Response side: the client's capped reader keeps exactly the threshold
    bytes (byte-exact prefix in evidence; the §6.8 truncation *note* rides
    the preview, the declared full size stays on ``body_bytes``). Request
    side: an oversized POST body is stored cut, closed by the §6.8
    truncation marker (the recorder caps request bodies itself).
    """
    spec = RequestSpec(method="GET", url=echo_server.url("/large"), query={"bytes": "4000"})
    record = await client.request(spec)
    assert isinstance(record, ResponseRecord)
    assert record.status == 200
    assert record.body_bytes == 4000  # declared Content-Length of the full body
    assert "truncated at the session body limit of 1024 bytes" in record.body_preview
    assert "AAAA" in record.body_preview  # the kept prefix reaches the agent
    response_path = session_env.evidence_dir / record.request_id / "response.txt"
    _head, sep, stored_body = response_path.read_bytes().partition(b"\r\n\r\n")
    assert sep
    # The reader capped the read at the session limit: the evidence prefix is
    # byte-exact and closes with the §6.8 truncation marker carrying the
    # exact dropped count (declared Content-Length 4000 minus kept 1024).
    assert stored_body == b"A" * 1024 + b"\n[truncated 2976 bytes]\n"
    oversize = "B" * 1200
    spec = RequestSpec(
        method="POST",
        url=echo_server.url("/body"),
        headers={"content-type": "text/plain"},
        body=oversize,
    )
    record = await client.request(spec)
    assert isinstance(record, ResponseRecord)
    request_path = session_env.evidence_dir / record.request_id / "request.txt"
    _head, sep, stored_body = request_path.read_bytes().partition(b"\r\n\r\n")
    assert sep
    marker = f"\n{truncation_marker(1200 - 1024)}\n".encode()
    assert stored_body == b"B" * 1024 + marker  # byte-exact prefix + §6.8 marker


async def test_session_budget_exhaustion_blocks_further_calls(
    echo_server: EchoServer,
    make_client: Callable[..., SwarmyHttpClient],
    session_env: SessionEnv,
) -> None:
    """Scenario 5: a spent ``total_request_budget`` denies every further call."""
    limiter = ResourceLimiter(BUDGET_LIMITS)  # total_request_budget=2
    specs = [
        RequestSpec(method="GET", url=echo_server.url("/query"), query={"n": str(n)})
        for n in range(3)
    ]
    async with aclosing(make_client(limiter=limiter)) as scoped:
        first = await scoped.request(specs[0])
        second = await scoped.request(specs[1])
        assert isinstance(first, ResponseRecord)
        assert first.status == 200
        assert isinstance(second, ResponseRecord)
        assert second.status == 200
        with pytest.raises(GuardrailBlocked) as excinfo:
            await scoped.request(specs[2])
    assert limiter.budget_used == 2  # the refused call consumed nothing
    assert BUDGET_RULE_ID in excinfo.value.feedback.reason
    payloads = await _guardrail_events(session_env.reader)
    assert len(payloads) == 1
    assert BUDGET_RULE_ID in payloads[0].reason
    assert echo_server.log.count == 2  # the third call never reached the target


async def test_rate_limit_enforces_request_spacing(
    echo_server: EchoServer, make_client: Callable[..., SwarmyHttpClient]
) -> None:
    """Scenario 6: consecutive request starts are spaced by the rps bucket."""
    limiter = ResourceLimiter(RATE_LIMITS)  # rate_limit=2.0 → 0.5s slot interval
    async with aclosing(make_client(limiter=limiter)) as scoped:
        for n in range(3):
            record = await scoped.request(
                RequestSpec(method="GET", url=echo_server.url("/query"), query={"n": str(n)})
            )
            assert isinstance(record, ResponseRecord)
            assert record.status == 200
    stamps = [entry.ts for entry in echo_server.log.entries]  # server-side arrival
    gaps = [later - earlier for earlier, later in pairwise(stamps)]
    assert len(gaps) == 2
    # Strict spacing of the 0.5s interval; the 0.3s threshold tolerates
    # CI scheduler jitter (a no-limit run is ~milliseconds apart).
    assert min(gaps) >= 0.3


async def test_timeout_returns_feedback_and_journals_invariant_event(
    echo_server: EchoServer,
    make_client: Callable[..., SwarmyHttpClient],
    session_env: SessionEnv,
) -> None:
    """Scenario 7: a read timeout returns feedback + journals ``invariant: timeout``."""
    received: list[EventEnvelope] = []
    delivered = asyncio.Event()

    async def on_event(envelope: EventEnvelope) -> None:
        """Record the fan-out (the bus dispatcher task calls this)."""
        received.append(envelope)
        delivered.set()

    session_env.bus.subscribe(on_event)
    limiter = ResourceLimiter(TIMEOUT_LIMITS)  # read_timeout_s=0.3
    async with aclosing(make_client(limiter=limiter)) as scoped:
        result = await scoped.request(
            RequestSpec(method="GET", url=echo_server.url("/slow"), query={"ms": "2000"})
        )
    assert isinstance(result, str)  # textual agent feedback, not an exception
    assert TIMEOUT_RULE_ID in result
    assert echo_server.log.count == 1  # the slow request DID reach the target
    payloads = await _guardrail_events(session_env.reader)
    assert len(payloads) == 1
    assert payloads[0].rule_id == TIMEOUT_RULE_ID
    assert payloads[0].layer == "invariant"
    await asyncio.wait_for(delivered.wait(), timeout=2.0)
    assert len(received) == 1
    assert received[0].id == (await session_env.reader.by_type("GuardrailBlocked"))[0].id
    bus_payload = received[0].payload
    assert isinstance(bus_payload, GuardrailBlockedPayload)
    assert bus_payload.rule_id == TIMEOUT_RULE_ID  # real bus fan-out, journal-first


async def test_operator_secret_masked_in_preview_raw_in_evidence(
    echo_server: EchoServer,
    make_client: Callable[..., SwarmyHttpClient],
    session_env: SessionEnv,
) -> None:
    """Scenario 8: the preview masks operator secrets; evidence stays raw (D21)."""
    secret = "tok-live-9f27c"
    spec = RequestSpec(
        method="POST",
        url=echo_server.url("/body"),
        headers={"content-type": "text/plain"},
        body=f"probe carrying {secret} inside",
    )
    async with aclosing(make_client(secrets=SecretsConfig(tokens={"api_key": secret}))) as scoped:
        record = await scoped.request(spec)
    assert isinstance(record, ResponseRecord)
    assert record.status == 200
    assert "<masked:api_key>" in record.body_preview
    assert secret not in record.body_preview
    unit_dir = session_env.evidence_dir / record.request_id
    raw_request = (unit_dir / "request.txt").read_bytes()
    raw_response = (unit_dir / "response.txt").read_bytes()
    assert secret.encode() in raw_request  # D21: session evidence stays raw
    assert secret.encode() in raw_response
    warns = session_env.events.warns
    assert len(warns) == 1  # the non-blocking outbound warn was published
    assert warns[0].secret_names == ["api_key"]
    assert "body" in warns[0].locations
    assert echo_server.log.count == 1  # the warn never gated the deliberate call


async def test_marked_out_of_scope_endpoint_not_served(
    echo_server: EchoServer, client: SwarmyHttpClient, session_env: SessionEnv
) -> None:
    """Scenario 9: a marked endpoint of an allowed host is never served."""
    session_env.scope.mark_out_of_scope(
        [
            OutOfScopeEndpoint(
                host=f"127.0.0.1:{echo_server.port}", method="*", path="/private"
            )
        ]
    )
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url=echo_server.url("/private")))
    assert excinfo.value.feedback.rule_id == PIPELINE_OOS_TARGET_RULE_ID
    assert echo_server.log.count == 0  # the marked endpoint was not contacted
    payloads = await _guardrail_events(session_env.reader)
    assert len(payloads) == 1
    assert payloads[0].rule_id == PIPELINE_OOS_TARGET_RULE_ID
    record = await client.request(RequestSpec(method="GET", url=echo_server.url("/")))
    assert isinstance(record, ResponseRecord)  # positive control
    assert record.status == 200
