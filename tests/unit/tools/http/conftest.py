"""Shared fixtures and doubles for the ``tools.http`` unit tests (T2.2.*).

The client is exercised on ``httpx.MockTransport`` (roadmap T2.2.2 AC) with
a recording handler: every request the client would put on the wire is
captured in ``calls``, so "never opened a connection" is a list-length
assertion. The event/recorder doubles implement the client's typed
protocols structurally; the timeout AC additionally journals the
``invariant: timeout`` event through a **real** ``JournalWriter``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import pytest

from swarmy.core.config import SecretsConfig
from swarmy.core.database import Database
from swarmy.events.journal import JournalReader, JournalWriter
from swarmy.events.models import EventSource, GuardrailBlockedPayload
from swarmy.guardrails.invariants import InvariantLayer, session_invariants
from swarmy.guardrails.pipeline import GuardrailPipeline
from swarmy.memory.models import Evidence, EvidenceKind
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex
from swarmy.memory.store import MemoryStore
from swarmy.tools.http.client import (
    EvidenceSink,
    HttpClientEvents,
    OutboundSecretWarn,
    SwarmyHttpClient,
)
from swarmy.tools.limits import ResourceLimiter, ResourceLimits
from swarmy.tools.projector import ContextProjector
from swarmy.tools.scope import ScopeEntries, ScopeRegistry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Mapping, Sequence
    from pathlib import Path

    from swarmy.tools.http.models import HopRecord

#: In-scope origin used across the tests (scope fixture allowlists it).
BASE_URL = "http://app.example.com"

#: Fast session limits: the rate bucket spacing (~0.2 ms) keeps redirect
#: chains quick; generous budget/concurrency so tests fail on their own
#: assertions, not on incidental exhaustion.
LIMITS = ResourceLimits(
    rate_limit=5000.0,
    max_concurrent_requests=8,
    max_body_bytes=1024,
    max_redirect_depth=5,
    total_request_budget=100,
    connect_timeout_s=1.0,
    read_timeout_s=1.0,
)


def make_scope() -> ScopeRegistry:
    """Allowlist covering ``example.com`` (default ports/schemes)."""
    return ScopeRegistry(ScopeEntries(domains=["example.com"]))


def route_transport(
    routes: Mapping[str, httpx.Response], calls: list[httpx.Request]
) -> httpx.MockTransport:
    """Mock transport serving ``path → response`` and recording requests."""
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        response = routes.get(request.url.path)
        if response is None:
            return httpx.Response(404, text="not found")
        return response

    return httpx.MockTransport(handler)


def redirect_to(status: int, location: str) -> httpx.Response:
    """One redirect response with a ``Location`` header."""
    return httpx.Response(status, headers={"Location": location})


class EventSpy:
    """In-memory implementation of ``HttpClientEvents`` (records payloads)."""

    def __init__(self) -> None:
        """Start with empty recordings."""
        self.blocked: list[GuardrailBlockedPayload] = []
        self.warns: list[OutboundSecretWarn] = []

    async def guardrail_blocked(self, payload: GuardrailBlockedPayload) -> None:
        """Record the payload (the wiring would journal it here)."""
        self.blocked.append(payload)

    async def outbound_secret_warn(self, payload: OutboundSecretWarn) -> None:
        """Record the payload (the wiring would journal it here)."""
        self.warns.append(payload)


class JournalBlockedEvents:
    """Journals ``GuardrailBlocked`` through a real ``JournalWriter``.

    Proves the client's payloads decode through the ``EventRegistry``
    (journal-first wiring, arch §5.3); warns are recorded in memory — the
    v0.1 taxonomy has no warn type yet, so the contour wiring decides the
    journal docking of that platform event.
    """

    def __init__(self, writer: JournalWriter) -> None:
        """Bind the session journal writer."""
        self._writer = writer
        self.warns: list[OutboundSecretWarn] = []

    async def guardrail_blocked(self, payload: GuardrailBlockedPayload) -> None:
        """Append the ``GuardrailBlocked`` event to the journal (then fan out)."""
        await self._writer.append(
            type="GuardrailBlocked",
            source=EventSource.PLATFORM,
            source_detail="http-client",
            correlation_id="",
            payload=payload,
        )

    async def outbound_secret_warn(self, payload: OutboundSecretWarn) -> None:
        """Record the warn (journal docking decided by the contour)."""
        self.warns.append(payload)


class EvidenceSpy:
    """Recording double of the ``EvidenceSink`` protocol.

    Returns sequentially numbered ``Evidence`` records so the
    ``ResponseRecord.evidence_id`` linkage is observable.
    """

    def __init__(self) -> None:
        """Start with no calls and id counter at zero."""
        self.calls: list[dict[str, object]] = []
        self._next_id = 0

    async def record(
        self,
        *,
        request_head: bytes,
        request_body: bytes,
        tool: str,
        correlation_id: str,
        request_id: str,
        include_response: bool,
        response_head: bytes,
        response_body: bytes,
        response_truncated: bool = False,
        response_dropped_bytes: int | None = None,
        hops: Sequence[HopRecord] = (),
    ) -> Evidence:
        """Record the call and return a fresh ``Evidence`` pointer."""
        self.calls.append(
            {
                "request_head": request_head,
                "request_body": request_body,
                "tool": tool,
                "correlation_id": correlation_id,
                "request_id": request_id,
                "include_response": include_response,
                "response_head": response_head,
                "response_body": response_body,
                "response_truncated": response_truncated,
                "response_dropped_bytes": response_dropped_bytes,
                "hops": hops,
            }
        )
        self._next_id += 1
        return Evidence(
            id=self._next_id,
            kind=EvidenceKind.HTTP_REQUEST_RESPONSE,
            session_paths=[f"evidence/{request_id}/request.txt"],
            metadata={},
            created_at=datetime.now(UTC),
        )


@pytest.fixture
def scope() -> ScopeRegistry:
    """Fresh allowlist per test (``example.com``)."""
    return make_scope()


@pytest.fixture
def base_url() -> str:
    """The in-scope origin of the tests (``http://app.example.com``)."""
    return BASE_URL


@pytest.fixture
def default_limits() -> ResourceLimits:
    """Fresh fast session limits per test (no cross-test leakage)."""
    return ResourceLimits(
        rate_limit=LIMITS.rate_limit,
        max_concurrent_requests=LIMITS.max_concurrent_requests,
        max_body_bytes=LIMITS.max_body_bytes,
        max_redirect_depth=LIMITS.max_redirect_depth,
        total_request_budget=LIMITS.total_request_budget,
        connect_timeout_s=LIMITS.connect_timeout_s,
        read_timeout_s=LIMITS.read_timeout_s,
    )


@pytest.fixture
def make_transport() -> Callable[..., httpx.MockTransport]:
    """Factory of recording mock transports (``routes, calls`` arguments)."""
    return route_transport


@pytest.fixture
def redirect_response() -> Callable[[int, str], httpx.Response]:
    """Factory of redirect responses (``status, location`` arguments)."""
    return redirect_to


@pytest.fixture
def limiter() -> ResourceLimiter:
    """Fresh session limiter per test (fast limits)."""
    return ResourceLimiter(LIMITS)


@pytest.fixture
def projector() -> ContextProjector:
    """Default projector (no injected secrets: client-level masking is under test)."""
    return ContextProjector()


@pytest.fixture
def secrets() -> SecretsConfig:
    """One operator token secret the hygiene detector must catch."""
    return SecretsConfig(tokens={"api_key": "sekret-value-123"})


@pytest.fixture
def event_spy() -> EventSpy:
    """Fresh event spy per test."""
    return EventSpy()


@pytest.fixture
def evidence_spy() -> EvidenceSpy:
    """Fresh evidence spy per test."""
    return EvidenceSpy()


@pytest.fixture
def make_client(
    scope: ScopeRegistry,
    projector: ContextProjector,
    secrets: SecretsConfig,
    event_spy: EventSpy,
    evidence_spy: EvidenceSpy,
) -> Callable[..., SwarmyHttpClient]:
    """Client factory: real perimeter, mock transport, spy wiring.

    Overrides keep the pipeline consistent with the effective limiter (the
    layer-1 budget check reads the same instance the client acquires from).
    """

    def _make(
        *,
        transport: httpx.AsyncBaseTransport,
        limiter_override: ResourceLimiter | None = None,
        events: HttpClientEvents | None = None,
        evidence: EvidenceSink | None = None,
        secrets_override: SecretsConfig | None = None,
        pipeline_override: GuardrailPipeline | None = None,
    ) -> SwarmyHttpClient:
        limiter = limiter_override if limiter_override is not None else ResourceLimiter(LIMITS)
        pipeline = (
            pipeline_override
            if pipeline_override is not None
            else GuardrailPipeline(invariants=InvariantLayer(session_invariants(scope, limiter)))
        )
        return SwarmyHttpClient(
            scope=scope,
            limiter=limiter,
            pipeline=pipeline,
            projector=projector,
            secrets=secrets_override if secrets_override is not None else secrets,
            evidence=evidence if evidence is not None else evidence_spy,
            events=events if events is not None else event_spy,
            transport=transport,
        )

    return _make


@pytest.fixture
async def journal_env(
    tmp_path: Path,
) -> AsyncIterator[tuple[Database, JournalWriter, JournalReader]]:
    """Opened session database with a real journal writer/reader."""
    database = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await database.open()
    writer = JournalWriter(await database.connection("events"))
    reader = JournalReader(await database.connection("events"))
    yield database, writer, reader
    await database.close()


@pytest.fixture
def journal_events(
    journal_env: tuple[Database, JournalWriter, JournalReader],
) -> JournalBlockedEvents:
    """Event wiring that journals ``GuardrailBlocked`` through the real writer."""
    _database, writer, _reader = journal_env
    return JournalBlockedEvents(writer)


@pytest.fixture
async def store_env(tmp_path: Path) -> AsyncIterator[tuple[MemoryStore, Database]]:
    """Real ``MemoryStore`` over a migrated session database (T2.2.4)."""
    database = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await database.open()
    index = Fts5SearchIndex(await database.connection("search"))
    yield MemoryStore(database, index), database
    await database.close()
