"""Integration-suite fixtures: the echo app + the real session perimeter.

The echo-app pytest fixtures (T2.4.1) start/stop :class:`EchoServer`
instances on OS-assigned free ports; a factory fixture spawns additional
(out-of-scope) servers. The session fixtures (T2.4.2) wire the **real**
F2 contour of arch §6.2 — migrated session database, journal + event bus
(journal-first fan-out), ``MemoryStore``, ``GuardrailPipeline`` over the
layer-1 session invariants, ``ContextProjector`` and the real
``EvidenceRecorder`` — and hand the scenarios a ``SwarmyHttpClient``
factory bound to that perimeter. No transport doubles: the scenarios hit
the echo server over real sockets.

The echo-app module is loaded through ``importlib`` from its file path
(the ``tests/fixtures/`` tree is data, not a package — same pattern as the
``dummy`` module loader smoke test); ``aiohttp`` therefore never becomes a
runtime import of ``swarmy`` (T2.4.1 AC, asserted by a dedicated test).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

import pytest

from swarmy.core.config import SecretsConfig
from swarmy.core.database import Database
from swarmy.events.bus import EventBus
from swarmy.events.journal import JournalReader, JournalWriter
from swarmy.events.models import EventSource, GuardrailBlockedPayload
from swarmy.guardrails.invariants import InvariantLayer, session_invariants
from swarmy.guardrails.pipeline import GuardrailPipeline
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex
from swarmy.memory.store import MemoryStore
from swarmy.tools.http.client import (
    OutboundSecretWarn,
    SwarmyHttpClient,
)
from swarmy.tools.http.evidence import EvidenceRecorder
from swarmy.tools.limits import ResourceLimiter, ResourceLimits
from swarmy.tools.projector import ContextProjector
from swarmy.tools.scope import ScopeEntries, ScopeRegistry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable
    from types import ModuleType

    # Type-only: the runtime import goes through importlib in
    # :func:`_load_echo_app_module` (the ``tests/fixtures/`` tree is data,
    # not an importable package — same pattern as the loader smoke test).
    from tests.fixtures.echo_app.app import EchoServer

#: File path of the echo-app module (loaded via importlib, not as a package).
ECHO_APP_FILE: Final[Path] = (
    Path(__file__).resolve().parents[1] / "fixtures" / "echo_app" / "app.py"
)

#: Stable importlib name of the loaded echo-app module (per-process cache key).
ECHO_APP_MODULE_NAME: Final[str] = "swarmy_tests_echo_app"

#: Fast default session limits: generous rate/budget so scenarios fail on
#: their own assertions, not on incidental exhaustion; the body budget is
#: small on purpose — the byte-exact/truncation scenarios need it.
DEFAULT_LIMITS: Final[ResourceLimits] = ResourceLimits(
    rate_limit=5000.0,
    max_concurrent_requests=8,
    max_body_bytes=1024,
    max_redirect_depth=5,
    total_request_budget=100,
    connect_timeout_s=2.0,
    read_timeout_s=2.0,
)


def _load_echo_app_module() -> ModuleType:
    """Load (and cache in ``sys.modules``) the echo-app module by path."""
    cached = sys.modules.get(ECHO_APP_MODULE_NAME)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(ECHO_APP_MODULE_NAME, ECHO_APP_FILE)
    if spec is None or spec.loader is None:  # pragma: no cover - importlib contract
        msg = f"cannot load echo-app module from {ECHO_APP_FILE}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[ECHO_APP_MODULE_NAME] = module
    return module


class SessionEnv(NamedTuple):
    """One wired session contour (real DB/journal/bus/store, T2.4.2)."""

    scope: ScopeRegistry
    limiter: ResourceLimiter
    pipeline: GuardrailPipeline
    projector: ContextProjector
    store: MemoryStore
    bus: EventBus
    writer: JournalWriter
    reader: JournalReader
    events: JournalBusEvents
    evidence_dir: Path


class JournalBusEvents:
    """Journal-first ``HttpClientEvents`` wiring over the real journal + bus.

    Mirrors the session contour (arch §5.3 invariant 2): every
    ``GuardrailBlocked`` is appended to the journal *before* the bus
    fan-out; the non-blocking outbound-secret warn has no journal type in
    the v0.1 taxonomy yet, so it is recorded in memory for assertions.
    """

    def __init__(self, writer: JournalWriter, bus: EventBus) -> None:
        """Bind the journal writer and the fan-out bus."""
        self._writer = writer
        self._bus = bus
        self.warns: list[OutboundSecretWarn] = []

    async def guardrail_blocked(self, payload: GuardrailBlockedPayload) -> None:
        """Append the event to the journal, then fan it out on the bus."""
        envelope = await self._writer.append(
            type="GuardrailBlocked",
            source=EventSource.PLATFORM,
            source_detail="http-client",
            correlation_id="",
            payload=payload,
        )
        await self._bus.publish(envelope)

    async def outbound_secret_warn(self, payload: OutboundSecretWarn) -> None:
        """Record the warn (its journal docking is contour policy, not client)."""
        self.warns.append(payload)


@pytest.fixture
async def spawn_echo_server() -> AsyncIterator[Callable[[], Awaitable[EchoServer]]]:
    """Factory spawning echo servers on free ports (stopped at teardown).

    Scenarios needing a *second* (out-of-scope) target call the factory
    again — every instance binds ``port=0``, so ports never collide.
    """
    started: list[EchoServer] = []

    async def _spawn() -> EchoServer:
        echo_app = _load_echo_app_module()
        server = await echo_app.EchoServer.start()
        started.append(server)
        return server

    yield _spawn
    for server in started:
        await server.stop()


@pytest.fixture
async def echo_server(spawn_echo_server: Callable[[], Awaitable[EchoServer]]) -> EchoServer:
    """The in-scope target of the session (one fixture server, free port)."""
    return await spawn_echo_server()


@pytest.fixture
def echo_scope(echo_server: EchoServer) -> ScopeRegistry:
    """Allowlist covering exactly the fixture server (loopback IP + port)."""
    return ScopeRegistry(
        ScopeEntries(ip_subnets=["127.0.0.1/32"], ports=[echo_server.port], schemes=["http"])
    )


@pytest.fixture
async def session_env(
    tmp_path: Path, echo_scope: ScopeRegistry
) -> AsyncIterator[SessionEnv]:
    """The real session contour: database, journal, bus, store, pipeline."""
    database = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await database.open()
    writer = JournalWriter(await database.connection("events"))
    reader = JournalReader(await database.connection("events"))
    index = Fts5SearchIndex(await database.connection("search"))
    store = MemoryStore(database, index)
    bus = EventBus()
    limiter = ResourceLimiter(DEFAULT_LIMITS)
    pipeline = GuardrailPipeline(invariants=InvariantLayer(session_invariants(echo_scope, limiter)))
    env = SessionEnv(
        scope=echo_scope,
        limiter=limiter,
        pipeline=pipeline,
        projector=ContextProjector(),
        store=store,
        bus=bus,
        writer=writer,
        reader=reader,
        events=JournalBusEvents(writer, bus),
        evidence_dir=tmp_path / "evidence",
    )
    yield env
    await bus.close()
    await database.close()


@pytest.fixture
def make_client(
    session_env: SessionEnv,
) -> Callable[..., SwarmyHttpClient]:
    """Factory of clients wired to the session contour (real network).

    Every override rebuilds the pipeline so the layer-1 budget invariant
    reads the *same* limiter instance the client acquires from; evidence
    goes through the real :class:`EvidenceRecorder` into the session dir.
    """

    def _make(
        *,
        limiter: ResourceLimiter | None = None,
        secrets: SecretsConfig | None = None,
    ) -> SwarmyHttpClient:
        effective_limiter = limiter if limiter is not None else session_env.limiter
        pipeline = GuardrailPipeline(
            invariants=InvariantLayer(session_invariants(session_env.scope, effective_limiter))
        )
        recorder = EvidenceRecorder(
            evidence_dir=session_env.evidence_dir,
            store=session_env.store,
            max_body_bytes=effective_limiter.limits.max_body_bytes,
        )
        return SwarmyHttpClient(
            scope=session_env.scope,
            limiter=effective_limiter,
            pipeline=pipeline,
            projector=session_env.projector,
            secrets=secrets if secrets is not None else SecretsConfig(),
            evidence=recorder,
            events=session_env.events,
        )

    return _make


@pytest.fixture
async def client(make_client: Callable[..., SwarmyHttpClient]) -> AsyncIterator[SwarmyHttpClient]:
    """One default client per test (closed cleanly afterwards)."""
    client = make_client()
    yield client
    await client.aclose()


__all__ = [
    "DEFAULT_LIMITS",
    "ECHO_APP_FILE",
    "JournalBusEvents",
    "SessionEnv",
]
