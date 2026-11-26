"""The out-of-scope contour end-to-end (Issue #8 ↔ F-1, arch §6.3).

Drives the **real** Session composition: a memory endpoint flagged
``out_of_scope=True`` enters SQLite through the platform tool, the platform
event rides the journal + bus (journal-first), the session contour feeds
``ScopeRegistry.mark_out_of_scope``, and the next ``http`` call to the
marked path dies pre-connect under ``invariant: out-of-scope-target`` with
a journal row. The deny must survive a resume (the persisted flags re-mark
the registry before the first agent runs), and the operator scope-change
contour must widen the allowlist only through ``Session.extend_scope``
(journaled ``ScopeChanged``, ``origin="operator"``).

These tests pin the fail-closed semantics: marking is a restriction (any
code path may add one), unmarking is a widening (operator decision only).
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from swarmy.events.emit import make_emit_tool
from swarmy.events.models import EventSource
from swarmy.guardrails.models import GuardrailBlocked
from swarmy.memory.models import ScopeEntry
from swarmy.tools.http.models import RequestSpec
from swarmy.tools.platform import make_memory_tools
from tests.helpers.fake_models import one_shot_model

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from tests.fixtures.echo_app.app import EchoServer

pytestmark = pytest.mark.integration


def _config(port: int) -> SessionConfig:
    """Session over the fixture echo server (loopback, exact port)."""
    return SessionConfig(
        target=TargetConfig(base_url=f"http://127.0.0.1:{port}/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], ports=[port], schemes=["http"]),
        agents_dirs=[],
    )


def _memory_tools(session: Session) -> dict[str, object]:
    """The platform memory tools wired like the module toolset (§6.1).

    The contour under test is the platform event path (the store publishes
    nothing itself): the tool wrapper emits ``EndpointsDiscovered`` /
    ``EndpointUpdated`` journal-first, the session feed re-marks the
    registry from the bus envelopes.
    """
    journal = session.journal
    bus = session.bus
    store = session.memory
    assert journal is not None, "session composed"
    assert bus is not None, "session composed"
    assert store is not None, "session composed"
    emit = make_emit_tool(
        journal=journal,
        bus=bus,
        source=EventSource.PLATFORM,
        source_detail="platform.memory:contour-test",
    )
    return make_memory_tools(store, emit)


async def _wait_marked(
    session: Session, url: str, method: str = "GET", timeout_s: float = 5.0
) -> None:
    """Wait until the bus-fed registry denies ``url`` (delivery is async)."""
    scope = session.scope
    assert scope is not None, "session composed"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if scope.out_of_scope_reason(url, method) is not None:
            return
        await asyncio.sleep(0.01)
    pytest.fail("the endpoint event never reached ScopeRegistry.mark_out_of_scope")


@pytest.fixture
async def contour_session(
    echo_server: EchoServer, tmp_path: Path
) -> AsyncIterator[tuple[Session, EchoServer]]:
    """A real open session against the echo server (closed at teardown)."""
    session = await Session.open(
        config=_config(echo_server.port),
        session_dir=tmp_path / "s",
        model=one_shot_model(),
    )
    yield session, echo_server
    await session.close()


async def test_marked_endpoint_denied_by_invariant_and_journaled(
    contour_session: tuple[Session, EchoServer],
) -> None:
    """AC: upsert out_of_scope=True → http_get denied + journaled (Issue #8).

    The deny is the layer-1 invariant (``invariant: out-of-scope-target``),
    the journal carries the GuardrailBlocked row, and a sibling path of the
    same host stays reachable (the mark is endpoint-precise).
    """
    session, server = contour_session
    tools = _memory_tools(session)
    marked_url = f"http://127.0.0.1:{server.port}/admin/export"
    created = json.loads(
        str(
            await tools["memory_upsert_endpoint"](
                host=f"127.0.0.1:{server.port}",
                method="GET",
                path="/admin/export",
                out_of_scope=True,
            )
        )
    )
    assert created["out_of_scope"] is True
    await _wait_marked(session, marked_url)
    client = session.http_client
    reader = session.reader
    assert client is not None, "session composed"
    assert reader is not None, "session composed"
    with pytest.raises(GuardrailBlocked) as excinfo:
        await client.request(RequestSpec(method="GET", url=marked_url), tool_name="http_get")
    assert excinfo.value.feedback.rule_id == "invariant:out-of-scope-target"
    blocked = await reader.by_type("GuardrailBlocked")
    assert any(
        envelope.payload.rule_id == "invariant:out-of-scope-target" for envelope in blocked
    )
    # precision: the mark never widens into a host-wide deny
    ok = await client.request(
        RequestSpec(method="GET", url=f"http://127.0.0.1:{server.port}/"), tool_name="http_get"
    )
    assert not isinstance(ok, str)


async def test_denied_mark_survives_resume(
    echo_server: EchoServer, tmp_path: Path
) -> None:
    """AC: the deny survives a resume — the DB flags re-mark the registry."""
    session_dir = tmp_path / "s"
    first = await Session.open(
        config=_config(echo_server.port), session_dir=session_dir, model=one_shot_model()
    )
    tools = _memory_tools(first)
    marked_url = f"http://127.0.0.1:{echo_server.port}/admin/export"
    await tools["memory_upsert_endpoint"](
        host=f"127.0.0.1:{echo_server.port}",
        method="GET",
        path="/admin/export",
        out_of_scope=True,
    )
    await _wait_marked(first, marked_url)
    await first.close()

    resumed = await Session.resume(session_dir=session_dir, model=one_shot_model())
    try:
        scope = resumed.scope
        assert scope is not None, "session composed"
        assert scope.marked_endpoints(), "resume re-marked nothing from the DB"
        client = resumed.http_client
        assert client is not None, "session composed"
        with pytest.raises(GuardrailBlocked) as excinfo:
            await client.request(
                RequestSpec(method="GET", url=marked_url), tool_name="http_get"
            )
        assert excinfo.value.feedback.rule_id == "invariant:out-of-scope-target"
    finally:
        await resumed.close()


async def test_operator_scope_change_journals_and_widens(
    contour_session: tuple[Session, EchoServer],
) -> None:
    """The operator contour: extend(origin='operator') + journaled ScopeChanged.

    ``Session.extend_scope`` is the only production path passing
    ``origin="operator"``; the event is appended to the journal (and then
    fanned out) with the operator comment and the verbatim added entries.
    """
    session, _server = contour_session
    outside = "http://extra.example.com/"
    scope = session.scope
    assert scope is not None, "session composed"
    assert scope.check(outside).allowed is False
    await session.extend_scope(
        ScopeEntries(domains=["extra.example.com"], ports=[80]),
        operator_comment="operator widened for phase 2",
    )
    assert scope.check(outside).allowed is True
    reader = session.reader
    assert reader is not None, "session composed"
    events = await reader.by_type("ScopeChanged")
    assert len(events) == 1
    payload = events[0].payload
    assert payload.operator_comment == "operator widened for phase 2"
    assert payload.added == [
        ScopeEntry(id=0, kind="domain", value="extra.example.com", origin="operator"),
        ScopeEntry(id=0, kind="port", value="80", origin="operator"),
    ]
    assert all(entry.origin == "operator" for entry in payload.added)
