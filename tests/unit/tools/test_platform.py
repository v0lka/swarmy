"""Platform memory tools tests (T1.2.6, arch §4.4/§6.1).

Acceptance criteria under test: every tool validates its arguments through
the Pydantic draft models *before* a store call (invalid args raise and the
store is not mutated), ``upsert_endpoint`` publishes ``EndpointsDiscovered``
for new rows and ``EndpointUpdated`` for existing ones, ``update_finding_status``
publishes ``FindingVerified``/``FindingRejected`` by target status, and all
tools return JSON strings with fully typed signatures and non-empty docstrings.

The emit stub is a recording wrapper around the *real* ``make_emit_tool``
backed by a real ``Database`` + journal: after each successful call it
captures the freshly appended envelope from the journal tail.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from swarmy.core.database import Database
from swarmy.events import (
    EmitEventTool,
    EventBus,
    EventSource,
    JournalReader,
    JournalWriter,
    JsonValue,
    make_emit_tool,
)
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex
from swarmy.memory.store import MemoryStore
from swarmy.tools.platform import make_memory_tools

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping
    from pathlib import Path

    import aiosqlite

    from swarmy.events.models import EventEnvelope

_EXPECTED_TOOLS = frozenset(
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


class _EmitRecorder:
    """Emit stub wrapping the real tool; records each published envelope."""

    def __init__(self, inner: EmitEventTool, reader: JournalReader) -> None:
        self._inner = inner
        self._reader = reader
        self.envelopes: list[EventEnvelope] = []

    async def __call__(self, type: str, payload: Mapping[str, JsonValue]) -> str:
        result = await self._inner(type, payload)
        (last,) = await self._reader.tail(1)  # sequential calls: tail = just appended
        self.envelopes.append(last)
        return result


@pytest.fixture
async def platform_env(
    tmp_path: Path,
) -> AsyncIterator[
    tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection]
]:
    """Real store + real emit tool wrapped in a recorder; ready-to-use tools."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    store = MemoryStore(db, Fts5SearchIndex(await db.connection("search")))
    events_conn = await db.connection("events")
    writer = JournalWriter(events_conn)
    bus = EventBus()
    emit = make_emit_tool(
        journal=writer, bus=bus, source=EventSource.PLATFORM, source_detail="platform.tools"
    )
    recorder = _EmitRecorder(emit, JournalReader(events_conn))
    tools = make_memory_tools(store, recorder)
    memory_conn = await db.connection("memory")
    yield tools, store, recorder, memory_conn
    await bus.close()
    await db.close()


async def _rows(conn: aiosqlite.Connection, table: str) -> int:
    """Row count of one table (async direct SQL assertion helper)."""
    cursor = await conn.execute(f"SELECT COUNT(*) AS n FROM {table}")
    row = await cursor.fetchone()
    assert row is not None
    return int(row[0])


async def test_toolset_names_and_docstrings(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """The toolset matches arch §4.4 and every docstring is non-empty (G10)."""
    tools, _store, _recorder, _conn = platform_env
    assert set(tools) == _EXPECTED_TOOLS
    for name, fn in tools.items():
        docstring = getattr(fn, "__doc__", None)
        assert docstring is not None, name
        assert docstring.strip(), name


async def test_upsert_endpoint_publishes_discovered_then_updated(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """New (host, method, path) → EndpointsDiscovered; repeat → EndpointUpdated."""
    tools, _store, recorder, _conn = platform_env
    upsert = tools["memory_upsert_endpoint"]
    first = await upsert(host="app.example.com:443", method="GET", path="/items")
    created = json.loads(str(first))
    assert created["id"] == 1
    discovered = recorder.envelopes[-1]
    assert discovered.type == "EndpointsDiscovered"
    assert discovered.payload.endpoints == [1]
    assert discovered.payload.out_of_scope_count == 0
    second = await upsert(host="app.example.com:443", method="GET", path="/items", notes="recheck")
    assert json.loads(str(second))["id"] == 1
    updated = recorder.envelopes[-1]
    assert updated.type == "EndpointUpdated"
    assert updated.payload.endpoint_id == 1
    await upsert(host="app.example.com:443", method="GET", path="/admin", out_of_scope=True)
    admin_event = recorder.envelopes[-1]
    assert admin_event.type == "EndpointsDiscovered"
    assert admin_event.payload.out_of_scope_count == 1


async def test_invalid_args_raise_and_leave_store_unmutated(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """Every tool validates args via drafts before any store mutation."""
    tools, store, recorder, conn = platform_env
    with pytest.raises(ValidationError, match="type"):
        await tools["memory_save_finding"](
            type="nosqli", severity="high", title="t", description="d", created_by="m"
        )
    with pytest.raises(ValidationError, match="research_status"):
        await tools["memory_upsert_endpoint"](
            host="h", method="GET", path="/x", research_status="bogus"
        )
    with pytest.raises(ValidationError, match="location"):
        await tools["memory_upsert_endpoint"](
            host="h", method="GET", path="/x", parameters=[{"name": "q", "location": "sideways"}]
        )
    with pytest.raises(ValidationError, match="kind"):
        await tools["memory_link_attack_node"](kind="bogus", title="t")
    with pytest.raises(ValueError, match="status must be one of"):
        await tools["update_finding_status"](finding_id=1, status="bogus")
    assert await store.list_findings() == []
    assert await store.list_endpoints() == []
    assert await _rows(conn, "attack_nodes") == 0
    assert recorder.envelopes == []  # failed calls publish no events


async def test_save_finding_publishes_candidate_and_json_reads(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """FindingCandidate payload, memory_get/search JSON contracts (§5.5/§4.4)."""
    tools, _store, recorder, _conn = platform_env
    await tools["memory_upsert_endpoint"](host="app.example.com:443", method="GET", path="/q")
    saved = await tools["memory_save_finding"](
        type="xss",
        severity="medium",
        title="Reflected XSS in q",
        description="q parameter echoed",
        created_by="xss-detector",
        endpoint_ref=1,
    )
    finding = json.loads(str(saved))
    assert finding["status"] == "candidate"
    assert finding["id"] == 1
    candidate = recorder.envelopes[-1]
    assert candidate.type == "FindingCandidate"
    assert candidate.payload.finding_id == 1
    assert candidate.payload.finding_type == "xss"
    assert candidate.payload.endpoint_ref == 1
    assert candidate.payload.evidence_refs == []
    fetched = json.loads(str(await tools["memory_get"]("finding", 1)))
    assert fetched["title"] == "Reflected XSS in q"
    hits = json.loads(str(await tools["memory_search"]("Reflected")))
    assert hits
    assert set(hits[0]) == {"entity_type", "id", "title_snippet", "score"}
    assert hits[0]["entity_type"] == "findings"
    filtered = json.loads(
        str(await tools["memory_search"]("Reflected", entity_types=["findings"]))
    )
    assert filtered == hits
    with pytest.raises(ValueError, match="entity_types items must be"):
        await tools["memory_search"]("Reflected", entity_types=["bogus"])
    with pytest.raises(ValueError, match="entity_type must be"):
        await tools["memory_get"]("bogus", 1)
    with pytest.raises(KeyError, match="not found"):
        await tools["memory_get"]("finding", 999)


async def test_update_finding_status_publishes_verified_and_rejected(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """The verification tool emits FindingVerified / FindingRejected (§6.1)."""
    tools, store, recorder, _conn = platform_env
    await tools["memory_save_finding"](
        type="auth", severity="high", title="Broken auth", description="d", created_by="m"
    )
    verified_json = await tools["update_finding_status"](
        finding_id=1, status="verified", severity="critical", reason="confirmed"
    )
    assert json.loads(str(verified_json))["status"] == "verified"
    verified = recorder.envelopes[-1]
    assert verified.type == "FindingVerified"
    assert verified.payload.finding_id == 1
    assert verified.payload.severity == "critical"
    assert verified.payload.reason == "confirmed"
    rejected_json = await tools["update_finding_status"](
        finding_id=1, status="rejected", reason="duplicate"
    )
    assert json.loads(str(rejected_json))["status"] == "rejected"
    rejected = recorder.envelopes[-1]
    assert rejected.type == "FindingRejected"
    assert rejected.payload.reason == "duplicate"
    statuses = [finding.status for finding in await store.list_findings()]
    assert statuses == ["rejected"]
    with pytest.raises(KeyError, match="not found"):
        await tools["update_finding_status"](finding_id=42, status="verified")


async def test_link_attack_node_publishes_node_and_edge_events(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """AttackTreeUpdated add_node + one add_edge per edge (§5.5)."""
    tools, _store, recorder, conn = platform_env
    created = await tools["memory_link_attack_node"](
        kind="precondition",
        title="SQLi reachable",
        edges=[{"src": None, "dst": None, "kind": "leads_to"}],
    )
    assert json.loads(str(created))["id"] == 1
    assert [envelope.type for envelope in recorder.envelopes] == [
        "AttackTreeUpdated",
        "AttackTreeUpdated",
    ]
    node_event, edge_event = recorder.envelopes
    assert node_event.payload.op == "add_node"
    assert node_event.payload.node_id == 1
    assert edge_event.payload.op == "add_edge"
    assert edge_event.payload.tree_id == 1
    with pytest.raises(ValidationError):
        await tools["memory_link_attack_node"](
            kind="goal", title="bad edge", edges=[{"src": None, "dst": 999, "kind": "bogus"}]
        )
    assert await _rows(conn, "attack_edges") == 1  # the failed call rolled back


async def test_add_fact_and_note_return_json(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """Facts/notes are plain JSON records; search finds them via FTS."""
    tools, _store, recorder, _conn = platform_env
    fact = json.loads(str(await tools["memory_add_fact"](
        subject="framework", predicate="runs", obj="Django 4.2", tags=["stack"]
    )))
    assert (fact["subject"], fact["predicate"], fact["obj"]) == (
        "framework",
        "runs",
        "Django 4.2",
    )
    note = json.loads(str(await tools["memory_add_note"](
        text="admin panel at /admin", tags=["recon"], author="crawler"
    )))
    assert note["text"] == "admin panel at /admin"
    assert recorder.envelopes == []  # facts/notes publish no v0.1 events
    hits = json.loads(
        str(await tools["memory_search"]("Django", entity_types=["facts"]))
    )
    assert hits
    assert hits[0]["id"] == fact["id"]


async def test_upsert_endpoint_normalizes_method_at_the_boundary(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """Methods upper-case and RFC 9110 tokens only (F-15 handoff, option b).

    A lower-case alias dedups onto the canonical row; a junk value (a
    target-controlled or hallucinated non-token) is rejected with an
    agent-addressable error and nothing is stored.
    """
    tools, _store, _recorder, conn = platform_env
    upsert = tools["memory_upsert_endpoint"]
    created = json.loads(str(await upsert(host="app.example.com:443", method="get", path="/")))
    assert created["method"] == "GET"
    # the canonical upper-case spelling dedups onto the same row
    updated = json.loads(
        str(await upsert(host="app.example.com:443", method="GET", path="/", notes="seen"))
    )
    assert updated["id"] == created["id"]
    with pytest.raises(ValueError, match="invalid HTTP method"):
        await upsert(host="app.example.com:443", method="[/etc/passwd]", path="/x")
    with pytest.raises(ValueError, match="invalid HTTP method"):
        await upsert(host="app.example.com:443", method="get /admin", path="/x")
    with pytest.raises(ValueError, match="invalid HTTP method"):
        await upsert(host="app.example.com:443", method="", path="/x")
    assert await _rows(conn, "endpoints") == 1  # junk never entered memory


async def test_upsert_endpoint_sentinels_preserve_stored_values(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """Re-upserting a known endpoint keeps omitted fields (Issue #9, option a).

    ``None`` is the sentinel for "keep the stored value": a crawler
    re-discovering a known endpoint without repeating the flag/status/notes
    must not reset them — combined with the fail-closed unmark rule this
    keeps the ``out_of_scope`` contour state agent-proof.
    """
    tools, store, _recorder, _conn = platform_env
    upsert = tools["memory_upsert_endpoint"]
    await upsert(
        host="app.example.com:443",
        method="POST",
        path="/admin/export",
        auth_requirements=["admin_cookie"],
        research_status="probed",
        out_of_scope=True,
        notes="operator excluded: corrupts production data",
    )
    # re-discovery with every optional field omitted (the crawler default)
    rediscovered = json.loads(
        str(await upsert(host="app.example.com:443", method="POST", path="/admin/export"))
    )
    assert rediscovered["out_of_scope"] is True
    assert rediscovered["research_status"] == "probed"
    assert rediscovered["notes"] == "operator excluded: corrupts production data"
    assert rediscovered["auth_requirements"] == ["admin_cookie"]
    rows = await store.list_endpoints()
    assert len(rows) == 1
    assert rows[0].out_of_scope is True


async def test_upsert_endpoint_cannot_clear_out_of_scope_mark(
    platform_env: tuple[dict[str, object], MemoryStore, _EmitRecorder, aiosqlite.Connection],
) -> None:
    """Clearing an existing mark is refused (fail-closed, arch §6.3).

    ``out_of_scope=False`` on an already-marked endpoint raises an
    agent-addressable error naming the operator decision requirement; the
    stored flag (and the other fields) survive the refused call. Explicit
    ``False`` on an unmarked endpoint stays a legal no-op.
    """
    tools, store, _recorder, _conn = platform_env
    upsert = tools["memory_upsert_endpoint"]
    await upsert(
        host="app.example.com:443",
        method="GET",
        path="/soft",
        out_of_scope=True,
        notes="fragile legacy app",
    )
    with pytest.raises(ValueError, match="operator decision"):
        await upsert(
            host="app.example.com:443",
            method="GET",
            path="/soft",
            out_of_scope=False,
            notes="trying to widen the perimeter",
        )
    rows = await store.list_endpoints()
    assert len(rows) == 1
    assert rows[0].out_of_scope is True  # the deny never cleared the mark
    assert rows[0].notes == "fragile legacy app"  # nothing was written
    # explicit False on an *unmarked* endpoint stays legal (no widening)
    await upsert(host="app.example.com:443", method="GET", path="/open", out_of_scope=False)
    unmarked = [row for row in await store.list_endpoints() if row.path == "/open"]
    assert len(unmarked) == 1
    assert unmarked[0].out_of_scope is False
