"""MemoryStore tests (roadmap T1.2.5): every arch §4.4 API method.

Covers the acceptance criteria: upsert dedup by ``(host, method, path)`` with
append-parameters, ``save_finding`` evidence-ref validation, the atomic
``link_attack_node`` rollback on a bad edge, concrete models from ``get``,
and the list filters. The store publishes no events (arch §5.2) - that is
asserted implicitly by having no event/emit machinery involved at all.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.memory.models import (
    AttackEdgeDraft,
    AttackNodeDraft,
    Endpoint,
    EndpointDraft,
    EntityType,
    Fact,
    FactDraft,
    Finding,
    FindingDraft,
    FindingStatus,
    FindingType,
    Note,
    NoteDraft,
    ParameterDraft,
    ScopeEntry,
    SearchableEntity,
    Severity,
    Target,
)
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex
from swarmy.memory.store import MemoryStore, MemoryStoreBusy

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    import aiosqlite


def _j(value: object) -> str:
    """JSON-encode a column value for direct SQL seeding."""
    return json.dumps(value)


_ENDPOINT_DRAFT = EndpointDraft(host="app.example.com:443", method="GET", path="/items")

_FINDING_DRAFT = FindingDraft(
    type=FindingType.XSS,
    severity=Severity.MEDIUM,
    title="Reflected XSS in q",
    description="q parameter echoed",
    created_by="xss-detector",
)


@pytest.fixture
async def memory_env(
    tmp_path: Path,
) -> AsyncIterator[tuple[MemoryStore, aiosqlite.Connection, Database]]:
    """Opened database with store + raw connection (for seeding/assertions)."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn = await db.connection("memory")
    index = Fts5SearchIndex(await db.connection("search"))
    yield MemoryStore(db, index), conn, db
    await db.close()


async def _count(conn: aiosqlite.Connection, table: str) -> int:
    """Row count of a table (direct SQL, assertion helper)."""
    cursor = await conn.execute(f"SELECT COUNT(*) AS n FROM {table}")
    row = await cursor.fetchone()
    assert row is not None
    return int(row["n"])


async def _insert_evidence(conn: aiosqlite.Connection, paths: list[str]) -> int:
    """Seed one evidence row and return its id."""
    cursor = await conn.execute(
        "INSERT INTO evidence (kind, session_paths, metadata, created_at)"
        " VALUES ('http_request_response', ?, ?, '2026-01-01T00:00:00+00:00')",
        (_j(paths), _j({"ts": "2026-01-01T00:00:00+00:00"})),
    )
    await conn.commit()
    assert cursor.lastrowid is not None
    return int(cursor.lastrowid)


async def test_get_returns_concrete_models(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """`get` decodes every entity type into its concrete Pydantic model."""
    store, conn, _db = memory_env
    endpoint = await store.upsert_endpoint(_ENDPOINT_DRAFT)
    await conn.execute(
        "INSERT INTO target (base_url, stack_metadata) VALUES (?, ?)",
        ("https://app.example.com", _j({"server": "nginx"})),
    )
    await conn.execute(
        "INSERT INTO scope_entries (kind, value, origin) VALUES ('domain', ?, 'config')",
        ("app.example.com",),
    )
    await conn.execute(
        "INSERT INTO parameters (endpoint_id, name, location, type, examples)"
        " VALUES (?, 'page', 'query', 'int', ?)",
        (endpoint.id, _j(["1", "2"])),
    )
    evidence_id = await _insert_evidence(conn, ["evidence/e1/request.txt"])
    finding = await store.save_finding(_FINDING_DRAFT)
    node = await store.link_attack_node(AttackNodeDraft(kind="goal", title="admin access"))
    fact = await store.add_fact(
        FactDraft(subject="app.example.com", predicate="runs", obj="nginx", source="crawler")
    )
    note = await store.add_note(NoteDraft(text="admin panel", author="crawler"))
    await conn.commit()

    target = await store.get(EntityType.TARGET, 1)
    scope_entry = await store.get(EntityType.SCOPE_ENTRY, 1)
    parameter = await store.get(EntityType.PARAMETER, 1)
    evidence = await store.get(EntityType.EVIDENCE, evidence_id)
    stored_node = await store.get(EntityType.ATTACK_NODE, node.id)
    cursor = await conn.execute("SELECT id FROM attack_edges")
    edge_row = await cursor.fetchone()
    assert edge_row is None, "no edges were requested"
    stored_fact = await store.get(EntityType.FACT, fact.id)
    stored_note = await store.get(EntityType.NOTE, note.id)
    stored_finding = await store.get(EntityType.FINDING, finding.id)
    stored_endpoint = await store.get(EntityType.ENDPOINT, endpoint.id)

    assert isinstance(target, Target)
    assert str(target.base_url).startswith("https://")
    assert isinstance(scope_entry, ScopeEntry)
    assert scope_entry.kind == "domain"
    assert isinstance(stored_endpoint, Endpoint)
    assert stored_endpoint.host == "app.example.com:443"
    assert parameter.endpoint_id == endpoint.id
    assert parameter.examples == ["1", "2"]
    assert evidence.session_paths == ["evidence/e1/request.txt"]
    assert evidence.metadata == {"ts": "2026-01-01T00:00:00+00:00"}
    assert isinstance(stored_finding, Finding)
    assert stored_finding.evidence_refs == []
    assert stored_node.kind == "goal"
    assert isinstance(stored_fact, Fact)
    assert stored_fact.obj == "nginx"
    assert isinstance(stored_note, Note)
    assert stored_note.author == "crawler"


async def test_get_attack_edge_model(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """`get` covers AttackEdge - the remaining EntityType member."""
    store, conn, _db = memory_env
    goal = await store.link_attack_node(AttackNodeDraft(kind="goal", title="admin access"))
    finder = await store.link_attack_node(
        AttackNodeDraft(kind="finding", title="SQLi"),
        edges=(AttackEdgeDraft(src=None, dst=goal.id, kind="leads_to"),),
    )
    cursor = await conn.execute("SELECT id FROM attack_edges")
    row = await cursor.fetchone()
    assert row is not None
    edge = await store.get(EntityType.ATTACK_EDGE, int(row["id"]))
    assert edge.src == finder.id
    assert edge.dst == goal.id
    assert edge.kind == "leads_to"


async def test_get_missing_raises_keyerror(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """`get` raises KeyError (not an SQL error) for unknown ids."""
    store, _conn, _db = memory_env
    with pytest.raises(KeyError, match="endpoint"):
        await store.get(EntityType.ENDPOINT, 404)


async def test_upsert_endpoint_dedups_and_appends_parameters(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """AC (T1.2.5): second upsert updates the row - no duplicate is created."""
    store, conn, _db = memory_env
    first = await store.upsert_endpoint(
        EndpointDraft(
            host="app.example.com:443",
            method="GET",
            path="/items",
            notes="first pass",
            auth_requirements=["api-key"],
            research_status="probed",
            parameters=[ParameterDraft(name="page", location="query", examples=["1"])],
        )
    )
    second = await store.upsert_endpoint(
        EndpointDraft(
            host="app.example.com:443",
            method="GET",
            path="/items",
            notes="second pass",
            auth_requirements=[],
            research_status="analyzed",
            out_of_scope=True,
            parameters=[
                ParameterDraft(name="page", location="query", examples=["2"]),
                ParameterDraft(name="q", location="query"),
            ],
        )
    )
    assert second.id == first.id, "dedup key (host, method, path) must match the old row"
    assert await _count(conn, "endpoints") == 1
    assert second.notes == "second pass"
    assert second.auth_requirements == []
    assert second.research_status == "analyzed"
    assert second.out_of_scope is True

    cursor = await conn.execute(
        "SELECT name, examples FROM parameters WHERE endpoint_id = ? ORDER BY name",
        (first.id,),
    )
    rows = await cursor.fetchall()
    assert [(str(row["name"]), json.loads(str(row["examples"]))) for row in rows] == [
        ("page", ["2"]),  # same key -> updated in place
        ("q", []),  # new key -> appended
    ]


async def test_save_finding_validates_evidence_refs(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """AC (T1.2.5): unknown evidence_ref -> ValueError listing the missing ids."""
    store, conn, _db = memory_env
    draft = _FINDING_DRAFT.model_copy(
        update={"evidence_refs": [404, 405], "endpoint_ref": None}
    )
    with pytest.raises(ValueError, match=r"\[404, 405\]"):
        await store.save_finding(draft)
    assert await _count(conn, "findings") == 0, "invalid draft must persist nothing"


async def test_save_finding_attaches_evidence(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """save_finding links referenced evidence rows via `finding_ref`."""
    store, conn, _db = memory_env
    e1 = await _insert_evidence(conn, ["evidence/e1/request.txt"])
    e2 = await _insert_evidence(conn, ["evidence/e1/response.txt"])
    finding = await store.save_finding(
        _FINDING_DRAFT.model_copy(update={"evidence_refs": [e1, e2]})
    )
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.evidence_refs == [e1, e2]
    cursor = await conn.execute(
        "SELECT finding_ref FROM evidence WHERE id IN (?, ?)", (e1, e2)
    )
    refs = [int(row["finding_ref"]) for row in await cursor.fetchall()]
    assert refs == [finding.id, finding.id]
    assert finding.created_at.utcoffset() is not None  # stamped now UTC by the store


async def test_update_finding_status(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """Status updates; severity None keeps the old severity; unknown id raises."""
    store, _conn, _db = memory_env
    finding = await store.save_finding(_FINDING_DRAFT)
    verified = await store.update_finding_status(
        finding.id, FindingStatus.VERIFIED, Severity.HIGH
    )
    assert verified.status is FindingStatus.VERIFIED
    assert verified.severity is Severity.HIGH
    rejected = await store.update_finding_status(finding.id, FindingStatus.REJECTED)
    assert rejected.severity is Severity.HIGH, "severity=None must keep the old value"
    with pytest.raises(KeyError, match="finding"):
        await store.update_finding_status(999, FindingStatus.VERIFIED)


async def test_link_attack_node_with_edges(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """Node + typed edges (None = the new node) are created in one call."""
    store, conn, _db = memory_env
    goal = await store.link_attack_node(
        AttackNodeDraft(kind="goal", title="admin access", description="final goal")
    )
    assert goal.kind == "goal"
    finder = await store.link_attack_node(
        AttackNodeDraft(kind="finding", title="SQLi in login", description=""),
        edges=(
            AttackEdgeDraft(src=None, dst=goal.id, kind="leads_to"),
            AttackEdgeDraft(src=goal.id, dst=None, kind="requires"),
        ),
    )
    cursor = await conn.execute(
        "SELECT src, dst, kind FROM attack_edges ORDER BY id"
    )
    edges = [(int(row["src"]), int(row["dst"]), str(row["kind"])) for row in await cursor.fetchall()]
    assert edges == [
        (finder.id, goal.id, "leads_to"),
        (goal.id, finder.id, "requires"),
    ]
    assert await _count(conn, "attack_nodes") == 2


async def test_link_attack_node_rollback_on_bad_edge(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """AC (T1.2.5): an invalid edge rolls the whole operation back - zero rows."""
    store, conn, _db = memory_env
    with pytest.raises(ValueError, match="999"):
        await store.link_attack_node(
            AttackNodeDraft(kind="goal", title="RCE"),
            edges=(AttackEdgeDraft(src=999, dst=None, kind="requires"),),
        )
    assert await _count(conn, "attack_nodes") == 0, "node must roll back with the edge"
    assert await _count(conn, "attack_edges") == 0


async def test_add_fact_roundtrip(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """add_fact inserts and decodes tags/created_at correctly."""
    store, conn, _db = memory_env
    fact = await store.add_fact(
        FactDraft(
            subject="app.example.com",
            predicate="uses",
            obj="react",
            tags=["infra", "frontend"],
            source="crawler",
        )
    )
    assert fact.id >= 1
    assert fact.tags == ["infra", "frontend"]
    assert fact.created_at.utcoffset() is not None
    assert await _count(conn, "facts") == 1


async def test_list_facts_returns_the_full_ledger_in_row_order(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """list_facts reads every row of one subject in insertion order.

    A ranked/limited search result would truncate a long ledger
    arbitrarily — the machine-readable ledger replay (judge class gates,
    §6.7) needs the complete, deterministically ordered domain read.
    """
    store, _conn, _db = memory_env
    for index in range(4):
        await store.add_fact(
            FactDraft(
                subject="judge_class_gate",
                predicate="network-write",
                obj="escalate" if index % 2 == 0 else "reject",
                tags=[f"gate:{index}"],
                source="swarmy/judge",
            )
        )
    await store.add_fact(
        FactDraft(subject="other", predicate="p", obj="o", tags=[], source="s")
    )
    ledger = await store.list_facts("judge_class_gate")
    assert [fact.tags[0] for fact in ledger] == ["gate:0", "gate:1", "gate:2", "gate:3"]
    assert [fact.obj for fact in ledger] == ["escalate", "reject", "escalate", "reject"]
    assert all(isinstance(fact, Fact) for fact in ledger)
    assert await store.list_facts("nothing-here") == []


async def test_add_note_roundtrip(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """add_note inserts and decodes text/tags/author correctly."""
    store, conn, _db = memory_env
    note = await store.add_note(
        NoteDraft(text="admin panel at /admin", tags=["recon"], author="crawler")
    )
    assert note.text == "admin panel at /admin"
    assert note.tags == ["recon"]
    assert note.author == "crawler"
    assert await _count(conn, "notes") == 1


async def test_list_endpoints_filter(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """list_endpoints filters by out_of_scope (read-only API)."""
    store, _conn, _db = memory_env
    in_scope = await store.upsert_endpoint(_ENDPOINT_DRAFT)
    out_scope = await store.upsert_endpoint(
        _ENDPOINT_DRAFT.model_copy(update={"path": "/internal", "out_of_scope": True})
    )
    assert [ep.id for ep in await store.list_endpoints()] == [in_scope.id, out_scope.id]
    assert [ep.id for ep in await store.list_endpoints(out_of_scope=True)] == [out_scope.id]
    assert [ep.id for ep in await store.list_endpoints(out_of_scope=False)] == [in_scope.id]


async def test_list_findings_filters(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """list_findings filters by status, severity, and both combined."""
    store, _conn, _db = memory_env
    critical = await store.save_finding(
        _FINDING_DRAFT.model_copy(update={"severity": Severity.CRITICAL})
    )
    low = await store.save_finding(_FINDING_DRAFT.model_copy(update={"severity": Severity.LOW}))
    await store.update_finding_status(critical.id, FindingStatus.VERIFIED)

    all_findings = await store.list_findings()
    assert [f.id for f in all_findings] == [critical.id, low.id]
    assert [f.id for f in await store.list_findings(status=FindingStatus.VERIFIED)] == [
        critical.id
    ]
    assert [f.id for f in await store.list_findings(severity=Severity.LOW)] == [low.id]
    assert (
        await store.list_findings(status=FindingStatus.CANDIDATE, severity=Severity.CRITICAL)
    ) == []


async def test_search_delegates_to_index(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """store.search proxies the SearchIndex backend (arch §4.4)."""
    store, _conn, _db = memory_env
    await store.upsert_endpoint(
        _ENDPOINT_DRAFT.model_copy(update={"path": "/searchme", "notes": "unique token here"})
    )
    hits = await store.search("searchme")
    assert hits
    assert hits[0].entity_type is SearchableEntity.ENDPOINTS
    assert await store.search("zzzqqq") == []


# ---------------------------------------------------------------------------
# Lifecycle enforcement (#12), ref validation (#63), transaction retry (#53).
# ---------------------------------------------------------------------------


async def test_update_finding_status_rejects_demotion_and_terminal_states(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """Only the documented lifecycle transitions pass (#12, RD-5).

    ``verified -> candidate`` is a demotion; a ``rejected`` finding is
    terminal. The error names current and target statuses so the agent can
    self-correct.
    """
    store, _conn, _db = memory_env
    finding = await store.save_finding(_FINDING_DRAFT)
    verified = await store.update_finding_status(finding.id, FindingStatus.VERIFIED)
    assert verified.status is FindingStatus.VERIFIED
    with pytest.raises(ValueError, match=r"invalid finding status transition verified -> candidate"):
        await store.update_finding_status(finding.id, FindingStatus.CANDIDATE)
    rejected = await store.update_finding_status(finding.id, FindingStatus.REJECTED)
    assert rejected.status is FindingStatus.REJECTED
    for target in (FindingStatus.CANDIDATE, FindingStatus.VERIFIED):
        with pytest.raises(
            ValueError, match=rf"invalid finding status transition rejected -> {target.value}"
        ):
            await store.update_finding_status(finding.id, target)
    assert [f.id for f in await store.list_findings(status=FindingStatus.REJECTED)] == [
        finding.id
    ]


async def test_update_finding_status_same_status_updates_severity(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """Re-setting the current status stays allowed (severity-update path)."""
    store, _conn, _db = memory_env
    finding = await store.save_finding(_FINDING_DRAFT)
    updated = await store.update_finding_status(
        finding.id, FindingStatus.CANDIDATE, Severity.HIGH
    )
    assert updated.status is FindingStatus.CANDIDATE
    assert updated.severity is Severity.HIGH


async def test_save_finding_rejects_unknown_endpoint_ref(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """A dangling endpoint_ref is an agent-facing ValueError, not FK noise (#63)."""
    store, _conn, _db = memory_env
    with pytest.raises(ValueError, match=r"endpoint_ref not found in endpoints: 999"):
        await store.save_finding(_FINDING_DRAFT.model_copy(update={"endpoint_ref": 999}))
    endpoint = await store.upsert_endpoint(_ENDPOINT_DRAFT)
    finding = await store.save_finding(
        _FINDING_DRAFT.model_copy(update={"endpoint_ref": endpoint.id})
    )
    assert finding.endpoint_ref == endpoint.id


async def test_link_attack_node_rejects_unknown_finding_ref(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
) -> None:
    """A dangling finding_ref is an agent-facing ValueError; nothing persists (#63)."""
    store, conn, _db = memory_env
    with pytest.raises(ValueError, match=r"finding_ref not found in findings: 999"):
        await store.link_attack_node(
            AttackNodeDraft(kind="finding", title="ghost node", finding_ref=999)
        )
    cursor = await conn.execute("SELECT COUNT(*) AS n FROM attack_nodes")
    row = await cursor.fetchone()
    assert row is not None
    assert int(row["n"]) == 0, "the failed call must not persist the node"
    finding = await store.save_finding(_FINDING_DRAFT)
    node = await store.link_attack_node(
        AttackNodeDraft(kind="finding", title="real node", finding_ref=finding.id)
    )
    assert node.finding_ref == finding.id


async def test_begin_collision_exhausts_retries_into_memory_store_busy(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A held write transaction surfaces as agent-facing MemoryStoreBusy (#53)."""
    store, conn, _db = memory_env
    monkeypatch.setattr("swarmy.memory.store._TX_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr("swarmy.memory.store._TX_RETRY_JITTER_S", 0.0)
    await conn.execute("BEGIN IMMEDIATE")  # simulate an interleaved multi-step writer
    with pytest.raises(MemoryStoreBusy, match="memory subsystem is busy"):
        await store.save_target("https://app.example.com")
    await conn.rollback()  # the interleaved writer finishes
    target = await store.save_target("https://app.example.com")  # store usable again
    assert target.id == 1


async def test_begin_collision_retries_until_writer_commits(
    memory_env: tuple[MemoryStore, aiosqlite.Connection, Database],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """save_target succeeds once the colliding writer commits mid-retry (#53)."""
    store, conn, _db = memory_env
    monkeypatch.setattr("swarmy.memory.store._TX_RETRY_BASE_DELAY_S", 0.01)
    monkeypatch.setattr("swarmy.memory.store._TX_RETRY_JITTER_S", 0.0)

    async def finish_writer() -> None:
        """Release the held transaction while the store call is retrying."""
        await asyncio.sleep(0.02)
        await conn.commit()

    await conn.execute("BEGIN IMMEDIATE")
    finisher = asyncio.create_task(finish_writer())
    target = await store.save_target("https://app.example.com")
    await finisher
    assert target.id == 1
