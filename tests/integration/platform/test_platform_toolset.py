"""The real platform toolset over the session contour (arch §4.4/§5.2).

``make_memory_tools`` + ``make_emit_tool`` are wired against the **real**
``MemoryStore``, journal and bus (the same contour the HTTP scenarios use):
every mutation lands in SQLite, publishes its arch §5.5 platform event
journal-first, and the FTS index becomes searchable through
``memory_search`` — the memory half of the F2 contour, end to end.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from swarmy.events.emit import make_emit_tool
from swarmy.events.models import EventSource
from swarmy.memory.models import EvidenceDraft, EvidenceKind
from swarmy.tools.platform import make_memory_tools

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.fixtures.echo_app.app import EchoServer

    from ..conftest import SessionEnv


def _emit(session_env: SessionEnv, allowed_types: set[str] | None = None) -> Callable[..., object]:
    """Build the session ``emit_event`` tool of the test contour."""
    return make_emit_tool(
        journal=session_env.writer,
        bus=session_env.bus,
        source=EventSource.PLATFORM,
        source_detail="platform-tools",
        allowed_types=allowed_types,
    )


async def _journal_types(session_env: SessionEnv) -> set[str]:
    """All event types recorded so far in the test's session journal."""
    return {envelope.type for envelope in await session_env.reader.range(0)}


async def test_platform_toolset_round_trip(
    echo_server: EchoServer, session_env: SessionEnv
) -> None:
    """A discovery flow: endpoint → evidence → finding → verified, all via tools."""
    tools = make_memory_tools(session_env.store, _emit(session_env))
    endpoint = json.loads(
        await tools["memory_upsert_endpoint"](
            host=f"127.0.0.1:{echo_server.port}",
            method="GET",
            path="/query",
            parameters=[{"name": "q", "location": "query"}],
        )
    )
    assert endpoint["id"] > 0
    evidence = await session_env.store.add_evidence(
        EvidenceDraft(
            kind=EvidenceKind.HTTP_REQUEST_RESPONSE,
            session_paths=["evidence/probe/request.txt"],
            metadata={},
        )
    )
    finding = json.loads(
        await tools["memory_save_finding"](
            type="xss",
            severity="high",
            title="Reflected XSS in /query",
            description="the q parameter is reflected unescaped",
            created_by="xss-detector",
            endpoint_ref=endpoint["id"],
            evidence_refs=[evidence.id],
            reproduction=["GET /query?q=<svg/onload>", "payload lands in the body"],
        )
    )
    assert finding["status"] == "candidate"
    await tools["memory_add_fact"](
        subject="auth", predicate="uses", obj="JWT", tags=["probe"], source="integration"
    )
    await tools["memory_add_note"](text="echo app probed", author="integration")
    await tools["memory_link_attack_node"](
        kind="finding",
        title="XSS tree node",
        finding_ref=finding["id"],
        edges=[{"src": None, "dst": None, "kind": "leads_to"}],
    )
    verified = json.loads(
        await tools["update_finding_status"](
            finding["id"], "verified", reason="payload echoed verbatim"
        )
    )
    assert verified["status"] == "verified"
    # FTS finds the finding through the real search index
    hits = json.loads(await tools["memory_search"]("Reflected XSS"))
    assert any(hit["entity_type"] == "findings" and hit["id"] == finding["id"] for hit in hits)
    # memory_get round-trips the stored endpoint record
    fetched = json.loads(await tools["memory_get"]("endpoint", endpoint["id"]))
    assert fetched["host"] == f"127.0.0.1:{echo_server.port}"
    assert fetched["method"] == "GET"
    assert fetched["path"] == "/query"
    # the platform event trail of the whole flow (arch §5.5)
    assert await _journal_types(session_env) >= {
        "EndpointsDiscovered",
        "FindingCandidate",
        "AttackTreeUpdated",
        "FindingVerified",
    }


async def test_endpoint_upsert_deduplicates_and_updates(
    echo_server: EchoServer, session_env: SessionEnv
) -> None:
    """A second upsert of the same triple updates the row and publishes the update."""
    tools = make_memory_tools(session_env.store, _emit(session_env))
    first = json.loads(
        await tools["memory_upsert_endpoint"](
            host=f"127.0.0.1:{echo_server.port}", method="POST", path="/body"
        )
    )
    second = json.loads(
        await tools["memory_upsert_endpoint"](
            host=f"127.0.0.1:{echo_server.port}",
            method="POST",
            path="/body",
            notes="probe recorded",
        )
    )
    assert second["id"] == first["id"]
    updated = await session_env.reader.by_type("EndpointUpdated")
    assert len(updated) == 1


async def test_emit_tool_rejects_undeclared_unknown_and_invalid(
    session_env: SessionEnv,
) -> None:
    """``emit_event`` validation gates: manifest, registry, payload schema."""
    restricted = _emit(session_env, allowed_types={"FindingCandidate"})
    with pytest.raises(ValueError, match="not declared in this agent's manifest"):
        await restricted("EndpointsDiscovered", {"endpoints": [1], "out_of_scope_count": 0})
    unrestricted = _emit(session_env)
    with pytest.raises(ValueError, match="unknown event type"):
        await unrestricted("NoSuchEventType", {})
    with pytest.raises(ValueError, match="invalid payload"):
        await unrestricted("FindingCandidate", {"bogus": True})
    # none of the rejected calls touched the journal (fail before append)
    assert await _journal_types(session_env) == set()


async def test_memory_tools_reject_invalid_arguments(
    echo_server: EchoServer, session_env: SessionEnv
) -> None:
    """Argument validation errors are agent-addressable ValueErrors (arch §4.4)."""
    tools = make_memory_tools(session_env.store, _emit(session_env))
    with pytest.raises(ValueError, match="entity_types items"):
        await tools["memory_search"]("anything", entity_types=["nope"])
    with pytest.raises(ValueError, match="entity_type"):
        await tools["memory_get"]("unicorns", 1)
    with pytest.raises(ValueError, match="status"):
        await tools["update_finding_status"](1, "forgotten")
