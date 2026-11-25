"""Journal tests: append-only writer + read models (T1.3.2, arch §5.4).

Acceptance criteria under test: monotonic ids and UTC ISO stamps, payload
JSON round-trip, tail/range/by_correlation/by_type semantics, and the DB-level
append-only enforcement (UPDATE/DELETE rejected by schema triggers).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.events.journal import JournalReader, JournalWriter
from swarmy.events.models import (
    EventEnvelope,
    EventSource,
    FindingCandidatePayload,
    OperatorMessagePayload,
    ScopeChangedPayload,
)
from swarmy.memory.models import ScopeEntry
from swarmy.memory.schema import MIGRATIONS

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    import aiosqlite


@pytest.fixture
async def journal_env(
    tmp_path: Path,
) -> AsyncIterator[tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database]]:
    """Opened database with writer/reader bound to the events connection."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn = await db.connection("events")
    yield JournalWriter(conn), JournalReader(conn), conn, db
    await db.close()


async def _append_candidate(
    writer: JournalWriter,
    finding_id: int = 1,
    correlation_id: str = "",
    ts: datetime | None = None,
) -> EventEnvelope:
    """Append one FindingCandidate event (the workhorse of these tests)."""
    return await writer.append(
        type="FindingCandidate",
        source=EventSource.MODULE,
        source_detail="xss-detector",
        correlation_id=correlation_id,
        payload=_candidate_payload(finding_id),
        ts=ts,
    )


def _candidate_payload(finding_id: int) -> FindingCandidatePayload:
    """A FindingCandidate payload model."""
    return FindingCandidatePayload(
        finding_id=finding_id, finding_type="xss", endpoint_ref=None, evidence_refs=[]
    )


async def test_append_assigns_monotonic_ids_and_utc_ts(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """Ids grow strictly with append order; ts is timezone-aware UTC (§5.4)."""
    writer, reader, conn, _db = journal_env
    ids: list[int] = []
    for finding_id in range(1, 4):
        envelope = await _append_candidate(writer, finding_id=finding_id)
        ids.append(envelope.id)
        assert envelope.ts.tzinfo is not None
        assert envelope.ts.utcoffset() == timedelta(0)
    assert ids == sorted(ids)
    assert len(set(ids)) == 3
    cursor = await conn.execute("SELECT ts FROM events ORDER BY id LIMIT 1")
    row = await cursor.fetchone()
    assert row is not None
    stored = datetime.fromisoformat(str(row["ts"]))
    assert stored.utcoffset() == timedelta(0)
    assert len(await reader.tail(10)) == 3


async def test_append_stores_source_and_custom_ts(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """The envelope equals the stored row: source enum, detail, given stamp."""
    writer, _reader, conn, _db = journal_env
    stamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    envelope = await _append_candidate(writer, ts=stamp)
    cursor = await conn.execute("SELECT ts, source, type FROM events WHERE id = ?", (envelope.id,))
    row = await cursor.fetchone()
    assert row is not None
    assert str(row["ts"]) == envelope.ts.isoformat()
    assert str(row["source"]) == EventSource.MODULE.value
    assert str(row["type"]) == "FindingCandidate"


async def test_payload_json_round_trip(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """Payloads survive the JSON TEXT column byte-identical (arch §4.3)."""
    writer, reader, _conn, _db = journal_env
    payload = FindingCandidatePayload(
        finding_id=9, finding_type="sqli", endpoint_ref=4, evidence_refs=[1, 2, 3]
    )
    await writer.append(
        type="FindingCandidate",
        source=EventSource.MODULE,
        source_detail="sqli-detector",
        correlation_id="c-1",
        payload=payload,
    )
    (decoded,) = await reader.tail(1)
    assert decoded.payload == payload  # pydantic model equality


async def test_nested_scope_entry_round_trip(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """The sanctioned nested ScopeEntry survives the journal round-trip."""
    writer, reader, _conn, _db = journal_env
    payload = ScopeChangedPayload(
        added=[ScopeEntry(id=3, kind="domain", value="example.com", origin="operator")],
        operator_comment="operator approved",
    )
    await writer.append(
        type="ScopeChanged",
        source=EventSource.PLATFORM,
        source_detail="tui",
        correlation_id="",
        payload=payload,
    )
    (decoded,) = await reader.tail(1)
    assert decoded.payload == payload


async def test_tail_semantics(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """tail(n): last n events, ascending; over-long n returns everything."""
    writer, reader, _conn, _db = journal_env
    for finding_id in range(1, 5):
        await _append_candidate(writer, finding_id=finding_id)
    tail2 = await reader.tail(2)
    assert [envelope.id for envelope in tail2] == [3, 4]
    assert (await reader.tail(0)) == []
    tail_all = await reader.tail(99)
    assert [envelope.id for envelope in tail_all] == [1, 2, 3, 4]


async def test_range_semantics(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """range(from_id): events with id > from_id, ascending (resume path)."""
    writer, reader, _conn, _db = journal_env
    for finding_id in range(1, 5):
        await _append_candidate(writer, finding_id=finding_id)
    after_two = await reader.range(2)
    assert [envelope.id for envelope in after_two] == [3, 4]
    assert len(await reader.range(0)) == 4
    assert (await reader.range(4)) == []


async def test_by_correlation_rebuilds_the_chain(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """by_correlation returns one chain in id order (synthetic data)."""
    writer, reader, _conn, _db = journal_env
    await _append_candidate(writer, finding_id=1, correlation_id="chain-1")
    await _append_candidate(writer, finding_id=2, correlation_id="chain-2")
    await _append_candidate(writer, finding_id=3, correlation_id="chain-1")
    chain = await reader.by_correlation("chain-1")
    assert [envelope.payload.finding_id for envelope in chain] == [1, 3]
    assert (await reader.by_correlation("missing")) == []


async def test_by_type_filters(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """by_type returns only the events of that type, ascending."""
    writer, reader, _conn, _db = journal_env
    await _append_candidate(writer, finding_id=1)
    await writer.append(
        type="OperatorMessage",
        source=EventSource.PLATFORM,
        source_detail="tui",
        correlation_id="",
        payload=OperatorMessagePayload(text_digest="<digest>"),
    )
    await _append_candidate(writer, finding_id=2)
    candidates = await reader.by_type("FindingCandidate")
    assert [envelope.id for envelope in candidates] == [1, 3]
    assert [envelope.payload.finding_id for envelope in candidates] == [1, 2]
    assert (await reader.by_type("TargetSet")) == []


async def test_append_only_enforced_by_triggers(
    journal_env: tuple[JournalWriter, JournalReader, aiosqlite.Connection, Database],
) -> None:
    """UPDATE and DELETE on events are rejected at the DB level (arch §4.3)."""
    writer, _reader, conn, _db = journal_env
    await _append_candidate(writer, finding_id=1)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await conn.execute("UPDATE events SET type = 'Tampered'")
    await conn.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await conn.execute("DELETE FROM events")
    await conn.rollback()
