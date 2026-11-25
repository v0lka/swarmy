"""Contour test «event → journal → subscribers» (T1.3.5, arch §5.3/§5.4).

The canonical proof of the durability-before-delivery property:

* N events emitted through the real ``emit_event`` tool against a real
  SQLite ``Database`` (no mocks);
* every subscriber receives them in ascending journal-id order;
* *inside* a handler the journal already contains the event being delivered
  (journal-first: append happens before fan-out);
* a filtered subscriber sees only its own types;
* ``tail``/``range``/``by_type`` stay consistent with the emitted stream,
  and a fresh reader (resume catch-up) reads the same tail.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.events import (
    EmitEventTool,
    EventBus,
    EventSource,
    JournalReader,
    JournalWriter,
    make_emit_tool,
)
from swarmy.memory.schema import MIGRATIONS

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    import aiosqlite

    from swarmy.events.models import EventEnvelope

_N_EVENTS = 6
_CHAIN_ID = "chain-1"


class _JournalProbe:
    """Subscriber asserting journal-first: the event is durable at delivery."""

    def __init__(self, reader: JournalReader) -> None:
        self._reader = reader
        self.delivered_ids: list[int] = []
        self.in_journal_at_delivery: list[bool] = []

    async def __call__(self, envelope: EventEnvelope) -> None:
        chain = await self._reader.by_correlation(envelope.correlation_id)
        self.in_journal_at_delivery.append(
            any(event.id == envelope.id for event in chain)
        )
        self.delivered_ids.append(envelope.id)


class _Recorder:
    """Plain subscriber stub."""

    def __init__(self) -> None:
        self.events: list[EventEnvelope] = []

    async def __call__(self, envelope: EventEnvelope) -> None:
        self.events.append(envelope)


@pytest.fixture
async def contour_env(
    tmp_path: Path,
) -> AsyncIterator[
    tuple[aiosqlite.Connection, JournalReader, _JournalProbe, _Recorder, _Recorder]
]:
    """Real database + bus + three subscribers, after emitting N events."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn = await db.connection("events")
    writer = JournalWriter(conn)
    reader = JournalReader(conn)
    bus = EventBus()
    probe = _JournalProbe(reader)
    everything = _Recorder()
    findings_only = _Recorder()
    probe_sub = bus.subscribe(probe)
    everything_sub = bus.subscribe(everything)
    findings_sub = bus.subscribe(findings_only, types=frozenset({"FindingCandidate"}))
    emit = make_emit_tool(
        journal=writer,
        bus=bus,
        source=EventSource.PLATFORM,
        source_detail="contour-test",
    )
    chain_emit: EmitEventTool = make_emit_tool(
        journal=writer,
        bus=bus,
        source=EventSource.PLATFORM,
        source_detail="contour-test",
        correlation_provider=lambda: _CHAIN_ID,
    )
    for i in range(_N_EVENTS):
        if i < 3:
            await chain_emit(
                "FindingCandidate",
                {
                    "finding_id": i,
                    "finding_type": "xss",
                    "endpoint_ref": None,
                    "evidence_refs": [],
                },
            )
        else:
            await emit("OperatorMessage", {"text_digest": f"<digest-{i}>"})
    # Deterministic drain: every queued envelope has been handled (task_done)
    # before the test asserts on delivery — no sleeps, no races.
    await asyncio.gather(
        probe_sub.queue.join(), everything_sub.queue.join(), findings_sub.queue.join()
    )
    yield conn, reader, probe, everything, findings_only
    await bus.close()
    await db.close()


async def test_contour_journal_first_delivery_and_catch_up(
    contour_env: tuple[
        aiosqlite.Connection, JournalReader, _JournalProbe, _Recorder, _Recorder
    ],
) -> None:
    """The full contour: ordering, durability-before-delivery, filtering, reads."""
    conn, reader, probe, everything, findings_only = contour_env

    # 1. Journal-first: at delivery time the event was already in the journal.
    assert probe.in_journal_at_delivery == [True] * _N_EVENTS

    # 2. Ascending id order per subscriber (arch §5.3).
    assert probe.delivered_ids == sorted(probe.delivered_ids)
    all_ids = [event.id for event in everything.events]
    assert all_ids == sorted(all_ids)
    assert len(all_ids) == _N_EVENTS

    # 3. Filtered subscriber: only FindingCandidate events.
    finding_ids = [event.id for event in findings_only.events]
    assert len(finding_ids) == 3
    assert set(finding_ids) <= set(all_ids)

    # 4. Reader read models stay consistent with the emitted stream (§5.4).
    tail = await reader.tail(3)
    assert [event.id for event in tail] == all_ids[-3:]
    after_first = await reader.range(all_ids[0])
    assert [event.id for event in after_first] == all_ids[1:]
    by_type = await reader.by_type("FindingCandidate")
    assert [event.id for event in by_type] == finding_ids
    chain = await reader.by_correlation(_CHAIN_ID)
    assert [event.id for event in chain] == all_ids[:3]

    # 5. Resume simulation: a fresh reader over the same connection catch-up.
    resumed = JournalReader(conn)
    catch_up = await resumed.range(all_ids[0] - 1)
    assert [event.id for event in catch_up] == all_ids
