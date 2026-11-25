"""``emit_event`` factory tests (T1.3.4, arch §5.2).

Acceptance criteria under test: a valid call appends to the journal AND
delivers to subscribers; unknown types and invalid payloads are rejected with
agent-addressable ValueErrors and nothing is appended; ``source`` is bound by
the factory (never taken from the caller); the correlation id comes from the
provider (empty string until the runtime installs the delegation context).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.events import (
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

    from swarmy.events import EmitEventTool, EventEnvelope


class _Recorder:
    """Subscriber stub collecting envelopes in delivery order."""

    def __init__(self) -> None:
        self.events: list[EventEnvelope] = []

    async def __call__(self, envelope: EventEnvelope) -> None:
        self.events.append(envelope)


@pytest.fixture
async def emit_env(
    tmp_path: Path,
) -> AsyncIterator[tuple[EmitEventTool, EventBus, JournalReader, _Recorder]]:
    """Real database/journal/bus with a module-bound emit tool and a recorder."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn: aiosqlite.Connection = await db.connection("events")
    writer = JournalWriter(conn)
    reader = JournalReader(conn)
    bus = EventBus()
    recorder = _Recorder()
    bus.subscribe(recorder)
    emit = make_emit_tool(
        journal=writer,
        bus=bus,
        source=EventSource.MODULE,
        source_detail="xss-detector",
    )
    yield emit, bus, reader, recorder
    await bus.close()
    await db.close()


_CANDIDATE: dict[str, object] = {
    "finding_id": 1,
    "finding_type": "xss",
    "endpoint_ref": None,
    "evidence_refs": [],
}


async def test_valid_emit_appends_and_delivers(
    emit_env: tuple[EmitEventTool, EventBus, JournalReader, _Recorder],
) -> None:
    """A valid call returns a confirmation; the event is durable and delivered."""
    emit, _bus, reader, recorder = emit_env
    confirmation = await emit("FindingCandidate", _CANDIDATE)
    assert "FindingCandidate" in confirmation
    assert "id=" in confirmation
    journal_tail = await reader.tail(5)
    assert [envelope.type for envelope in journal_tail] == ["FindingCandidate"]
    await asyncio.sleep(0.05)
    assert [envelope.type for envelope in recorder.events] == ["FindingCandidate"]
    envelope = recorder.events[0]
    assert envelope.source is EventSource.MODULE  # bound by the factory, §5.2
    assert envelope.source_detail == "xss-detector"
    assert envelope.correlation_id == ""


async def test_unknown_type_rejected_without_appending(
    emit_env: tuple[EmitEventTool, EventBus, JournalReader, _Recorder],
) -> None:
    """An unregistered type fails loudly; journal and bus stay untouched."""
    emit, _bus, reader, recorder = emit_env
    with pytest.raises(ValueError, match="unknown event type"):
        await emit("NoSuchType", {})
    assert (await reader.tail(5)) == []
    await asyncio.sleep(0.05)
    assert recorder.events == []


async def test_invalid_payload_rejected_without_appending(
    emit_env: tuple[EmitEventTool, EventBus, JournalReader, _Recorder],
) -> None:
    """A payload failing schema validation fails loudly; nothing is stored."""
    emit, _bus, reader, recorder = emit_env
    with pytest.raises(ValueError, match="invalid payload"):
        await emit("FindingCandidate", {"finding_type": "xss"})  # missing finding_id
    assert (await reader.tail(5)) == []
    await asyncio.sleep(0.05)
    assert recorder.events == []


async def test_correlation_provider_feeds_the_envelope(
    tmp_path: Path,
) -> None:
    """The correlation id is taken from the provider (contextvar stand-in)."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn = await db.connection("events")
    writer = JournalWriter(conn)
    reader = JournalReader(conn)
    bus = EventBus()
    emit = make_emit_tool(
        journal=writer,
        bus=bus,
        source=EventSource.ORCHESTRATOR,
        source_detail="orchestrator",
        correlation_provider=lambda: "task-42",
    )
    await emit("OperatorMessage", {"text_digest": "<digest>"})
    (tail_last,) = await reader.tail(1)
    assert tail_last.correlation_id == "task-42"
    (stored,) = await reader.by_correlation("task-42")
    assert stored.correlation_id == "task-42"
    assert stored.source is EventSource.ORCHESTRATOR
    await bus.close()
    await db.close()
