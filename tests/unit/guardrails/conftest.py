"""Shared fixtures of the guardrails suite (arch §15.1, T1.4.5/T1.4.6).

Provides the journal+bus wiring the violation-semantics tests need: a real
SQLite ``events`` connection, a ``JournalWriter``/``JournalReader`` pair, an
``EventBus`` and a ``blocked_sink`` with the canonical order — journal
append *before* bus fan-out (arch §5.3) — exactly how the engine wiring
binds the pipeline in production.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.events import EventBus, EventSource, JournalReader, JournalWriter
from swarmy.guardrails.models import BlockedFeedback, GuardrailLayer
from swarmy.memory.schema import MIGRATIONS

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from swarmy.events.bus import Subscription
    from swarmy.events.models import EventEnvelope, GuardrailBlockedPayload


class RecordingSink:
    """Violation sink with the production order: journal first, then bus.

    Records the appended envelopes so tests can assert on ids, and lets the
    bus-side probe verify the journal-first property at delivery time.
    """

    def __init__(self, journal: JournalWriter, bus: EventBus, reader: JournalReader) -> None:
        self._journal = journal
        self._bus = bus
        self._reader = reader
        self.envelopes: list[EventEnvelope] = []
        self.in_journal_at_publish: list[bool] = []

    async def __call__(self, payload: GuardrailBlockedPayload) -> None:
        """Append the GuardrailBlocked event, then fan it out (arch §5.3)."""
        envelope = await self._journal.append(
            type="GuardrailBlocked",
            source=EventSource.PLATFORM,
            source_detail="guardrails",
            correlation_id="",
            payload=payload,
        )
        self.envelopes.append(envelope)
        self.in_journal_at_publish.append(
            bool(await self._reader.by_type("GuardrailBlocked"))
        )
        await self._bus.publish(envelope)


class BusProbe:
    """Subscriber asserting the event was durable when delivery happened."""

    def __init__(self, reader: JournalReader) -> None:
        self._reader = reader
        self.delivered: list[EventEnvelope] = []
        self.in_journal_at_delivery: list[bool] = []

    async def __call__(self, envelope: EventEnvelope) -> None:
        """Record delivery and re-read the journal synchronously."""
        journal_events = await self._reader.by_type("GuardrailBlocked")
        self.in_journal_at_delivery.append(
            any(event.id == envelope.id for event in journal_events)
        )
        self.delivered.append(envelope)


class ToolSpy:
    """Spy handler standing in for the L0 tool execution (no network)."""

    def __init__(self) -> None:
        self.calls: list[object] = []

    async def __call__(self, request: object) -> object:
        """Record the call and return the tool's would-be result."""
        self.calls.append(request)
        return "tool-was-executed"


@pytest.fixture
async def guardrails_env(
    tmp_path: Path,
) -> AsyncIterator[
    tuple[JournalWriter, JournalReader, EventBus, RecordingSink, BusProbe, Subscription]
]:
    """Real database + journal + bus + recording sink, wired for one test."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn = await db.connection("events")
    writer = JournalWriter(conn)
    reader = JournalReader(conn)
    bus = EventBus()
    sink = RecordingSink(writer, bus, reader)
    probe = BusProbe(reader)
    subscription = bus.subscribe(probe)
    yield writer, reader, bus, sink, probe, subscription
    await bus.close()
    await db.close()


def make_feedback(
    rule_id: str = "invariant:platform-http",
    layer: GuardrailLayer = "invariant",
    reason: str = "blocked for testing",
) -> BlockedFeedback:
    """Build a feedback triple for feedback-rendering tests."""
    return BlockedFeedback(rule_id=rule_id, layer=layer, reason=reason)
