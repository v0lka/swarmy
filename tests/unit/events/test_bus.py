"""EventBus tests: queues, filtering, isolation, unsubscribe, close (T1.3.3).

Acceptance criteria under test: per-subscriber queues, subscription type
filters (None = all), handler-exception isolation with logging, unsubscribe
stops delivery, and ``close()`` joins every dispatcher task.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from swarmy.events.bus import EventBus
from swarmy.events.models import (
    EventEnvelope,
    EventSource,
    FindingCandidatePayload,
    OperatorMessagePayload,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def _envelope(event_id: int, event_type: str) -> EventEnvelope:
    """Build a valid envelope of the given registered type."""
    payload: FindingCandidatePayload | OperatorMessagePayload
    if event_type == "FindingCandidate":
        payload = FindingCandidatePayload(
            finding_id=event_id, finding_type="xss", endpoint_ref=None, evidence_refs=[]
        )
    else:
        payload = OperatorMessagePayload(text_digest="<digest>")
    return EventEnvelope(
        id=event_id,
        ts=datetime.now(UTC),
        type=event_type,
        source=EventSource.PLATFORM,
        source_detail="test",
        payload=payload,
    )


class _Recorder:
    """Subscriber stub collecting envelopes in delivery order."""

    def __init__(self) -> None:
        self.events: list[EventEnvelope] = []

    async def __call__(self, envelope: EventEnvelope) -> None:
        self.events.append(envelope)


async def _until(predicate: Callable[[], bool], max_wait: float = 2.0) -> None:
    """Await until predicate() holds; fail loudly on timeout."""
    deadline = time.monotonic() + max_wait
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail("condition not reached within timeout")
        await asyncio.sleep(0.01)


async def test_each_subscriber_has_its_own_queue() -> None:
    """Two subscribers both receive every event, each in publish order."""
    bus = EventBus()
    first, second = _Recorder(), _Recorder()
    bus.subscribe(first)
    bus.subscribe(second)
    for event_id in (1, 2):
        await bus.publish(_envelope(event_id, "OperatorMessage"))
    await _until(lambda: len(first.events) == 2 and len(second.events) == 2)
    assert [envelope.id for envelope in first.events] == [1, 2]
    assert [envelope.id for envelope in second.events] == [1, 2]


async def test_type_filter_selects_matching_events_only() -> None:
    """A typed subscription sees only its types; None sees everything (§5.3)."""
    bus = EventBus()
    narrow, wide = _Recorder(), _Recorder()
    bus.subscribe(narrow, types=frozenset({"FindingCandidate"}))
    bus.subscribe(wide)
    await bus.publish(_envelope(1, "FindingCandidate"))
    await bus.publish(_envelope(2, "OperatorMessage"))
    await _until(lambda: len(wide.events) == 2)
    assert [envelope.id for envelope in narrow.events] == [1]
    assert [envelope.id for envelope in wide.events] == [1, 2]


async def test_handler_exception_is_isolated_and_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A raising handler is logged; its subscriber continues; others unaffected."""
    bus = EventBus()
    survivor, fragile = _Recorder(), _Recorder()

    async def flaky(envelope: EventEnvelope) -> None:
        fragile.events.append(envelope)
        if envelope.id == 1:
            raise RuntimeError("handler exploded")

    bus.subscribe(flaky)
    bus.subscribe(survivor)
    with caplog.at_level(logging.ERROR, logger="swarmy.events"):
        await bus.publish(_envelope(1, "OperatorMessage"))
        await bus.publish(_envelope(2, "OperatorMessage"))
        await _until(lambda: len(survivor.events) == 2 and len(fragile.events) == 2)
    assert [envelope.id for envelope in fragile.events] == [1, 2]
    error_records = [record for record in caplog.records if record.name == "swarmy.events"]
    assert error_records
    failed = error_records[0]
    assert failed.exc_info is not None  # logged with the full traceback (§5.3)
    assert "id=1" in failed.getMessage()
    assert any(envelope.id == 1 for envelope in survivor.events)


async def test_unsubscribe_stops_delivery() -> None:
    """After unsubscribe the dispatcher is cancelled and receives nothing."""
    bus = EventBus()
    recorder = _Recorder()
    subscription = bus.subscribe(recorder)
    await bus.publish(_envelope(1, "OperatorMessage"))
    await _until(lambda: len(recorder.events) == 1)
    subscription.unsubscribe()  # idempotent: a second call is a no-op
    subscription.unsubscribe()
    with contextlib.suppress(asyncio.CancelledError):
        await subscription.task
    assert subscription.task.cancelled()
    await bus.publish(_envelope(2, "OperatorMessage"))
    await asyncio.sleep(0.05)
    assert [envelope.id for envelope in recorder.events] == [1]


async def test_close_joins_all_dispatcher_tasks() -> None:
    """close() cancels and awaits every dispatcher; bus is empty afterwards."""
    bus = EventBus()
    subs = [bus.subscribe(_Recorder()) for _ in range(3)]
    await bus.publish(_envelope(1, "OperatorMessage"))
    await bus.close()
    assert all(sub.task.done() for sub in subs)
    await bus.publish(_envelope(2, "OperatorMessage"))  # no subscribers left
    await asyncio.sleep(0.05)
    assert bus._subs == []  # every subscription detached (§5.3 close)
