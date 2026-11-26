"""Append-only event journal over the ``events`` table (arch §5.4, T1.3.2).

``JournalWriter`` performs exactly one operation — INSERT (the table itself
rejects UPDATE/DELETE via schema triggers, arch §4.3). SQLite assigns the
monotonic ``id``; the write is committed *before* the envelope is returned,
which is what makes the journal-first order of arch §5.3 real: anything the
bus ever delivers is already durable.

``JournalReader`` gives the four read models of arch §5.4: ``tail`` (TUI
session open), ``range`` (resume catch-up), ``by_correlation`` (audit trail
of a delegation/finding chain) and ``by_type`` (statistics).

Field formats follow arch §4.3: ``payload`` is a JSON string of the payload
model, ``ts`` is UTC ISO-8601.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from swarmy.events.models import (
    EventEnvelope,
    EventRegistry,
    EventSource,
    UnknownEventPayload,
)

if TYPE_CHECKING:
    import aiosqlite
    from pydantic import BaseModel

_APPEND_SQL = (
    "INSERT INTO events (ts, type, source, source_detail, correlation_id, payload)"
    " VALUES (?, ?, ?, ?, ?, ?)"
)
_TAIL_SQL = (
    "SELECT * FROM (SELECT * FROM events ORDER BY id DESC LIMIT ?) ORDER BY id"
)
_RANGE_SQL = "SELECT * FROM events WHERE id > ? ORDER BY id"
_BY_CORRELATION_SQL = "SELECT * FROM events WHERE correlation_id = ? ORDER BY id"
_BY_TYPE_SQL = "SELECT * FROM events WHERE type = ? ORDER BY id"


def _utc_moment(ts: datetime | None) -> str:
    """Normalize an optional stamp to a UTC ISO-8601 TEXT value (arch §4.3)."""
    moment = ts if ts is not None else datetime.now(UTC)
    if moment.tzinfo is None:  # defensive: treat a naive stamp as UTC
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat()


def _payload_dict(raw: object, event_id: int) -> dict[str, object]:
    """Decode a stored payload JSON TEXT value into a mapping (arch §4.3)."""
    decoded = json.loads(str(raw))
    if not isinstance(decoded, dict):
        msg = f"corrupt journal row {event_id}: payload is not a JSON object"
        raise RuntimeError(msg)
    return decoded


def _envelope_from_row(row: aiosqlite.Row) -> EventEnvelope:
    """Decode one ``events`` row into a fully typed envelope.

    Tolerant decode (consolidated review #7/#29 ↔ F-5): a row whose type is
    absent from ``EventRegistry`` in this process (unloaded module, journal
    written by a newer build) decodes with an :class:`UnknownEventPayload`
    placeholder instead of raising — one unknown row must never brick
    resume/report/TUI reads. Corruption of a *known* type (non-object JSON,
    schema-invalid payload) still fails loudly.
    """
    event_id = int(row["id"])
    event_type = str(row["type"])
    raw_payload_text = str(row["payload"])
    raw = _payload_dict(raw_payload_text, event_id)
    try:
        payload = EventRegistry.create(event_type, raw)
    except KeyError:
        payload = UnknownEventPayload(
            original_type=event_type,
            raw_payload=raw_payload_text,
        )
    return EventEnvelope(
        id=event_id,
        ts=datetime.fromisoformat(str(row["ts"])),
        type=event_type,
        source=EventSource(str(row["source"])),
        source_detail=str(row["source_detail"]),
        correlation_id=str(row["correlation_id"]),
        payload=payload,
    )


class JournalWriter:
    """INSERT-only writer of the ``events`` journal (arch §5.4)."""

    def __init__(self, events_connection: aiosqlite.Connection) -> None:
        """Bind the writer to the journal subsystem's dedicated connection."""
        self._conn = events_connection

    async def append(
        self,
        type: str,
        source: EventSource,
        source_detail: str,
        correlation_id: str,
        payload: BaseModel,
        ts: datetime | None = None,
    ) -> EventEnvelope:
        """Append one event and return its envelope with the SQLite id.

        The INSERT is committed before this call returns — append happens
        before any fan-out (journal-first, arch §5.3). ``payload`` is stored
        as ``model_dump_json()``; ``ts`` defaults to now (UTC). The id is
        taken from the INSERT cursor itself (``lastrowid`` — per-cursor
        state), not from a follow-up ``SELECT last_insert_rowid()``: two
        concurrent emissions interleave at ``await`` boundaries, and a
        follow-up read could return another writer's row (consolidated
        review #52).
        """
        ts_text = _utc_moment(ts)
        cursor = await self._conn.execute(
            _APPEND_SQL,
            (
                ts_text,
                type,
                source.value,
                source_detail,
                correlation_id,
                payload.model_dump_json(),
            ),
        )
        row_id = cursor.lastrowid
        if row_id is None:
            msg = "journal INSERT did not yield a rowid"
            raise RuntimeError(msg)
        await self._conn.commit()  # durable before any fan-out sees the id
        return EventEnvelope(
            id=row_id,
            ts=datetime.fromisoformat(ts_text),
            type=type,
            source=source,
            source_detail=source_detail,
            correlation_id=correlation_id,
            payload=payload,
        )


class JournalReader:
    """Read models over the append-only journal (arch §5.4)."""

    def __init__(self, events_connection: aiosqlite.Connection) -> None:
        """Bind the reader to the journal subsystem's dedicated connection."""
        self._conn = events_connection

    async def tail(self, n: int) -> list[EventEnvelope]:
        """Last ``n`` events, ascending by id (TUI session open, arch §5.4)."""
        cursor = await self._conn.execute(_TAIL_SQL, (n,))
        rows = await cursor.fetchall()
        return [_envelope_from_row(row) for row in rows]

    async def range(self, from_id: int) -> list[EventEnvelope]:
        """All events with ``id > from_id``, ascending (resume catch-up)."""
        cursor = await self._conn.execute(_RANGE_SQL, (from_id,))
        rows = await cursor.fetchall()
        return [_envelope_from_row(row) for row in rows]

    async def by_correlation(self, correlation_id: str) -> list[EventEnvelope]:
        """The full chain of one correlation id, ascending (audit, arch §5.4)."""
        cursor = await self._conn.execute(_BY_CORRELATION_SQL, (correlation_id,))
        rows = await cursor.fetchall()
        return [_envelope_from_row(row) for row in rows]

    async def by_type(self, type: str) -> list[EventEnvelope]:
        """All events of one type, ascending (statistics, arch §5.4)."""
        cursor = await self._conn.execute(_BY_TYPE_SQL, (type,))
        rows = await cursor.fetchall()
        return [_envelope_from_row(row) for row in rows]
