"""Typed domain CRUD over the SQLite memory (arch §4.4, roadmap T1.2.5).

``MemoryStore`` is the only writer of the domain tables (arch §4.3); every
public method maps to one platform tool of ``tools/platform.py`` (prefix
``memory_``, plus the verification-only ``update_finding_status``). The store
publishes no events itself - platform wrappers publish after a successful
mutation (§5.2: the event is created by the platform, not by the agent).

JSON encode/decode helpers are private to this module: multi-value fields
(``tags``, ``examples``, ``evidence_refs``, ...) travel as JSON TEXT and
datetimes as UTC ISO-8601 TEXT (arch §4.3).
"""

from __future__ import annotations

import asyncio
import json
import random
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from swarmy.memory.models import (
    AttackEdge,
    AttackNode,
    Endpoint,
    EntityType,
    Evidence,
    Fact,
    Finding,
    FindingStatus,
    Note,
    Parameter,
    ScopeEntry,
    Severity,
    Target,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import aiosqlite

    from swarmy.core.database import Database
    from swarmy.memory.models import (
        AttackEdgeDraft,
        AttackNodeDraft,
        EndpointDraft,
        EvidenceDraft,
        FactDraft,
        FindingDraft,
        NoteDraft,
        ParameterDraft,
        SearchableEntity,
        SearchHit,
    )
    from swarmy.memory.search import SearchIndex

# Concrete model union returned by `get` (arch §4.4).
_DomainModel = (
    Target
    | ScopeEntry
    | Endpoint
    | Parameter
    | Finding
    | Evidence
    | AttackNode
    | AttackEdge
    | Note
    | Fact
)

# ---------------------------------------------------------------------------
# JSON helpers (arch §4.3: multi-value fields are JSON TEXT) - private.
# ---------------------------------------------------------------------------


def _dumps(value: object) -> str:
    """Encode a JSON column value (compact, lossless for our models)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _json_str_list(raw: object) -> list[str]:
    """Decode a JSON TEXT column into ``list[str]``."""
    value = json.loads(str(raw))
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _json_int_list(raw: object) -> list[int]:
    """Decode a JSON TEXT column into ``list[int]``."""
    value = json.loads(str(raw))
    if not isinstance(value, list):
        return []
    return [int(item) for item in value]


def _json_dict(raw: object) -> dict[str, str]:
    """Decode a JSON TEXT column into ``dict[str, str]``."""
    value = json.loads(str(raw))
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _utcnow_iso() -> str:
    """Current UTC time as ISO-8601 TEXT (arch §4.3 datetime format)."""
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Row decoders: SQLite rows -> concrete Pydantic models (arch §4.4 `get`).
# ---------------------------------------------------------------------------


def _target_from(row: sqlite3.Row) -> Target:
    """Decode one ``target`` row."""
    return Target.model_validate(
        {
            "id": int(row["id"]),
            "base_url": str(row["base_url"]),
            "stack_metadata": _json_dict(row["stack_metadata"]),
        }
    )


def _scope_entry_from(row: sqlite3.Row) -> ScopeEntry:
    """Decode one ``scope_entries`` row."""
    return ScopeEntry.model_validate(
        {
            "id": int(row["id"]),
            "kind": str(row["kind"]),
            "value": str(row["value"]),
            "origin": str(row["origin"]),
        }
    )


def _endpoint_from(row: sqlite3.Row) -> Endpoint:
    """Decode one ``endpoints`` row."""
    return Endpoint.model_validate(
        {
            "id": int(row["id"]),
            "host": str(row["host"]),
            "method": str(row["method"]),
            "path": str(row["path"]),
            "auth_requirements": _json_str_list(row["auth_requirements"]),
            "research_status": str(row["research_status"]),
            "out_of_scope": bool(row["out_of_scope"]),
            "notes": str(row["notes"]),
        }
    )


def _parameter_from(row: sqlite3.Row) -> Parameter:
    """Decode one ``parameters`` row."""
    return Parameter.model_validate(
        {
            "id": int(row["id"]),
            "endpoint_id": int(row["endpoint_id"]),
            "name": str(row["name"]),
            "location": str(row["location"]),
            "type": str(row["type"]),
            "examples": _json_str_list(row["examples"]),
        }
    )


def _finding_from(row: sqlite3.Row) -> Finding:
    """Decode one ``findings`` row."""
    return Finding.model_validate(
        {
            "id": int(row["id"]),
            "type": str(row["type"]),
            "status": str(row["status"]),
            "severity": str(row["severity"]),
            "cvss_vector": None if row["cvss_vector"] is None else str(row["cvss_vector"]),
            "endpoint_ref": None if row["endpoint_ref"] is None else int(row["endpoint_ref"]),
            "evidence_refs": _json_int_list(row["evidence_refs"]),
            "title": str(row["title"]),
            "description": str(row["description"]),
            "reproduction": _json_str_list(row["reproduction"]),
            "created_by": str(row["created_by"]),
            "created_at": str(row["created_at"]),
        }
    )


def _evidence_from(row: sqlite3.Row) -> Evidence:
    """Decode one ``evidence`` row."""
    return Evidence.model_validate(
        {
            "id": int(row["id"]),
            "kind": str(row["kind"]),
            "session_paths": _json_str_list(row["session_paths"]),
            "finding_ref": None if row["finding_ref"] is None else int(row["finding_ref"]),
            "metadata": _json_dict(row["metadata"]),
            "created_at": str(row["created_at"]),
        }
    )


def _attack_node_from(row: sqlite3.Row) -> AttackNode:
    """Decode one ``attack_nodes`` row."""
    return AttackNode.model_validate(
        {
            "id": int(row["id"]),
            "kind": str(row["kind"]),
            "finding_ref": None if row["finding_ref"] is None else int(row["finding_ref"]),
            "title": str(row["title"]),
            "description": str(row["description"]),
        }
    )


def _attack_edge_from(row: sqlite3.Row) -> AttackEdge:
    """Decode one ``attack_edges`` row."""
    return AttackEdge.model_validate(
        {
            "id": int(row["id"]),
            "src": int(row["src"]),
            "dst": int(row["dst"]),
            "kind": str(row["kind"]),
        }
    )


def _note_from(row: sqlite3.Row) -> Note:
    """Decode one ``notes`` row."""
    return Note.model_validate(
        {
            "id": int(row["id"]),
            "text": str(row["text"]),
            "tags": _json_str_list(row["tags"]),
            "author": str(row["author"]),
            "created_at": str(row["created_at"]),
        }
    )


def _fact_from(row: sqlite3.Row) -> Fact:
    """Decode one ``facts`` row."""
    return Fact.model_validate(
        {
            "id": int(row["id"]),
            "subject": str(row["subject"]),
            "predicate": str(row["predicate"]),
            "obj": str(row["obj"]),
            "tags": _json_str_list(row["tags"]),
            "source": str(row["source"]),
            "created_at": str(row["created_at"]),
        }
    )


# ---------------------------------------------------------------------------
# Transaction discipline (#52/#53) - private.
# ---------------------------------------------------------------------------

class MemoryStoreBusy(RuntimeError):
    """A multi-step memory mutation could not start its write transaction.

    Raised after the bounded ``BEGIN IMMEDIATE`` retry budget is exhausted
    (consolidated review #53). The message is agent-addressable: the
    platform ``memory_*`` tool result tells the caller to retry, instead of
    surfacing a raw sqlite error.
    """


#: BEGIN IMMEDIATE retry budget (consolidated review #53). The connection's
#: ``busy_timeout`` (core.database, 5 s) already waits out cross-connection
#: lock contention; what remains is same-connection interleaving — two
#: coroutines reaching BEGIN on the one shared memory connection between
#: awaits — which fails immediately with "cannot start a transaction within
#: a transaction" until the other writer commits. A short bounded backoff
#: with jitter rides out that window. Module constants so tests can shrink
#: the delays.
_TX_BEGIN_ATTEMPTS = 5
_TX_RETRY_BASE_DELAY_S = 0.02
_TX_RETRY_JITTER_S = 0.05

#: Finding lifecycle transition matrix (RD-5, §4.2; consolidated review #12):
#: candidate → verified | rejected, verified → rejected. Re-setting the
#: current status is always allowed (severity update path).
_ALLOWED_STATUS_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.CANDIDATE: frozenset({FindingStatus.VERIFIED, FindingStatus.REJECTED}),
    FindingStatus.VERIFIED: frozenset({FindingStatus.REJECTED}),
    FindingStatus.REJECTED: frozenset(),
}


def _insert_row_id(cursor: aiosqlite.Cursor) -> int:
    """Return the rowid assigned to *this* INSERT cursor (#52).

    ``cursor.lastrowid`` is per-cursor state and immune to concurrent
    writers on the shared connection — unlike a follow-up
    ``SELECT last_insert_rowid()``, which a concurrent INSERT between the
    two awaits can hijack (the id would silently point at another row).
    """
    row_id = cursor.lastrowid
    if row_id is None:
        msg = "INSERT did not yield a rowid"
        raise RuntimeError(msg)
    return row_id


# ---------------------------------------------------------------------------
# Literal SQL (no composed table names) + the `get` dispatch table (§4.4).
# ---------------------------------------------------------------------------

_ENDPOINT_EXISTS_SQL = "SELECT id FROM endpoints WHERE id = ?"
_ENDPOINT_BY_KEY_SQL = "SELECT * FROM endpoints WHERE host = ? AND method = ? AND path = ?"
_ENDPOINT_BY_ID_SQL = "SELECT * FROM endpoints WHERE id = ?"
_ENDPOINT_INSERT_SQL = (
    "INSERT INTO endpoints"
    " (host, method, path, auth_requirements, research_status, out_of_scope, notes)"
    " VALUES (?, ?, ?, ?, ?, ?, ?)"
)
_ENDPOINT_UPDATE_SQL = (
    "UPDATE endpoints SET auth_requirements = ?, research_status = ?,"
    " out_of_scope = ?, notes = ? WHERE id = ?"
)
_PARAMETER_SELECT_SQL = (
    "SELECT id FROM parameters WHERE endpoint_id = ? AND name = ? AND location = ?"
)
_PARAMETER_INSERT_SQL = (
    "INSERT INTO parameters (endpoint_id, name, location, type, examples)"
    " VALUES (?, ?, ?, ?, ?)"
)
_PARAMETER_UPDATE_SQL = "UPDATE parameters SET type = ?, examples = ? WHERE id = ?"
_PARAMETERS_BY_ENDPOINT_SQL = "SELECT * FROM parameters WHERE endpoint_id = ? ORDER BY id"
_FINDING_BY_ID_SQL = "SELECT * FROM findings WHERE id = ?"
_FINDING_EXISTS_SQL = "SELECT id FROM findings WHERE id = ?"
_FINDING_INSERT_SQL = (
    "INSERT INTO findings"
    " (type, status, severity, cvss_vector, endpoint_ref, evidence_refs,"
    " title, description, reproduction, created_by, created_at)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_EVIDENCE_EXISTS_SQL = "SELECT id FROM evidence WHERE id = ?"
_EVIDENCE_ATTACH_SQL = "UPDATE evidence SET finding_ref = ? WHERE id = ?"
_EVIDENCE_BY_ID_SQL = "SELECT * FROM evidence WHERE id = ?"
_EVIDENCE_INSERT_SQL = (
    "INSERT INTO evidence (kind, session_paths, metadata, created_at) VALUES (?, ?, ?, ?)"
)
_FINDING_UPDATE_STATUS_SQL = "UPDATE findings SET status = ? WHERE id = ?"
_FINDING_UPDATE_SEVERITY_SQL = "UPDATE findings SET status = ?, severity = ? WHERE id = ?"
_ATTACK_NODE_BY_ID_SQL = "SELECT * FROM attack_nodes WHERE id = ?"
_ATTACK_NODE_EXISTS_SQL = "SELECT id FROM attack_nodes WHERE id = ?"
_ATTACK_NODE_INSERT_SQL = (
    "INSERT INTO attack_nodes (kind, finding_ref, title, description)"
    " VALUES (?, ?, ?, ?)"
)
_ATTACK_EDGE_INSERT_SQL = "INSERT INTO attack_edges (src, dst, kind) VALUES (?, ?, ?)"
_FACT_BY_ID_SQL = "SELECT * FROM facts WHERE id = ?"
_FACTS_BY_SUBJECT_SQL = "SELECT * FROM facts WHERE subject = ? ORDER BY id"
_FACT_INSERT_SQL = (
    "INSERT INTO facts (subject, predicate, obj, tags, source, created_at)"
    " VALUES (?, ?, ?, ?, ?, ?)"
)
_NOTE_BY_ID_SQL = "SELECT * FROM notes WHERE id = ?"
_NOTE_INSERT_SQL = "INSERT INTO notes (text, tags, author, created_at) VALUES (?, ?, ?, ?)"
_TARGET_INSERT_SQL = "INSERT INTO target (base_url) VALUES (?)"

_GET_SPECS: dict[EntityType, tuple[str, Callable[[sqlite3.Row], _DomainModel]]] = {
    EntityType.TARGET: ("SELECT * FROM target WHERE id = ?", _target_from),
    EntityType.SCOPE_ENTRY: ("SELECT * FROM scope_entries WHERE id = ?", _scope_entry_from),
    EntityType.ENDPOINT: (_ENDPOINT_BY_ID_SQL, _endpoint_from),
    EntityType.PARAMETER: ("SELECT * FROM parameters WHERE id = ?", _parameter_from),
    EntityType.FINDING: (_FINDING_BY_ID_SQL, _finding_from),
    EntityType.EVIDENCE: ("SELECT * FROM evidence WHERE id = ?", _evidence_from),
    EntityType.ATTACK_NODE: (_ATTACK_NODE_BY_ID_SQL, _attack_node_from),
    EntityType.ATTACK_EDGE: ("SELECT * FROM attack_edges WHERE id = ?", _attack_edge_from),
    EntityType.NOTE: (_NOTE_BY_ID_SQL, _note_from),
    EntityType.FACT: (_FACT_BY_ID_SQL, _fact_from),
}


class MemoryStore:
    """Typed facade over the domain tables - the API table of arch §4.4."""

    def __init__(self, db: Database, search: SearchIndex) -> None:
        """Bind the store to one open ``Database`` and a search backend."""
        self._db = db
        self._search = search
        self._conn: aiosqlite.Connection | None = None

    async def _memory(self) -> aiosqlite.Connection:
        """One dedicated connection per subsystem (AD-6): subsystem ``memory``."""
        if self._conn is None:
            self._conn = await self._db.connection("memory")
        return self._conn

    async def _begin_write(self, conn: aiosqlite.Connection) -> None:
        """``BEGIN IMMEDIATE`` with bounded retry + jitter (#53).

        A concurrent multi-step mutation on the same shared connection can
        leave this BEGIN arriving inside that writer's open transaction;
        the sqlite error is transient (it clears when the other writer
        commits), so a short bounded backoff retries it. On exhaustion the
        failure surfaces as :class:`MemoryStoreBusy` — an agent-facing
        message, never a raw sqlite traceback.
        """
        for attempt in range(1, _TX_BEGIN_ATTEMPTS + 1):
            try:
                await conn.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.OperationalError as exc:
                if attempt == _TX_BEGIN_ATTEMPTS:
                    msg = (
                        "memory subsystem is busy: could not start a write "
                        f"transaction after {_TX_BEGIN_ATTEMPTS} attempts; "
                        "retry the call"
                    )
                    raise MemoryStoreBusy(msg) from exc
                await asyncio.sleep(
                    _TX_RETRY_BASE_DELAY_S + random.uniform(0.0, _TX_RETRY_JITTER_S)
                )

    async def save_target(self, base_url: str) -> Target:
        """Insert the session target row and return it (§4.2, T3.1.2).

        Called exactly once by the session composition root when a session
        folder is created (``Session.open``); ``resume`` must not call it —
        the row already exists and ``TargetSet`` is not re-emitted. There is
        no update path in v0.1: one session, one target (spec §6.1).
        """
        conn = await self._memory()
        await self._begin_write(conn)
        try:
            cursor = await conn.execute(_TARGET_INSERT_SQL, (base_url,))
            target_id = _insert_row_id(cursor)
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
        # The TARGET spec in _GET_SPECS decodes rows with _target_from, so a
        # fetched row is always a Target; ``get`` is typed for the union of
        # all domain models (§4.4 memory_get), hence the narrow cast.
        return cast("Target", await self.get(EntityType.TARGET, target_id))

    async def search(
        self,
        query: str,
        entity_types: list[SearchableEntity] | None = None,
        limit: int = 20,
    ) -> list[SearchHit]:
        """FTS5 search, filtered by entity kinds (arch §4.4: ``memory_search``)."""
        return await self._search.search(query, entity_types, limit)

    async def get(self, entity_type: EntityType, id: int) -> _DomainModel:
        """Return one domain entity as its concrete model (§4.4: ``memory_get``).

        Raises ``KeyError`` when the row does not exist.
        """
        conn = await self._memory()
        sql, decode = _GET_SPECS[entity_type]
        cursor = await conn.execute(sql, (id,))
        row = await cursor.fetchone()
        if row is None:
            raise KeyError(f"{entity_type.value} {id} not found")
        return decode(row)

    async def upsert_endpoint(self, draft: EndpointDraft) -> Endpoint:
        """Insert or dedup-update one endpoint by ``(host, method, path)`` (§4.4).

        Existing rows get ``auth_requirements``/``research_status``/
        ``out_of_scope``/``notes`` overwritten; parameters are appended -
        one matching ``(endpoint_id, name, location)`` is updated in place,
        new ones inserted.
        """
        conn = await self._memory()
        await self._begin_write(conn)
        try:
            cursor = await conn.execute(
                _ENDPOINT_BY_KEY_SQL, (draft.host, draft.method, draft.path)
            )
            row = await cursor.fetchone()
            if row is None:
                insert_cursor = await conn.execute(
                    _ENDPOINT_INSERT_SQL,
                    (
                        draft.host,
                        draft.method,
                        draft.path,
                        _dumps(draft.auth_requirements),
                        draft.research_status,
                        int(draft.out_of_scope),
                        draft.notes,
                    ),
                )
                endpoint_id = _insert_row_id(insert_cursor)
            else:
                endpoint_id = int(row["id"])
                await conn.execute(
                    _ENDPOINT_UPDATE_SQL,
                    (
                        _dumps(draft.auth_requirements),
                        draft.research_status,
                        int(draft.out_of_scope),
                        draft.notes,
                        endpoint_id,
                    ),
                )
            await self._sync_parameters(conn, endpoint_id, draft.parameters)
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
        return await self._endpoint_by_id(conn, endpoint_id)

    async def save_finding(self, draft: FindingDraft) -> Finding:
        """Insert a finding candidate; validate evidence and endpoint refs (§4.4).

        Raises ``ValueError`` listing every ``evidence_refs`` id that has no
        ``evidence`` row, and naming ``endpoint_ref`` when it has no
        ``endpoints`` row (agent-addressable instead of a raw FK error,
        consolidated review #63). On success the referenced evidence rows
        are attached (``finding_ref``) to the new finding.
        """
        conn = await self._memory()
        if draft.endpoint_ref is not None:
            cursor = await conn.execute(_ENDPOINT_EXISTS_SQL, (draft.endpoint_ref,))
            if await cursor.fetchone() is None:
                msg = f"endpoint_ref not found in endpoints: {draft.endpoint_ref}"
                raise ValueError(msg)
        missing = await self._missing_evidence(conn, draft.evidence_refs)
        if missing:
            raise ValueError(f"evidence_refs not found in evidence: {missing}")
        await self._begin_write(conn)
        try:
            insert_cursor = await conn.execute(
                _FINDING_INSERT_SQL,
                (
                    draft.type.value,
                    FindingStatus.CANDIDATE.value,
                    draft.severity.value,
                    draft.cvss_vector,
                    draft.endpoint_ref,
                    _dumps(draft.evidence_refs),
                    draft.title,
                    draft.description,
                    _dumps(draft.reproduction),
                    draft.created_by,
                    _utcnow_iso(),  # created_at = now UTC (arch §4.3)
                ),
            )
            finding_id = _insert_row_id(insert_cursor)
            for ref in draft.evidence_refs:
                await conn.execute(_EVIDENCE_ATTACH_SQL, (finding_id, ref))
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
        return await self._finding_by_id(conn, finding_id)

    async def update_finding_status(
        self, id: int, status: FindingStatus, severity: Severity | None = None
    ) -> Finding:
        """Set the lifecycle status (and optionally the severity) of a finding.

        Enforces the documented finding lifecycle (RD-5, §4.2; consolidated
        review #12): allowed transitions are ``candidate -> verified``,
        ``candidate -> rejected`` and ``verified -> rejected``; re-setting
        the current status is allowed (the severity-update path). Any other
        transition (e.g. demoting a verified finding back to candidate, or
        resurrecting a rejected one) raises ``ValueError`` naming the
        current and target statuses. Raises ``KeyError`` for an unknown
        finding id.
        """
        conn = await self._memory()
        # #53 discipline: the read-validate-write sequence is one multi-step
        # mutation — under the BEGIN IMMEDIATE lock a concurrent writer
        # cannot slip a status change between the lifecycle validation and
        # the UPDATE (single-writer semantics of every store mutation).
        await self._begin_write(conn)
        try:
            cursor = await conn.execute(_FINDING_BY_ID_SQL, (id,))
            row = await cursor.fetchone()
            if row is None:
                raise KeyError(f"finding {id} not found")
            current = FindingStatus(str(row["status"]))
            if status != current and status not in _ALLOWED_STATUS_TRANSITIONS[current]:
                allowed = ", ".join(
                    f"{source.value} -> {target.value}"
                    for source, targets in _ALLOWED_STATUS_TRANSITIONS.items()
                    for target in sorted(targets, key=lambda item: item.value)
                )
                msg = (
                    f"invalid finding status transition {current.value} -> "
                    f"{status.value}; allowed transitions: {allowed}"
                )
                raise ValueError(msg)
            if severity is None:
                await conn.execute(_FINDING_UPDATE_STATUS_SQL, (status.value, id))
            else:
                await conn.execute(
                    _FINDING_UPDATE_SEVERITY_SQL, (status.value, severity.value, id)
                )
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
        return await self._finding_by_id(conn, id)

    async def link_attack_node(
        self, node: AttackNodeDraft, edges: Sequence[AttackEdgeDraft] = ()
    ) -> AttackNode:
        """Create a node plus its typed edges in ONE transaction (§4.4).

        Edge endpoints may be ``None`` (the new node itself) or existing
        ``attack_nodes`` ids; any unknown reference rolls the whole operation
        back - no node, no edges persist. A non-``None`` ``finding_ref``
        without a ``findings`` row is rejected the same way (agent-facing
        ``ValueError`` naming the field, consolidated review #63) instead of
        a raw FK error.
        """
        conn = await self._memory()
        await self._begin_write(conn)
        try:
            # The schema FK on attack_nodes.finding_ref fires on the INSERT
            # itself, so the ref is validated first — an agent-facing
            # ValueError instead of a raw IntegrityError (#63).
            if node.finding_ref is not None:
                cursor = await conn.execute(_FINDING_EXISTS_SQL, (node.finding_ref,))
                if await cursor.fetchone() is None:
                    msg = f"finding_ref not found in findings: {node.finding_ref}"
                    raise ValueError(msg)
            insert_cursor = await conn.execute(
                _ATTACK_NODE_INSERT_SQL,
                (node.kind, node.finding_ref, node.title, node.description),
            )
            node_id = _insert_row_id(insert_cursor)
            for edge in edges:
                src = node_id if edge.src is None else edge.src
                dst = node_id if edge.dst is None else edge.dst
                for ref in (src, dst):
                    if ref == node_id:
                        continue  # the new node exists inside this transaction
                    cursor = await conn.execute(_ATTACK_NODE_EXISTS_SQL, (ref,))
                    if await cursor.fetchone() is None:
                        raise ValueError(f"unknown attack node reference: {ref}")
                await conn.execute(_ATTACK_EDGE_INSERT_SQL, (src, dst, edge.kind))
            await conn.commit()
        except BaseException:
            await conn.rollback()  # atomic: node + all edges or nothing (arch §4.4)
            raise
        cursor = await conn.execute(_ATTACK_NODE_BY_ID_SQL, (node_id,))
        row = await cursor.fetchone()
        if row is None:  # pragma: no cover - committed above, defensive only
            raise RuntimeError(f"attack node {node_id} vanished after its own commit")
        return _attack_node_from(row)

    async def add_fact(self, draft: FactDraft) -> Fact:
        """Insert one machine-readable statement and return it (§4.4)."""
        conn = await self._memory()
        cursor = await conn.execute(
            _FACT_INSERT_SQL,
            (
                draft.subject,
                draft.predicate,
                draft.obj,
                _dumps(draft.tags),
                draft.source,
                _utcnow_iso(),
            ),
        )
        fact_id = _insert_row_id(cursor)
        cursor = await conn.execute(_FACT_BY_ID_SQL, (fact_id,))
        row = await cursor.fetchone()
        if row is None:  # pragma: no cover - committed above, defensive only
            raise RuntimeError(f"fact {fact_id} vanished after its own insert")
        return _fact_from(row)

    async def add_note(self, draft: NoteDraft) -> Note:
        """Insert one free-form observation and return it (§4.4)."""
        conn = await self._memory()
        cursor = await conn.execute(
            _NOTE_INSERT_SQL,
            (draft.text, _dumps(draft.tags), draft.author, _utcnow_iso()),
        )
        note_id = _insert_row_id(cursor)
        cursor = await conn.execute(_NOTE_BY_ID_SQL, (note_id,))
        row = await cursor.fetchone()
        if row is None:  # pragma: no cover - committed above, defensive only
            raise RuntimeError(f"note {note_id} vanished after its own insert")
        return _note_from(row)

    async def add_evidence(self, draft: EvidenceDraft) -> Evidence:
        """Insert one evidence pointer row and return it (§4.4, T2.2.4).

        The row points at raw session files (``session_paths`` relative to
        the session directory, arch §4.2); the files themselves are written
        by the ``EvidenceRecorder`` before this insert. ``finding_ref`` is
        not set here - findings attach evidence via ``save_finding``.
        """
        conn = await self._memory()
        cursor = await conn.execute(
            _EVIDENCE_INSERT_SQL,
            (
                draft.kind.value,
                _dumps(draft.session_paths),
                _dumps(draft.metadata),
                _utcnow_iso(),
            ),
        )
        evidence_id = _insert_row_id(cursor)
        cursor = await conn.execute(_EVIDENCE_BY_ID_SQL, (evidence_id,))
        row = await cursor.fetchone()
        if row is None:  # pragma: no cover - committed above, defensive only
            raise RuntimeError(f"evidence {evidence_id} vanished after its own insert")
        return _evidence_from(row)

    async def list_facts(self, subject: str) -> list[Fact]:
        """Every fact with exactly this subject, in ledger (row) order.

        A direct domain-table read (not FTS): the full, deterministically
        ordered ledger — a ranked/limited search result would truncate a
        long ledger arbitrarily and turn the replay of machine-readable
        statements (e.g. the judge-gate ledger, §6.7) unsound.
        """
        conn = await self._memory()
        cursor = await conn.execute(_FACTS_BY_SUBJECT_SQL, (subject,))
        rows = await cursor.fetchall()
        return [_fact_from(row) for row in rows]

    async def list_endpoints(self, out_of_scope: bool | None = None) -> list[Endpoint]:
        """List endpoints, optionally filtered by scope status (read-only)."""
        conn = await self._memory()
        if out_of_scope is None:
            cursor = await conn.execute("SELECT * FROM endpoints ORDER BY id")
            rows = await cursor.fetchall()
        else:
            cursor = await conn.execute(
                "SELECT * FROM endpoints WHERE out_of_scope = ? ORDER BY id",
                (int(out_of_scope),),
            )
            rows = await cursor.fetchall()
        return [_endpoint_from(row) for row in rows]

    async def list_findings(
        self, status: FindingStatus | None = None, severity: Severity | None = None
    ) -> list[Finding]:
        """List findings, optionally filtered by status and/or severity."""
        conn = await self._memory()
        if status is None:
            if severity is None:
                sql = "SELECT * FROM findings ORDER BY id"
                params: tuple[object, ...] = ()
            else:
                sql = "SELECT * FROM findings WHERE severity = ? ORDER BY id"
                params = (severity.value,)
        elif severity is None:
            sql = "SELECT * FROM findings WHERE status = ? ORDER BY id"
            params = (status.value,)
        else:
            sql = "SELECT * FROM findings WHERE status = ? AND severity = ? ORDER BY id"
            params = (status.value, severity.value)
        cursor = await conn.execute(sql, params)
        rows = await cursor.fetchall()
        return [_finding_from(row) for row in rows]

    async def list_attack_nodes(self) -> list[AttackNode]:
        """List attack-tree nodes, ascending by id (read-only, T4.4.1)."""
        conn = await self._memory()
        cursor = await conn.execute("SELECT * FROM attack_nodes ORDER BY id")
        rows = await cursor.fetchall()
        return [_attack_node_from(row) for row in rows]

    async def list_attack_edges(self) -> list[AttackEdge]:
        """List attack-tree edges, ascending by id (read-only, T4.4.1)."""
        conn = await self._memory()
        cursor = await conn.execute("SELECT * FROM attack_edges ORDER BY id")
        rows = await cursor.fetchall()
        return [_attack_edge_from(row) for row in rows]

    async def list_parameters(self, endpoint_id: int) -> list[Parameter]:
        """List one endpoint's parameters, ascending by id (read-only, T5.4.1).

        Added for the report generator's endpoint appendix (arch §11):
        parameter names/locations of every researched endpoint.
        """
        conn = await self._memory()
        cursor = await conn.execute(_PARAMETERS_BY_ENDPOINT_SQL, (endpoint_id,))
        rows = await cursor.fetchall()
        return [_parameter_from(row) for row in rows]

    async def _endpoint_by_id(self, conn: aiosqlite.Connection, endpoint_id: int) -> Endpoint:
        """Fetch and decode one endpoint row (insert/update just happened)."""
        cursor = await conn.execute(_ENDPOINT_BY_ID_SQL, (endpoint_id,))
        row = await cursor.fetchone()
        if row is None:  # pragma: no cover - committed above, defensive only
            raise RuntimeError(f"endpoint {endpoint_id} vanished after its own upsert")
        return _endpoint_from(row)

    async def _finding_by_id(self, conn: aiosqlite.Connection, finding_id: int) -> Finding:
        """Fetch and decode one finding row (insert/update just happened)."""
        cursor = await conn.execute(_FINDING_BY_ID_SQL, (finding_id,))
        row = await cursor.fetchone()
        if row is None:  # pragma: no cover - committed above, defensive only
            raise RuntimeError(f"finding {finding_id} vanished after its own write")
        return _finding_from(row)

    async def _sync_parameters(
        self,
        conn: aiosqlite.Connection,
        endpoint_id: int,
        parameters: Sequence[ParameterDraft],
    ) -> None:
        """Append parameters (§4.4): matching key updated in place, new inserted."""
        for param in parameters:
            cursor = await conn.execute(
                _PARAMETER_SELECT_SQL, (endpoint_id, param.name, param.location)
            )
            row = await cursor.fetchone()
            if row is None:
                await conn.execute(
                    _PARAMETER_INSERT_SQL,
                    (
                        endpoint_id,
                        param.name,
                        param.location,
                        param.type,
                        _dumps(param.examples),
                    ),
                )
            else:
                await conn.execute(
                    _PARAMETER_UPDATE_SQL,
                    (param.type, _dumps(param.examples), int(row["id"])),
                )

    async def _missing_evidence(
        self, conn: aiosqlite.Connection, refs: Sequence[int]
    ) -> list[int]:
        """Return the subset of ``refs`` without an ``evidence`` row."""
        missing: list[int] = []
        for ref in refs:
            cursor = await conn.execute(_EVIDENCE_EXISTS_SQL, (ref,))
            if await cursor.fetchone() is None:
                missing.append(ref)
        return missing
