"""Schema migration tests (roadmap T1.2.3): tables, trigger sync, append-only.

Covers arch §4.3: migration 1 creates exactly the documented tables (10
domain + events + 4 FTS5), INSERT/UPDATE on endpoints/findings/facts/notes
synchronously update the matching FTS table (verified through
``Fts5SearchIndex``), the ``events`` table is append-only (RAISE(ABORT)
triggers), and the DDL never creates L0 checkpointer tables.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.memory.models import SearchableEntity
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    import aiosqlite

_DOMAIN_TABLES = {
    "target",
    "scope_entries",
    "endpoints",
    "parameters",
    "findings",
    "evidence",
    "attack_nodes",
    "attack_edges",
    "notes",
    "facts",
}
_FTS_TABLES = {"fts_endpoints", "fts_findings", "fts_facts", "fts_notes"}


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    """One opened Database over a fresh session file (closed on teardown)."""
    database = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await database.open()
    yield database
    await database.close()


def _index(db: Database, conn: aiosqlite.Connection) -> Fts5SearchIndex:
    """Build the FTS index over the given connection (schema tests only)."""
    return Fts5SearchIndex(conn)


async def test_migration_creates_all_documented_tables(db: Database) -> None:
    """AC (T1.2.3): migration 1 creates exactly the arch §4.3 table set."""
    conn = await db.connection("schema")
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    rows = await cursor.fetchall()
    names = {str(row["name"]) for row in rows}
    expected = _DOMAIN_TABLES | _FTS_TABLES | {"events", "schema_migrations"}
    assert expected <= names, f"missing tables: {expected - names}"
    leftovers = names - expected
    assert leftovers, "FTS5 shadow tables must exist"
    for name in leftovers:
        assert name.startswith("fts_"), f"unexpected table beyond arch §4.3: {name}"


async def test_domain_triggers_sync_fts_tables(db: Database) -> None:
    """AC (T1.2.3): INSERT/UPDATE on domain rows synchronously update their FTS table."""
    conn = await db.connection("schema")
    index = _index(db, conn)

    await conn.execute(
        "INSERT INTO endpoints (host, method, path, notes)"
        " VALUES ('web.example.com:443', 'GET', '/login', 'login form discovered')"
    )
    await conn.execute(
        "INSERT INTO findings (type, status, severity, title, description, created_by, created_at)"
        " VALUES ('xss', 'candidate', 'high', 'Reflected XSS in search',"
        " 'payload echoed back by the search box', 'xss-detector',"
        " '2026-01-01T00:00:00+00:00')"
    )
    await conn.execute(
        "INSERT INTO facts (subject, predicate, obj, source, created_at)"
        " VALUES ('web.example.com', 'runs', 'nginx', 'crawler',"
        " '2026-01-01T00:00:00+00:00')"
    )
    await conn.execute(
        "INSERT INTO notes (text, tags, author, created_at)"
        " VALUES ('WAF detected: cloudflare edge', '[\"infra\"]', 'crawler',"
        " '2026-01-01T00:00:00+00:00')"
    )
    await conn.commit()

    hits = await index.search("login", None, 10)
    assert any(
        hit.entity_type is SearchableEntity.ENDPOINTS
        and hit.title_snippet.startswith("web.example.com:443 GET /login")
        for hit in hits
    )
    assert await index.search("echoed", None, 10)  # findings body
    assert await index.search("nginx", None, 10)  # facts body
    assert await index.search("cloudflare", None, 10)  # notes body/tags

    # UPDATE: endpoint notes replaced -> old token gone, new token present.
    await conn.execute("UPDATE endpoints SET notes = 'admin panel found' WHERE path = '/login'")
    await conn.commit()
    updated = await index.search("admin", None, 10)
    assert any(
        hit.entity_type is SearchableEntity.ENDPOINTS for hit in updated
    ), "UPDATE trigger must reindex the row"
    stale = await index.search("discovered", None, 10)
    assert not any(
        hit.entity_type is SearchableEntity.ENDPOINTS for hit in stale
    ), "old body text must not survive an UPDATE"


async def test_findings_update_reindexes_fts(db: Database) -> None:
    """Finding title UPDATE: new term searchable, old one gone (trigger pair)."""
    conn = await db.connection("schema")
    index = _index(db, conn)
    await conn.execute(
        "INSERT INTO findings (type, status, severity, title, description, created_by, created_at)"
        " VALUES ('sqli', 'candidate', 'critical', 'SQLi in login form',"
        " 'boolean-based blind injection', 'sqli-probe',"
        " '2026-01-01T00:00:00+00:00')"
    )
    await conn.commit()
    assert await index.search("boolean", None, 10)

    await conn.execute("UPDATE findings SET title = 'Time-based SQLi found'")
    await conn.commit()
    fresh = await index.search("time-based", None, 10)
    assert any(hit.entity_type is SearchableEntity.FINDINGS for hit in fresh)
    gone = await index.search("login", None, 10)
    assert not any(hit.entity_type is SearchableEntity.FINDINGS for hit in gone)


async def test_events_table_is_append_only(db: Database) -> None:
    """AC (T1.2.3, arch §5.4): UPDATE/DELETE on events abort via trigger."""
    conn = await db.connection("schema")
    await conn.execute(
        "INSERT INTO events (ts, type, source, payload)"
        " VALUES ('2026-01-01T00:00:00+00:00', 'TargetSet', 'platform', '{}')"
    )
    await conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await conn.execute("UPDATE events SET type = 'OperatorMessage'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        await conn.execute("DELETE FROM events")
    cursor = await conn.execute("SELECT COUNT(*) AS n FROM events")
    row = await cursor.fetchone()
    assert row is not None
    assert int(row["n"]) == 1


def test_ddl_creates_no_checkpointer_tables() -> None:
    """AC (T1.2.3): L0 checkpointer owns its tables - never our DDL (arch §4.3)."""
    for _version, ddl in MIGRATIONS:
        lowered = ddl.lower()
        assert "checkpoint" not in lowered, "DDL must not create checkpointer tables"
