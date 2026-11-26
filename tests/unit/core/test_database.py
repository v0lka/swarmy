"""Database wrapper tests (roadmap T1.2.2): pragmas, migrations, resume, guard.

Covers the acceptance criteria of arch §4.3: pragmas on every connection
(WAL / busy_timeout / foreign_keys), transactional migration application
recorded in ``schema_migrations``, idempotent re-open (arch §13.1) and the
explicit newer-schema rejection naming both versions. AD-6 (exactly one
connection per subsystem) is verified here as well.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.memory.schema import MIGRATIONS

if TYPE_CHECKING:
    from pathlib import Path

    import aiosqlite

_BROKEN_MIGRATION_2 = (
    "CREATE TABLE migration_rollback_probe (id INTEGER);\n"
    "THIS IS NOT VALID SQL;"  # forces a syntax error inside migration 2's transaction
)


async def _pragma(conn: aiosqlite.Connection, statement: str) -> str:
    """Fetch one pragma value as text (aiosqlite rows are keyed/indexed)."""
    cursor = await conn.execute(statement)
    row = await cursor.fetchone()
    assert row is not None
    return str(row[0])


async def test_pragmas_applied_on_fresh_file(tmp_path: Path) -> None:
    """AC (T1.2.2, arch §4.3): every connection gets WAL/5000ms/foreign_keys=ON."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    try:
        conn = await db.connection("memory")
        assert await _pragma(conn, "PRAGMA journal_mode") == "wal"
        assert await _pragma(conn, "PRAGMA busy_timeout") == "5000"
        assert await _pragma(conn, "PRAGMA foreign_keys") == "1"
        # a second subsystem connection gets the same pragma set
        other = await db.connection("events")
        assert await _pragma(other, "PRAGMA journal_mode") == "wal"
        assert await _pragma(other, "PRAGMA foreign_keys") == "1"
    finally:
        await db.close()


async def test_one_connection_per_subsystem(tmp_path: Path) -> None:
    """AC (AD-6): `connection()` caches exactly one connection per subsystem."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    try:
        memory_first = await db.connection("memory")
        memory_second = await db.connection("memory")
        events = await db.connection("events")
        assert memory_first is memory_second
        assert memory_first is not events
    finally:
        await db.close()


async def test_connection_requires_open(tmp_path: Path) -> None:
    """Fail-fast: subsystem connections only exist after `open()`."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    with pytest.raises(RuntimeError, match="open"):
        await db.connection("memory")


async def test_migrations_recorded_in_schema_migrations(tmp_path: Path) -> None:
    """AC (T1.2.2): applied versions are recorded with a UTC ISO timestamp."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    try:
        conn = await db.connection("memory")
        cursor = await conn.execute(
            "SELECT version, applied_at FROM schema_migrations ORDER BY version"
        )
        rows = await cursor.fetchall()
        assert [int(row["version"]) for row in rows] == [version for version, _ in MIGRATIONS]
        for row in rows:
            applied_at = datetime.fromisoformat(str(row["applied_at"]))
            assert applied_at.utcoffset() is not None
    finally:
        await db.close()


async def test_failed_migration_rolls_back(tmp_path: Path) -> None:
    """AC (T1.2.2): migrations run in a transaction - a broken DDL leaves no trace."""
    migrations = [*MIGRATIONS, (2, _BROKEN_MIGRATION_2)]
    db = Database(tmp_path / "memory.sqlite", migrations)
    try:
        with pytest.raises(sqlite3.OperationalError, match="syntax"):
            await db.open()
        conn = await db.connection("memory")
        cursor = await conn.execute(
            "SELECT version FROM schema_migrations WHERE version = 2"
        )
        assert await cursor.fetchone() is None, "failed migration must not be recorded"
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'migration_rollback_probe'"
        )
        assert await cursor.fetchone() is None, "broken migration DDL must roll back"
    finally:
        await db.close()


async def test_reopen_is_idempotent(tmp_path: Path) -> None:
    """AC (T1.2.2, arch §13.1): re-open with the same version is a no-op."""
    path = tmp_path / "memory.sqlite"
    db = Database(path, MIGRATIONS)
    await db.open()
    conn = await db.connection("memory")
    await conn.execute(
        "INSERT INTO notes (text, tags, author, created_at)"
        " VALUES ('marker row', '[]', 'tester', '2026-01-01T00:00:00+00:00')"
    )
    await db.open()  # second open on the live instance - still a no-op
    await db.close()

    reopened = Database(path, MIGRATIONS)
    await reopened.open()
    try:
        conn = await reopened.connection("memory")
        cursor = await conn.execute(
            "SELECT COUNT(*) AS n FROM schema_migrations"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert int(row["n"]) == len(MIGRATIONS), "migrations must not be applied twice"
        cursor = await conn.execute("SELECT COUNT(*) AS n FROM notes")
        row = await cursor.fetchone()
        assert row is not None
        assert int(row["n"]) == 1, "data must survive the resume unchanged"
    finally:
        await reopened.close()


async def test_newer_schema_file_is_rejected(tmp_path: Path) -> None:
    """AC (T1.2.2): opening a newer-schema session fails, naming both versions."""
    path = tmp_path / "memory.sqlite"
    db = Database(path, MIGRATIONS)
    await db.open()
    await db.close()

    # Simulate a session directory written by a newer swarmy build.
    with sqlite3.connect(path) as rogue:
        rogue.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (99, '2030-01-01T00:00:00+00:00')"
        )
    rogue.close()

    newer = Database(path, MIGRATIONS)
    try:
        with pytest.raises(RuntimeError) as excinfo:
            await newer.open()
        message = str(excinfo.value)
        assert "99" in message, "the error must name the file's schema version"
        assert "version 1" in message, "the error must name this build's newest migration"
    finally:
        await newer.close()  # the control connection must stay closeable


async def test_migration_ddl_with_quoted_semicolons_and_trigger_bodies(tmp_path: Path) -> None:
    """Issue #43: statement splitting is quote/trigger-safe, bookkeeping bound.

    A migration whose DDL carries a string literal with a semicolon/apostrophe
    and a ``CREATE TRIGGER ... BEGIN ... END`` body must apply atomically and
    record its ``schema_migrations`` row — the pre-#43 f-string interpolation
    and a naive ``str.split(";")`` both break on exactly this shape.
    """
    ddl = (
        "CREATE TABLE probe_quotes (x TEXT DEFAULT 'a;b''c');\n"
        "CREATE TRIGGER probe_guard BEFORE INSERT ON probe_quotes\n"
        "BEGIN\n"
        "  SELECT RAISE(ABORT, 'no insert; allowed') WHERE NEW.x = 'end;';\n"
        "END;"
    )
    migrations = [*MIGRATIONS, (99, ddl)]
    db = Database(tmp_path / "memory.sqlite", migrations)
    await db.open()
    try:
        conn = await db.connection("memory")
        cursor = await conn.execute(
            "SELECT applied_at FROM schema_migrations WHERE version = 99"
        )
        row = await cursor.fetchone()
        assert row is not None, "the multi-statement migration must be recorded"
        applied_at = str(row["applied_at"])
        assert "T" in applied_at  # a plain ISO timestamp: bound, never interpolated
        cursor = await conn.execute("SELECT x FROM probe_quotes LIMIT 1")
        assert await cursor.fetchone() is None  # the table exists (DDL applied)
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name='probe_guard'"
        )
        assert await cursor.fetchone() is not None  # the trigger body survived the split
    finally:
        await db.close()


def test_split_statements_respects_literals_and_trigger_bodies() -> None:
    """The splitter never splits inside string literals or trigger bodies."""
    from swarmy.core.database import _split_statements

    script = (
        "CREATE TABLE a (x TEXT DEFAULT 'a;b');\n"
        "CREATE TRIGGER t BEFORE INSERT ON a BEGIN SELECT RAISE(ABORT, 'x;y') ;\n"
        "END;\n"
        "CREATE TABLE b (y INTEGER);"
    )
    statements = _split_statements(script)
    assert len(statements) == 3  # the trigger body's semicolon did not split
    assert statements[0] == "CREATE TABLE a (x TEXT DEFAULT 'a;b');"
    assert statements[1].startswith("CREATE TRIGGER t")
    assert statements[1].endswith("END;")
    assert statements[2] == "CREATE TABLE b (y INTEGER);"
