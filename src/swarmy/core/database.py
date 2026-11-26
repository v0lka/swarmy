"""Single-file SQLite wrapper: connections, pragmas, migrations (arch §4.3).

``Database`` owns every aiosqlite connection to one session file - the
portable ``memory.sqlite`` (arch §3.3). Each logical subsystem (domain
memory, event journal, search index, ...) gets exactly one dedicated
connection (AD-6), and every connection is configured with the same pragmas:
WAL journal mode (parallel readers, one serialized writer), a 5 s busy
timeout and enforced foreign keys.

The migrator applies the caller-injected, version-ordered migration list -
``(version, ddl)`` pairs - each inside its own transaction and records
applied versions in ``schema_migrations``. Re-opening an up-to-date file is
a no-op (resume behaviour, arch §13.1); a file carrying a *newer* schema
than this build knows is rejected with an error naming both versions.

Dependency inversion (roadmap T1.2.2): ``swarmy.core`` never imports
``swarmy.memory.schema`` - ``Session`` wires ``schema.MIGRATIONS`` in
(T3.1.2) and tests pass their own lists directly.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import aiosqlite

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

# Pragmas applied to every connection (arch §4.3).
_PRAGMAS: tuple[tuple[str, str], ...] = (
    ("journal_mode", "WAL"),  # parallel readers, single serialized writer (AD-6)
    ("busy_timeout", "5000"),  # lock-wait budget in ms (arch §4.3)
    ("foreign_keys", "ON"),  # FK constraints enforced (arch §4.3)
)

# Migrator bookkeeping table (arch §4.3: schema_migrations(version, applied_at)).
_SCHEMA_MIGRATIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
)


def _split_statements(script: str) -> list[str]:
    """Split a SQL script into complete statements (quote/trigger-safe).

    Uses :func:`sqlite3.complete_statement` — the same boundary detection as
    the sqlite3 shell — so semicolons inside string literals or inside
    ``CREATE TRIGGER ... BEGIN ... END`` bodies never split a statement
    (the plain ``str.split(";")`` of Issue #43's predecessor did exactly
    that on the schema's trigger DDL). A trailing fragment without a
    terminating semicolon is kept as the last statement (the caller strips
    the script's trailing ``;`` before splitting).

    Args:
        script: one migration's DDL text (possibly multi-statement).

    Returns:
        The stripped, non-empty statements in order.
    """
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            stripped = buffer.strip()
            if stripped:
                statements.append(stripped)
            buffer = ""
    tail = buffer.strip()
    if tail:
        statements.append(tail)
    return statements


class DatabaseSchemaError(RuntimeError):
    """The session database was written by a *newer* schema (#30).

    Raised by :meth:`Database.open` when ``schema_migrations`` holds versions
    this build does not know — the portable session folder cannot be
    downgraded, so start fails fast. Subclasses :class:`RuntimeError` (the
    previously documented type, #30) so existing ``except RuntimeError``
    guards keep catching it, while ``cli._start_error_types`` renders the
    typed one-line report instead of a raw traceback.
    """


class Database:
    """Connection manager and migrator for one ``memory.sqlite`` file (T1.2.2).

    The migration list is injected by the caller; this module stays free of
    ``swarmy.memory`` imports so the domain schema never leaks into core.
    """

    def __init__(self, path: Path, migrations: Sequence[tuple[int, str]]) -> None:
        """Store the session file path and the ordered migration list."""
        ordered = sorted(migrations, key=lambda pair: pair[0])
        versions = [version for version, _ in ordered]
        duplicates = sorted({v for v in versions if versions.count(v) > 1})
        if duplicates:
            raise ValueError(f"duplicate migration versions: {duplicates}")
        self._path = path
        self._migrations: tuple[tuple[int, str], ...] = tuple(ordered)
        self._control: aiosqlite.Connection | None = None
        self._connections: dict[str, aiosqlite.Connection] = {}

    async def _new_connection(self) -> aiosqlite.Connection:
        """Open one connection with the canonical pragma set (arch §4.3)."""
        conn = await aiosqlite.connect(
            self._path,
            # isolation_level must be set at creation: it engages the sqlite3
            # transaction machinery, which is thread-checked on the proxy.
            isolation_level=None,  # explicit BEGIN/COMMIT only; DDL stays transactional
        )
        conn.row_factory = sqlite3.Row  # keyed row access (plain member store - thread-safe)
        for pragma, value in _PRAGMAS:  # ← arch §4.3
            await conn.execute(f"PRAGMA {pragma} = {value}")
        return conn

    async def open(self) -> None:
        """Open the control connection and apply pending migrations.

        Each pending migration runs in its own transaction together with its
        ``schema_migrations`` row; already-applied versions are skipped, so
        re-opening a session with the same schema is a no-op (arch §13.1).
        Raises :class:`DatabaseSchemaError` when the file was written by a
        *newer* schema than this build knows (naming both versions; #30).
        """
        if self._control is None:
            self._control = await self._new_connection()
        control = self._control
        await control.execute(_SCHEMA_MIGRATIONS_DDL)
        cursor = await control.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
        )
        row = await cursor.fetchone()
        max_applied = int(row[0]) if row is not None else 0
        newest = self._migrations[-1][0] if self._migrations else 0
        if max_applied > newest:
            raise DatabaseSchemaError(
                f"session database {self._path} has schema version {max_applied}, "
                f"which is newer than the newest migration of this swarmy build "
                f"(version {newest}); upgrade swarmy to open this session"
            )
        for version, ddl in self._migrations:
            if version <= max_applied:
                continue  # resume (arch §13.1): already applied - skip
            applied_at = datetime.now(UTC).isoformat()
            statements = _split_statements(ddl.strip().rstrip(";"))
            try:
                await control.execute("BEGIN")
                for statement in statements:  # transactional DDL (arch §4.3)
                    await control.execute(statement)
                # Bound parameters (Issue #43): the bookkeeping row must not
                # interpolate values into SQL - executescript cannot bind, so
                # the DDL and the INSERT run as separate statements inside one
                # explicit transaction instead.
                await control.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (int(version), applied_at),
                )
                await control.execute("COMMIT")
            except aiosqlite.Error:
                await control.rollback()  # leave no half-applied transaction behind
                raise

    async def connection(self, subsystem: str) -> aiosqlite.Connection:
        """Return the dedicated, cached connection for one subsystem (AD-6).

        Exactly one connection is created per subsystem name; every call
        returns the same object until ``close()``. Requires ``open()`` first.
        """
        conn = self._connections.get(subsystem)
        if conn is None:
            if self._control is None:
                raise RuntimeError("database is not open - call open() first")
            conn = await self._new_connection()
            self._connections[subsystem] = conn
        return conn

    async def close(self) -> None:
        """Close every subsystem connection and the control connection."""
        for subsystem in list(self._connections):
            conn = self._connections.pop(subsystem)
            await conn.close()
        if self._control is not None:
            control, self._control = self._control, None
            await control.close()

    async def checkpoint(self) -> None:
        """Run a truncating WAL checkpoint on the session file (arch §3.3).

        Called by ``Session.close()`` (T3.1.2): the ``memory.sqlite-wal`` /
        ``-shm`` side files only fold into the portable session archive after
        an explicit checkpoint, so a copied session folder opens "on another
        machine". Requires ``open()``.

        Raises:
            RuntimeError: when the database is not open.
        """
        if self._control is None:
            raise RuntimeError("database is not open - call open() first")
        await self._control.execute("PRAGMA wal_checkpoint(TRUNCATE)")
