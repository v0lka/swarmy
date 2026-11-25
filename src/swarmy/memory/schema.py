"""DDL migrations for the single session memory file (arch §4.3, RD-8).

One SQLite file - ``memory.sqlite`` - hosts the whole session memory (AD-6):

* the **domain tables** (owned by ``MemoryStore``),
* the **append-only** ``events`` journal (owned by ``JournalWriter``),
* four **FTS5** search tables (owned by ``SearchIndex``; kept in sync by
  ``AFTER INSERT``/``AFTER UPDATE`` triggers on the domain tables),
* ``schema_migrations`` - created by the migrator in ``core.database``.

``MIGRATIONS`` is the *single* migration list for the whole file (RD-8); it is
applied transactionally by ``Database.open()``. Field-format rules (arch
§4.3): multi-value fields (``tags``, ``examples``, ``evidence_refs``, ...) are
JSON TEXT columns; datetimes are UTC ISO-8601 TEXT; every domain table has
``id INTEGER PRIMARY KEY AUTOINCREMENT``; column sets mirror the Pydantic
models of ``swarmy.memory.models``.

The DDL here deliberately does **not** create L0 checkpointer tables
(``checkpoints``, ``checkpoint_writes``, ...) - their owner is the deepagents
SQLite checkpointer (arch §4.3).
"""

from __future__ import annotations

_MIGRATION_1_DDL = """
CREATE TABLE target (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    base_url TEXT NOT NULL,
    stack_metadata TEXT NOT NULL DEFAULT '{}' -- JSON dict[str, str]
);

CREATE TABLE scope_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('domain', 'ip_subnet', 'port', 'scheme')),
    value TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('config', 'operator'))
);

CREATE TABLE endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    auth_requirements TEXT NOT NULL DEFAULT '[]', -- JSON list[str]
    research_status TEXT NOT NULL DEFAULT 'undiscovered'
        CHECK (research_status IN ('undiscovered', 'probed', 'analyzed')),
    out_of_scope INTEGER NOT NULL DEFAULT 0, -- bool: 0/1
    notes TEXT NOT NULL DEFAULT '',
    UNIQUE (host, method, path)
);

CREATE TABLE parameters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    location TEXT NOT NULL CHECK (location IN ('query', 'body', 'header')),
    type TEXT NOT NULL DEFAULT 'string',
    examples TEXT NOT NULL DEFAULT '[]', -- JSON list[str]
    UNIQUE (endpoint_id, name, location)
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK (status IN ('candidate', 'verified', 'rejected')),
    severity TEXT NOT NULL -- mandatory, D14
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_vector TEXT,
    endpoint_ref INTEGER REFERENCES endpoints(id),
    evidence_refs TEXT NOT NULL DEFAULT '[]', -- JSON list[int] -> evidence.id
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    reproduction TEXT NOT NULL DEFAULT '[]', -- JSON list[str]
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL -- UTC ISO-8601
);

CREATE TABLE evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL -- D20: only http_request_response is produced in v0.1
        CHECK (kind IN ('http_request_response', 'screenshot', 'har', 'grpc_file')),
    session_paths TEXT NOT NULL, -- JSON list[str]
    finding_ref INTEGER REFERENCES findings(id),
    metadata TEXT NOT NULL, -- JSON dict[str, str]
    created_at TEXT NOT NULL
);

CREATE TABLE attack_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('precondition', 'finding', 'goal')),
    finding_ref INTEGER REFERENCES findings(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE attack_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src INTEGER NOT NULL REFERENCES attack_nodes(id),
    dst INTEGER NOT NULL REFERENCES attack_nodes(id),
    kind TEXT NOT NULL CHECK (kind IN ('requires', 'enables', 'leads_to'))
);

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]', -- JSON list[str]
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    obj TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]', -- JSON list[str]
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, -- UTC ISO-8601
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    source_detail TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL -- JSON payload model (arch SS4.3, SS5.1)
);

CREATE TRIGGER events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only: UPDATE is forbidden (arch 4.3/5.4)');
END;

CREATE TRIGGER events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only: DELETE is forbidden (arch 4.3/5.4)');
END;

CREATE VIRTUAL TABLE fts_endpoints USING fts5(title, body, ref_id UNINDEXED);
CREATE VIRTUAL TABLE fts_findings USING fts5(title, body, ref_id UNINDEXED);
CREATE VIRTUAL TABLE fts_facts USING fts5(title, body, ref_id UNINDEXED);
CREATE VIRTUAL TABLE fts_notes USING fts5(title, body, ref_id UNINDEXED);

CREATE TRIGGER endpoints_fts_insert
AFTER INSERT ON endpoints
BEGIN
    INSERT INTO fts_endpoints (title, body, ref_id)
    VALUES (new.host || ' ' || new.method || ' ' || new.path, new.notes, new.id);
END;

CREATE TRIGGER endpoints_fts_update
AFTER UPDATE ON endpoints
BEGIN
    DELETE FROM fts_endpoints WHERE ref_id = old.id;
    INSERT INTO fts_endpoints (title, body, ref_id)
    VALUES (new.host || ' ' || new.method || ' ' || new.path, new.notes, new.id);
END;

CREATE TRIGGER findings_fts_insert
AFTER INSERT ON findings
BEGIN
    INSERT INTO fts_findings (title, body, ref_id)
    VALUES (new.title, new.description, new.id);
END;

CREATE TRIGGER findings_fts_update
AFTER UPDATE ON findings
BEGIN
    DELETE FROM fts_findings WHERE ref_id = old.id;
    INSERT INTO fts_findings (title, body, ref_id)
    VALUES (new.title, new.description, new.id);
END;

CREATE TRIGGER facts_fts_insert
AFTER INSERT ON facts
BEGIN
    INSERT INTO fts_facts (title, body, ref_id)
    VALUES (new.subject || ' ' || new.predicate, new.obj, new.id);
END;

CREATE TRIGGER facts_fts_update
AFTER UPDATE ON facts
BEGIN
    DELETE FROM fts_facts WHERE ref_id = old.id;
    INSERT INTO fts_facts (title, body, ref_id)
    VALUES (new.subject || ' ' || new.predicate, new.obj, new.id);
END;

CREATE TRIGGER notes_fts_insert
AFTER INSERT ON notes
BEGIN
    INSERT INTO fts_notes (title, body, ref_id)
    VALUES (substr(new.text, 1, 60), new.text || ' ' || new.tags, new.id);
END;

CREATE TRIGGER notes_fts_update
AFTER UPDATE ON notes
BEGIN
    DELETE FROM fts_notes WHERE ref_id = old.id;
    INSERT INTO fts_notes (title, body, ref_id)
    VALUES (substr(new.text, 1, 60), new.text || ' ' || new.tags, new.id);
END;
"""

# Single migration list for the whole memory.sqlite (RD-8): sequential
# (version, ddl) pairs, applied by Database.open() - never edited in place.
MIGRATIONS: list[tuple[int, str]] = [(1, _MIGRATION_1_DDL)]

__all__ = ["MIGRATIONS"]
