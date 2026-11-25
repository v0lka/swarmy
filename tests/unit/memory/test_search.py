"""Search tests (roadmap T1.2.4): relevance, title boost, filters, safety.

Covers arch §4.5 acceptance criteria: fixture data returns relevant hits, a
term matched in the title ranks above the same term matched in the body
only (bm25 with a 10x title weight), the ``entity_types`` filter works, and
unknown tokens return an empty list without raising. ``index_up`` is
exercised as the manual re-index path.
"""

from __future__ import annotations

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

_SEED_SQL = (
    # endpoint with 'dashboard' in the TITLE (host || method || path), empty notes
    (
        "INSERT INTO endpoints (host, method, path, notes)"
        " VALUES ('app.example.com:443', 'GET', '/dashboard', '')"
    ),
    # endpoint with 'dashboard' in the BODY (notes) only
    (
        "INSERT INTO endpoints (host, method, path, notes)"
        " VALUES ('app.example.com:443', 'GET', '/api/users', 'returns dashboard widgets json')"
    ),
    # finding with 'xss' in title and 'dashboard' in body only
    (
        "INSERT INTO findings (type, status, severity, title, description, created_by, created_at)"
        " VALUES ('xss', 'candidate', 'high', 'Stored XSS in comment form',"
        " 'script persists on dashboard page', 'xss-detector',"
        " '2026-01-01T00:00:00+00:00')"
    ),
    # fact: title 'app.example.com uses', body contains 'dashboard'
    (
        "INSERT INTO facts (subject, predicate, obj, source, created_at)"
        " VALUES ('app.example.com', 'uses', 'react dashboard framework', 'crawler',"
        " '2026-01-01T00:00:00+00:00')"
    ),
    # note: 'dashboard' only inside the tags part of the body
    (
        "INSERT INTO notes (text, tags, author, created_at)"
        " VALUES ('admin panel requires session cookie', '[\"dashboard\"]', 'crawler',"
        " '2026-01-01T00:00:00+00:00')"
    ),
)


@pytest.fixture
async def index(
    tmp_path: Path,
) -> AsyncIterator[tuple[Fts5SearchIndex, aiosqlite.Connection]]:
    """One opened database seeded with fixture rows; triggers keep FTS in sync."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn = await db.connection("search")
    for statement in _SEED_SQL:
        await conn.execute(statement)
    await conn.commit()
    yield Fts5SearchIndex(conn), conn
    await db.close()


async def test_fixture_data_returns_relevant_hits(
    index: tuple[Fts5SearchIndex, aiosqlite.Connection],
) -> None:
    """AC (T1.2.4): searches over fixture data return the right rows."""
    search, _conn = index
    hits = await search.search("xss", None, 10)
    assert [hit.id for hit in hits if hit.entity_type is SearchableEntity.FINDINGS] == [1]

    dashboard_hits = await search.search("dashboard", None, 10)
    found_kinds = {(hit.entity_type, hit.id) for hit in dashboard_hits}
    assert (SearchableEntity.ENDPOINTS, 1) in found_kinds
    assert (SearchableEntity.ENDPOINTS, 2) in found_kinds
    assert (SearchableEntity.FINDINGS, 1) in found_kinds
    assert (SearchableEntity.FACTS, 1) in found_kinds
    assert (SearchableEntity.NOTES, 1) in found_kinds


async def test_title_match_outranks_body_match(
    index: tuple[Fts5SearchIndex, aiosqlite.Connection],
) -> None:
    """AC (T1.2.4): the title hit (bm25 weight 10) scores above body-only hits."""
    search, _conn = index
    hits = await search.search("dashboard", None, 10)
    assert hits, "fixture data must match the query"
    best = hits[0]
    assert best.entity_type is SearchableEntity.ENDPOINTS
    assert best.id == 1
    assert best.title_snippet == "app.example.com:443 GET /dashboard"
    assert all(hit.score < best.score for hit in hits[1:])


async def test_entity_types_filter(
    index: tuple[Fts5SearchIndex, aiosqlite.Connection],
) -> None:
    """AC (T1.2.4): entity_types restricts the searched tables."""
    search, _conn = index
    hits = await search.search("dashboard", [SearchableEntity.NOTES], 10)
    assert len(hits) == 1
    assert hits[0].entity_type is SearchableEntity.NOTES
    assert hits[0].id == 1

    two_kinds = await search.search(
        "dashboard", [SearchableEntity.FINDINGS, SearchableEntity.FACTS], 10
    )
    assert {hit.entity_type for hit in two_kinds} == {
        SearchableEntity.FINDINGS,
        SearchableEntity.FACTS,
    }


async def test_unknown_token_returns_empty_without_raising(
    index: tuple[Fts5SearchIndex, aiosqlite.Connection],
) -> None:
    """AC (T1.2.4): unknown tokens and hostile input yield [], never an error."""
    search, _conn = index
    assert await search.search("zzzqqq", None, 10) == []
    assert await search.search('zzz" OR 1=1 --', None, 10) == []
    assert await search.search("   ", None, 10) == []


async def test_search_respects_limit(
    index: tuple[Fts5SearchIndex, aiosqlite.Connection],
) -> None:
    """`limit` caps the merged result list across tables."""
    search, _conn = index
    hits = await search.search("dashboard", None, 2)
    assert len(hits) == 2


async def test_index_up_replaces_document(
    index: tuple[Fts5SearchIndex, aiosqlite.Connection],
) -> None:
    """`index_up` rewrites one document (repair path of arch §4.5)."""
    search, _conn = index
    await search.index_up(SearchableEntity.NOTES, 1, "hand rewritten title")
    hits = await search.search("rewritten", None, 10)
    assert [(hit.entity_type, hit.id, hit.title_snippet) for hit in hits] == [
        (SearchableEntity.NOTES, 1, "hand rewritten title")
    ]
    stale = await search.search("cookie", None, 10)
    assert not [hit for hit in stale if hit.entity_type is SearchableEntity.NOTES]
