"""Search abstraction (arch §4.5) and its FTS5 implementation (T1.2.4).

``SearchIndex`` is the backend-neutral protocol every client depends on
(``MemoryStore.search``, later the ``memory_search`` tool). The v0.1
implementation is ``Fts5SearchIndex`` over the four ``fts_*`` virtual tables
of arch §4.3; a future ``VecSearchIndex`` (sqlite-vec, phase 2) can implement
the same protocol - the config key ``memory.search_backend`` selects the
backend (§12.1), the abstraction is in place without two implementations (P4).

Row synchronization of the FTS tables is trigger-driven (``schema.py``);
``index_up`` exists only for manual re-indexing/repair of one document.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple, Protocol

from swarmy.memory.models import SearchableEntity, SearchHit

if TYPE_CHECKING:
    import aiosqlite


class SearchIndex(Protocol):
    """Backend-neutral search surface (arch §4.5) - clients use this only."""

    async def index_up(self, entity_type: SearchableEntity, doc_id: int, text: str) -> None:
        """Write or replace the indexed document of one entity row."""

    async def search(
        self, query: str, entity_types: list[SearchableEntity] | None, limit: int
    ) -> list[SearchHit]:
        """Return up to ``limit`` hits, best first (``score``: higher is better)."""


class _TableSpec(NamedTuple):
    """Literal SQL for one FTS5 table (no string composition of table names)."""

    delete_by_ref: str
    insert_doc: str
    search_bm25: str


# One spec per searchable entity kind; bm25 gives the title column a 10x
# weight, so a title match outranks a body-only match (arch §4.5).
_SPECS: dict[SearchableEntity, _TableSpec] = {
    SearchableEntity.ENDPOINTS: _TableSpec(
        delete_by_ref="DELETE FROM fts_endpoints WHERE ref_id = ?",
        insert_doc="INSERT INTO fts_endpoints (title, body, ref_id) VALUES (?, ?, ?)",
        search_bm25=(
            "SELECT ref_id, title, bm25(fts_endpoints, 10.0, 1.0) AS rank "
            "FROM fts_endpoints WHERE fts_endpoints MATCH ? "
            "ORDER BY rank LIMIT ?"
        ),
    ),
    SearchableEntity.FINDINGS: _TableSpec(
        delete_by_ref="DELETE FROM fts_findings WHERE ref_id = ?",
        insert_doc="INSERT INTO fts_findings (title, body, ref_id) VALUES (?, ?, ?)",
        search_bm25=(
            "SELECT ref_id, title, bm25(fts_findings, 10.0, 1.0) AS rank "
            "FROM fts_findings WHERE fts_findings MATCH ? "
            "ORDER BY rank LIMIT ?"
        ),
    ),
    SearchableEntity.FACTS: _TableSpec(
        delete_by_ref="DELETE FROM fts_facts WHERE ref_id = ?",
        insert_doc="INSERT INTO fts_facts (title, body, ref_id) VALUES (?, ?, ?)",
        search_bm25=(
            "SELECT ref_id, title, bm25(fts_facts, 10.0, 1.0) AS rank "
            "FROM fts_facts WHERE fts_facts MATCH ? "
            "ORDER BY rank LIMIT ?"
        ),
    ),
    SearchableEntity.NOTES: _TableSpec(
        delete_by_ref="DELETE FROM fts_notes WHERE ref_id = ?",
        insert_doc="INSERT INTO fts_notes (title, body, ref_id) VALUES (?, ?, ?)",
        search_bm25=(
            "SELECT ref_id, title, bm25(fts_notes, 10.0, 1.0) AS rank "
            "FROM fts_notes WHERE fts_notes MATCH ? "
            "ORDER BY rank LIMIT ?"
        ),
    ),
}


_QUOTE = '"'


def _quoted_term(token: str) -> str:
    """Render one query token as a double-quoted FTS5 term (injection-safe)."""
    escaped = token.replace(_QUOTE, _QUOTE * 2)
    return f'"{escaped}"'


def _match_expression(query: str) -> str:
    """Tokenize the query into OR-joined, quoted FTS5 terms.

    Quoting neutralizes FTS5 query syntax characters, so arbitrary user
    input can never change the shape of the MATCH expression.
    """
    return " OR ".join(_quoted_term(token) for token in query.split())


class Fts5SearchIndex:
    """FTS5-backed ``SearchIndex`` over the ``fts_*`` tables (arch §4.5).

    Ranking: SQLite ``bm25`` with a 10x title-column weight; ``SearchHit.score``
    is ``-bm25_rank``, i.e. higher (less negative rank) is better.
    """

    def __init__(self, search_index_connection: aiosqlite.Connection) -> None:
        """Bind the index to the search subsystem's dedicated connection."""
        self._conn = search_index_connection

    async def index_up(self, entity_type: SearchableEntity, doc_id: int, text: str) -> None:
        """Replace the indexed document of one entity row (repair path).

        ``text`` becomes the title and the body stays empty - normal flows
        keep the tables in sync via the schema triggers instead (arch §4.5).
        """
        spec = _SPECS[entity_type]
        await self._conn.execute(spec.delete_by_ref, (doc_id,))
        await self._conn.execute(spec.insert_doc, (text, "", doc_id))
        await self._conn.commit()

    async def search(
        self, query: str, entity_types: list[SearchableEntity] | None, limit: int
    ) -> list[SearchHit]:
        """Match ``query`` across the selected entity kinds, ranked best-first.

        ``entity_types=None`` searches all four tables; unknown tokens yield
        an empty list rather than an error.
        """
        expression = _match_expression(query)
        if not expression:
            return []
        kinds = list(entity_types) if entity_types is not None else list(SearchableEntity)
        hits: list[SearchHit] = []
        for kind in kinds:
            spec = _SPECS[kind]
            cursor = await self._conn.execute(spec.search_bm25, (expression, limit))
            rows = await cursor.fetchall()
            for row in rows:
                hits.append(
                    SearchHit(
                        entity_type=kind,
                        id=int(row["ref_id"]),
                        title_snippet=str(row["title"]),
                        score=-float(row["rank"]),  # bm25 rank: lower (more negative) is better
                    )
                )
        hits.sort(key=lambda hit: (-hit.score, hit.entity_type.value, hit.id))
        return hits[:limit]
