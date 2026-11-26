"""Shared memory: domain models (leaf), SQLite schema, store, FTS search (arch §4).

Public surface of the subsystem (roadmap T1.2.1-T1.2.5): the domain models,
the ``MemoryStore`` facade, and the ``SearchIndex`` protocol with its FTS5
implementation. Imports stay boundary-safe (arch §2.5): ``swarmy.memory.*``
only - the store imports ``swarmy.core.database``, never events/tools/tui.
"""

from __future__ import annotations

from swarmy.memory.models import (
    AttackEdge,
    AttackEdgeDraft,
    AttackNode,
    AttackNodeDraft,
    Endpoint,
    EndpointDraft,
    EntityType,
    Evidence,
    EvidenceKind,
    Fact,
    FactDraft,
    Finding,
    FindingDraft,
    FindingStatus,
    FindingType,
    Note,
    NoteDraft,
    Parameter,
    ParameterDraft,
    ScopeEntry,
    SearchableEntity,
    SearchHit,
    Severity,
    Target,
)
from swarmy.memory.search import Fts5SearchIndex, SearchIndex
from swarmy.memory.store import MemoryStore, MemoryStoreBusy

__all__ = [
    "AttackEdge",
    "AttackEdgeDraft",
    "AttackNode",
    "AttackNodeDraft",
    "Endpoint",
    "EndpointDraft",
    "EntityType",
    "Evidence",
    "EvidenceKind",
    "Fact",
    "FactDraft",
    "Finding",
    "FindingDraft",
    "FindingStatus",
    "FindingType",
    "Fts5SearchIndex",
    "MemoryStore",
    "MemoryStoreBusy",
    "Note",
    "NoteDraft",
    "Parameter",
    "ParameterDraft",
    "ScopeEntry",
    "SearchHit",
    "SearchIndex",
    "SearchableEntity",
    "Severity",
    "Target",
]
