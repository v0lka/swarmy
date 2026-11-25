"""Domain entities - Pydantic v2 models (arch §4.1-§4.2, D9).

Leaf module (arch §2.5): imports only `pydantic` and the standard library -
every other swarmy package may import these models without creating cycles.
References between entities are `int` primary keys; models never embed object
graphs (arch §4.2). This module is the single home of domain types (§4.1),
including the *Draft* input models used by `MemoryStore` (§4.4) to validate
tool arguments before a mutation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


def _utcnow() -> datetime:
    """Return the current UTC time (naive fields are forbidden, arch §5.1)."""
    return datetime.now(UTC)


class Severity(StrEnum):
    """Finding severity - mandatory on every Finding (D14)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """Finding lifecycle: candidate → verified | rejected (§4.2)."""

    CANDIDATE = "candidate"
    VERIFIED = "verified"
    REJECTED = "rejected"


class FindingType(StrEnum):
    """Finding categories (open set - v0.1 ships xss/sqli/auth, §4.2)."""

    XSS = "xss"
    SQLI = "sqli"
    AUTH = "auth"


class EvidenceKind(StrEnum):
    """Evidence kinds (D20): v0.1 emits only HTTP request/response pairs."""

    HTTP_REQUEST_RESPONSE = "http_request_response"
    SCREENSHOT = "screenshot"  # reserved, phase 2 (D20)
    HAR = "har"  # reserved, phase 2 (D20)
    GRPC_FILE = "grpc_file"  # reserved, phase 2 (D20)


class EntityType(StrEnum):
    """Entities addressable by `MemoryStore.get` and the search index (§4.4-§4.5)."""

    TARGET = "target"
    SCOPE_ENTRY = "scope_entry"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    FINDING = "finding"
    EVIDENCE = "evidence"
    ATTACK_NODE = "attack_node"
    ATTACK_EDGE = "attack_edge"
    NOTE = "note"
    FACT = "fact"


class SearchableEntity(StrEnum):
    """Entity kinds backed by an FTS5 table (arch §4.3, §4.5)."""

    ENDPOINTS = "endpoints"
    FINDINGS = "findings"
    FACTS = "facts"
    NOTES = "notes"


class SearchHit(BaseModel):
    """One search result row (arch §4.4)."""

    entity_type: SearchableEntity
    id: int
    title_snippet: str
    score: float  # higher is better (-bm25 with a title-match boost)


class _DomainModel(BaseModel):
    """Common base: immutable-ish domain records with strict extra policy."""

    model_config = ConfigDict(extra="forbid")


class Target(_DomainModel):
    """Audited target of the session (§4.2)."""

    id: int
    base_url: HttpUrl
    stack_metadata: dict[str, str] = Field(default_factory=dict)  # filled in as research progresses


class ScopeEntry(_DomainModel):
    """One allowlist entry of the session scope (§4.2, §6.3 arch)."""

    id: int
    kind: Literal["domain", "ip_subnet", "port", "scheme"]
    value: str  # domain: "example.com"; subnet: "10.0.0.0/24"; port: "443"; scheme: "https"
    origin: Literal["config", "operator"]  # operator additions only via OperatorDecision (§7.5)


class Endpoint(_DomainModel):
    """Discovered endpoint; `host` carries the full host:port (§4.2)."""

    id: int
    host: str  # full host:port - needed for out-of-scope checks
    method: str  # GET/POST/...
    path: str
    auth_requirements: list[str] = Field(default_factory=list)  # secret/auth-scheme names
    research_status: Literal["undiscovered", "probed", "analyzed"] = "undiscovered"
    out_of_scope: bool = False  # network tools refuse to serve such records (§6.3)
    notes: str = ""


class Parameter(_DomainModel):
    """Request parameter attached to an endpoint (§4.2)."""

    id: int
    endpoint_id: int
    name: str
    location: Literal["query", "body", "header"]
    type: str = "string"  # free-form type label (string/number/enum...)
    examples: list[str] = Field(default_factory=list)


class Finding(_DomainModel):
    """Security finding; severity is mandatory, cvss optional (D14, §4.2)."""

    id: int
    type: FindingType
    status: FindingStatus
    severity: Severity  # mandatory (D14)
    cvss_vector: str | None = None
    endpoint_ref: int | None = None  # → endpoints.id
    evidence_refs: list[int] = Field(default_factory=list)  # → evidence.id
    title: str
    description: str
    reproduction: list[str] = Field(default_factory=list)  # reproduction steps (for the report)
    created_by: str  # module/orchestrator name
    created_at: datetime


class Evidence(_DomainModel):
    """Pointer to raw evidence files under `<session-dir>/evidence/` (§4.2)."""

    id: int
    kind: EvidenceKind
    session_paths: list[str]  # paths relative to the session directory
    finding_ref: int | None = None  # attached when a finding is saved
    metadata: dict[str, str]  # ts, tool, correlation_id
    created_at: datetime


class AttackNode(_DomainModel):
    """Attack-tree node: precondition | finding | goal (§4.2)."""

    id: int
    kind: Literal["precondition", "finding", "goal"]
    finding_ref: int | None = None  # required reference for kind == "finding"
    title: str
    description: str


class AttackEdge(_DomainModel):
    """Typed edge of an attack tree (§4.2)."""

    id: int
    src: int  # → attack_nodes.id
    dst: int  # → attack_nodes.id
    kind: Literal["requires", "enables", "leads_to"]


class Note(_DomainModel):
    """Free-form observation by a human or an agent (§4.2)."""

    id: int
    text: str
    tags: list[str] = Field(default_factory=list)
    author: str
    created_at: datetime


class Fact(_DomainModel):
    """Machine-readable statement about the target/stack (§4.2)."""

    id: int
    subject: str
    predicate: str
    obj: str
    tags: list[str] = Field(default_factory=list)
    source: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Draft models - validated tool/store inputs without server-assigned ids (§4.4).
# ---------------------------------------------------------------------------


class _DraftModel(BaseModel):
    """Common base for input drafts (strict extra policy, §4.4)."""

    model_config = ConfigDict(extra="forbid")


class ParameterDraft(_DraftModel):
    """New parameter to append to an endpoint (§4.4: updates are appends)."""

    name: str
    location: Literal["query", "body", "header"]
    type: str = "string"
    examples: list[str] = Field(default_factory=list)


class EndpointDraft(_DraftModel):
    """Upsert payload for `MemoryStore.upsert_endpoint` (§4.4)."""

    host: str
    method: str
    path: str
    auth_requirements: list[str] = Field(default_factory=list)
    research_status: Literal["undiscovered", "probed", "analyzed"] = "undiscovered"
    out_of_scope: bool = False
    notes: str = ""
    parameters: list[ParameterDraft] = Field(default_factory=list)  # appended on upsert


class FindingDraft(_DraftModel):
    """Creation payload for `MemoryStore.save_finding` (§4.4, D14)."""

    type: FindingType
    severity: Severity  # mandatory (D14)
    cvss_vector: str | None = None
    endpoint_ref: int | None = None
    evidence_refs: list[int] = Field(default_factory=list)
    title: str
    description: str
    reproduction: list[str] = Field(default_factory=list)
    created_by: str


class AttackNodeDraft(_DraftModel):
    """Creation payload for `MemoryStore.link_attack_node` (§4.4)."""

    kind: Literal["precondition", "finding", "goal"]
    finding_ref: int | None = None
    title: str
    description: str = ""


class AttackEdgeDraft(_DraftModel):
    """Edge to link together with a new node (§4.4: node + edges atomically).

    `src`/`dst` reference existing `attack_nodes.id` values; `None` refers to
    the node being created in the same call.
    """

    src: int | None = None
    dst: int | None = None
    kind: Literal["requires", "enables", "leads_to"]


class FactDraft(_DraftModel):
    """Creation payload for `MemoryStore.add_fact` (§4.4)."""

    subject: str
    predicate: str
    obj: str
    tags: list[str] = Field(default_factory=list)
    source: str


class NoteDraft(_DraftModel):
    """Creation payload for `MemoryStore.add_note` (§4.4)."""

    text: str
    tags: list[str] = Field(default_factory=list)
    author: str


class EvidenceDraft(_DraftModel):
    """Creation payload for `MemoryStore.add_evidence` (§4.4, T2.2.4).

    ``kind`` is `EvidenceKind`; v0.1 produces only `http_request_response`
    (D20 - the other kinds are reserved). `created_at` and `finding_ref`
    are store-managed (now UTC / attached via `save_finding`).
    """

    kind: EvidenceKind
    session_paths: list[str] = Field(min_length=1)  # paths relative to the session dir
    metadata: dict[str, str] = Field(default_factory=dict)  # ts, tool, correlation_id


class ReportStatistics(_DomainModel):
    """Journal-derived session statistics for the report (arch §11, T5.4.1).

    Leaf placement (§4.1): the statistics DTO crosses the core/report
    boundary without either side importing the other — the session wiring
    computes it from the journal, ``swarmy.report`` renders it.
    """

    events_total: int = 0
    events_by_type: dict[str, int] = Field(default_factory=dict)
    period_start: str = "n/a"  # UTC ISO ts of the first journaled event
    period_end: str = "n/a"  # UTC ISO ts of the last journaled event


__all__ = [
    "AttackEdge",
    "AttackEdgeDraft",
    "AttackNode",
    "AttackNodeDraft",
    "Endpoint",
    "EndpointDraft",
    "EntityType",
    "Evidence",
    "EvidenceDraft",
    "EvidenceKind",
    "Fact",
    "FactDraft",
    "Finding",
    "FindingDraft",
    "FindingStatus",
    "FindingType",
    "Note",
    "NoteDraft",
    "Parameter",
    "ParameterDraft",
    "ReportStatistics",
    "ScopeEntry",
    "SearchHit",
    "SearchableEntity",
    "Severity",
    "Target",
]
