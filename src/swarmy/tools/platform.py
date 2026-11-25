"""Platform ``memory_*`` tools and the verification tool (arch §4.4, §6.1, T1.2.6).

``make_memory_tools`` wires the ``MemoryStore`` and the session's ``emit_event``
tool into LLM-facing tool functions. Contract of every tool here:

* fully typed primitive arguments (G3: no ``Any``, no ``dict[str, Any]``);
* non-empty LLM-facing docstrings (G10);
* arguments validated through the Pydantic draft models *before* any store
  call — an invalid argument raises and the memory is not touched (arch §4.4);
* JSON-string results (``model_dump_json`` / ``json.dumps``), never a raw
  ``dict`` (LLM serialization boundary);
* after a successful mutation the platform publishes the corresponding event
  of arch §5.5 — the event is created by the platform, not by the agent, so
  ``source`` can not be forged (arch §5.2).

Boundary (arch §2.5): ``swarmy.tools`` may use memory models/store and the
events package, never ``swarmy.core`` / ``swarmy.modules`` / ``swarmy.tui``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Literal

from swarmy.events import JsonValue  # noqa: TC001 - runtime: tool-call schema
from swarmy.memory.models import (
    AttackEdgeDraft,
    AttackNodeDraft,
    EndpointDraft,
    EntityType,
    FactDraft,
    FindingDraft,
    FindingStatus,
    NoteDraft,
    ParameterDraft,
    SearchableEntity,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from pydantic import BaseModel

    from swarmy.events import EmitEventTool
    from swarmy.memory.models import Finding
    from swarmy.memory.store import MemoryStore
    from swarmy.tools.limits import ResourceLimiter
    from swarmy.tools.scope import ScopeEntries


def _json_of(items: Sequence[BaseModel]) -> str:
    """Serialize a sequence of Pydantic models to a JSON array string."""
    return json.dumps([item.model_dump(mode="json") for item in items])


def _searchable(value: str) -> SearchableEntity:
    """Validate one search entity kind with an agent-addressable message."""
    try:
        return SearchableEntity(value)
    except ValueError as exc:
        allowed = [item.value for item in SearchableEntity]
        msg = f"entity_types items must be one of {allowed}, got {value!r}"
        raise ValueError(msg) from exc


def _entity_type(value: str) -> EntityType:
    """Validate one memory_get entity kind with an agent-addressable message."""
    try:
        return EntityType(value)
    except ValueError as exc:
        allowed = [item.value for item in EntityType]
        msg = f"entity_type must be one of {allowed}, got {value!r}"
        raise ValueError(msg) from exc


def _finding_status(value: str) -> FindingStatus:
    """Validate one lifecycle status (arch §4.4: candidate/verified/rejected)."""
    try:
        return FindingStatus(value)
    except ValueError as exc:
        allowed = [item.value for item in FindingStatus]
        msg = f"status must be one of {allowed}, got {value!r}"
        raise ValueError(msg) from exc


def _severity_or_none(value: str | None) -> Severity | None:
    """Validate an optional severity string into the enum."""
    if value is None:
        return None
    try:
        return Severity(value)
    except ValueError as exc:
        allowed = [item.value for item in Severity]
        msg = f"severity must be one of {allowed}, got {value!r}"
        raise ValueError(msg) from exc


def _resolution_event(
    finding: Finding, reason: str | None
) -> tuple[str, Mapping[str, JsonValue]]:
    """Pick the §5.5 event of a finding status change and its payload."""
    payload: Mapping[str, JsonValue] = {
        "finding_id": finding.id,
        "severity": finding.severity,
        "reason": reason,
    }
    if finding.status is FindingStatus.VERIFIED:
        return "FindingVerified", payload
    return "FindingRejected", payload


def make_memory_tools(
    store: MemoryStore, emit: EmitEventTool
) -> dict[str, Callable[..., object]]:
    """Build the ``memory_*`` tools plus ``update_finding_status`` (arch §4.4).

    ``emit`` is the session's ``emit_event`` tool (arch §5.2): the wrappers
    publish platform events through it after each successful mutation.
    """
    # Store + emit tool live only in this closure; the tool functions below
    # never import session machinery themselves (arch §8.5 pattern).

    async def memory_search(
        query: str, entity_types: list[str] | None = None, limit: int = 20
    ) -> str:
        """Full-text search over the shared session memory (FTS5, bm25).

        Searches endpoints, findings, facts and notes recorded so far in this
        session — use it before saving anything new to avoid duplicates and
        to recall prior observations.

        Args:
            query: free-text query; every whitespace-separated word is an OR
                term (unknown words simply yield no hits).
            entity_types: optional filter, a list drawn from
                ``["endpoints", "findings", "facts", "notes"]``; all kinds
                when omitted.
            limit: maximum number of hits to return (default 20).

        Returns:
            JSON array of hits ``{entity_type, id, title_snippet, score}``,
            best first; ``id`` addresses ``memory_get``.
        """
        kinds = [_searchable(value) for value in entity_types] if entity_types else None
        hits = await store.search(query, kinds, limit)
        return _json_of(hits)

    async def memory_get(entity_type: str, id: int) -> str:
        """Return one stored entity of the session memory by id.

        Valid ``entity_type`` values: ``target``, ``scope_entry``,
        ``endpoint``, ``parameter``, ``finding``, ``evidence``,
        ``attack_node``, ``attack_edge``, ``note``, ``fact``.

        Args:
            entity_type: one of the entity kinds above.
            id: primary key of the entity row.

        Returns:
            The full entity record as a JSON object.
        """
        kind = _entity_type(entity_type)
        entity = await store.get(kind, id)
        return entity.model_dump_json()

    async def memory_upsert_endpoint(
        host: str,
        method: str,
        path: str,
        auth_requirements: list[str] | None = None,
        research_status: Literal["undiscovered", "probed", "analyzed"] = "undiscovered",
        out_of_scope: bool = False,
        notes: str = "",
        parameters: list[dict[str, str | list[str]]] | None = None,
    ) -> str:
        """Insert or update one endpoint of the target (dedup key: host+method+path).

        Records an application endpoint you discovered. A new
        ``(host, method, path)`` triple is created; an existing one is
        updated (auth requirements, research status, scope flag, notes are
        overwritten, parameters are merged). The platform publishes
        ``EndpointsDiscovered`` for a new row and ``EndpointUpdated`` for an
        update.

        Args:
            host: full ``host:port`` of the target, e.g. ``app.example.com:443``.
            method: HTTP method, e.g. ``GET`` or ``POST``.
            path: request path, e.g. ``/api/items``.
            auth_requirements: secret/auth-scheme names this endpoint needs.
            research_status: one of ``undiscovered`` (default), ``probed``,
                ``analyzed``.
            out_of_scope: whether the endpoint lies outside the allowlisted
                scope — out-of-scope records are never served by http tools.
            notes: free-form observations.
            parameters: known request parameters, each a JSON object
                ``{name, location}`` with ``location`` in ``query``/``body``/
                ``header``, optionally ``type`` and ``examples`` (list of str).

        Returns:
            The stored endpoint record as a JSON object (including ``id``).
        """
        draft = EndpointDraft(
            host=host,
            method=method,
            path=path,
            auth_requirements=list(auth_requirements) if auth_requirements else [],
            research_status=research_status,
            out_of_scope=out_of_scope,
            notes=notes,
            parameters=[
                ParameterDraft.model_validate(item) for item in (parameters or [])
            ],
        )
        known = await store.list_endpoints()
        was_known = any(
            row.host == host and row.method == method and row.path == path
            for row in known
        )
        endpoint = await store.upsert_endpoint(draft)
        if was_known:
            payload: Mapping[str, JsonValue] = {"endpoint_id": endpoint.id}
            await emit("EndpointUpdated", payload)
        else:
            payload = {
                "endpoints": [endpoint.id],
                "out_of_scope_count": 1 if endpoint.out_of_scope else 0,
            }
            await emit("EndpointsDiscovered", payload)
        return endpoint.model_dump_json()

    async def memory_save_finding(
        type: str,
        severity: str,
        title: str,
        description: str,
        created_by: str,
        cvss_vector: str | None = None,
        endpoint_ref: int | None = None,
        evidence_refs: list[int] | None = None,
        reproduction: list[str] | None = None,
    ) -> str:
        """Save a new finding candidate into the session memory.

        Records a suspected or confirmed weakness. The finding enters the
        lifecycle as ``candidate``; verification moves it to ``verified`` or
        ``rejected`` (see ``update_finding_status``). The platform publishes
        ``FindingCandidate``.

        Args:
            type: finding category: ``xss``, ``sqli`` or ``auth``.
            severity: one of ``critical``, ``high``, ``medium``, ``low``,
                ``info`` — mandatory for every finding.
            title: short human-readable headline.
            description: what the weakness is and why it matters.
            created_by: name of the authoring module or agent.
            cvss_vector: optional CVSS vector string, e.g. ``CVSS:3.1/AV:N/...``.
            endpoint_ref: id of the affected endpoint (from ``memory_get``
                or ``memory_search``) when one exists.
            evidence_refs: ids of evidence rows supporting the finding; each
                must exist, otherwise the call fails without saving.
            reproduction: ordered reproduction steps for the report.

        Returns:
            The stored finding record as a JSON object (including ``id``).
        """
        draft = FindingDraft(
            type=type,
            severity=severity,
            cvss_vector=cvss_vector,
            endpoint_ref=endpoint_ref,
            evidence_refs=list(evidence_refs) if evidence_refs else [],
            title=title,
            description=description,
            reproduction=list(reproduction) if reproduction else [],
            created_by=created_by,
        )
        finding = await store.save_finding(draft)
        payload: Mapping[str, JsonValue] = {
            "finding_id": finding.id,
            "finding_type": finding.type,
            "endpoint_ref": finding.endpoint_ref,
            "evidence_refs": finding.evidence_refs,
        }
        await emit("FindingCandidate", payload)
        return finding.model_dump_json()

    async def memory_link_attack_node(
        kind: Literal["precondition", "finding", "goal"],
        title: str,
        description: str = "",
        finding_ref: int | None = None,
        edges: list[dict[str, str | int | None]] | None = None,
    ) -> str:
        """Create one attack-tree node, optionally linking typed edges in one call.

        Attack trees model preconditions → findings → goals. Nodes of kind
        ``finding`` should reference the finding id. ``MemoryStore`` returns
        only the created node (arch §4.4), so per-edge ``AttackTreeUpdated``
        events carry ``edge_id: null`` while the edges themselves are
        durably stored; edge ids become readable via ``memory_get``.

        Args:
            kind: node role: ``precondition``, ``finding`` or ``goal``.
            title: short human-readable label of the node.
            description: optional details.
            finding_ref: id of the backing finding (required semantics for
                ``kind == "finding"``).
            edges: optional list of JSON objects ``{src, dst, kind}`` where
                ``src``/``dst`` are existing node ids or ``null`` (meaning
                the node created by this call) and ``kind`` is one of
                ``requires``, ``enables``, ``leads_to``. Unknown node ids
                abort the whole call — no node, no edges persist.

        Returns:
            The stored attack node record as a JSON object (including ``id``).
        """
        node = AttackNodeDraft(
            kind=kind,
            finding_ref=finding_ref,
            title=title,
            description=description,
        )
        edge_drafts = [AttackEdgeDraft.model_validate(item) for item in (edges or [])]
        created = await store.link_attack_node(node, edge_drafts)
        payload: Mapping[str, JsonValue] = {
            "tree_id": created.id,
            "op": "add_node",
            "node_id": created.id,
        }
        await emit("AttackTreeUpdated", payload)
        for _edge in edge_drafts:
            edge_payload: Mapping[str, JsonValue] = {
                "tree_id": created.id,
                "op": "add_edge",
                "edge_id": None,  # store API returns the node only (arch §4.4)
            }
            await emit("AttackTreeUpdated", edge_payload)
        return created.model_dump_json()

    async def memory_add_fact(
        subject: str,
        predicate: str,
        obj: str,
        tags: list[str] | None = None,
        source: str = "",
    ) -> str:
        """Store one machine-readable fact about the target or stack.

        Facts are triple-shaped statements (`subject predicate object`) that
        later searches can recall, e.g. subject ``framework``, predicate
        ``runs``, object ``Django 4.2``.

        Args:
            subject: what the statement is about, e.g. ``auth``.
            predicate: the relation, e.g. ``uses``.
            obj: the value, e.g. ``JWT in localStorage``.
            tags: optional labels for filtering.
            source: optional provenance (module or tool name).

        Returns:
            The stored fact record as a JSON object (including ``id``).
        """
        draft = FactDraft(
            subject=subject, predicate=predicate, obj=obj, tags=tags or [], source=source
        )
        fact = await store.add_fact(draft)
        return fact.model_dump_json()

    async def memory_add_note(
        text: str, tags: list[str] | None = None, author: str = ""
    ) -> str:
        """Store one free-form observation in the session memory.

        Use it for anything worth remembering that fits neither an endpoint
        nor a finding nor a fact — hunches, dead ends, operator remarks.

        Args:
            text: the observation itself (markdown allowed).
            tags: optional labels for filtering.
            author: optional author name.

        Returns:
            The stored note record as a JSON object (including ``id``).
        """
        draft = NoteDraft(text=text, tags=tags or [], author=author)
        note = await store.add_note(draft)
        return note.model_dump_json()

    async def update_finding_status(
        finding_id: int,
        status: str,
        severity: str | None = None,
        reason: str | None = None,
    ) -> str:
        """Move a finding through its lifecycle (platform verification tool).

        Allowed transitions: ``candidate`` → ``verified`` or ``rejected``.
        This is the only tool that may change a finding's status; call it
        after you actually verified (or disproved) the weakness, not on a
        hunch. The platform publishes ``FindingVerified`` or
        ``FindingRejected`` so policies and the TUI react.

        Args:
            finding_id: id of the finding (from ``memory_search``/``memory_get``).
            status: target status: ``verified`` or ``rejected`` (``candidate``
                is the initial state and legal input).
            severity: optionally update the severity (``critical``/``high``/
                ``medium``/``low``/``info``) together with the status.
            reason: optional human-readable justification, stored on the event.

        Returns:
            The updated finding record as a JSON object.
        """
        new_status = _finding_status(status)
        new_severity = _severity_or_none(severity)
        finding = await store.update_finding_status(finding_id, new_status, new_severity)
        event_type, payload = _resolution_event(finding, reason)
        await emit(event_type, payload)
        return finding.model_dump_json()

    tools: dict[str, Callable[..., object]] = {
        "memory_search": memory_search,
        "memory_get": memory_get,
        "memory_upsert_endpoint": memory_upsert_endpoint,
        "memory_save_finding": memory_save_finding,
        "memory_link_attack_node": memory_link_attack_node,
        "memory_add_fact": memory_add_fact,
        "memory_add_note": memory_add_note,
        "update_finding_status": update_finding_status,
    }
    return tools


def make_session_info_tool(
    *,
    base_url: str,
    scope_entries: ScopeEntries,
    limiter: ResourceLimiter,
    profile: str,
    mode: str,
    store: MemoryStore,
) -> Callable[..., object]:
    """Build the orchestrator's ``session_info`` tool (arch §6.1, T3.1.5).

    Reports the session state an orchestrator needs for planning: the target
    base URL, the scope allowlist (domains/subnets/ports/schemes), the HITL
    profile and autonomy mode, the session-global request budget and the
    research progress (endpoint/finding counts by status). No secret values
    exist in the closure — the tool structurally cannot leak one (arch §6.1;
    T3.1.5 AC: a secret-value scan over the output finds nothing).

    Returns:
        The async no-argument tool function; its result is a JSON string
        (LLM serialization boundary).
    """

    async def session_info() -> str:
        """Report the session state: target, scope, HITL mode, budget, progress.

        Returns:
            A JSON object with the sections ``target``, ``scope``, ``hitl``,
            ``budget`` and ``research``. Scope and budget are the live
            session values; ``research`` counts stored endpoints and
            findings by status. Contains no secret material.
        """
        endpoints = await store.list_endpoints()
        findings_by_status: dict[str, int] = {}
        for status in ("candidate", "verified", "rejected"):
            found = await store.list_findings(status=FindingStatus(status))
            findings_by_status[status] = len(found)
        state = {
            "target": {"base_url": base_url},
            "scope": {
                "domains": list(scope_entries.domains),
                "ip_subnets": list(scope_entries.ip_subnets),
                "ports": list(scope_entries.ports),
                "schemes": list(scope_entries.schemes),
            },
            "hitl": {"profile": profile, "mode": mode},
            "budget": {
                "used": limiter.budget_used,
                "remaining": limiter.limits.total_request_budget - limiter.budget_used,
            },
            "research": {
                "endpoints": len(endpoints),
                "findings": findings_by_status,
            },
        }
        return json.dumps(state)

    session_info.__name__ = "session_info"
    doc = (
        "Report the session state for planning: the authorized target base "
        "URL, the scope allowlist (domains, IP subnets, ports, schemes), the "
        "HITL strictness profile and autonomy mode, the remaining global "
        "request budget, and research progress (endpoint count, findings by "
        "status). Call this before planning work; it contains no secrets."
    )
    session_info.__doc__ = doc
    return session_info
