"""``ReportGenerator`` — the deterministic markdown session report (arch §11, F6).

The generator is a *read-only* consumer of the session memory: it queries
the ``MemoryStore`` (findings by severity, endpoints with parameters, attack
trees), renders ``report/templates/report.md.j2`` through jinja2 and returns
the markdown for ``<session-dir>/report.md``. No LLM and no network
participate anywhere — the ``generate_report`` tool (wired into the
orchestrator's toolset by the session, RD-7) merely triggers the render.

Boundary (arch §2.5): ``swarmy.report`` imports only the memory store/models
(read-only) plus pydantic/jinja2/stdlib. Session-wide journal statistics are
computed by the session wiring (core may read the journal) and injected as
a :class:`ReportStatistics` value — this package never opens the journal.

Draft discipline (spec §10): the first line of every generated report is
the draft mark — the report is a verification aid, never a deliverable
before a pentester reviewed it.

Mermaid subset (arch §19.4 / R8, decision fixed in the template header):
only ``graph TD``, double-quoted node labels and ``-->``/``-->|label|``
edges — the intersection supported by the widespread renderers; node labels
are sanitized to a safe character set without ``<``/``>`` (raw-HTML vector
in loose renderers). A plain-text rendering of every tree precedes the
mermaid block (text render = fallback).

Escaping contract (spec §10; review Issues #40/#18): every target/LLM-derived
string rendered into ``report.md`` (finding titles, descriptions,
reproduction steps, endpoint path/host/parameters, tree text) is
markdown/HTML-neutralized by :func:`_report_safe` in the view models — the
template interpolates only report-safe text plus structural tokens; the
draft mark keeps the report a verification aid.
"""

from __future__ import annotations

import re
from importlib import resources
from typing import TYPE_CHECKING, Final

import jinja2
from pydantic import BaseModel, ConfigDict

from swarmy.memory.models import (
    AttackEdge,
    AttackNode,
    Endpoint,
    EntityType,
    Evidence,
    Finding,
    FindingStatus,
    ReportStatistics,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Coroutine, Sequence
    from pathlib import Path

    from swarmy.memory.store import MemoryStore

#: Severity ranking of the findings section: critical first, info last.
SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

#: First line of every generated report (spec §10: draft mark).
DRAFT_MARK: Final[str] = "**DRAFT — requires pentester review before any use.**"

#: Status ordering: verified findings first, then candidates, rejections last.
_STATUS_RANK: Final[dict[str, int]] = {
    FindingStatus.VERIFIED.value: 0,
    FindingStatus.CANDIDATE.value: 1,
    FindingStatus.REJECTED.value: 2,
}

#: Characters allowed in mermaid node labels (everything else is stripped).
#: ``<``/``>`` are deliberately excluded: they buy nothing inside a quoted
#: label and are the raw-HTML vector in renderers with loose ``htmlLabels``
#: security (Issue #40).
_MERMAID_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"[^A-Za-z0-9 .,:;!?%&*+_/ -]"
)

#: Maximum rendered length of one mermaid node label.
_MERMAID_LABEL_MAX: Final[int] = 120


def _report_safe(text: str) -> str:
    """Escape markdown/HTML-sensitive sequences of target/LLM-derived text.

    The report-escaping contract (spec §10; review Issues #40/#18): every
    finding, tree and endpoint string that may carry target-controlled
    content is neutralized before it enters ``report.md`` — raw HTML cannot
    survive (``<``/``>`` become entities), table pipes, code-span backticks
    and link/image brackets lose their markdown structure, and no line
    starts with a heading/image marker. Evidence paths stay verbatim (they
    are session-generated, not target-derived).
    """
    escaped = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("[", "\\[")
    )
    return "\n".join(
        f"\\{line}" if line.startswith(("#", "!")) else line
        for line in escaped.split("\n")
    )


def _template_text() -> str:
    """Load ``report/templates/report.md.j2`` from the installed package."""
    return (
        resources.files("swarmy.report")
        .joinpath("templates/report.md.j2")
        .read_text(encoding="utf-8")
    )


class EvidenceRef(BaseModel):
    """One evidence file of a finding, report-rendered."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: int
    kind: str
    path: str  # session-relative link target (exists on disk by construction)


class FindingView(BaseModel):
    """Report row of one finding (severity-sorted, evidence-resolved).

    ``title``/``description``/``reproduction``/``created_by``/
    ``endpoint_label``/``cvss_vector`` carry report-safe
    (markdown/HTML-neutralized) text; ``evidence`` paths stay verbatim
    session-relative links.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: int
    type: str
    status: str
    severity: str
    cvss_vector: str | None
    title: str
    description: str
    reproduction: list[str]
    created_by: str
    endpoint_label: str | None  # "METHOD path (host)" when endpoint_ref is set
    evidence: list[EvidenceRef]


class EndpointView(BaseModel):
    """Report row of one endpoint (appendix table; report-safe text)."""

    model_config = ConfigDict(extra="forbid")

    endpoint_id: int
    method: str  # report-safe: escaped even for pre-normalization rows
    path: str
    host: str
    research_status: str
    out_of_scope: bool
    parameters: str  # "name(query), name(body)" — pipe-free for the table


class AttackTreeView(BaseModel):
    """One rendered attack tree: text chain plus the mermaid subset block."""

    model_config = ConfigDict(extra="forbid")

    root_id: int
    lines: list[str]  # text rendering: "precondition --enables--> finding"
    mermaid: list[str]  # mermaid subset lines (graph TD, quoted labels)


class ReportData(BaseModel):
    """Everything the template renders (assembled by the generator)."""

    model_config = ConfigDict(extra="forbid")

    target_base_url: str
    scope_entries: list[str]  # "kind=value"
    statistics: ReportStatistics
    findings: list[FindingView]
    endpoints: list[EndpointView]
    trees: list[AttackTreeView]
    findings_total: int
    verified_total: int
    endpoints_total: int
    nodes_total: int


class ReportGenerator:
    """Assembles :class:`ReportData` from memory and renders the template.

    The store is used strictly read-only (arch §2.5); constructing the
    generator performs no I/O beyond loading the bundled template.
    """

    __slots__ = ("_store", "_template")

    def __init__(
        self, store: MemoryStore, template_text: str | None = None
    ) -> None:
        """Bind the read-only store; ``template_text`` defaults to the
        bundled ``report.md.j2`` (overridable for tests)."""
        self._store = store
        self._template: jinja2.Template = jinja2.Environment(
            autoescape=False,  # markdown output; text is report-safe (escaped in the view models)
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        ).from_string(_template_text() if template_text is None else template_text)

    async def generate(
        self,
        target_base_url: str,
        scope_labels: list[str],
        statistics: ReportStatistics,
    ) -> str:
        """Render the full report markdown (read-only over memory).

        The returned string always starts with :data:`DRAFT_MARK` followed
        by a newline — the draft discipline of spec §10. ``scope_labels``
        are the session wiring's rendering of the resolved scope allowlist
        (this package never imports the scope machinery, arch §2.5).
        """
        data = await self._collect(
            target_base_url=target_base_url,
            scope_labels=scope_labels,
            statistics=statistics,
        )
        return f"{DRAFT_MARK}\n{self._template.render(data.model_dump())}"

    # ---- collection (read-only store queries, no LLM/network) ----

    async def _collect(
        self,
        *,
        target_base_url: str,
        scope_labels: list[str],
        statistics: ReportStatistics,
    ) -> ReportData:
        """Query the store and build every template view model."""
        findings = await self._sorted_findings()
        finding_views = [await self._finding_view(f) for f in findings]
        endpoints = await self._store.list_endpoints()
        endpoint_views = [await self._endpoint_view(e) for e in endpoints]
        trees = await self._tree_views()
        return ReportData(
            target_base_url=target_base_url,
            scope_entries=scope_labels,
            statistics=statistics,
            findings=finding_views,
            endpoints=endpoint_views,
            trees=trees,
            findings_total=len(findings),
            verified_total=sum(
                1 for f in findings if f.status is FindingStatus.VERIFIED
            ),
            endpoints_total=len(endpoints),
            nodes_total=len(trees),
        )

    async def _sorted_findings(self) -> list[Finding]:
        """All findings: verified first, severity-ranked, stable by id."""
        findings = await self._store.list_findings()
        return sorted(
            findings,
            key=lambda f: (
                _STATUS_RANK.get(f.status.value, 3),
                SEVERITY_ORDER.index(f.severity),
                f.id,
            ),
        )

    async def _finding_view(self, finding: Finding) -> FindingView:
        """Resolve one finding's endpoint label and evidence file paths."""
        endpoint_label: str | None = None
        if finding.endpoint_ref is not None:
            record = await self._store.get(EntityType.ENDPOINT, finding.endpoint_ref)
            if isinstance(record, Endpoint):
                endpoint_label = f"{record.method} {record.path} ({record.host})"
        evidence: list[EvidenceRef] = []
        for evidence_id in finding.evidence_refs:
            record = await self._store.get(EntityType.EVIDENCE, evidence_id)
            if isinstance(record, Evidence) and record.session_paths:
                evidence.append(
                    EvidenceRef(
                        evidence_id=record.id,
                        kind=record.kind.value,
                        path=record.session_paths[0],
                    )
                )
        return FindingView(
            finding_id=finding.id,
            type=finding.type.value,
            status=finding.status.value,
            severity=finding.severity.value,
            cvss_vector=None if finding.cvss_vector is None else _report_safe(finding.cvss_vector),
            title=_report_safe(finding.title),
            description=_report_safe(finding.description),
            reproduction=[_report_safe(step) for step in finding.reproduction],
            created_by=_report_safe(finding.created_by),
            endpoint_label=None if endpoint_label is None else _report_safe(endpoint_label),
            evidence=evidence,
        )

    async def _endpoint_view(self, endpoint: Endpoint) -> EndpointView:
        """Render one endpoint row with its parameter summary."""
        parameters = await self._store.list_parameters(endpoint.id)
        names = ", ".join(f"{p.name}({p.location})" for p in parameters)
        return EndpointView(
            endpoint_id=endpoint.id,
            method=_report_safe(endpoint.method),
            path=_report_safe(endpoint.path),
            host=_report_safe(endpoint.host),
            research_status=endpoint.research_status,
            out_of_scope=endpoint.out_of_scope,
            parameters=_report_safe(names),
        )

    async def _tree_views(self) -> list[AttackTreeView]:
        """Render every connected component of the attack-node graph.

        A "tree" here is one weakly connected component over the typed
        edges; components are ordered by their smallest node id. Nodes not
        touched by any edge form their own single-node component.
        """
        nodes = await self._store.list_attack_nodes()
        edges = await self._store.list_attack_edges()
        if not nodes:
            return []
        parent = {node.id: node.id for node in nodes}

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for edge in edges:
            if edge.src in parent and edge.dst in parent:
                root_src, root_dst = find(edge.src), find(edge.dst)
                if root_src != root_dst:
                    parent[max(root_src, root_dst)] = min(root_src, root_dst)
        components: dict[int, list[int]] = {}
        for node in nodes:
            components.setdefault(find(node.id), []).append(node.id)
        views: list[AttackTreeView] = []
        for root in sorted(components):
            members = set(components[root])
            component_edges = [
                e for e in edges if e.src in members and e.dst in members
            ]
            views.append(self._tree_view(root, members, component_edges, nodes))
        return views

    def _tree_view(
        self,
        root: int,
        members: set[int],
        edges: list[AttackEdge],
        nodes: list[AttackNode],
    ) -> AttackTreeView:
        """Text + mermaid rendering of one tree component."""
        by_id = {node.id: node for node in nodes}
        label_of: dict[int, str] = {}
        lines: list[str] = []
        mermaid: list[str] = ["graph TD"]
        for number, node_id in enumerate(sorted(members), start=1):
            node = by_id[node_id]
            label = _mermaid_label(f"{node.kind}: {node.title}")
            label_of[node_id] = f"N{number}"
            mermaid.append(f'    N{number}["{label}"]')
            lines.append(f"[N{number}] {node.kind}: {_report_safe(node.title)}")
        for edge in edges:
            src_label = label_of.get(edge.src, "?")
            dst_label = label_of.get(edge.dst, "?")
            edge_kind = _mermaid_label(edge.kind)
            lines.append(f"[{src_label}] --{edge_kind}--> [{dst_label}]")
            mermaid.append(f"    {src_label} -->|{edge_kind}| {dst_label}")
        return AttackTreeView(root_id=root, lines=lines, mermaid=mermaid)


def _mermaid_label(text: str) -> str:
    """Sanitize a node label for the mermaid subset (quote-free, one line)."""
    cleaned = _MERMAID_LABEL_RE.sub(" ", text.replace('"', "'"))
    return " ".join(cleaned.split())[:_MERMAID_LABEL_MAX]


def make_generate_report_tool(
    *,
    store: MemoryStore,
    session_dir: Path,
    base_url: str,
    scope_labels: Sequence[str],
    statistics: Callable[[], Awaitable[ReportStatistics]],
) -> Callable[..., Coroutine[object, object, str]]:
    """Build the orchestrator's ``generate_report`` platform tool (RD-7).

    The closure binds the read-only store and the session facts (target,
    scope labels) plus a statistics provider — the session wiring computes
    the journal statistics (this package never touches the journal,
    arch §2.5). The tool is deterministic: it renders the template and
    writes ``<session-dir>/report.md``; it never calls an LLM or the
    network. Risk class: undeclared → the registry ``passive`` default
    (AD-7), so the tool is never HITL-gated.

    Args:
        store: the session ``MemoryStore`` (read-only use).
        session_dir: the portable session folder receiving ``report.md``.
        base_url: the audited target base URL (summary section).
        scope_labels: rendered allowlist entries (summary section).
        statistics: async provider of the journal-derived statistics.

    Returns:
        The zero-argument ``generate_report`` tool function.
    """

    async def generate_report() -> str:
        """Write the session report to ``<session-dir>/report.md``.

        Deterministic generation: the findings are sorted by severity and
        verification status, every evidence reference is a session-relative
        file path, the attack trees render as text plus a mermaid block.
        The first line marks the report as a draft requiring pentester
        review. No LLM and no network calls happen here.

        Returns:
            A one-line confirmation naming the written report path.
        """
        generator = ReportGenerator(store)
        markdown = await generator.generate(
            base_url, list(scope_labels), await statistics()
        )
        report_path = session_dir / "report.md"
        report_path.write_text(markdown, encoding="utf-8")
        return f"report written to {report_path} ({len(markdown)} bytes)"

    return generate_report


__all__ = [
    "DRAFT_MARK",
    "SEVERITY_ORDER",
    "AttackTreeView",
    "EndpointView",
    "EvidenceRef",
    "FindingView",
    "ReportData",
    "ReportGenerator",
    "ReportStatistics",
    "make_generate_report_tool",
]
