"""T5.4.3 - the F6 criterion: report.md generates from the session state.

Canonical carrier of roadmap T5.4.3 (the F5 demo itself exercises report
generation end-to-end in ``tests/integration/scenarios/test_demo_f5.py``;
this module pins the generator contract against session-shaped data: the
complete section structure, evidence links that resolve to real files, and
the verified-first / severity-ranked finding order).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

import pytest

from swarmy.core.database import Database
from swarmy.memory.models import (
    AttackEdgeDraft,
    AttackNodeDraft,
    EndpointDraft,
    EvidenceDraft,
    FindingDraft,
    FindingStatus,
    ReportStatistics,
    Severity,
)
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex
from swarmy.memory.store import MemoryStore
from swarmy.report.generator import DRAFT_MARK, make_generate_report_tool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Coroutine
    from pathlib import Path

pytestmark = pytest.mark.integration

#: Evidence file written into the session folder (raw artifact, §6.8).
EVIDENCE_REL: Final[str] = "evidence/ev-1/request.txt"
EVIDENCE_BODY: Final[str] = "GET /q?q=swxdemo0000000001\nHost: 127.0.0.1\n"


@pytest.fixture
async def session_dir(tmp_path: Path) -> Path:
    """The portable session folder (evidence layout included)."""
    directory = tmp_path / "s"
    (directory / "evidence" / "ev-1").mkdir(parents=True)
    (directory / EVIDENCE_REL).write_text(EVIDENCE_BODY, encoding="utf-8")
    return directory


@pytest.fixture
async def store(session_dir: Path) -> AsyncIterator[MemoryStore]:
    """The report's read-only view: fresh migrated database per test."""
    db = Database(session_dir / "memory.sqlite", MIGRATIONS)
    await db.open()
    try:
        yield MemoryStore(db, Fts5SearchIndex(await db.connection("search")))
    finally:
        await db.close()


@pytest.fixture
async def seeded(store: MemoryStore) -> dict[str, int]:
    """Demo-session-shaped state: findings across severities + a tree."""
    evidence = await store.add_evidence(
        EvidenceDraft(
            kind="http_request_response",
            session_paths=[EVIDENCE_REL],
            metadata={"ts": "now", "tool": "http_get", "correlation_id": ""},
        )
    )
    endpoint = await store.upsert_endpoint(
        EndpointDraft(host="127.0.0.1", method="GET", path="/q")
    )
    critical = await store.save_finding(
        FindingDraft(
            type="xss",
            severity=Severity.CRITICAL,
            title="critical verified xss",
            description="marker reflected in the q parameter",
            reproduction=["GET /q?q=<marker>"],
            evidence_refs=[evidence.id],
            endpoint_ref=endpoint.id,
            created_by="xss-detector",
        )
    )
    medium = await store.save_finding(
        FindingDraft(
            type="xss",
            severity=Severity.MEDIUM,
            title="medium candidate xss",
            description="candidate awaiting verification",
            created_by="xss-detector",
        )
    )
    low = await store.save_finding(
        FindingDraft(
            type="auth",
            severity=Severity.LOW,
            title="low rejected lead",
            description="rejected by verification",
            created_by="xss-detector",
        )
    )
    await store.update_finding_status(critical.id, FindingStatus.VERIFIED)
    await store.update_finding_status(low.id, FindingStatus.REJECTED)
    precondition = await store.link_attack_node(
        AttackNodeDraft(kind="precondition", title='attacker controls "q"'), []
    )
    finding_node = await store.link_attack_node(
        AttackNodeDraft(kind="finding", finding_ref=critical.id, title="xss in q"),
        [AttackEdgeDraft(src=precondition.id, dst=None, kind="enables")],
    )
    await store.link_attack_node(
        AttackNodeDraft(kind="goal", title="session theft"),
        [AttackEdgeDraft(src=finding_node.id, dst=None, kind="leads_to")],
    )
    return {"evidence": evidence.id, "critical": critical.id, "medium": medium.id}


async def _statistics() -> ReportStatistics:
    """Journal-derived statistics (the session wiring provides these)."""
    return ReportStatistics(
        events_total=9,
        events_by_type={
            "TargetSet": 1,
            "EndpointsDiscovered": 2,
            "FindingCandidate": 1,
            "FindingVerified": 1,
            "AttackTreeUpdated": 3,
        },
        period_start="2026-11-25T10:00:00+00:00",
        period_end="2026-11-25T10:05:00+00:00",
    )


def _report_tool(
    store: MemoryStore, session_dir: Path
) -> Callable[[], Coroutine[object, object, str]]:
    """The orchestrator's ``generate_report`` platform tool (RD-7)."""
    return make_generate_report_tool(
        store=store,
        session_dir=session_dir,
        base_url="http://127.0.0.1:9/",
        scope_labels=["ip=127.0.0.1/32", "scheme=http"],
        statistics=_statistics,
    )


async def test_f6_report_generates_from_the_session(
    store: MemoryStore, session_dir: Path, seeded: dict[str, int]
) -> None:
    """AC T5.4.3 / F6: report.md is generated from the session state."""
    del seeded  # the fixture seeds the store the tool reads
    tool = _report_tool(store, session_dir)
    confirmation = await tool()
    report_path = session_dir / "report.md"
    assert report_path.is_file()
    assert str(report_path) in confirmation
    report = report_path.read_text(encoding="utf-8")
    assert report.splitlines()[0] == DRAFT_MARK
    for section in (
        "## Summary",
        "## Findings",
        "## Attack trees",
        "## Appendix: researched endpoints",
    ):
        assert section in report, section
    # the endpoint and the tree made it into the appendix / tree section
    assert "GET /q" in report
    assert "attacker controls" in report


async def test_report_evidence_links_point_to_existing_files(
    store: MemoryStore, session_dir: Path, seeded: dict[str, int]
) -> None:
    """AC T5.4.3: every evidence link resolves to a file on disk."""
    del seeded
    tool = _report_tool(store, session_dir)
    await tool()
    report = (session_dir / "report.md").read_text(encoding="utf-8")
    links = re.findall(r"\[evidence #\d+\]\(([^)]+)\)", report)
    assert links, "the verified finding must reference its evidence"
    for relative in links:
        target = session_dir / relative
        assert target.is_file(), relative
        assert target.read_text(encoding="utf-8") == EVIDENCE_BODY


async def test_findings_are_verified_first_then_severity_ranked(
    store: MemoryStore, session_dir: Path, seeded: dict[str, int]
) -> None:
    """AC T5.4.3: verified findings lead; severity ranks within groups."""
    del seeded
    tool = _report_tool(store, session_dir)
    await tool()
    report = (session_dir / "report.md").read_text(encoding="utf-8")
    order = re.findall(
        r"^### \[(\w+)\] (.+?) \((\w+)\)$", report, flags=re.MULTILINE
    )
    assert [entry[2] for entry in order] == [
        "verified",
        "candidate",
        "rejected",
    ], order
    verified = [entry for entry in order if entry[2] == "verified"]
    assert [entry[0] for entry in verified] == ["CRITICAL"]
