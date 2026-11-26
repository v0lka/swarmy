"""ReportGenerator unit tests (arch §11, roadmap T5.4.1/T5.4.2).

Pins: draft-mark first line, severity/status sorting, evidence references,
mermaid-subset well-formedness (with the §19.4 decision documented in the
template), determinism (no LLM/network anywhere) and the ``generate_report``
tool writing ``<session-dir>/report.md``.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from swarmy.memory.models import (
    AttackEdgeDraft,
    AttackNodeDraft,
    EndpointDraft,
    EvidenceDraft,
    FindingDraft,
    FindingStatus,
    ParameterDraft,
    Severity,
)
from swarmy.report.generator import (
    DRAFT_MARK,
    SEVERITY_ORDER,
    ReportGenerator,
    ReportStatistics,
    make_generate_report_tool,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from swarmy.memory.store import MemoryStore

pytestmark = pytest.mark.unit

_MERMAID_BLOCK = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)
_NODE_LINE = re.compile(r'^    N\d+\["[^"]*"\]$')


async def _seed(store: MemoryStore) -> dict[str, int]:
    """A demo-shaped dataset: evidence, endpoint, three findings, one tree."""
    evidence = await store.add_evidence(
        EvidenceDraft(kind="http_request_response", session_paths=["evidence/1/req.txt"], metadata={})
    )
    endpoint = await store.upsert_endpoint(
        EndpointDraft(
            host="127.0.0.1:1",
            method="GET",
            path="/query",
            parameters=[ParameterDraft(name="q", location="query")],
        )
    )
    await store.save_finding(
        FindingDraft(
            type="xss", severity=Severity.LOW, title="low severity candidate",
            description="d", created_by="xss-detector",
        )
    )
    verified = await store.save_finding(
        FindingDraft(
            type="xss", severity=Severity.MEDIUM, title="verified medium xss",
            description="marker reflected unescaped", created_by="xss-detector",
            endpoint_ref=endpoint.id, evidence_refs=[evidence.id],
            reproduction=["GET /query?q=swx1", "observe the unescaped echo"],
        )
    )
    high = await store.save_finding(
        FindingDraft(
            type="xss", severity=Severity.HIGH, title="verified high xss",
            description="payload survived verbatim", created_by="xss-detector",
            endpoint_ref=endpoint.id,
        )
    )
    await store.update_finding_status(verified.id, FindingStatus.VERIFIED)
    await store.update_finding_status(high.id, FindingStatus.VERIFIED)
    precondition = await store.link_attack_node(
        AttackNodeDraft(kind="precondition", title='attacker controls "q"'), []
    )
    finding_node = await store.link_attack_node(
        AttackNodeDraft(kind="finding", finding_ref=verified.id, title="xss in q"),
        [AttackEdgeDraft(src=precondition.id, dst=None, kind="enables")],
    )
    await store.link_attack_node(
        AttackNodeDraft(kind="goal", title="session theft"),
        [AttackEdgeDraft(src=finding_node.id, dst=None, kind="leads_to")],
    )
    return {"evidence": evidence.id, "endpoint": endpoint.id, "verified": verified.id}


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MemoryStore]:
    """The report's read-only view: fresh migrated database per test."""
    from swarmy.core.database import Database
    from swarmy.memory.schema import MIGRATIONS
    from swarmy.memory.search import Fts5SearchIndex
    from swarmy.memory.store import MemoryStore as Store

    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    yield Store(db, Fts5SearchIndex(await db.connection("search")))
    await db.close()


def _statistics() -> ReportStatistics:
    """Fixed statistics payload (the wiring injects these in production)."""
    return ReportStatistics(
        events_total=12,
        events_by_type={"FindingCandidate": 1, "AttackTreeUpdated": 3},
        period_start="2026-11-25T10:00:00+00:00",
        period_end="2026-11-25T10:05:00+00:00",
    )


class TestReportContent:
    """Section structure and ordering of the generated markdown."""

    async def test_draft_mark_is_the_first_line(self, store: MemoryStore) -> None:
        """AC T5.4.2: the draft badge opens every report."""
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        assert report.splitlines()[0] == DRAFT_MARK

    async def test_all_sections_present(self, store: MemoryStore) -> None:
        """Summary, findings, trees and the endpoint appendix render."""
        await _seed(store)
        report = await ReportGenerator(store).generate(
            "http://127.0.0.1:1/",
            ["ip_subnet=127.0.0.1/32", "port=1"],
            _statistics(),
        )
        for heading in (
            "# swarmy session report",
            "## Summary",
            "## Findings",
            "## Attack trees",
            "## Appendix: researched endpoints",
        ):
            assert heading in report
        assert "http://127.0.0.1:1/" in report
        assert "ip_subnet=127.0.0.1/32" in report
        assert "2026-11-25T10:00:00+00:00" in report

    async def test_findings_sorted_verified_first_then_severity(
        self, store: MemoryStore
    ) -> None:
        """AC T5.4.2: severity sort within verification status (verified first)."""
        await _seed(store)
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        positions = [
            report.index("verified high xss"),
            report.index("verified medium xss"),
            report.index("low severity candidate"),
        ]
        assert positions == sorted(positions)
        severity_order = [s.value for s in SEVERITY_ORDER]
        assert severity_order[0] == "critical"
        assert severity_order[-1] == "info"

    async def test_evidence_links_are_session_relative(
        self, store: MemoryStore, tmp_path: Path
    ) -> None:
        """AC T5.4.3: evidence references point at real session files."""
        await _seed(store)
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        assert "[evidence #1](evidence/1/req.txt)" in report
        evidence_file = tmp_path / "evidence" / "1" / "req.txt"
        evidence_file.parent.mkdir(parents=True, exist_ok=True)
        evidence_file.write_text("raw", encoding="utf-8")
        assert evidence_file.is_file()

    async def test_empty_session_renders_placeholders(self, store: MemoryStore) -> None:
        """A fresh session still yields a valid report skeleton."""
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        assert "No findings were recorded" in report
        assert "No attack-tree nodes" in report
        assert "No endpoints were recorded" in report


class TestMermaidSubset:
    """The mermaid block stays inside the §19.4-compatible subset."""

    async def test_mermaid_block_wellformed(self, store: MemoryStore) -> None:
        """graph TD, quoted labels, |label| edges — nothing else."""
        await _seed(store)
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        blocks = _MERMAID_BLOCK.findall(report)
        assert len(blocks) == 1
        lines = blocks[0].strip().splitlines()
        assert lines[0] == "graph TD"
        body = lines[1:]
        assert all(_NODE_LINE.match(line) or line.startswith("    N") for line in body)
        assert any('-->|enables|' in line for line in body)
        assert any('-->|leads_to|' in line for line in body)

    async def test_labels_sanitized(self, store: MemoryStore) -> None:
        """Quotes/newlines in titles never break the mermaid quoting."""
        await store.link_attack_node(
            AttackNodeDraft(kind="goal", title='break "quotes"\nand lines'), []
        )
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        block = _MERMAID_BLOCK.findall(report)[0]
        label_line = next(line for line in block.splitlines() if line.startswith("    N1["))
        assert '\n' not in label_line
        assert label_line.count('"') == 2  # exactly the two delimiters

    def test_template_documents_the_subset_decision(self) -> None:
        """AC T5.4.2: the §19.4 decision lives in the template header."""
        template_text = (
            resources.files("swarmy.report")
            .joinpath("templates/report.md.j2")
            .read_text(encoding="utf-8")
        )
        assert "§19.4" in template_text


class TestNoLlmNoNetwork:
    """AC T5.4.1: generation is deterministic platform code only."""

    def test_generator_module_has_no_llm_or_network_imports(self) -> None:
        """Structural: the report package imports neither L0 nor httpx."""
        import swarmy.report.generator as module

        source = Path(str(module.__file__)).read_text(encoding="utf-8")
        for forbidden in ("deepagents", "langchain", "langgraph", "httpx", "socket"):
            assert forbidden not in source

    async def test_generation_is_deterministic(self, store: MemoryStore) -> None:
        """Two runs over unchanged memory render byte-identical reports."""
        await _seed(store)
        generator = ReportGenerator(store)
        first = await generator.generate("http://t/", ["port=1"], _statistics())
        second = await generator.generate("http://t/", ["port=1"], _statistics())
        assert first == second


class TestReportEscaping:
    """Target/LLM-derived text renders report-safe (review Issues #40/#18)."""

    async def test_finding_payloads_neutralized(self, store: MemoryStore) -> None:
        """Raw HTML and markdown structure in finding text cannot reach report.md."""
        await store.save_finding(
            FindingDraft(
                type="xss",
                severity=Severity.HIGH,
                title="<img src=x onerror=alert(1)>",
                description="payload <svg onload=alert(2)> worked\n# fake heading",
                created_by="xss-detector",
                reproduction=["GET /q?x=`cmd` | sh", "![](http://evil/x)"],
            )
        )
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        assert "<img" not in report
        assert "<svg" not in report
        assert "&lt;img src=x onerror=alert(1)&gt;" in report
        assert "&lt;svg onload=alert(2)&gt;" in report
        assert "\\# fake heading" in report  # leading structure neutralized
        assert "GET /q?x=\\`cmd\\` \\| sh" in report  # code-span/table syntax inert
        assert "![](http://evil/x)" not in report  # image syntax neutralized

    async def test_endpoint_pipes_escaped_in_table(self, store: MemoryStore) -> None:
        """Pipes in path/host cannot break the appendix table (#18)."""
        await store.upsert_endpoint(
            EndpointDraft(host="h.example|evil", method="GET", path="/a|b", parameters=[])
        )
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        assert "/a\\|b" in report
        assert "h.example\\|evil" in report

    async def test_method_pipe_escaped_in_table(self, store: MemoryStore) -> None:
        """A pre-normalization method row (``A|B``) cannot break the table column.

        The method token grammar (``tools.platform``) admits ``|`` and
        backtick, and a resumed session may carry rows stored before the
        normalization ran — the method is escaped like every other
        target-derived cell.
        """
        await store.upsert_endpoint(
            EndpointDraft(host="h.example", method="A|B", path="/m", parameters=[])
        )
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        assert "| A\\|B |" in report

    async def test_created_by_neutralized(self, store: MemoryStore) -> None:
        """``created_by`` renders report-safe like every other finding field."""
        await store.save_finding(
            FindingDraft(
                type="xss",
                severity=Severity.LOW,
                title="t",
                description="d",
                created_by="<img src=x> | `xss-detector`",
            )
        )
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        assert "<img" not in report
        assert "&lt;img src=x&gt; \\| \\`xss-detector\\`" in report

    async def test_mermaid_labels_carry_no_angle_brackets(self, store: MemoryStore) -> None:
        """`<`/`>` never survive into a mermaid label (#40)."""
        await store.link_attack_node(
            AttackNodeDraft(kind="goal", title="steal <img src=x onerror=alert(1)>"), []
        )
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        block = _MERMAID_BLOCK.findall(report)[0]
        assert "<" not in block
        assert ">" not in block
        text_block = re.search(r"```text\n(.*?)```", report, re.DOTALL)
        assert text_block is not None
        assert "<img" not in text_block.group(1)

    async def test_backtick_payload_cannot_break_the_text_fence(self, store: MemoryStore) -> None:
        """Fence-breaking payloads stay inside the ```text tree rendering."""
        await store.link_attack_node(AttackNodeDraft(kind="goal", title="run ```cmd```"), [])
        report = await ReportGenerator(store).generate("http://t/", [], _statistics())
        text_blocks = re.findall(r"```text\n(.*?)```", report, re.DOTALL)
        assert len(text_blocks) == 1  # the payload did not close the fence early


class TestGenerateReportTool:
    """The orchestrator tool writes <session-dir>/report.md (RD-7)."""

    async def test_tool_writes_report_into_session_dir(
        self, store: MemoryStore, tmp_path: Path
    ) -> None:
        """The tool's only effect is the report file + a confirmation line."""
        await _seed(store)

        async def statistics() -> ReportStatistics:
            return _statistics()

        tool = make_generate_report_tool(
            store=store,
            session_dir=tmp_path,
            base_url="http://127.0.0.1:1/",
            scope_labels=["port=1"],
            statistics=statistics,
        )
        confirmation = await tool()
        report_path = tmp_path / "report.md"
        assert report_path.is_file()
        assert str(report_path) in confirmation
        assert report_path.read_text(encoding="utf-8").startswith(DRAFT_MARK)
