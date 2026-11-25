"""T5.3.2 acceptance: the headless F5 demo scenario (spec F5 criterion).

The REAL built-in modules (``crawler`` + ``xss-detector``, loaded from the
installed package) run the whole arch §13.4 chain against the echo app:
operator goal → todos/`task(crawler)` → endpoints in memory
(``EndpointsDiscovered``) → `task(xss-detector)` → marker/reflection →
HITL-approved POST probe (profile ``normal``) → ``FindingCandidate`` →
policy ``verify_finding`` → re-verification (RD-5) → ``FindingVerified`` →
policy ``tree_proposal`` → `memory_link_attack_node` → ``AttackTreeUpdated``.
The journal holds the full correlation trace; no TUI is opened (headless),
but the TUI-facing facade sees the tree.

The subagent scripts are the *tool calls a real LLM would issue*: crawler
fetches robots/sitemap and parses them with the real parser tools; the
detector injects a fixed marker, analyzes the real reflection and verifies
with an inert safe payload. The chat model is the only double.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest
from langchain_core.messages import AIMessage

from swarmy.core.config import PolicySpec, ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from swarmy.report.generator import make_generate_report_tool
from swarmy.tui.state import SessionView
from tests.helpers.fake_models import ScriptedChatModel, final_reply

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

pytestmark = pytest.mark.integration

#: The fixed marker of the scripted detector (unique per session would be
#: a real run's `make_marker` output; the script pins one value).
MARKER: Final = "swxdemo0000000001"

#: The safe payload the scripted detector verifies with (inert tag).
PAYLOAD: Final = "<swxtag" + MARKER + ">"

#: The echo app's static robots.txt body (tests/fixtures/echo_app/app.py).
ROBOTS_BODY: Final = "User-agent: *\nAllow: /\nDisallow: /private\n"

#: The echo app's static sitemap body (literal `{base_path}` placeholder).
SITEMAP_BODY: Final = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    "  <url><loc>/{base_path}/echo</loc></url>\n"
    "  <url><loc>/{base_path}/query</loc></url>\n"
    "  <url><loc>/{base_path}/form</loc></url>\n"
    "</urlset>\n"
)

#: Body of `GET /query?q=<marker>` on the echo app (k=v lines).
QUERY_ECHO: Final = f"q={MARKER}\n"

#: Body of `POST /form` with the payload field (JSON field echo).
FORM_ECHO: Final = '{"fields": {"q": "' + PAYLOAD + '"}}'


def _tool_call(name: str, args: dict[str, object], call_id: str) -> dict[str, object]:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


def _ai(*tool_calls: dict[str, object]) -> AIMessage:
    return AIMessage(content="", tool_calls=list(tool_calls))  # type: ignore[arg-type]


def _scripts(base: str, host: str) -> dict[str, Any]:
    """The scripted tool-call plans of the orchestrator and both modules.

    Script keys are markers the routing fake matches against each agent's
    system message (longest match wins). The detector key is the unique
    22-char phrase of its AGENT.md body — longer than ``orchestrator``
    (the detector prompt mentions the orchestrator, so the plain name
    would tie and mis-route; tests/helpers/fake_models.py).
    """
    detector_key = "reflected-XSS subagent"
    return {
        "orchestrator": [
            _ai(_tool_call("task",
                           {"description": f"crawl {base} and map endpoints",
                            "subagent_type": "crawler"}, "o1")),
            final_reply("endpoints expected"),
            _ai(_tool_call("task",
                           {"description": f"probe {base} endpoints for reflected XSS",
                            "subagent_type": "xss-detector"}, "o2")),
            final_reply("candidate expected"),
            _ai(_tool_call("task",
                           {"description": "re-verify finding #1 with safe payloads",
                            "subagent_type": "xss-detector"}, "o3")),
            final_reply("verification expected"),
            _ai(_tool_call("task",
                           {"description": "link finding #1 into the attack tree",
                            "subagent_type": "xss-detector"}, "o4")),
            final_reply("tree expected"),
            final_reply("demo finished"),
        ],
        "crawler": [
            _ai(_tool_call("http_get", {"url": f"{base}/robots.txt"}, "c1")),
            _ai(
                _tool_call("parse_robots_txt",
                           {"text": ROBOTS_BODY, "base_url": f"{base}/robots.txt"}, "c2"),
                _tool_call("http_get", {"url": f"{base}/sitemap.xml"}, "c3"),
            ),
            _ai(
                _tool_call("parse_sitemap_xml",
                           {"text": SITEMAP_BODY, "base_url": f"{base}/sitemap.xml"}, "c4"),
                _tool_call("http_get", {"url": f"{base}/query?q=crawlprobe"}, "c5"),
            ),
            _ai(_tool_call(
                "memory_upsert_endpoint",
                {"host": host, "method": "GET", "path": "/query",
                 "notes": "reflects query parameters (echo app)",
                 "parameters": [{"name": "q", "location": "query"}]}, "c6"),
            ),
            final_reply("endpoint map recorded"),
        ],
        detector_key: [
            _ai(
                _tool_call("memory_search",
                           {"query": "query", "entity_types": ["endpoints"]}, "d1"),
                _tool_call("make_marker", {}, "d2"),
            ),
            _ai(
                _tool_call("build_probe_url",
                           {"url": f"{base}/query", "param": "q", "value": MARKER}, "d3"),
            ),
            _ai(_tool_call("http_get", {"url": f"{base}/query?q={MARKER}"}, "d4")),
            _ai(
                _tool_call("analyze_reflection",
                           {"body": QUERY_ECHO, "marker": MARKER, "param": "q"}, "d5"),
                _tool_call("plan_payloads", {"marker": MARKER, "context": "html_text"}, "d6"),
            ),
            # The gated POST probe MUST be a solo AI turn (observed L0,
            # M4 notes: a batched interrupt double-executes on resume).
            _ai(_tool_call("http_post",
                           {"url": f"{base}/form", "body": f"q={PAYLOAD}"}, "d7")),
            _ai(
                _tool_call("safe_payload_report",
                           {"body": FORM_ECHO, "payload": PAYLOAD}, "d8"),
                _tool_call("memory_save_finding",
                           {"type": "xss", "severity": "high",
                            "title": "Reflected XSS in the q parameter of /query",
                            "description": (
                                "marker and the inert safe payload are reflected "
                                "unescaped into the HTML text context"
                            ),
                            "created_by": "xss-detector",
                            "endpoint_ref": 1,
                            "evidence_refs": [4, 5],
                            "reproduction": [
                                f"GET /query?q={MARKER} — marker echoed unescaped",
                                f"POST /form with q={PAYLOAD} — payload echoed verbatim",
                            ]}, "d9"),
            ),
            final_reply("candidate stored with evidence"),
            # --- verification delegation (RD-5) ---
            _ai(_tool_call("http_get", {"url": f"{base}/query?q={MARKER}"}, "v1")),
            _ai(
                _tool_call("analyze_reflection",
                           {"body": QUERY_ECHO, "marker": MARKER, "param": "q"}, "v2"),
                _tool_call("update_finding_status",
                           {"finding_id": 1, "status": "verified", "severity": "high",
                            "reason": "marker reflection + inert payload reproduced"},
                           "v3"),
            ),
            final_reply("verification reproduced"),
            # --- tree-linking delegation (tree_proposal) ---
            _ai(_tool_call("memory_link_attack_node",
                           {"kind": "precondition",
                            "title": "attacker controls the q parameter value",
                            "description": "reflected input on /query"}, "t1")),
            _ai(_tool_call("memory_link_attack_node",
                           {"kind": "finding", "finding_ref": 1,
                            "title": "reflected XSS in /query?q",
                            "edges": [{"src": 1, "dst": None, "kind": "enables"}]}, "t2")),
            _ai(_tool_call("memory_link_attack_node",
                           {"kind": "goal",
                            "title": "script execution in the victim's browser",
                            "edges": [{"src": 2, "dst": None, "kind": "leads_to"}]}, "t3")),
            final_reply("attack tree linked"),
        ],
    }


@pytest.fixture
async def demo_session(
    tmp_path: Path, echo_server: Any
) -> AsyncIterator[Session]:
    """The headless F5 demo session over the real built-in modules."""
    base = f"http://127.0.0.1:{echo_server.port}"
    host = f"127.0.0.1:{echo_server.port}"
    model = ScriptedChatModel(scripts=_scripts(base, host), fallback_reply="done")
    config = SessionConfig(
        target=TargetConfig(base_url=f"{base}/"),
        scope=ScopeEntries(
            ip_subnets=["127.0.0.1/32"], ports=[echo_server.port], schemes=["http"]
        ),
        profile="normal",
        policies=[
            PolicySpec(on="EndpointsDiscovered", action="notify_orchestrator",
                       template="generic"),
            PolicySpec(on="FindingCandidate", action="notify_orchestrator",
                       template="verify_finding"),
            PolicySpec(on="FindingVerified", action="notify_orchestrator",
                       template="tree_proposal"),
        ],
    )
    session = await Session.open(
        config=config,
        session_dir=tmp_path / "demo",
        model=model,
        report_tool_factory=make_generate_report_tool,
    )
    try:
        yield session
    finally:
        await session.close()


class TestDemoF5Scenario:
    """AC: goal → endpoints → candidate → verification → tree node.

    ``run_step`` drains pending policy injections within one call (the TUI
    drives it in a loop, arch §10.2), so the test advances the session in a
    bounded loop and reacts to what the journal shows — the gate interrupt
    and the closing tree update are the two synchronization points.
    """

    async def test_full_demo_chain_with_hitl_and_correlation(
        self, demo_session: Session, echo_server: Any
    ) -> None:
        session = demo_session
        runtime = session.runtime
        reader = session.reader

        def posts_seen() -> int:
            return sum(1 for entry in echo_server.log.entries if entry.method == "POST")

        # Goal turn: the orchestrator delegates the crawler, which crawls
        # robots + sitemap (real parser tools) and records /query.
        await runtime.run_step("check the target for reflected XSS")
        discovered = await reader.by_type("EndpointsDiscovered")
        assert discovered, "crawler recorded no endpoints"
        endpoints = await session.memory.list_endpoints()
        assert [endpoint.path for endpoint in endpoints] == ["/query"]
        parameters = await session.memory.list_parameters(endpoints[0].id)
        assert [parameter.name for parameter in parameters] == ["q"]

        # Drive the session until the POST probe surfaces in the FIFO.
        gate = None
        for _ in range(10):
            pending = session.approvals.pending()
            if pending:
                gate = pending[0]
                break
            await runtime.run_step()
        assert gate is not None, "the POST probe must gate under profile normal"
        assert gate.tool == "http_post"
        assert gate.origin == "profile"  # network-write gate of profile normal
        assert posts_seen() == 0  # invariant 1: gated call never reached the target

        # The operator approves; the resumed detector probes and stores the
        # candidate; verify_finding then tree_proposal complete the chain.
        await runtime.submit_decision(gate.request_id, "approve")
        completed = False
        for _ in range(15):
            pending = session.approvals.pending()
            if pending:  # no further gates are scripted — fail loudly
                pytest.fail(f"unexpected additional gate: {pending[0].tool}")
            await runtime.run_step()
            if await reader.by_type("AttackTreeUpdated"):
                completed = True
                break
        assert completed, "the demo chain never reached the attack tree"

        # F5 criterion: goal → endpoints → candidate → verification → tree.
        candidates = await reader.by_type("FindingCandidate")
        assert candidates, "no finding candidate was stored"
        verified_events = await reader.by_type("FindingVerified")
        assert verified_events, "the candidate was not re-verified"
        tree_events = await reader.by_type("AttackTreeUpdated")
        assert tree_events, "no AttackTreeUpdated reached the journal"

        finding = await session.memory.get("finding", 1)
        assert finding is not None
        assert finding.type.value == "xss"
        assert finding.status.value == "verified"
        assert finding.evidence_refs == [4, 5]

        # The POST probe executed exactly once, only after the approval.
        assert posts_seen() == 1
        decisions = await reader.by_type("OperatorDecision")
        assert [decision.payload.decision for decision in decisions] == ["approve"]

        # AC: the demo tree is precondition → finding → goal, typed edges.
        nodes = {node.kind: node for node in await session.memory.list_attack_nodes()}
        assert set(nodes) == {"precondition", "finding", "goal"}
        assert nodes["finding"].finding_ref == 1
        edges = await session.memory.list_attack_edges()
        assert [(edge.kind, edge.src, edge.dst) for edge in edges] == [
            ("enables", nodes["precondition"].id, nodes["finding"].id),
            ("leads_to", nodes["finding"].id, nodes["goal"].id),
        ]

        # AC (T5.3.1): the tree reaches the TUI through the SessionView facade.
        view = SessionView(session)
        view_nodes = await view.attack_nodes()
        view_edges = await view.attack_edges()
        assert {node.kind for node in view_nodes} == {"precondition", "finding", "goal"}
        assert len(view_edges) == 2

        # AC: evidence files of the finding exist in the session folder.
        for evidence_id in finding.evidence_refs:
            record = await session.memory.get("evidence", evidence_id)
            for session_path in record.session_paths:
                evidence_file = session.session_dir / session_path
                assert evidence_file.is_file(), session_path

        # AC: the journal holds the full chain by correlation_id — every
        # phase lands in the chain of a TaskRequested delegation.
        requested = await reader.by_type("TaskRequested")
        chains = {
            envelope.correlation_id: {
                item.type for item in await reader.by_correlation(envelope.correlation_id)
            }
            for envelope in requested
        }
        for phase in (
            "EndpointsDiscovered",
            "FindingCandidate",
            "FindingVerified",
            "AttackTreeUpdated",
        ):
            assert any(phase in chain for chain in chains.values()), phase
        assert len({envelope.correlation_id for envelope in requested}) >= 4

        # No guardrail denied anything in the happy path; the only operator
        # interaction was the single approval above.
        blocked = await reader.by_type("GuardrailBlocked")
        assert blocked == []
        assert session.approvals.pending() == ()

    async def test_report_generates_from_the_demo_session(
        self, demo_session: Session
    ) -> None:
        """T5.4.3 seed: generate_report runs on the demo session state."""
        session = demo_session
        runtime = session.runtime
        await runtime.run_step("check the target for reflected XSS")
        gate = None
        for _ in range(10):
            pending = session.approvals.pending()
            if pending:
                gate = pending[0]
                break
            await runtime.run_step()
        assert gate is not None
        await runtime.submit_decision(gate.request_id, "approve")
        for _ in range(15):
            await runtime.run_step()
            if await session.reader.by_type("AttackTreeUpdated"):
                break

        tool = session._orchestrator_tools["generate_report"]
        confirmation = await tool()
        report_path = session.session_dir / "report.md"
        assert report_path.is_file()
        assert str(report_path) in confirmation
        report = report_path.read_text(encoding="utf-8")
        assert report.startswith("**DRAFT")
        assert "## Findings" in report
        assert "## Attack trees" in report

