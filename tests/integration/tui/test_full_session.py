"""T4.3.2 acceptance: the F4 criterion — a full session driven from the TUI.

Roadmap T4.3.2 (F4 DoD, RD-6): with the Textual harness (headless CI mode)
the operator runs a REAL session end-to-end without any CLI input:

1. the chat panel sends the opening command (OperatorMessage → interactive
   contour → crawler delegation over the real echo target);
2. the declarative policies chain the verification delegation;
3. the profile's ``verify`` gate interrupts the verifier — the operator
   approves through the HITL modal (the swarm's own loop keeps serving
   batches meanwhile — T4.3.1 non-blocking property);
4. the candidate is stored, the status changes through the platform tool,
   and the journal holds the full correlation trace;
5. the panels reflect the final state (approvals FIFO drained, findings
   table verified, raw card on request).

Every operator input goes through the console: no ``runtime.run_step`` call
is made by the test itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from langchain_core.messages import AIMessage
from textual.widgets import Button, DataTable, Input, RichLog

from swarmy.core.config import PolicySpec, ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from swarmy.tui.app import SwarmyTui
from swarmy.tui.approvals import ApprovalModal, ApprovalsPanel
from swarmy.tui.panels.findings import FindingsPanel
from tests.helpers.agent_modules import crawler_prompt, make_module, verifier_prompt
from tests.helpers.fake_models import ScriptedChatModel, final_reply

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration

RAW_PAYLOAD = "<script>alert('e2e-xss')</script>"


def _tool_call(name: str, args: dict[str, object], call_id: str) -> dict[str, object]:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


def _ai(*tool_calls: dict[str, object]) -> AIMessage:
    return AIMessage(content="", tool_calls=list(tool_calls))  # type: ignore[arg-type]


@pytest.fixture
async def e2e_session(tmp_path: Path, echo_server: Any) -> Session:
    """The F4 session: crawler + gated verifier + the three event policies."""
    agents = tmp_path / "agents"
    make_module(
        agents, "e2e_crawler", description="E2E crawler (fixture).",
        prompt=crawler_prompt("e2e_crawler"),
    )
    make_module(
        agents, "e2e_verifier", description="E2E verifier (fixture).",
        prompt=verifier_prompt("e2e_verifier"),
        risk="verify",  # the normal profile gates this tool → the modal path
    )
    base = f"http://127.0.0.1:{echo_server.port}"
    orchestrator = ScriptedChatModel(
        scripts={
            "orchestrator": [
                _ai(_tool_call("task",
                               {"description": f"crawl {base}/query?q=xss",
                                "subagent_type": "e2e_crawler"}, "call-o1")),
                final_reply("crawl finished; awaiting the discovery notification"),
                _ai(_tool_call("task",
                               {"description": "verify the finding",
                                "subagent_type": "e2e_verifier"}, "call-o2")),
                final_reply("candidate stored; awaiting verification"),
                _ai(_tool_call("task",
                               {"description": "resolve the finding status",
                                "subagent_type": "e2e_verifier"}, "call-o3")),
                final_reply("session goal reached"),
                # the FindingVerified injection arrives after the resume and
                # triggers one more orchestrator step (arch §9.2 chaining)
                final_reply("all notifications served"),
            ],
            "e2e_crawler": [
                _ai(
                    _tool_call("http_get",
                               {"url": f"{base}/query?q={RAW_PAYLOAD}"}, "c1"),
                    _tool_call("memory_upsert_endpoint",
                               {"host": f"127.0.0.1:{echo_server.port}", "method": "GET",
                                "path": "/query"}, "c2"),
                ),
                final_reply("crawl done"),
            ],
            # Delegation 2 (d2): store the candidate — no gated call in this
            # batch (an interrupt inside a parallel tool batch would replay
            # the store writes on resume). Delegation 3 (d3): the gated probe
            # is a SOLO turn — the operator's approve resumes exactly it —
            # then the status change runs through the platform tool.
            "e2e_verifier": [
                _ai(
                    _tool_call("http_get",
                               {"url": f"{base}/query?q={RAW_PAYLOAD}"}, "v1"),
                    _tool_call("memory_save_finding",
                               {"type": "xss", "severity": "high",
                                "title": "reflected XSS in /query",
                                "description": f"the q parameter reflects {RAW_PAYLOAD}",
                                "reproduction": [f"GET /query?q={RAW_PAYLOAD}"],
                                "created_by": "e2e_verifier"}, "v2"),
                ),
                final_reply("candidate stored"),
                _ai(_tool_call("e2e_verifier_probe", {"message": "safe payload"}, "v3")),
                _ai(_tool_call("update_finding_status",
                               {"finding_id": 1, "status": "verified", "severity": "high",
                                "reason": "re-verified with a safe payload"}, "v4")),
                final_reply("verification done"),
            ],
        },
        fallback_reply="done",
    )
    config = SessionConfig(
        target=TargetConfig(base_url=f"{base}/"),
        scope=ScopeEntries(
            ip_subnets=["127.0.0.1/32"], ports=[echo_server.port], schemes=["http"]
        ),
        agents_dirs=[str(agents)],
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
    session = await Session.open(config=config, session_dir=tmp_path / "s",
                                 model=orchestrator)
    return session


async def test_full_session_driven_from_the_tui(tmp_path: Path, e2e_session: Session) -> None:
    """The F4 criterion: start → swarm → HITL approve → chat → verified."""
    session = e2e_session
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)

        # 1. The operator opens the engagement through the CHAT PANEL.
        await pilot.press("1")  # focus the chat input (priority digit binding)
        app.query_one("#chat-input", Input).value = "probe the target"
        await pilot.press("enter")
        await pilot.pause(3.0)

        reader = session.reader
        assert reader is not None
        discovered = await reader.by_type("EndpointsDiscovered")
        assert discovered != []  # the crawler hit the real echo target

        # 2. The verify gate interrupted the verifier: the FIFO is visible.
        approvals = app.query_one("#panel-approvals", ApprovalsPanel)
        table = approvals.query_one("#approval-table", DataTable)
        assert table.row_count == 1
        pending = app.state.approvals[0]
        assert pending.tool == "e2e_verifier_probe"
        assert pending.origin == "profile"  # strictness-matrix gate (§7.2)

        # 3. The modal opens for the addressable request; decide APPROVE.
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, ApprovalModal)
        modal.query_one("#btn-approve", Button).press()
        await pilot.pause(4.0)

        # The decision resumed exactly one interrupt; the policy chain
        # (FindingCandidate → verify_finding) then ran WITHOUT operator input.
        assert table.row_count == 0  # the FIFO drained
        candidate = await reader.by_type("FindingCandidate")
        assert candidate != []
        decisions = await reader.by_type("OperatorDecision")
        assert [d.payload.decision for d in decisions] == ["approve"]

        # 4. The panels reflect the final state; the card shows RAW values.
        findings_panel = app.query_one("#panel-findings", FindingsPanel)
        rows = findings_panel.query_one("#finding-table", DataTable)
        assert rows.row_count == 1
        memory = session.memory
        assert memory is not None
        stored = await memory.get("finding", 1)
        assert stored is not None
        assert stored.status.value == "verified"  # changed by the platform tool
        feed_text = "\n".join(
            strip.text for strip in app.query_one("#activity-log", RichLog).lines
        )
        assert RAW_PAYLOAD not in feed_text  # feeds stay masked (§6.8)
        assert len(await reader.by_type("TaskCompleted")) == 3
        requested = await reader.by_type("TaskRequested")
        assert len(requested) >= 3
        # The approved delegation re-enters the interrupted task node on
        # resume (documented L0 §19.2 replay), which carries a FRESH
        # correlation id — hence 3 completed delegations may hold 3+4
        # requested events. Every completed delegation has a requested one.
        completed_cids = {
            envelope.payload.correlation_id
            for envelope in await reader.by_type("TaskCompleted")
        }
        requested_cids = {envelope.payload.correlation_id for envelope in requested}
        assert completed_cids <= requested_cids

    await session.close()
