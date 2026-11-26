"""T4.1.2 - T4.4.2 acceptance criteria against the Textual harness (headless).

Every panel of the D10 grid is exercised on a REAL composed session with a
scripted chat model (no network, no API keys — the M3 pattern). The harness
drives the same event loop the workers run on, so the session worker serves
coalesced batches exactly like in production.
"""

from __future__ import annotations

import asyncio
import io
from typing import TYPE_CHECKING, Any

import pytest
from rich.console import Console
from tests.helpers.agent_modules import make_module
from tests.helpers.fake_models import ScriptedChatModel, final_reply, one_shot_model
from textual.widgets import Button, DataTable, Input, RichLog, Static, TextArea, Tree

from swarmy.core.config import ScopeEntries, SecretsConfig, SessionConfig, TargetConfig
from swarmy.core.session import Session
from swarmy.memory.models import (
    AttackEdgeDraft,
    AttackNodeDraft,
    EndpointDraft,
    EvidenceDraft,
    FindingDraft,
    Severity,
)
from swarmy.tui.app import SwarmyTui
from swarmy.tui.approvals import ApprovalModal, ApprovalsPanel
from swarmy.tui.panels.chat import ChatPanel
from swarmy.tui.panels.findings import FindingCardRequested, FindingsPanel
from swarmy.tui.panels.plans import PlansPanel
from swarmy.tui.panels.trees import TreesPanel

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit

SECRET_VALUE = "op-secret-123"


def _tool_call(name: str, args: dict[str, object], call_id: str) -> dict[str, object]:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


def _ai(*tool_calls: dict[str, object]) -> Any:
    from langchain_core.messages import AIMessage

    return AIMessage(content="", tool_calls=list(tool_calls))  # type: ignore[arg-type]


def renderable_text(renderable: object) -> str:
    """Render one rich renderable to plain text (the §6.8 scan surface)."""
    console = Console(width=200, file=io.StringIO(), legacy_windows=False)
    console.print(renderable)  # type: ignore[arg-type]
    return str(console.file.getvalue())


def static_text(widget: Static) -> str:
    """The rendered text of a Static (unwraps the harness RichVisual)."""
    visual = widget.render()
    return renderable_text(getattr(visual, "_renderable", visual))


def richlog_text(log: RichLog) -> str:
    """The rendered text of a RichLog widget."""
    return "\n".join(strip.text for strip in log.lines)


async def make_session(
    tmp_path: Path,
    scripts: dict[str, list[object]] | None = None,
    *,
    risk: str = "passive",
    module_name: str = "probe_mod",
    secrets: SecretsConfig | None = None,
) -> Session:
    """One composed session with a scripted model and one fixture module."""
    agents = tmp_path / "agents"
    make_module(
        agents,
        module_name,
        description="Fixture module for the harness.",
        prompt=f"You are {module_name}: probe the authorized target.",
        risk=risk,  # type: ignore[arg-type]
    )
    model: ScriptedChatModel | Any
    if scripts is None:
        model = one_shot_model()
    else:
        model = ScriptedChatModel(scripts=scripts, fallback_reply="done")
    config = SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
        agents_dirs=[str(agents)],
        profile="normal",
    )
    return await Session.open(
        config=config, session_dir=tmp_path / "s", secrets=secrets, model=model
    )


# ---------------------------------------------------------------------------
# T4.1.2 — the app starts on a real session; workers do not block the UI
# ---------------------------------------------------------------------------


async def test_app_starts_with_six_panels(tmp_path: Path) -> None:
    """AC T4.1.2: the D10 grid mounts over a real composed session."""
    session = await make_session(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        for panel_id in (
            "#panel-chat",
            "#panel-activity",
            "#panel-findings",
            "#panel-approvals",
            "#panel-trees",
            "#panel-plans",
        ):
            assert app.query_one(panel_id) is not None
        # the preloaded journal tail is on screen (TargetSet of the fresh session)
        feed_text = richlog_text(app.query_one("#activity-log", RichLog))
        assert "TargetSet" in feed_text
    await session.close()


async def test_workers_do_not_block_ui(tmp_path: Path) -> None:
    """AC T4.1.2: rendering ticks during an event flow; keys keep working."""
    session = await make_session(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        writer = session.journal
        bus = session.bus
        assert writer is not None
        assert bus is not None
        from swarmy.events.models import EndpointsDiscoveredPayload, EventSource

        for _index in range(12):
            envelope = await writer.append(
                type="EndpointsDiscovered",
                source=EventSource.PLATFORM,
                source_detail="test",
                correlation_id="",
                payload=EndpointsDiscoveredPayload(endpoints=[], out_of_scope_count=0),
            )
            await bus.publish(envelope)
        await pilot.pause(0.5)
        feed_lines = len(app.query_one("#activity-log", RichLog).lines)
        assert feed_lines >= 12  # every event reached the feed
        await pilot.press("1")  # focus the chat panel's input
        await pilot.pause()
        assert isinstance(app.focused, Input)
    await session.close()


# ---------------------------------------------------------------------------
# T4.2.2 — the delegation table reconciles against the journal
# ---------------------------------------------------------------------------


async def test_delegation_table_matches_the_journal(tmp_path: Path) -> None:
    """AC T4.2.2: the delegation tree mirrors TaskRequested/TaskCompleted.

    The Swarm Activity delegation table is compared row-by-row with the
    journal (the source of truth): one row per TaskRequested correlation_id,
    the subagent name from the request, and the status/digest taken from the
    matching TaskCompleted payload.
    """
    session = await make_session(
        tmp_path,
        {
            "orchestrator": [
                _ai(
                    _tool_call(
                        "task",
                        {"description": "probe once", "subagent_type": "probe_mod"},
                        "call-o1",
                    )
                ),
                final_reply("delegation finished"),
            ],
            "probe_mod": [
                _ai(_tool_call("probe_mod_probe", {"message": "ping"}, "m1")),
                final_reply("probe done"),
            ],
        },
        risk="passive",
    )
    app = SwarmyTui(session)
    try:
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("1")  # focus the chat input
            app.query_one("#chat-input", Input).value = "run the probe"
            await pilot.press("enter")
            # wait until the delegation completes per the journal (truth)
            reader = session.reader
            assert reader is not None
            completed: list = []
            for _ in range(100):
                completed = await reader.by_type("TaskCompleted")
                if completed:
                    break
                await asyncio.sleep(0.1)
            requested = await reader.by_type("TaskRequested")
            assert len(requested) == 1, "the delegation never reached the journal"
            assert len(completed) == 1, "the delegation never completed"
            request_payload = requested[0].payload
            completion_payload = completed[0].payload
            assert completion_payload.correlation_id == request_payload.correlation_id
            # settle: the session worker must finish draining the step
            # before close, otherwise the app worker dies mid-run_step
            runtime = session.runtime
            assert runtime is not None
            for _ in range(100):
                if app.view.pending_injections() == 0 and runtime.active_calls == 0:
                    break
                await pilot.pause(0.1)
            # reconcile the on-screen delegation table against the journal
            app.refresh_panels()
            await pilot.pause(0.3)
            table = app.query_one("#delegation-table", DataTable)
            assert table.row_count == 1
            row_keys = list(table.rows)
            cells = table.get_row(row_keys[0])
            assert str(row_keys[0].value) == request_payload.correlation_id
            assert cells[0] == request_payload.correlation_id[:8]
            assert cells[1] == request_payload.subagent
            assert cells[2] == completion_payload.status
            # the digest cell is the projected summary: masked (masker) and
            # wrapped in untrusted-target-content markers (arch §6.8); the
            # panel renders through rich-escape, so brackets appear as \[...]
            digest_cell = str(cells[3])
            assert completion_payload.summary_digest in digest_cell
            assert "untrusted-target-content begin" in digest_cell
            assert "untrusted-target-content end" in digest_cell
    finally:
        await session.close()


# ---------------------------------------------------------------------------
# T4.2.1 — chat round trip + sanitized subagent inspection
# ---------------------------------------------------------------------------


async def test_chat_round_trip(tmp_path: Path) -> None:
    """AC T4.2.1: send → orchestrator → reply rendered, OperatorMessage journaled."""
    session = await make_session(
        tmp_path,
        {"orchestrator": [final_reply("ack: continuing recon")]},
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("1")  # focus the chat input
        app.query_one("#chat-input", Input).value = "please continue"
        await pilot.press("enter")
        await pilot.pause(1.0)
        transcript = richlog_text(app.query_one("#chat-log", RichLog))
        assert "please continue" in transcript
        assert "ack: continuing recon" in transcript
        reader = session.reader
        assert reader is not None
        assert len(await reader.by_type("OperatorMessage")) == 1
    await session.close()


async def test_subagent_inspection_is_sanitized(tmp_path: Path) -> None:
    """AC T4.2.1: the delegation snapshot masks operator secrets (§6.8)."""
    session = await make_session(
        tmp_path,
        secrets=SecretsConfig(auth_headers={"X-Token": SECRET_VALUE}),
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        app.state.subagent_transcripts["probe_mod"] = [
            "task: probe with token " + SECRET_VALUE,
            "result recorded",
        ]
        chat = app.query_one("#panel-chat", ChatPanel)
        chat.cycle_target(app.state)
        app.refresh_panels()
        await pilot.pause()
        transcript = richlog_text(chat.log_widget)
        assert SECRET_VALUE not in transcript  # masked away
        assert "<masked:X-Token>" in transcript
        assert "result recorded" in transcript
    await session.close()


# ---------------------------------------------------------------------------
# T4.2.3 — findings card: raw values + evidence paths
# ---------------------------------------------------------------------------


async def test_finding_card_shows_raw_values_and_evidence(tmp_path: Path) -> None:
    """AC T4.2.3: the card carries raw payload + resolvable evidence paths."""
    session = await make_session(tmp_path)
    memory = session.memory
    assert memory is not None
    evidence_dir = session.session_dir / "evidence" / "ev-1"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_file = evidence_dir / "request.txt"
    raw_file.write_text("GET /q?q=EVIL_XSS_PAYLOAD\n", encoding="utf-8")
    evidence = await memory.add_evidence(
        EvidenceDraft(
            kind="http_request_response",
            session_paths=["evidence/ev-1/request.txt"],
            metadata={"ts": "now", "tool": "test", "correlation_id": ""},
        )
    )
    finding = await memory.save_finding(
        FindingDraft(
            type="xss",
            severity=Severity.HIGH,
            title="reflected XSS",
            description="the q parameter reflects EVIL_XSS_PAYLOAD unescaped",
            reproduction=["GET /q?q=EVIL_XSS_PAYLOAD"],
            evidence_refs=[evidence.id],
            created_by="test",
        )
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        await app._open_finding_card(FindingCardRequested(finding.id))
        await pilot.pause()
        findings = app.query_one("#panel-findings", FindingsPanel)
        card_text = static_text(findings.query_one("#finding-card", Static))
        assert "EVIL_XSS_PAYLOAD" in card_text  # RAW (arch §6.8)
        assert raw_file.as_posix() in card_text
        assert raw_file.is_file()
        assert (await memory.list_findings())[0].status.value == "candidate"
    await session.close()


# ---------------------------------------------------------------------------
# T4.2.4 — plans: statistics reconcile with the store; todos reflect the graph
# ---------------------------------------------------------------------------


async def test_plans_stats_and_todos(tmp_path: Path) -> None:
    """AC T4.2.4: statistics match MemoryStore; todos come from the L0 state."""
    session = await make_session(tmp_path)
    memory = session.memory
    assert memory is not None
    await memory.upsert_endpoint(EndpointDraft(host="h1", method="GET", path="/a"))
    probed = await memory.upsert_endpoint(EndpointDraft(host="h2", method="GET", path="/b"))
    probed_row = probed.model_copy(update={"research_status": "probed"})
    del probed_row  # statuses change only via tools; counts below use candidates
    await memory.save_finding(
        FindingDraft(
            type="xss", severity=Severity.HIGH, title="f1", description="d",
            created_by="test",
        )
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        app.state.absorb(
            {"todos": [{"content": "crawl target", "status": "in_progress"}]}
        )
        app.refresh_panels()
        await pilot.pause()
        plans = app.query_one("#panel-plans", PlansPanel)
        todos_text = static_text(plans.query_one("#plans-todos", Static))
        stats_text = static_text(plans.query_one("#plans-stats", Static))
        assert "crawl target" in todos_text
        assert "endpoints" in stats_text
        # statistics reconcile with the store (AC: the counts match MemoryStore)
        endpoints = await memory.list_endpoints()
        findings = await memory.list_findings()
        assert f"undiscovered: {sum(1 for e in endpoints if e.research_status == 'undiscovered')}" in stats_text
        assert stats_text.count("high: 1") == 1
        assert len(findings) == 1
    await session.close()


# ---------------------------------------------------------------------------
# T4.3.1 — approvals panel + modal (FIFO, non-blocking, edit validation)
# ---------------------------------------------------------------------------


async def _session_with_pending_interrupt(tmp_path: Path) -> Session:
    """A session whose scripted subagent hits the profile's verify gate."""
    return await make_session(
        tmp_path,
        {
            "orchestrator": [
                _ai(_tool_call("task", {"description": "run the gated probe",
                                        "subagent_type": "probe_mod"}, "call-o1")),
                final_reply("delegation finished"),
            ],
            "probe_mod": [
                _ai(_tool_call("probe_mod_probe", {"message": "ping"}, "m1")),
                final_reply("probe done"),
            ],
        },
        risk="verify",
    )


async def test_approval_modal_approve_flow(tmp_path: Path) -> None:
    """AC T4.3.1: FIFO visible, decision addresses the request, queue drains."""
    session = await _session_with_pending_interrupt(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("1")  # focus chat input
        app.query_one("#chat-input", Input).value = "run the gated probe"
        await pilot.press("enter")
        await pilot.pause(1.5)
        # AC: the queue shows the pending request...
        approvals = app.query_one("#panel-approvals", ApprovalsPanel)
        table = approvals.query_one("#approval-table", DataTable)
        assert table.row_count == 1
        # ...and the swarm is not blocked while the modal is open (AC 2):
        table.focus()  # focus the approvals table directly
        await pilot.pause()
        await pilot.press("enter")  # open the modal
        await pilot.pause()
        assert isinstance(app.screen, ApprovalModal)
        writer = session.journal
        bus = session.bus
        assert writer is not None
        assert bus is not None
        from swarmy.events.models import EventSource, TargetSetPayload

        envelope = await writer.append(
            type="TargetSet",
            source=EventSource.PLATFORM,
            source_detail="test",
            correlation_id="",
            payload=TargetSetPayload(target_id=1, base_url="http://127.0.0.1:9/"),
        )
        await bus.publish(envelope)
        await pilot.pause(0.3)
        assert "TargetSet" in richlog_text(app.query_one("#activity-log", RichLog))
        # decide: approve → the interrupt resumes and the tool executes
        app.screen.query_one("#btn-approve", Button).press()
        await pilot.pause(1.5)
        assert not isinstance(app.screen, ApprovalModal)
        assert table.row_count == 0  # the FIFO drained
        reader = session.reader
        assert reader is not None
        decisions = await reader.by_type("OperatorDecision")
        assert [d.payload.decision for d in decisions] == ["approve"]
        assert len(await reader.by_type("TaskCompleted")) == 1
        blocked = await reader.by_type("GuardrailBlocked")
        assert blocked == []  # approve authorizes; the invariants still ran
    await session.close()


async def test_approval_edit_form_validation(tmp_path: Path) -> None:
    """AC T4.3.1: bad JSON keeps the modal open; valid JSON submits the edit."""
    session = await _session_with_pending_interrupt(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("1")
        app.query_one("#chat-input", Input).value = "run the gated probe"
        await pilot.press("enter")
        await pilot.pause(1.5)
        table = app.query_one("#approval-table", DataTable)
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, ApprovalModal)
        modal.query_one("#btn-edit", Button).press()
        await pilot.pause()
        editor = modal.query_one("#approval-edit-args", TextArea)
        editor.text = "{not valid json"
        modal.query_one("#btn-edit-save", Button).press()
        await pilot.pause()
        error_text = static_text(modal.query_one("#approval-error", Static))
        assert "not valid JSON" in error_text  # validation keeps the modal open
        assert isinstance(app.screen, ApprovalModal)
        editor.text = '{"message": "edited-by-operator"}'
        modal.query_one("#btn-edit-save", Button).press()
        await pilot.pause(1.5)
        assert not isinstance(app.screen, ApprovalModal)
        reader = session.reader
        assert reader is not None
        decisions = await reader.by_type("OperatorDecision")
        assert [d.payload.decision for d in decisions] == ["edit"]
        # the sanitized edited args rode the journaled decision (§10.3), and
        # the resume carried them into the L0 resume payload — the delegation
        # completed (the subagent-internal tool result stays in its own graph).
        assert decisions[0].payload.edited_args_digest is not None
        assert "edited-by-operator" in decisions[0].payload.edited_args_digest
        assert len(await reader.by_type("TaskCompleted")) == 1
    await session.close()


# ---------------------------------------------------------------------------
# T4.4.1 — attack trees on fixture data (RD-9) + the node → finding transition
# ---------------------------------------------------------------------------


async def _seed_tree(session: Session) -> int:
    """Fixture tree: precondition → finding(#1) → goal (written via the store)."""
    memory = session.memory
    assert memory is not None
    finding = await memory.save_finding(
        FindingDraft(
            type="sqli", severity=Severity.CRITICAL, title="SQLi in /login",
            description="payload ' OR 1=1 --", created_by="test",
        )
    )
    root = await memory.link_attack_node(
        AttackNodeDraft(kind="precondition", title="login form reachable"),
    )
    finding_node = await memory.link_attack_node(
        AttackNodeDraft(kind="finding", finding_ref=finding.id, title="inject login"),
        edges=[AttackEdgeDraft(src=root.id, kind="enables")],
    )
    await memory.link_attack_node(
        AttackNodeDraft(kind="goal", title="dump users"),
        edges=[AttackEdgeDraft(src=finding_node.id, kind="leads_to")],
    )
    return finding.id


async def test_trees_fixture_render_and_node_to_finding(tmp_path: Path) -> None:
    """AC T4.4.1: the tree renders fixture data; a finding node opens the card."""
    session = await make_session(tmp_path)
    finding_id = await _seed_tree(session)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        trees = app.query_one("#panel-trees", TreesPanel)
        tree = trees.tree_widget
        # RD-9: the forest renders from the fixture store rows — one root,
        # three nodes chained by typed edges.
        assert len(tree.root.children) == 1
        root_node = tree.root.children[0]
        assert len(root_node.children) == 1
        finding_node = root_node.children[0]
        assert finding_node.data is not None
        kind, finding_ref, _title = finding_node.data
        assert (kind, finding_ref) == ("finding", finding_id)
        assert len(finding_node.children) == 1  # the goal hangs below
        # AC: node → finding card transition (arch §10.1)
        trees.on_tree_node_selected(Tree.NodeSelected(finding_node))
        await pilot.pause(0.5)
        findings = app.query_one("#panel-findings", FindingsPanel)
        assert findings.selected_finding is not None
        assert findings.selected_finding.id == finding_id
        card_text = static_text(findings.query_one("#finding-card", Static))
        assert "SQLi in /login" in card_text
    await session.close()


# ---------------------------------------------------------------------------
# T4.4.2 — the raw/masked regression scan over the whole console
# ---------------------------------------------------------------------------


async def test_masking_scan_no_secret_anywhere(tmp_path: Path) -> None:
    """AC T4.4.2: no secret value in ANY panel; raw payload only in the card.

    Seeds: an operator secret, feed/chat activity, a finding with a raw
    payload + evidence file, and a fixture tree — then scans every rendered
    text surface of the console.
    """
    session = await make_session(
        tmp_path,
        secrets=SecretsConfig(auth_headers={"X-Token": SECRET_VALUE}),
    )
    memory = session.memory
    assert memory is not None
    evidence_dir = session.session_dir / "evidence" / "ev-1"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "request.txt").write_text("q=EVIL_XSS_PAYLOAD\n", encoding="utf-8")
    evidence = await memory.add_evidence(
        EvidenceDraft(
            kind="http_request_response",
            session_paths=["evidence/ev-1/request.txt"],
            metadata={"ts": "now", "tool": "test", "correlation_id": ""},
        )
    )
    finding = await memory.save_finding(
        FindingDraft(
            type="xss",
            severity=Severity.HIGH,
            title="reflected XSS",
            description=f"reflects EVIL_XSS_PAYLOAD via token {SECRET_VALUE}",
            evidence_refs=[evidence.id],
            created_by="test",
        )
    )
    await _seed_tree(session)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        # the card surface is the ONLY raw surface (arch §6.8):
        await app._open_finding_card(FindingCardRequested(finding.id))
        app.refresh_panels()
        await pilot.pause()
        findings = app.query_one("#panel-findings", FindingsPanel)
        card_text = static_text(findings.query_one("#finding-card", Static))
        assert "EVIL_XSS_PAYLOAD" in card_text
        # the secret is masked even in the raw card (AGENTS.md security rule)
        assert SECRET_VALUE not in card_text
        assert "<masked:X-Token>" in card_text
        # scan every other rendered surface:
        surfaces = {
            "feed": richlog_text(app.query_one("#activity-log", RichLog)),
            "chat": richlog_text(app.query_one("#chat-log", RichLog)),
            "plans": static_text(
                app.query_one("#panel-plans", PlansPanel).query_one("#plans-stats", Static)
            ),
        }
        tables = [
            app.query_one("#endpoint-table", DataTable),
            app.query_one("#finding-table", DataTable),
            app.query_one("#delegation-table", DataTable),
            app.query_one("#approval-table", DataTable),
        ]
        for table in tables:
            for row_key in table.rows:
                cells = table.get_row(row_key)
                surfaces[f"table-{table.id}"] = (
                    surfaces.get(f"table-{table.id}", "") + " ".join(str(cell) for cell in cells)
                )
        for name, text in surfaces.items():
            assert SECRET_VALUE not in text, f"secret leaked in {name}"
            assert "EVIL_XSS_PAYLOAD" not in text, f"raw payload leaked in {name}"
    await session.close()
