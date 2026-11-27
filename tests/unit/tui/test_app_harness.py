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
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape as rich_escape
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
from swarmy.tui.approvals import (
    ApprovalModal,
    ApprovalModalOpen,
    ApprovalsPanel,
    ModalDecision,
)
from swarmy.tui.panels.activity import ActivityPanel
from swarmy.tui.panels.chat import ChatPanel
from swarmy.tui.panels.findings import FindingCardRequested, FindingsPanel
from swarmy.tui.panels.plans import PlansPanel
from swarmy.tui.panels.trees import TreesPanel
from swarmy.tui.state import SessionView

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


def status_text(app: SwarmyTui) -> str:
    """The rendered text of the global status bar."""
    return static_text(app.query_one("#status-bar", Static))


class GatedModel(ScriptedChatModel):
    """Scripted model whose answers wait for ``gate`` (a step that takes long)."""

    def __init__(self, gate: asyncio.Event, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._gate = gate

    async def _agenerate(self, messages: Any, stop: Any = None, **kwargs: Any) -> Any:
        await self._gate.wait()
        return await super()._agenerate(messages, stop=stop, **kwargs)


async def make_session(
    tmp_path: Path,
    scripts: dict[str, list[object]] | None = None,
    *,
    risk: str = "passive",
    module_name: str = "probe_mod",
    secrets: SecretsConfig | None = None,
    model: ScriptedChatModel | None = None,
) -> Session:
    """One composed session with a scripted model and one fixture module.

    ``model`` overrides the scripted default (a gated/slow double for the
    step-in-progress scenarios).
    """
    agents = tmp_path / "agents"
    make_module(
        agents,
        module_name,
        description="Fixture module for the harness.",
        prompt=f"You are {module_name}: probe the authorized target.",
        risk=risk,  # type: ignore[arg-type]
    )
    model_: ScriptedChatModel | Any
    if model is not None:
        model_ = model
    elif scripts is None:
        model_ = one_shot_model()
    else:
        model_ = ScriptedChatModel(scripts=scripts, fallback_reply="done")
    config = SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
        agents_dirs=[str(agents)],
        profile="normal",
    )
    return await Session.open(
        config=config, session_dir=tmp_path / "s", secrets=secrets, model=model_
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


async def test_typing_starts_in_the_chat_input(tmp_path: Path) -> None:
    """The opening goal can be typed without hunting for the input.

    Regression: Textual's default ``AUTO_FOCUS = "*"`` focused the Chat
    panel's ``RichLog`` (the first focusable widget in the DOM), so operator
    keystrokes went into the transcript viewer — no ``OperatorMessage`` was
    journaled and the mission never started. The digit bindings stay global
    (``2`` still switches to Activity); every other printable key starts a
    chat message.
    """
    session = await make_session(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        assert not isinstance(app.focused, Input)
        await pilot.press("h")
        await pilot.pause(0.2)
        assert isinstance(app.focused, Input)
        assert app.focused.id == "chat-input"
        assert app.query_one("#chat-input", Input).value == "h"
        # the digit panel bindings still work while the chat is not focused
        app.query_one("#chat-log", RichLog).focus()
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        assert app.focused is not None
        assert app.focused.id == "delegation-table"
    await session.close()


async def test_empty_chat_shows_the_start_hint(tmp_path: Path) -> None:
    """The empty chat panel tells the operator how to start the mission."""
    session = await make_session(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        transcript = richlog_text(app.query_one("#chat-log", RichLog))
        assert "Type your goal" in transcript
    await session.close()


async def test_typing_the_goal_starts_the_mission(tmp_path: Path) -> None:
    """No panel key, no click: typing the goal starts the orchestrator step.

    Regression for the "panels open but nothing happens" report: with the
    Chat ``RichLog`` focused, the typed goal never reached the input, so no
    ``OperatorMessage`` was journaled and the swarm stayed idle.
    """
    session = await make_session(
        tmp_path,
        {"orchestrator": [final_reply("ack: starting the probe")]},
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        for char in "run the probe":
            await pilot.press("space" if char == " " else char)
        await pilot.press("enter")
        await pilot.pause(1.0)
        reader = session.reader
        assert reader is not None
        assert len(await reader.by_type("OperatorMessage")) == 1
        transcript = richlog_text(app.query_one("#chat-log", RichLog))
        assert "ack: starting the probe" in transcript
    await session.close()


async def test_opening_goal_starts_the_mission_without_keystrokes(tmp_path: Path) -> None:
    """A goal file handed to the console starts the mission by itself (arch §3.4).

    The opening goal is journaled as the first ``OperatorMessage`` on mount
    and the worker's first pass runs the orchestrator step — nothing is
    typed, and the "Type your goal" hint never shows.
    """
    session = await make_session(
        tmp_path,
        {"orchestrator": [final_reply("ack: goal file received")]},
    )
    app = SwarmyTui(session, opening_goal="run the probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(1.0)
        reader = session.reader
        assert reader is not None
        assert len(await reader.by_type("OperatorMessage")) == 1
        assert app.view.pending_injections() == 0
        transcript = richlog_text(app.query_one("#chat-log", RichLog))
        assert "run the probe" in transcript
        assert "ack: goal file received" in transcript
        assert "Type your goal" not in transcript
    await session.close()


async def test_opening_goal_is_served_while_the_first_step_runs(tmp_path: Path) -> None:
    """The goal reaches the feed at once; live events keep flowing during a step.

    Regression (the "panels open, nothing happens" report of the goal-file
    auto-start): the worker used to await ``run_step`` directly, so a step
    that takes minutes — a ``task()`` delegation runs inside the graph
    invocation — froze every panel, and the opening goal stayed unserved
    behind an empty first batch with the "Type your goal" hint on screen for
    the whole step. The step now runs as a task while the loop keeps serving
    (arch §10.1).
    """
    gate = asyncio.Event()
    session = await make_session(
        tmp_path, model=GatedModel(gate, scripts={}, fallback_reply="ack: after the gate")
    )
    app = SwarmyTui(session, opening_goal="run the probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        runtime = session.runtime
        assert runtime is not None
        assert runtime.active_calls == 1  # the first step is still inside the model
        transcript = richlog_text(app.query_one("#chat-log", RichLog))
        assert "run the probe" in transcript  # served while the step runs
        assert "Type your goal" not in transcript
        # a swarm event landing mid-step reaches the panels without waiting
        journal, bus = session.journal, session.bus
        assert journal is not None
        assert bus is not None
        from swarmy.events.models import EndpointsDiscoveredPayload, EventSource

        envelope = await journal.append(
            type="EndpointsDiscovered",
            source=EventSource.PLATFORM,
            source_detail="test",
            correlation_id="",
            payload=EndpointsDiscoveredPayload(endpoints=[], out_of_scope_count=0),
        )
        await bus.publish(envelope)
        await pilot.pause(0.3)
        assert "EndpointsDiscovered" in richlog_text(app.query_one("#activity-log", RichLog))
        assert runtime.active_calls == 1  # still the one step (AD-8: single writer)
        gate.set()
        await pilot.pause(0.5)
        assert "ack: after the gate" in richlog_text(app.query_one("#chat-log", RichLog))
        assert runtime.active_calls == 0
    await session.close()


async def test_console_closes_while_a_step_is_still_running(tmp_path: Path) -> None:
    """ctrl+q during a long step: the step task is cancelled, the console exits.

    The step runs as a task (arch §10.1), so app shutdown cancels it instead
    of waiting for a model that may answer minutes later.
    """
    gate = asyncio.Event()
    session = await make_session(
        tmp_path, model=GatedModel(gate, scripts={}, fallback_reply="never delivered")
    )
    app = SwarmyTui(session, opening_goal="run the probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        runtime = session.runtime
        assert runtime is not None
        assert runtime.active_calls == 1
        # leaving the context quits the app with the step still inside the model
    await session.close()
    assert gate.is_set() is False  # the model never answered: the step was cancelled


async def test_without_an_opening_goal_the_console_stays_idle(tmp_path: Path) -> None:
    """No goal file: nothing is sent and the start hint shows (chat-only start)."""
    session = await make_session(
        tmp_path,
        {"orchestrator": [final_reply("must not run")]},
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.5)
        reader = session.reader
        assert reader is not None
        assert await reader.by_type("OperatorMessage") == []
        assert app.view.pending_injections() == 0
        transcript = richlog_text(app.query_one("#chat-log", RichLog))
        assert "Type your goal" in transcript
        assert "must not run" not in transcript
    await session.close()


# ---------------------------------------------------------------------------
# Status bar — liveness while the model works, completion when the turn ends
# ---------------------------------------------------------------------------


async def test_status_bar_is_idle_on_a_fresh_session(tmp_path: Path) -> None:
    """No goal, no step: the bar tells the operator how to start."""
    session = await make_session(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        text = status_text(app)
        assert "idle" in text
        assert "type a goal" in text
        assert "working" not in text
    await session.close()


async def test_status_bar_shows_working_and_elapsed_while_the_step_runs(
    tmp_path: Path,
) -> None:
    """A slow model step is visible as a spinner + elapsed time + last-event age.

    Regression for the "is the app frozen or waiting for the LLM?" report:
    before the status bar the console showed nothing at all for the whole
    model call.
    """
    gate = asyncio.Event()
    session = await make_session(
        tmp_path, model=GatedModel(gate, scripts={}, fallback_reply="ack: after the gate")
    )
    app = SwarmyTui(session, opening_goal="run the probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.4)
        working = status_text(app)
        assert "working" in working
        first_elapsed = app.state.step_elapsed()
        await pilot.pause(0.5)
        assert app.state.step_elapsed() > first_elapsed  # the clock really advances
        assert "working" in status_text(app)
        gate.set()
        await pilot.pause(0.8)
        assert "turn complete" in status_text(app)
        assert app._notified_turns >= 1  # one completion toast, not a storm
    await session.close()


async def test_status_bar_reports_turn_complete(tmp_path: Path) -> None:
    """After a normal step the bar persistently says the turn is over."""
    session = await make_session(
        tmp_path, {"orchestrator": [final_reply("ack: all done")]}
    )
    app = SwarmyTui(session, opening_goal="run the probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(1.0)
        assert "turn complete" in status_text(app)
    await session.close()


async def test_status_bar_reports_waiting_for_operator_approval(tmp_path: Path) -> None:
    """A pending HITL request is visible in the bar, not only in its panel."""
    session = await _session_with_pending_interrupt(tmp_path)
    app = SwarmyTui(session, opening_goal="run the gated probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(1.5)
        text = status_text(app)
        assert "waiting for operator approval" in text
        assert "1 in the HITL queue" in text
    await session.close()


async def test_status_bar_reports_plan_complete(tmp_path: Path) -> None:
    """All todos completed + nothing pending → the plan is complete, not just idle."""
    session = await make_session(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        app.state.step_started()
        app.state.step_finished()
        app.state.absorb(
            {"todos": [{"content": "map the target", "status": "completed"}]}
        )
        app._refresh_status_bar()
        assert "plan complete" in status_text(app)
    await session.close()


async def test_chat_renders_untrusted_markers_as_red_background(tmp_path: Path) -> None:
    """§6.8 markers in a reply never appear as text; the content stays visible."""
    from swarmy.tools.projector import UNTRUSTED_BEGIN, UNTRUSTED_END

    session = await make_session(
        tmp_path,
        {"orchestrator": [final_reply(
            f"quote: {UNTRUSTED_BEGIN} target said hello {UNTRUSTED_END}"
        )]},
    )
    app = SwarmyTui(session, opening_goal="run the probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(1.0)
        transcript = richlog_text(app.query_one("#chat-log", RichLog))
        assert "untrusted-target-content" not in transcript
        assert "target said hello" in transcript
    await session.close()


async def test_opening_goal_failure_degrades_to_the_error_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A journaling failure of the opening goal keeps the console up (Issue #28)."""

    async def broken(self: SessionView, text: str) -> None:
        raise RuntimeError("journal is closed")

    session = await make_session(tmp_path, {"orchestrator": [final_reply("unused")]})
    monkeypatch.setattr(SessionView, "send_operator_message", broken)
    app = SwarmyTui(session, opening_goal="run the probe")
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.5)
        assert any("journal is closed" in line for line in app.state.system_errors)
        # the console is still alive: the worker loop serves the preloaded feed
        assert app.state.event_count >= 1
        # the failed message was never queued, so the orchestrator did not step
        assert "unused" not in richlog_text(app.query_one("#chat-log", RichLog))
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
            # The digest cell is the projected summary: masked, with the §6.8
            # markers never printed as text — the TUI renderer paints the
            # enclosed content with a red background instead.
            digest_cell = cells[3]
            assert completion_payload.summary_digest in str(digest_cell)
            assert "untrusted-target-content" not in str(digest_cell)
            # the Plans panel shows the live delegation plan (no todos yet)
            plans = app.query_one("#panel-plans", PlansPanel)
            plans_text = static_text(plans.query_one("#plans-todos", Static))
            assert request_payload.subagent in plans_text
            assert completion_payload.status in plans_text
            assert "delegations" in static_text(plans.query_one("#plans-stats", Static))
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
        # The card shows the OS-native absolute path (what an operator pastes
        # into a shell) — backslashes on Windows, so no as_posix() here.
        assert str(raw_file) in card_text
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
        assert "delegations" in stats_text
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


# ---------------------------------------------------------------------------
# Consolidated-review regression pins: F-15, #19↔F-13, #15, #28, F-21, #45, #33
# ---------------------------------------------------------------------------


def test_modal_decision_accepts_nested_json() -> None:
    """Issue #45 (model level): edited args may hold nested dicts/lists."""
    decision = ModalDecision(
        request_id="r",
        decision="edit",
        edited_args={
            "url": "http://127.0.0.1:9/",
            "headers": {"X-A": "1"},
            "evidence_refs": [1, 2, {"k": None}],
        },
    )
    assert decision.edited_args is not None
    assert decision.edited_args["headers"] == {"X-A": "1"}


def test_modal_decision_rejects_non_json_edited_args() -> None:
    """The recursive JSON-shape validator refuses non-JSON values (D9)."""
    with pytest.raises(ValidationError):
        ModalDecision(request_id="r", decision="edit", edited_args={"x": object()})


async def test_endpoint_method_markup_does_not_crash_loop(tmp_path: Path) -> None:
    """F-15 pin: a poisoned ``method`` value renders escaped across refreshes.

    The old code interpolated ``endpoint.method`` raw into a markup-parsing
    DataTable cell; the worker re-renders every ~100 ms, so one poisoned row
    deterministically crash-looped the console — and persisted across resume.
    """
    session = await make_session(tmp_path)
    memory = session.memory
    assert memory is not None
    await memory.upsert_endpoint(EndpointDraft(host="h1", method="GET", path="/a"))
    await memory.upsert_endpoint(EndpointDraft(host="h2", method="[/etc/passwd]", path="/x"))
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.4)  # several worker ticks — no crash loop
        await pilot.pause(0.4)
        table = app.query_one("#endpoint-table", DataTable)
        assert table.row_count == 2
        methods = " | ".join(str(table.get_row(key)[2]) for key in table.rows)
        # The cell is a rich Text (literal, not markup): markup-looking
        # values cannot inject styles, so no escaping is needed on screen.
        assert "[/etc/passwd]" in methods
    await session.close()


async def test_finding_card_markup_title_renders(tmp_path: Path) -> None:
    """#19↔F-13 pin: an unbalanced markup token in a finding title is literal."""
    session = await make_session(tmp_path)
    memory = session.memory
    assert memory is not None
    finding = await memory.save_finding(
        FindingDraft(
            type="xss",
            severity=Severity.HIGH,
            title="Path traversal — arbitrary read of [/etc/passwd]",
            description="read of [/Authorization] confirmed",
            created_by="test",
        )
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        await app._open_finding_card(FindingCardRequested(finding.id))
        await pilot.pause(0.3)  # the worker re-renders the card — still alive
        card_text = static_text(
            app.query_one("#panel-findings", FindingsPanel).query_one("#finding-card", Static)
        )
        assert "[/etc/passwd]" in card_text  # literal characters (raw display)
    await session.close()


async def test_markup_surfaces_render_without_markuperror(tmp_path: Path) -> None:
    """#19↔F-13 pin: border titles, activity cells and the status line escape.

    Hostile (target/agent-influenced) strings flow through the trees/chat
    border titles and the approvals status line without a MarkupError.
    """
    session = await make_session(tmp_path)
    queue = session.approvals
    assert queue is not None
    await queue.enqueue_external(
        tool="[/tool]",
        args_digest="d",
        origin="judge",  # origin is a bounded literal; tool is the free-form cell
        rule_or_profile="[/rule]",
    )
    memory = session.memory
    assert memory is not None
    finding = await memory.save_finding(
        FindingDraft(
            type="sqli", severity=Severity.HIGH, title="[/title]", description="d",
            created_by="test",
        )
    )
    await memory.link_attack_node(
        AttackNodeDraft(kind="finding", finding_ref=finding.id, title="[/node]"),
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        # approvals status line: hostile tool/origin render as literals
        app.refresh_panels()
        await pilot.pause()
        status_text = static_text(
            app.query_one("#panel-activity", ActivityPanel).query_one(
                "#approvals-status", Static
            )
        )
        assert "[/tool]" in status_text  # hostile tool name renders as literal
        assert "[/rule]" not in status_text  # the rule rides the panel row, not here
        # chat border title: hostile subagent inspection name
        chat = app.query_one("#panel-chat", ChatPanel)
        app.state.subagent_transcripts["[/sub]"] = ["probe [/x]"]
        chat.cycle_target(app.state)
        assert rich_escape("[/sub]") in str(chat.border_title)
        app.refresh_panels()
        # trees border title: hostile node title on selection
        trees = app.query_one("#panel-trees", TreesPanel)
        node = trees.tree_widget.root.children[0]
        assert node.data is not None
        trees.on_tree_node_selected(Tree.NodeSelected(node))
        assert rich_escape("[/node]") in str(trees.border_title)
        await pilot.pause(0.3)  # worker still ticking, console alive
    await session.close()


async def test_cyclic_attack_graph_renders_with_cycle_marker(tmp_path: Path) -> None:
    """Issue #15 pin: a cycle reachable from a root terminates with a marker.

    Old behavior: ``_attach_children`` recursed until ``RecursionError`` on
    every refresh. Edges are LLM-authored; the store imposes no acyclicity.
    """
    session = await make_session(tmp_path)
    memory = session.memory
    assert memory is not None
    root = await memory.link_attack_node(AttackNodeDraft(kind="goal", title="dump users"))
    a = await memory.link_attack_node(
        AttackNodeDraft(kind="precondition", title="A"),
        edges=[AttackEdgeDraft(src=root.id, kind="enables")],  # root → A
    )
    b = await memory.link_attack_node(
        AttackNodeDraft(kind="precondition", title="B"),
        edges=[AttackEdgeDraft(src=a.id, kind="leads_to")],  # A → B
    )
    await memory.link_attack_node(
        AttackNodeDraft(kind="precondition", title="D"),
        edges=[
            AttackEdgeDraft(src=b.id, kind="requires"),  # B → D
            AttackEdgeDraft(src=None, dst=a.id, kind="enables"),  # D → A (cycle)
        ],
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.4)  # the old code crashed the worker here
        tree = app.query_one("#panel-trees", TreesPanel).tree_widget
        assert len(tree.root.children) == 1  # the root
        root_branch = tree.root.children[0]
        assert len(root_branch.children) == 1  # A
        branch_a = root_branch.children[0]
        assert len(branch_a.children) == 1  # B
        branch_b = branch_a.children[0]
        assert len(branch_b.children) == 1  # D
        branch_d = branch_b.children[0]
        assert len(branch_d.children) == 1  # the back-edge D → A: ONE marker
        marker = branch_d.children[0]
        assert marker.data == ("precondition", None, "A")  # points at the cycle head
        assert "cycle" in str(marker.label)
    await session.close()


async def test_session_worker_survives_step_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #28 pin: one failed ``run_step`` costs one step, not the console."""
    session = await make_session(
        tmp_path, {"orchestrator": [final_reply("recovered reply")]}
    )
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)

        async def boom() -> object:
            raise RuntimeError("provider exploded")

        monkeypatch.setattr(app.view, "run_step", boom)
        await pilot.press("1")
        app.query_one("#chat-input", Input).value = "trigger a failing step"
        await pilot.press("enter")
        transcript = ""
        for _ in range(40):  # the failure surfaces as a system> chat line
            transcript = richlog_text(app.query_one("#chat-log", RichLog))
            if "provider exploded" in transcript:
                break
            await pilot.pause(0.2)
        assert "provider exploded" in transcript
        monkeypatch.undo()
        app.query_one("#chat-input", Input).value = "please continue"
        await pilot.press("enter")
        transcript = ""
        for _ in range(40):  # the loop keeps running and the step succeeds
            transcript = richlog_text(app.query_one("#chat-log", RichLog))
            if "recovered reply" in transcript:
                break
            await pilot.pause(0.2)
        assert "recovered reply" in transcript
    await session.close()


async def test_double_approval_modal_is_guarded(tmp_path: Path) -> None:
    """F-21 pin (a): a double modal-open for one request stacks ONE modal."""
    session = await _session_with_pending_interrupt(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("1")
        app.query_one("#chat-input", Input).value = "run the gated probe"
        await pilot.press("enter")
        await pilot.pause(1.5)
        table = app.query_one("#approval-table", DataTable)
        request_id = next(iter(table.rows)).value
        assert request_id is not None
        app.post_message(ApprovalModalOpen(request_id))
        await pilot.pause()
        app.post_message(ApprovalModalOpen(request_id))  # the double-Enter race
        await pilot.pause()
        assert isinstance(app.screen, ApprovalModal)
        assert len(app.screen_stack) == 2  # base + exactly one modal
        app.screen.query_one("#btn-approve", Button).press()
        await pilot.pause(1.5)
        assert not isinstance(app.screen, ApprovalModal)
    await session.close()


async def test_stale_approval_decision_resyncs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-21 pin (b): a decision for an unknown request id must not crash."""
    session = await _session_with_pending_interrupt(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        severities: list[str | None] = []
        monkeypatch.setattr(app, "notify", lambda *a, **k: severities.append(k.get("severity")))
        await app._serve_decision(
            ModalDecision(request_id="no-such-request", decision="approve")
        )
        await pilot.pause()
        assert "warning" in severities  # stale-modal toast, queue re-synced
        assert app.query_one("#approval-table", DataTable) is not None
    await session.close()


async def test_decision_path_survives_transient_refresh_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read error in the post-decision snapshot refresh cannot kill the console.

    The refresh re-pull sits inside the decision guard (Issue #28): the
    failure degrades to the system error line and the console stays alive.
    """
    session = await _session_with_pending_interrupt(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("1")
        app.query_one("#chat-input", Input).value = "run the gated probe"
        await pilot.press("enter")
        table = app.query_one("#approval-table", DataTable)
        request_id = None
        for _ in range(50):
            await pilot.pause(0.2)
            if table.row_count:
                request_id = next(iter(table.rows)).value
                break
        assert request_id is not None, "the gated probe never produced an approval"

        async def failing_refresh() -> None:
            raise RuntimeError("transient read error")

        monkeypatch.setattr(app.state, "refresh", failing_refresh)
        await app._serve_decision(ModalDecision(request_id=request_id, decision="approve"))
        await pilot.pause()
        assert any(
            "transient read error" in str(error) for error in app.state.system_errors
        ), "the refresh failure must surface in the system error line"
        # the console is alive: the approvals table still queries fine
        assert app.query_one("#approval-table", DataTable) is not None
    await session.close()


async def test_chat_send_failure_does_not_kill_the_console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing ``send_operator_message`` degrades to the error line (#28)."""
    session = await make_session(tmp_path, {"orchestrator": [final_reply("unused")]})
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.2)

        async def boom(_text: str) -> None:
            raise RuntimeError("journal write failed")

        monkeypatch.setattr(app.view, "send_operator_message", boom)
        await pilot.press("1")
        app.query_one("#chat-input", Input).value = "this send will fail"
        await pilot.press("enter")
        await pilot.pause()
        assert any(
            "journal write failed" in str(error) for error in app.state.system_errors
        ), "the send failure must surface in the system error line"
        assert app.query_one("#chat-log", RichLog) is not None  # console alive
        reader = session.reader
        assert reader is not None
        assert len(await reader.by_type("OperatorMessage")) == 0
    await session.close()


async def test_approval_edit_accepts_nested_args(tmp_path: Path) -> None:
    """Issue #45 pin: 'Save edit' with nested dict/list args must not crash."""
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
        import json

        editor.text = json.dumps(
            {"message": "edited", "headers": {"X-A": "b"}, "evidence_refs": [1, 2]}
        )
        modal.query_one("#btn-edit-save", Button).press()
        await pilot.pause(1.5)
        assert not isinstance(app.screen, ApprovalModal)
        reader = session.reader
        assert reader is not None
        decisions = await reader.by_type("OperatorDecision")
        assert [d.payload.decision for d in decisions] == ["edit"]
    await session.close()


async def test_idle_ticks_skip_panel_rerender(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #33 pin: idle poll ticks do not re-render the six panels."""
    session = await make_session(tmp_path)
    app = SwarmyTui(session)
    async with app.run_test(size=(120, 44)) as pilot:
        await pilot.pause(0.3)
        calls = {"n": 0}
        panels = [
            app.query_one(panel_id, panel_type)
            for panel_id, panel_type in (
                ("#panel-chat", ChatPanel),
                ("#panel-activity", ActivityPanel),
                ("#panel-findings", FindingsPanel),
                ("#panel-approvals", ApprovalsPanel),
                ("#panel-trees", TreesPanel),
                ("#panel-plans", PlansPanel),
            )
        ]
        for panel in panels:
            original = panel.refresh_state

            def counting(state: object, view: object, _original: object = original) -> None:
                calls["n"] += 1
                _original(state, view)  # type: ignore[operator]

            monkeypatch.setattr(panel, "refresh_state", counting)
        before = calls["n"]
        await pilot.pause(0.5)  # ~5 idle poll ticks
        assert calls["n"] == before  # idle ticks do NOT re-render
        # a real batch still renders:
        writer = session.journal
        bus = session.bus
        assert writer is not None
        assert bus is not None
        from swarmy.events.models import EndpointsDiscoveredPayload, EventSource

        envelope = await writer.append(
            type="EndpointsDiscovered",
            source=EventSource.PLATFORM,
            source_detail="test",
            correlation_id="",
            payload=EndpointsDiscoveredPayload(endpoints=[], out_of_scope_count=0),
        )
        await bus.publish(envelope)
        for _ in range(20):
            if calls["n"] > before:
                break
            await pilot.pause(0.1)
        assert calls["n"] > before
    await session.close()
