"""SwarmyTui: the operator console (arch §10, roadmap T4.1.2).

Layout: the six MVP panels of D10 in a 2x3 grid — Chat, Swarm Activity,
Findings & Endpoints, HITL Approvals, Attack Trees, Progress & Plans. The
session loop runs as a Textual **worker** inside the app's event loop (arch
§2.2: the core never knows about Textual): every pass serves one coalesced
state batch (feed, snapshots, panels), then drains pending runtime
injections with one orchestrator step. Key bindings navigate the panels;
``ctrl+q`` checkpoints the WAL and leaves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Input

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
from swarmy.tui.state import SessionView, TuiState

if TYPE_CHECKING:
    from textual.widget import Widget

    from swarmy.core.session import Session

#: Panel order of the D10 grid (1-based, matches the digit bindings).
_PANEL_IDS: tuple[str, ...] = (
    "#panel-chat",
    "#panel-activity",
    "#panel-findings",
    "#panel-approvals",
    "#panel-trees",
    "#panel-plans",
)

#: Where the digit bindings land the focus inside each panel.
_FOCUS_TARGETS: dict[int, str | None] = {
    1: "#chat-input",
    2: "#delegation-table",
    3: "#finding-table",
    4: "#approval-table",
    5: "#attack-tree",
    6: None,
}


class SwarmyTui(App[None]):
    """The six-panel console over one open session (arch §10.1)."""

    CSS = """
    #panels { layout: grid; grid-size: 2; grid-rows: 1fr 1fr 1fr; height: 1fr; }
    #panels > * { border: round #555555; padding: 0 1; }
    #chat-log { height: 1fr; }
    #chat-input { dock: bottom; }
    #activity-log { height: 2fr; }
    #delegation-table { height: 1fr; }
    #approvals-status { dock: bottom; height: 1; }
    #findings-tables { height: 1fr; }
    #finding-card { dock: bottom; height: auto; max-height: 12; }
    """

    BINDINGS: ClassVar[list] = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("1", "panel(1)", "Chat", priority=True),
        Binding("2", "panel(2)", "Activity", priority=True),
        Binding("3", "panel(3)", "Findings", priority=True),
        Binding("4", "panel(4)", "Approvals", priority=True),
        Binding("5", "panel(5)", "Trees", priority=True),
        Binding("6", "panel(6)", "Plans", priority=True),
    ]

    def __init__(self, session: Session) -> None:
        """Bind one OPEN session (composition stays with open/resume)."""
        super().__init__()
        self.view = SessionView(session)
        self.state = TuiState(self.view)

    # ---- layout ----

    def compose(self) -> ComposeResult:
        """The 2x3 panel grid of arch §10.1."""
        with Horizontal(id="panels"):
            yield ChatPanel("panel-chat", self.view.mask)
            yield ActivityPanel("panel-activity", self.view.mask)
            yield FindingsPanel("panel-findings", self.view.mask)
            yield ApprovalsPanel("panel-approvals")
            yield TreesPanel("panel-trees", self.view.mask)
            yield PlansPanel("panel-plans")

    async def on_mount(self) -> None:
        """Subscribe the state, preload the journal tail, start the worker."""
        self.state.start()
        await self.state.preload()
        self.refresh_panels()
        self.run_session_loop()

    # ---- the session worker (arch §10.1: workers inside the Textual loop) ----

    def run_session_loop(self) -> None:
        """Start the session-loop worker (separate method for test seams)."""
        self._session_worker()

    @work(exclusive=True)
    async def _session_worker(self) -> None:
        """Serve coalesced batches; drain runtime injections step by step."""
        while True:
            batch = await self.state.wait_batch(poll_after=0.1)
            if batch:
                self.state.feed.extend(batch)  # coalescing: nothing is lost
            dirty = self.state.take_dirty()
            if batch or self.state.needs_snapshot(dirty):
                await self.state.refresh()
            self.refresh_panels()
            while self.view.pending_injections() > 0:
                result = await self.view.run_step()
                self.state.absorb(result)
                await self.state.refresh()
                self.refresh_panels()

    # ---- rendering ----

    def refresh_panels(self) -> None:
        """Push the current snapshot cache into every panel."""
        panels = (
            self.query_one("#panel-chat", ChatPanel),
            self.query_one("#panel-activity", ActivityPanel),
            self.query_one("#panel-findings", FindingsPanel),
            self.query_one("#panel-approvals", ApprovalsPanel),
            self.query_one("#panel-trees", TreesPanel),
            self.query_one("#panel-plans", PlansPanel),
        )
        for panel in panels:
            panel.refresh_state(self.state, self.view)

    # ---- navigation ----

    def action_panel(self, index: str) -> None:
        """Focus panel ``index`` (1..6, the D10 grid order)."""
        target = _FOCUS_TARGETS.get(int(index))
        if target is None:
            return
        widget: Widget = self.query_one(target)
        self.set_focus(widget)

    # ---- chat (T4.2.1) ----

    @on(Input.Submitted)
    async def _send_chat(self, event: Input.Submitted) -> None:
        """Send one operator message; the worker picks the injection up."""
        if event.input.id != "chat-input":
            return
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        await self.view.send_operator_message(text)
        self.state.kick()

    # ---- HITL modal (T4.3.1: modal for the operator, not for the swarm) ----

    @on(ApprovalModalOpen)
    def _open_approval_modal(self, event: ApprovalModalOpen) -> None:
        """Push the decision modal for the requested FIFO entry."""
        for item in self.state.approvals:
            if item.request_id == event.request_id:
                self.push_screen(ApprovalModal(item), self._serve_decision)
                return

    async def _serve_decision(self, decision: ModalDecision | None) -> None:
        """Serve the modal decision through the facade; wake the worker."""
        if decision is None:
            return
        result = await self.view.submit_decision(
            decision.request_id, decision.decision, decision.edited_args
        )
        # The resume continuation is a graph result like any step — fold it
        # into the state (transcripts/todos) and wake the loop for follow-ons.
        if result is not None:
            self.state.absorb(result)
            await self.state.refresh()
        self.refresh_panels()
        self.state.kick()

    # ---- finding cards (T4.2.3 / T4.4.1: node → finding transition) ----

    @on(FindingCardRequested)
    async def _open_finding_card(self, event: FindingCardRequested) -> None:
        """Resolve the raw finding + evidence paths and render the card."""
        try:
            finding = await self.view.finding(event.finding_id)
        except KeyError:
            return
        paths = await self.view.evidence_paths(finding.evidence_refs)
        panel = self.query_one("#panel-findings", FindingsPanel)
        panel.show_card(finding, paths)
        self.focus_panel_by_id("#panel-findings", "#finding-table")

    def focus_panel_by_id(self, panel_id: str, target: str) -> None:
        """Focus one panel's inner widget (tree → findings transition)."""
        del panel_id  # the target widget carries the focus; kept for clarity
        widget: Widget = self.query_one(target)
        self.set_focus(widget)

    # ---- lifecycle ----

    async def action_quit(self) -> None:
        """Checkpoint the WAL and release the session before exiting."""
        self.state.stop()
        await self.view.close()
        self.exit()
