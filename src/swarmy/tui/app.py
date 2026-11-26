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

import asyncio
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
        """Serve coalesced batches; drain runtime injections step by step.

        Every await in the loop is guarded (Issue #28): one failed pass — a
        provider hiccup on ``run_step``, a journal decode or render error —
        is reported as a system line in the chat feed and the loop continues;
        the worker used to be a bare ``while True`` whose first exception
        exited the whole console. Idle poll ticks (no batch, no dirty types)
        skip the panel re-render entirely (Issue #33: the console used to
        re-render all six panels ~10x/s even when nothing happened).
        """
        while True:
            try:
                batch = await self.state.wait_batch(poll_after=0.1)
                dirty = self.state.take_dirty()
                if not batch and not dirty and self.view.pending_injections() == 0:
                    continue  # idle poll tick: nothing new to render or drain
                if batch:
                    self.state.extend_feed(batch)  # coalescing: nothing is lost
                if batch or self.state.needs_snapshot(dirty):
                    await self.state.refresh()
                self.refresh_panels()
                while self.view.pending_injections() > 0:
                    result = await self.view.run_step()
                    self.state.absorb(result)
                    await self.state.refresh()
                    self.refresh_panels()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # one failed pass must not kill the TUI
                self._report_error(exc)
                await asyncio.sleep(0.5)  # back off before the retry pass

    # ---- rendering ----

    def refresh_panels(self) -> None:
        """Push the current snapshot cache into every panel.

        Panel render failures are isolated (Issue #28): one broken panel is
        reported to the error line and the others still update — a render
        defect can no longer crash the session worker through this path.
        """
        for panel_id, panel_type in (
            ("#panel-chat", ChatPanel),
            ("#panel-activity", ActivityPanel),
            ("#panel-findings", FindingsPanel),
            ("#panel-approvals", ApprovalsPanel),
            ("#panel-trees", TreesPanel),
            ("#panel-plans", PlansPanel),
        ):
            try:
                self.query_one(panel_id, panel_type).refresh_state(self.state, self.view)
            except Exception as exc:  # per-panel isolation is the point (Issue #28)
                self._report_error(exc)

    def _report_error(self, exc: Exception) -> None:
        """Surface one loop/render/decision failure without exiting (Issue #28).

        Must never raise itself: it only logs and appends to the bounded
        system-error buffer that the chat panel renders.
        """
        self.log.error(f"console failure: {type(exc).__name__}: {exc}")
        self.state.report_error(f"{type(exc).__name__}: {exc}")

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
        """Send one operator message; the worker picks the injection up.

        A ``send_operator_message`` failure (journal/bus fault) is reported
        to the error line instead of crashing the console (Issue #28).
        """
        if event.input.id != "chat-input":
            return
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        try:
            await self.view.send_operator_message(text)
        except Exception as exc:  # a journaling failure must not kill the console
            self._report_error(exc)
        self.state.kick()

    # ---- HITL modal (T4.3.1: modal for the operator, not for the swarm) ----

    @on(ApprovalModalOpen)
    def _open_approval_modal(self, event: ApprovalModalOpen) -> None:
        """Push the decision modal for the requested FIFO entry.

        Re-entrancy guard (F-21): at most ONE modal at a time — a double
        Enter (key repeat, or Enter racing the ~0.1 s panel refresh) used to
        stack a second modal whose later dismissal addressed an
        already-resolved request id and crashed the console.
        """
        if isinstance(self.screen, ApprovalModal):
            return
        for item in self.state.approvals:
            if item.request_id == event.request_id:
                self.push_screen(ApprovalModal(item), self._serve_decision)
                return

    async def _serve_decision(self, decision: ModalDecision | None) -> None:
        """Serve the modal decision through the facade; wake the worker.

        Failure paths degrade instead of crashing (F-21 / Issue #28): an
        unknown request id (a stale modal — the request was resolved while a
        duplicate modal lingered) re-syncs the queue with a warning toast;
        any resume/provider failure lands in the system error line.
        """
        if decision is None:
            return
        try:
            result = await self.view.submit_decision(
                decision.request_id, decision.decision, decision.edited_args
            )
            # The post-decision snapshot re-pull sits inside the same guard:
            # a transient read error must degrade to the error line, never
            # kill the console on the decision path (Issue #28 philosophy).
            if result is not None:
                self.state.absorb(result)
                await self.state.refresh()
        except ValueError as exc:
            self.notify(
                "approval already resolved — queue refreshed",
                title="Approvals",
                severity="warning",
                markup=False,
            )
            self.log.warning(f"stale approval modal: {exc}")
            await self._resync_after_stale_decision()
            return
        except Exception as exc:  # resume/provider failures keep the console up
            self._report_error(exc)
            self.state.kick()
            return
        self.refresh_panels()
        self.state.kick()

    async def _resync_after_stale_decision(self) -> None:
        """Re-pull the snapshots after a stale decision (F-21b re-sync)."""
        try:
            await self.state.refresh()
        except Exception as exc:  # even the re-sync must not kill the console
            self._report_error(exc)
        self.refresh_panels()

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
