"""SwarmyTui: the operator console (arch §10, roadmap T4.1.2).

Layout: the six MVP panels of D10 in a 2x3 grid — Chat, Swarm Activity,
Findings & Endpoints, HITL Approvals, Attack Trees, Progress & Plans. The
session loop runs as a Textual **worker** inside the app's event loop (arch
§2.2: the core never knows about Textual): every pass serves one coalesced
state batch (feed, snapshots, panels), then drains pending runtime
injections with one orchestrator step — the step runs as a task while the
loop keeps serving batches, so a long delegation never freezes the panels.
Key bindings navigate the panels;
``ctrl+q`` checkpoints the WAL and leaves.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, ClassVar

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Input, Static, TextArea

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
    from textual.timer import Timer
    from textual.widget import Widget

    from swarmy.core.session import Session
    from swarmy.events.models import EventEnvelope

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

#: The panel-navigation digits. They stay global while no text field is
#: focused; every other printable key starts a chat message (see
#: :meth:`SwarmyTui.on_key`).
_PANEL_KEYS: frozenset[str] = frozenset("123456")

#: Spinner frames of the status bar while an orchestrator step runs. The
#: frame advances with the elapsed time, so a frozen UI (no timer ticks) is
#: itself visible — the operator can tell "waiting for the model" from a
#: hang.
_SPINNER_FRAMES: tuple[str, ...] = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


class SwarmyTui(App[None]):
    """The six-panel console over one open session (arch §10.1).

    With an ``opening_goal`` (arch §3.4) the mission starts on mount: the
    goal is journaled as the first ``OperatorMessage`` and the worker's first
    pass runs the orchestrator step — no keystrokes needed.
    """

    # Textual's default AUTO_FOCUS="*" lands on the Chat panel's RichLog
    # (the first focusable widget in the DOM). That is deliberate here: the
    # global digit bindings must stay usable, and on_key routes every other
    # printable key into the chat input so the operator can type the opening
    # goal without first hunting for the input.
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
    #status-bar { height: 1; padding: 0 1; background: $panel-lighten-1; }
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

    def __init__(self, session: Session, *, opening_goal: str | None = None) -> None:
        """Bind one OPEN session (composition stays with open/resume).

        ``opening_goal`` — the mission goal from a goal file (arch §3.4). On
        mount the console journals it as the first ``OperatorMessage`` — the
        same path as a typed message — so the mission starts by itself
        instead of waiting for the operator to type the goal.
        """
        super().__init__()
        self.view = SessionView(session)
        self.state = TuiState(self.view)
        self.opening_goal = opening_goal
        # Status bar bookkeeping: the timer repaints on change only, and the
        # completion toast fires once per finished turn (no toast storm).
        self._status_timer: Timer | None = None
        self._last_status: str = ""
        self._notified_turns: int = 0

    # ---- layout ----

    def compose(self) -> ComposeResult:
        """The 2x3 panel grid of arch §10.1 plus the global status bar."""
        with Horizontal(id="panels"):
            yield ChatPanel("panel-chat", self.view.display)
            yield ActivityPanel("panel-activity", self.view.display)
            yield FindingsPanel("panel-findings", self.view.display)
            yield ApprovalsPanel("panel-approvals", self.view.display)
            yield TreesPanel("panel-trees", self.view.display)
            yield PlansPanel("panel-plans")
        yield Static("", id="status-bar", markup=False)

    async def on_mount(self) -> None:
        """Subscribe the state, preload the journal, start the worker, send the goal."""
        self.state.start()
        await self.state.preload()
        self.refresh_panels()
        # The status bar is the liveness/completion signal (arch §10.1): a
        # 0.2 s tick advances the spinner and the elapsed/last-event ages even
        # when no bus event arrives — exactly the "is it frozen or waiting
        # for the model?" question. The repaint is skipped when the text is
        # unchanged (Issue #33: no idle churn).
        self._status_timer = self.set_interval(0.2, self._refresh_status_bar)
        self._refresh_status_bar()
        # The worker starts BEFORE the opening goal is journaled on purpose:
        # the goal then reaches the feed through the ordinary bus path (its
        # dispatcher wakes the waiting worker with a real batch). Started
        # after the send, the worker's first ``wait_batch`` saw the wake flag
        # pre-set by ``kick()`` with the envelope still in the dispatcher's
        # queue — an empty batch, the "Type your goal" hint on screen and a
        # jump straight into the (minutes-long) first step with the goal
        # unserved: the "panels open, nothing happens" report.
        self.run_session_loop()
        await self._send_opening_goal()

    async def _send_opening_goal(self) -> None:
        """Journal the goal-file goal as the first operator message (arch §3.4).

        Same route as a typed message (:meth:`_send_chat`): the platform
        journals ``OperatorMessage`` and queues the injection, and the
        worker's first pass drains it into an orchestrator step. A journaling
        failure degrades to the error line (Issue #28 philosophy): the console
        stays up and the operator can still type the goal in the chat.
        """
        if not self.opening_goal:
            return
        try:
            await self.view.send_operator_message(self.opening_goal)
        except Exception as exc:  # a journaling failure must not kill the console
            self._report_error(exc)
            return
        self.state.kick()
        self._refresh_status_bar()

    # ---- the session worker (arch §10.1: workers inside the Textual loop) ----

    def run_session_loop(self) -> None:
        """Start the session-loop worker (separate method for test seams)."""
        self._session_worker()

    @work(exclusive=True)
    async def _session_worker(self) -> None:
        """Serve coalesced batches; drain runtime injections step by step.

        One orchestrator step at a time, run as a task (:meth:`_run_step`) so
        the loop keeps serving bus batches while the graph works: a ``task()``
        delegation runs inside the graph invocation and can take minutes, and
        awaiting it directly froze every panel for that time while the journal
        kept growing — the "panels open, nothing happens" trap of the goal-file
        auto-start. The step task stays the single writer (AD-8): no second
        step starts before the previous one completed.

        Every await in the loop is guarded (Issue #28): one failed pass — a
        provider hiccup on ``run_step``, a journal decode or render error —
        is reported as a system line in the chat feed and the loop continues;
        the worker used to be a bare ``while True`` whose first exception
        exited the whole console. Idle poll ticks (no batch, no dirty types,
        no injections) skip the panel re-render entirely (Issue #33: the
        console used to re-render all six panels ~10x/s even when nothing
        happened).
        """
        while True:
            try:
                batch = await self.state.wait_batch(poll_after=0.1)
                dirty = self.state.take_dirty()
                if batch or dirty:
                    await self._serve_batch(batch, dirty)
                while self.view.pending_injections() > 0:
                    result = await self._run_step()
                    self.state.absorb(result)
                    await self.state.refresh()
                    self.refresh_panels()
                self._refresh_status_bar()  # completion reaches the bar without waiting for the tick
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # one failed pass must not kill the TUI
                self._report_error(exc)
                self.refresh_panels()  # the new system> line must reach the chat
                await asyncio.sleep(0.5)  # back off before the retry pass

    async def _serve_batch(self, batch: list[EventEnvelope], dirty: set[str]) -> None:
        """Fold one coalesced batch into the feed/snapshots and repaint.

        ``dirty`` is the type set of exactly this batch (``take_dirty`` is
        read right after the drain, with no await in between — arch §5.3:
        nothing is lost, only redundant redraws collapse).
        """
        if batch:
            self.state.extend_feed(batch)  # coalescing: nothing is lost
        if batch or self.state.needs_snapshot(dirty):
            await self.state.refresh()
        self.refresh_panels()

    async def _run_step(self) -> object:
        """Run one orchestrator step as a task while the loop keeps serving batches.

        While the step works, every batch the bus dispatcher delivers is folded
        into the feed (the non-blocking :meth:`TuiState.drain_pending`) so the
        Activity/Findings panels show the swarm's progress as it happens
        instead of after the step. The result — or the step's exception — is
        returned exactly as ``view.run_step`` would; a worker cancellation
        takes the step task down with it.
        """
        step = asyncio.create_task(self.view.run_step())
        self.state.step_started()  # status bar: the model/tools are working
        try:
            while True:
                done, _ = await asyncio.wait({step}, timeout=0.1)
                late = self.state.drain_pending()
                if late:
                    await self._serve_batch(late, self.state.take_dirty())
                if done:
                    return step.result()
        finally:
            if not step.done():
                step.cancel()
            # A cancelled or failed step is not a completed turn — the
            # operator must not see "turn complete" for aborted work.
            completed = step.done() and not step.cancelled() and step.exception() is None
            self.state.step_finished(completed=completed)

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

    # ---- status bar (liveness / completion, arch §10.1) ----

    def _status_text(self) -> str:
        """The current status line: working, approval, queued, complete or idle.

        The working state carries a spinner frame, the elapsed step time and
        the age of the last folded event — the operator can distinguish
        "waiting for the model" from a frozen console. The completion states
        are persistent (the bar stays visible after the toast is gone).
        """
        state = self.state
        if state.step_active:
            elapsed = state.step_elapsed()
            frame = _SPINNER_FRAMES[int(elapsed * 8) % len(_SPINNER_FRAMES)]
            age = state.last_event_age()
            last = f" • last event {age:.0f}s ago" if age is not None else ""
            return f"{frame} orchestrator working… {elapsed:.0f}s{last}"
        if state.approvals:
            return (
                f"⏸ waiting for operator approval — "
                f"{len(state.approvals)} in the HITL queue"
            )
        pending = self.view.pending_injections()
        if pending:
            return f"… queued {pending} — starting…"
        if state.todos and all(todo.status == "completed" for todo in state.todos):
            return "✓ plan complete — idle (type a message to continue; ctrl+q quits)"
        if state.turns_completed:
            return "✓ turn complete — idle (type a message to continue; ctrl+q quits)"
        return (
            "idle — type a goal in Chat to start the mission "
            "(keys 1-6 switch panels; ctrl+q quits)"
        )

    def _refresh_status_bar(self) -> None:
        """Repaint the status bar when its text changed; check for completion."""
        try:
            text = self._status_text()
            if text != self._last_status:
                self.query_one("#status-bar", Static).update(text)
                self._last_status = text
            self._maybe_notify_completion()
        except Exception as exc:  # the status bar must never break the console
            self.log.warning(f"status bar refresh failed: {type(exc).__name__}: {exc}")

    def _maybe_notify_completion(self) -> None:
        """One toast per finished turn that leaves nothing pending."""
        state = self.state
        if state.step_active or state.approvals or self.view.pending_injections() > 0:
            return
        if state.turns_completed > self._notified_turns:
            self._notified_turns = state.turns_completed
            self.notify(
                "Orchestrator turn complete — nothing pending",
                title="Session",
                severity="information",
                timeout=5,
            )

    # ---- navigation ----

    def action_panel(self, index: str) -> None:
        """Focus panel ``index`` (1..6, the D10 grid order)."""
        target = _FOCUS_TARGETS.get(int(index))
        if target is None:
            return
        widget: Widget = self.query_one(target)
        self.set_focus(widget)

    async def on_key(self, event: events.Key) -> None:
        """Start a chat message from any printable key except panel digits.

        The console opens with the Chat ``RichLog`` focused so the global
        ``1``-``6`` panel bindings stay live. Every other printable key is
        routed into the chat input: the operator can type the opening goal
        without first clicking the input (the "panels open but nothing
        happens" trap). Digits remain navigation until the input is focused;
        afterwards they are ordinary text.
        """
        if len(self.screen_stack) > 1:
            return  # a modal owns the keyboard
        if isinstance(self.focused, (Input, TextArea)):
            return  # already typing in a text field
        if not event.is_printable or event.character is None:
            return
        if event.key in _PANEL_KEYS:
            return
        event.stop()
        chat_input = self.query_one("#chat-input", Input)
        chat_input.focus()
        chat_input.insert_text_at_cursor(event.character)

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
        self._refresh_status_bar()

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
                self.push_screen(ApprovalModal(item, self.view.display), self._serve_decision)
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
        completed = False
        self.state.step_started()  # resuming the interrupt is graph work too
        try:
            result = await self.view.submit_decision(
                decision.request_id, decision.decision, decision.edited_args
            )
            completed = result is not None
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
        finally:
            self.state.step_finished(completed=completed)
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
        if self._status_timer is not None:
            self._status_timer.stop()
            self._status_timer = None
        self.state.stop()
        await self.view.close()
        self.exit()
