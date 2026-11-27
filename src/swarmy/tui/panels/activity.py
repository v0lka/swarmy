"""Swarm Activity panel: live feed, delegation table, queue status (T4.2.2).

The feed rides the coalescing ``TuiState`` subscription (§5.3): lines are
appended per batch — nothing lost, one render per coalesced group. The
delegation table mirrors the journal's ``TaskRequested``/``TaskCompleted``
pairs by ``correlation_id``; every line passes through the §6.8 masker.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape
from textual.containers import Vertical
from textual.widgets import DataTable, RichLog, Static

from swarmy.events.models import TaskCompletedPayload, TaskRequestedPayload

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.text import Text
    from textual.app import ComposeResult

    from swarmy.events.models import EventEnvelope
    from swarmy.tui.state import SessionView, TuiState

_FEED_LIMIT: int = 400


class ActivityPanel(Vertical):
    """Live event feed + ``task()`` delegation overview + approvals status."""

    BORDER_TITLE = "Swarm Activity"

    def __init__(self, widget_id: str, masker: Callable[[str], Text]) -> None:
        """Bind the grid cell id and the §6.8 display renderer."""
        super().__init__(id=widget_id)
        self.masker = masker

    def compose(self) -> ComposeResult:
        """Feed log on top, delegation table below, queue status line last."""
        yield RichLog(id="activity-log", markup=True, wrap=True, highlight=False)
        yield DataTable(id="delegation-table", cursor_type="row")
        yield Static("", id="approvals-status")

    def on_mount(self) -> None:
        """One-time column setup of the delegation table."""
        table = self.query_one("#delegation-table", DataTable)
        table.add_columns("correlation", "subagent", "status", "summary")

    def refresh_state(self, state: TuiState, view: SessionView) -> None:
        """Re-render feed, delegations, and the approvals status (all masked)."""
        del view  # masking goes through the panel masker; the facade is unused
        log = self.query_one("#activity-log", RichLog)
        log.clear()
        for envelope in state.recent_feed(_FEED_LIMIT):
            log.write(self.masker(self._feed_line(envelope)))
        self._refresh_delegations(state)
        self._refresh_status(state)

    def _feed_line(self, envelope: EventEnvelope) -> str:
        """One masked-ready feed line for an envelope."""
        return (
            f"#{envelope.id} {envelope.type}"
            f" [{envelope.source.value}/{envelope.source_detail}]"
            f" {envelope.payload.model_dump(mode='json')}"
        )

    def _refresh_delegations(self, state: TuiState) -> None:
        """Mirror the journal's TaskRequested/TaskCompleted pairs by cid."""
        table = self.query_one("#delegation-table", DataTable)
        table.clear()
        requested: dict[str, tuple[str, str, str]] = {}
        for envelope in state.feed:
            payload = envelope.payload
            if isinstance(payload, TaskRequestedPayload):
                requested[payload.correlation_id] = (
                    payload.subagent,
                    payload.status,
                    payload.summary_digest,
                )
        completed: dict[str, TaskCompletedPayload] = {}
        for envelope in state.feed:
            payload = envelope.payload
            if isinstance(payload, TaskCompletedPayload):
                completed[payload.correlation_id] = payload
        for cid, (subagent, _status, summary) in requested.items():
            done = completed.get(cid)
            status = done.status if done is not None else "running"
            digest = done.summary_digest if done is not None else summary
            table.add_row(
                cid[:8],
                escape(subagent),
                escape(status),
                self.masker(digest),
                key=cid,
            )

    def _refresh_status(self, state: TuiState) -> None:
        """One-line approvals queue status (FIFO length, arch §10.1)."""
        status = self.query_one("#approvals-status", Static)
        count = len(state.approvals)
        if count == 0:
            status.update("approvals queue: empty")
        else:
            head = state.approvals[0]
            status.update(
                f"approvals queue: [bold]{count}[/] pending; head: "
                f"{escape(head.tool)} ({escape(head.origin)})"
            )
