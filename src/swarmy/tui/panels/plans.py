"""Progress & Plans panel: orchestrator todos + session statistics (T4.2.4).

Todos are the L0 state projection (``TuiState.absorb`` duck-types the step
result); the statistics reconcile memory + journal through the facade:
endpoints by research status, findings by class/severity/status. When the
orchestrator has not written todos yet, the left column shows the **live
delegation plan** from the journal's ``TaskRequested``/``TaskCompleted``
pairs — the panel must never look idle while the swarm works.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape
from rich.table import Table as RichTable
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from swarmy.memory.models import FindingStatus

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from swarmy.tui.state import DelegationItem, SessionView, TodoItem, TuiState

_STATUS_MARK: dict[str, str] = {
    "pending": "[ ]",
    "in_progress": "[~]",
    "completed": "[x]",
}


class PlansPanel(Vertical):
    """Todos of the orchestrator on the left, session statistics on the right."""

    BORDER_TITLE = "Progress & Plans"

    def __init__(self, widget_id: str) -> None:
        """Bind the grid cell id (rendering reads the snapshot caches)."""
        super().__init__(id=widget_id)

    def compose(self) -> ComposeResult:
        """Two statics side by side."""
        with Horizontal(id="plans-row"):
            yield Static("no todos yet", id="plans-todos")
            yield Static("no data yet", id="plans-stats")

    def refresh_state(self, state: TuiState, view: SessionView) -> None:
        """Re-render the progress column and statistics from the snapshot caches."""
        del view  # snapshots only; the facade is unused at render time
        todos = self.query_one("#plans-todos", Static)
        todos.update(self._progress_table(state))
        stats = self.query_one("#plans-stats", Static)
        stats.update(self._stats_table(state))

    @staticmethod
    def _progress_table(state: TuiState) -> RichTable:
        """Todos when the orchestrator wrote them; otherwise live delegations."""
        if state.todos:
            return PlansPanel._todos_table(state.todos)
        return PlansPanel._delegations_table(state.delegations())

    @staticmethod
    def _todos_table(todos: list[TodoItem]) -> RichTable:
        """The orchestrator todo list (L0 state projection)."""
        table = RichTable(show_header=False, padding=(0, 1), title="todos")
        if not todos:
            table.add_row("[dim]no todos yet[/]")
            return table
        for todo in todos:
            mark = _STATUS_MARK.get(todo.status, "[?]")
            table.add_row(mark, escape(todo.content))
        return table

    @staticmethod
    def _delegations_table(delegations: list[DelegationItem]) -> RichTable:
        """The live delegation plan (running/completed/failed) when no todos exist."""
        table = RichTable(show_header=False, padding=(0, 1), title="live delegations")
        if not delegations:
            table.add_row("[dim]no todos or delegations yet[/]")
            return table
        for item in delegations:
            mark = {
                "completed": "[green]✓[/]",
                "failed": "[red]✗[/]",
            }.get(item.status, "[yellow]▶[/]")
            table.add_row(
                mark,
                escape(item.subagent),
                escape(item.status),
                item.correlation_id[:8],
            )
        return table

    @staticmethod
    def _stats_table(state: TuiState) -> RichTable:
        """Session statistics reconciled against the memory snapshots."""
        table = RichTable(show_header=True, padding=(0, 1), title="session")
        table.add_column("metric")
        table.add_column("value", justify="right")
        by_status: dict[str, int] = {}
        for endpoint in state.endpoints:
            key = endpoint.research_status
            by_status[key] = by_status.get(key, 0) + 1
        rendered = ", ".join(f"{key}: {count}" for key, count in sorted(by_status.items()))
        table.add_row("endpoints", rendered or "—")
        table.add_row("endpoints out of scope", str(sum(1 for e in state.endpoints if e.out_of_scope)))
        by_severity: dict[str, int] = {}
        verified = 0
        for finding in state.findings:
            key = finding.severity.value
            by_severity[key] = by_severity.get(key, 0) + 1
            if finding.status == FindingStatus.VERIFIED:
                verified += 1
        rendered = ", ".join(f"{key}: {count}" for key, count in sorted(by_severity.items()))
        table.add_row("findings", rendered or "—")
        table.add_row("findings verified", str(verified))
        delegations = state.delegations()
        table.add_row(
            "delegations",
            "running: {}, completed: {}, failed: {}".format(
                sum(1 for item in delegations if item.status == "running"),
                sum(1 for item in delegations if item.status == "completed"),
                sum(1 for item in delegations if item.status == "failed"),
            ),
        )
        table.add_row("journal events (session)", str(state.event_count))
        return table
