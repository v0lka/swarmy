"""Findings & Endpoints panel: tables + the raw finding card (T4.2.3).

Data comes from ``SessionView`` (read-only ``MemoryStore`` queries). The §6.8
boundary lives HERE by design: the finding card shows **raw** values (the
pentester verifies against raw data), while the activity/chat feeds mask.
Evidence rows carry absolute paths of the raw files under ``evidence/``.

Row selection posts :class:`FindingCardRequested`; the app resolves the raw
finding + evidence paths through the facade and hands them back via
:meth:`FindingsPanel.show_card` (the attack-trees panel requests the same
message for its node → finding transition, arch §10.1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape
from rich.table import Table as RichTable
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import DataTable, Static

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.text import Text
    from textual.app import ComposeResult

    from swarmy.memory.models import Endpoint, Finding
    from swarmy.tui.state import SessionView, TuiState


class FindingCardRequested(Message):
    """A row (or tree node) asked for the raw card of one finding."""

    def __init__(self, finding_id: int) -> None:
        """Carry the requested finding id up to the app."""
        super().__init__()
        self.finding_id = finding_id


class FindingsPanel(Vertical):
    """Endpoint/finding tables on top, the raw finding card below."""

    BORDER_TITLE = "Findings & Endpoints (enter: card)"

    def __init__(self, widget_id: str, masker: Callable[[str], Text]) -> None:
        """Start with no selected finding (the card renders a hint)."""
        super().__init__(id=widget_id)
        self.masker = masker
        self.selected_finding: Finding | None = None
        self.evidence_paths: list[str] = []

    def compose(self) -> ComposeResult:
        """Two tables and the card stacked."""
        with Horizontal(id="findings-tables"):
            yield DataTable(id="endpoint-table", cursor_type="row")
            yield DataTable(id="finding-table", cursor_type="row")
        yield Static("select a finding row (enter) to open the card", id="finding-card")

    def on_mount(self) -> None:
        """One-time column setup."""
        endpoints = self.query_one("#endpoint-table", DataTable)
        endpoints.add_columns("id", "host", "method", "path", "status", "oos")
        findings = self.query_one("#finding-table", DataTable)
        findings.add_columns("id", "type", "severity", "status", "title")

    # ---- interactions ----

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Request the raw card of the selected finding row."""
        if event.data_table.id == "finding-table" and event.row_key.value is not None:
            self.post_message(FindingCardRequested(int(event.row_key.value)))

    def show_card(self, finding: Finding, evidence_paths: list[str]) -> None:
        """Render the raw card for one facade-resolved finding."""
        self.selected_finding = finding
        self.evidence_paths = evidence_paths
        self._render_card()

    # ---- rendering ----

    def refresh_state(self, state: TuiState, view: SessionView) -> None:
        """Rebuild the tables; the card re-renders against fresh evidence."""
        self._render_endpoints(state.endpoints)
        self._render_findings(state.findings)
        self._render_card()

    def _render_endpoints(self, endpoints: list[Endpoint]) -> None:
        """Fill the endpoint table (target data — shown raw per §6.8)."""
        table = self.query_one("#endpoint-table", DataTable)
        table.clear()
        for endpoint in endpoints:
            table.add_row(
                str(endpoint.id),
                self.masker(endpoint.host),
                self.masker(endpoint.method),
                self.masker(endpoint.path),
                endpoint.research_status,
                "yes" if endpoint.out_of_scope else "",
                key=str(endpoint.id),
            )

    def _render_findings(self, findings: list[Finding]) -> None:
        """Fill the finding table (titles are target data — raw)."""
        table = self.query_one("#finding-table", DataTable)
        table.clear()
        for finding in findings:
            table.add_row(
                str(finding.id),
                finding.type.value,
                finding.severity.value,
                finding.status.value,
                self.masker(finding.title),
                key=str(finding.id),
            )

    def _render_card(self) -> None:
        """Render the selected finding RAW (arch §6.8: pentester verification)."""
        card = self.query_one("#finding-card", Static)
        finding = self.selected_finding
        if finding is None:
            card.update("select a finding row (enter) to open the card")
            return
        table = RichTable(show_header=False, padding=(0, 1))
        table.add_row("[bold]finding[/]", self.masker(f"#{finding.id} {finding.title}"))
        table.add_row("[bold]class[/]", f"{finding.type.value} / {finding.severity.value}")
        table.add_row("[bold]status[/]", finding.status.value)
        if finding.endpoint_ref is not None:
            table.add_row("[bold]endpoint[/]", f"#{finding.endpoint_ref}")
        for step in finding.reproduction:
            table.add_row("[bold]step[/]", self.masker(step))
        table.add_row("[bold]description (raw)[/]", self.masker(finding.description))
        for path in self.evidence_paths:
            table.add_row("[bold]evidence[/]", escape(path))
        card.update(table)
