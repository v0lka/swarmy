"""HITL Approvals panel + decision modal (arch §10.3, T4.3.1).

The panel shows the visible FIFO of pending requests (tool, sanitized
``args_digest``, active rule/profile, gate origin: profile / module / judge
/ mode). The modal serves one request with ``approve`` / ``reject`` /
``edit`` (JSON form for the edited arguments — validated before submit).
The modal is modal **for the operator only**: it never blocks the swarm —
decisions go through ``SessionView.submit_decision``, which resumes exactly
one interrupt while other delegations keep running (arch §7.3).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator
from rich.markup import escape
from rich.text import Text
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Static, TextArea

from swarmy.tui.state import ApprovalChoice

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult

    from swarmy.tui.state import ApprovalItem, SessionView, TuiState


def _is_json_value(value: object) -> bool:
    """Whether ``value`` is a JSON-shaped scalar or nested value (recursive).

    The recursive JSON shape mirrors :data:`swarmy.events.models.JsonValue`
    (Issue #45: gated calls routinely hold nested arguments — ``http_post``'s
    ``headers`` dict, ``evidence_refs`` lists). A plain recursive alias can
    be used in annotations only; pydantic cannot resolve it (schema
    generation recurses forever), so the shape is enforced by this explicit
    check — values stay PLAIN json.loads output because edited arguments
    ride the L0 resume payload as real tool arguments.
    """
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if item is None or isinstance(item, (str, bool, int, float)):
            continue
        if isinstance(item, list):
            stack.extend(item)
            continue
        if isinstance(item, dict):
            stack.extend(item.values())
            continue
        return False
    return True


class ModalDecision(BaseModel):
    """One operator decision leaving the modal (UI boundary model, D9)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    decision: ApprovalChoice
    edited_args: dict[str, object] | None = None

    @field_validator("edited_args")
    @classmethod
    def _edited_args_are_json(
        cls, value: dict[str, object] | None
    ) -> dict[str, object] | None:
        """Enforce the recursive JSON shape on every edited argument."""
        if value is not None and not all(_is_json_value(item) for item in value.values()):
            raise ValueError("edited args must be JSON values (scalars, lists, objects)")
        return value


class ApprovalModalOpen(Message):
    """The panel asks the app to open the modal for one request id."""

    def __init__(self, request_id: str) -> None:
        """Carry the request id up to the app."""
        super().__init__()
        self.request_id = request_id


class ApprovalsPanel(Vertical):
    """The visible FIFO approval queue (arch §10.1/§10.3)."""

    BORDER_TITLE = "HITL Approvals (enter: decide)"

    def __init__(self, widget_id: str, render_text: Callable[[str], Text]) -> None:
        """Bind the grid cell id and the §6.8 display renderer."""
        super().__init__(id=widget_id)
        self.render_text = render_text

    def compose(self) -> ComposeResult:
        """One table over the pending requests."""
        yield DataTable(id="approval-table", cursor_type="row")

    def on_mount(self) -> None:
        """One-time column setup."""
        self.query_one("#approval-table", DataTable).add_columns(
            "request", "tool", "origin", "rule/profile", "args (sanitized)"
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Serve the selected request through the modal."""
        if event.data_table.id == "approval-table" and event.row_key.value is not None:
            self.post_message(ApprovalModalOpen(event.row_key.value))

    def refresh_state(self, state: TuiState, view: SessionView) -> None:
        """Re-render the FIFO from the snapshot cache (digests already sanitized)."""
        del view  # the snapshot cache carries the approvals; facade unused here
        table = self.query_one("#approval-table", DataTable)
        table.clear()
        for item in state.approvals:
            table.add_row(
                item.request_id,
                escape(item.tool),
                escape(item.origin),
                escape(item.rule_or_profile),
                self.render_text(item.args_digest),
                key=item.request_id,
            )
        count = len(state.approvals)
        self.border_title = (
            "HITL Approvals — FIFO empty (enter: decide)"
            if count == 0
            else f"HITL Approvals — {count} pending (enter: decide)"
        )


class ApprovalModal(ModalScreen[ModalDecision]):
    """Modal decision form for ONE approval request (§10.3).

    Shows the tool, the sanitized ``args_digest``, the active rule/profile
    and the gate origin; ``edit`` reveals a JSON form validated before the
    decision leaves the screen (invalid JSON keeps the modal open).
    """

    CSS = """
    ApprovalModal { align: center middle; }
    #approval-dialog { width: 72; height: auto; padding: 1 2; border: round grey; }
    #approval-details { margin-bottom: 1; }
    #approval-edit-area { height: 10; display: none; }
    #approval-edit-area.visible { display: block; }
    #approval-buttons { height: auto; margin-top: 1; }
    #approval-buttons > Button { margin-right: 1; }
    """

    def __init__(self, item: ApprovalItem, render_text: Callable[[str], Text]) -> None:
        """Bind the request under decision and the §6.8 display renderer."""
        super().__init__()
        self.item = item
        self.render_text = render_text

    def compose(self) -> ComposeResult:
        """Details, hidden edit form, decision buttons, error line."""
        with Vertical(id="approval-dialog"):
            yield Static(self._details_markup(), id="approval-details", markup=True)
            with Vertical(id="approval-edit-area"):
                yield TextArea("", id="approval-edit-args")
            with Horizontal(id="approval-buttons"):
                yield Button("Approve", id="btn-approve", variant="success")
                yield Button("Edit", id="btn-edit", variant="warning")
                yield Button("Reject", id="btn-reject", variant="error")
                yield Button("Save edit", id="btn-edit-save", variant="primary")
                yield Button("Cancel", id="btn-cancel")
            yield Static("", id="approval-error")

    def _details_markup(self) -> Text:
        """The §10.3 detail block (all content already sanitized upstream)."""
        item = self.item
        text = Text()
        text.append("tool ", style="bold")
        text.append(self.render_text(item.tool))
        text.append("    request ", style="bold")
        text.append(item.request_id)
        text.append("\ngate ", style="bold")
        text.append(self.render_text(item.origin))
        text.append("    rule/profile ", style="bold")
        text.append(self.render_text(item.rule_or_profile))
        text.append("\nargs (sanitized)\n", style="bold")
        text.append(self.render_text(item.args_digest))
        return text

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dispatch the pressed decision button."""
        button_id = event.button.id or ""
        if button_id == "btn-approve":
            self.dismiss(ModalDecision(request_id=self.item.request_id, decision="approve"))
        elif button_id == "btn-reject":
            self.dismiss(ModalDecision(request_id=self.item.request_id, decision="reject"))
        elif button_id == "btn-edit":
            self._show_edit_form()
        elif button_id == "btn-edit-save":
            self._submit_edit()
        elif button_id == "btn-cancel":
            self.dismiss(None)

    def _show_edit_form(self) -> None:
        """Reveal the JSON form prefilled from the sanitized digest (best effort)."""
        area = self.query_one("#approval-edit-area")
        area.add_class("visible")
        editor = self.query_one("#approval-edit-args", TextArea)
        editor.text = self._prefill_json()
        self._set_error("")

    def _prefill_json(self) -> str:
        """The sanitized digest as editable JSON (``{}`` when it is not one)."""
        try:
            parsed = json.loads(self.item.args_digest)
        except (json.JSONDecodeError, TypeError):
            return "{}"
        if isinstance(parsed, dict):
            return json.dumps(parsed, indent=2)
        return "{}"

    def _submit_edit(self) -> None:
        """Validate the edited JSON object; invalid input keeps the modal open."""
        editor = self.query_one("#approval-edit-args", TextArea)
        try:
            parsed: object = json.loads(editor.text)
        except json.JSONDecodeError as exc:
            self._set_error(f"edited args are not valid JSON: {exc.msg}")
            return
        if not isinstance(parsed, dict):
            self._set_error("edited args must be a JSON object of tool arguments")
            return
        try:
            decision = ModalDecision(
                request_id=self.item.request_id,
                decision="edit",
                edited_args={str(key): value for key, value in parsed.items()},
            )
        except ValidationError:  # pragma: no cover - defensive: JSON fits JsonValue
            self._set_error("edited args failed decision validation")
            return
        self.dismiss(decision)

    def _set_error(self, message: str) -> None:
        """Render the validation error line (empty clears it)."""
        error = self.query_one("#approval-error", Static)
        error.update(f"[red]{escape(message)}[/]" if message else "")
