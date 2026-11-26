"""Chat panel: the operator ↔ orchestrator dialog (arch §10.1, T4.2.1).

Sources: ``OperatorMessage`` envelopes from the journal and the live
orchestrator reply of each graph step. Sending routes through the facade
(``SessionView.send_operator_message`` → platform ``OperatorMessage`` in the
journal → runtime interactive contour). Switching the inspection target to a
subagent shows that delegation's **sanitized** transcript (§6.8 masking
applied at render time — the §10.1 raw-values rule does not extend to the
chat feed).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape
from textual.containers import Vertical
from textual.widgets import Input, RichLog

from swarmy.events.models import OperatorMessagePayload

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult

    from swarmy.tui.state import SessionView, TuiState


class ChatPanel(Vertical):
    """Transcript (journaled operator messages + orchestrator replies) + input.

    The inspection target cycles with ``ctrl+t``: orchestrator transcript
    first, then one sanitized snapshot per subagent seen in the session.
    """

    BORDER_TITLE = "Chat (ctrl+t: inspect subagent)"

    def __init__(self, widget_id: str, masker: Callable[[str], str]) -> None:
        """Start on the orchestrator transcript with an empty history.

        ``masker`` is the §6.8 projection applied to every rendered line —
        secrets never reach the transcript, target data passes untouched.
        """
        super().__init__(id=widget_id)
        self.masker = masker
        self.target = "orchestrator"
        self._known_targets: tuple[str, ...] = ("orchestrator",)

    def compose(self) -> ComposeResult:
        """The transcript log and the operator input line."""
        yield RichLog(id="chat-log", markup=True, wrap=True, highlight=False)
        yield Input(placeholder="Message the orchestrator…", id="chat-input")

    @property
    def log_widget(self) -> RichLog:
        """The transcript widget."""
        return self.query_one("#chat-log", RichLog)

    @property
    def input_widget(self) -> Input:
        """The operator input widget."""
        return self.query_one("#chat-input", Input)

    def cycle_target(self, state: TuiState) -> str:
        """Switch inspection to the next transcript source (orchestrator → agents)."""
        live = ("orchestrator", *sorted(state.subagent_transcripts))
        self._known_targets = live
        if self.target not in live:
            self.target = "orchestrator"
        index = live.index(self.target)
        self.target = live[(index + 1) % len(live)]
        self.border_title = f"Chat — inspecting: {escape(self.target)}"
        return self.target

    def refresh_state(self, state: TuiState, view: SessionView) -> None:
        """Re-render the transcript of the current inspection target (masked)."""
        del view  # masking goes through the panel masker; the facade is unused
        log = self.log_widget
        log.clear()
        for role, text in self._lines(state):
            log.write(f"[bold cyan]{escape(role)}[/] {escape(self.masker(text))}")
        if self.target != "orchestrator" and not state.subagent_transcripts:
            log.write("[dim]no delegation transcript yet[/]")

    def _lines(self, state: TuiState) -> list[tuple[str, str]]:
        """(role, raw text) pairs for the current target; masking happens outside."""
        if self.target != "orchestrator":
            return [
                ("subagent>", entry)
                for entry in state.subagent_transcripts.get(self.target, ())
            ]
        lines: list[tuple[str, str]] = []
        for envelope in state.feed:
            if envelope.type == "OperatorMessage":
                payload = envelope.payload
                digest = (
                    payload.text_digest
                    if isinstance(payload, OperatorMessagePayload)
                    else str(payload)
                )
                lines.append(("operator>", digest))
        if state.replies:
            # Issue #47: the transcript keeps the whole orchestrator dialog
            # (bounded by TuiState.replies), not only the latest reply.
            for reply in state.replies:
                lines.append(("orchestrator>", reply))
        elif state.last_reply:
            lines.append(("orchestrator>", state.last_reply))
        for error in state.system_errors:
            lines.append(("system>", error))
        return lines
