"""SessionView facade and TuiState (arch §10.2, roadmap T4.1.1).

``SessionView`` is the ONLY window the operator console has into the core:
read-only queries (memory, statuses, the approvals queue, the journal tail)
plus the operator actions that must go through the platform (chat messages,
HITL decisions, session close). Panels never touch ``MemoryStore``,
``EventBus`` or ``OrchestratorRuntime`` — arch §2.5: ``swarmy.tui`` imports
``swarmy.core.session`` (the facade's subject), ``swarmy.events.models`` and
the ``swarmy.memory.models`` leaf only.

``TuiState`` is the single owner of UI state: one ``EventBus`` subscription
with a **coalescing** queue (arch §5.3 — updates merge, no event is ever
dropped, only redundant redraws are) and a snapshot cache the panels pull
from. The coalescing contract: every appended envelope lands in the pending
batch (nothing lost); one consumer wake serves the whole batch at once.

The graph-result readers (:func:`orchestrator_reply`,
:func:`orchestrator_todos`, :func:`delegation_transcripts`) are duck-typed
on purpose: the result object comes from the L0 graph, and the TUI must not
import the L0 stack (arch §2.5) — plain structural checks only.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Final, Literal, TypeAlias, TypeVar, cast

from pydantic import BaseModel, ConfigDict

from swarmy.memory.models import EntityType, Evidence

if TYPE_CHECKING:
    from pathlib import Path

    from swarmy.core.session import Session
    from swarmy.events.bus import EventBus
    from swarmy.events.models import EventEnvelope
    from swarmy.memory.models import (
        AttackEdge,
        AttackNode,
        Endpoint,
        Finding,
    )

_T = TypeVar("_T")

#: Operator decisions served to the HITL queue (arch §7.2-§7.3 shape).
ApprovalChoice: TypeAlias = Literal["approve", "edit", "reject"]

#: Types whose arrival invalidates the memory snapshots (§5.5 taxonomy).
_SNAPSHOT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "EndpointsDiscovered",
        "EndpointUpdated",
        "FindingCandidate",
        "FindingVerified",
        "FindingRejected",
        "AttackTreeUpdated",
        "ScopeChanged",
    }
)

#: Default size of the bounded feed window (Issue #33: ``feed`` used to grow
#: without bound over a long session).
FEED_MAX: Final[int] = 1000

#: Bounded buffer of worker/decision error lines surfaced in the chat feed
#: (Issue #28 degradation path).
SYSTEM_ERRORS_MAX: Final[int] = 20

#: Bounded history of orchestrator replies rendered by the chat panel
#: (Issue #47: only the latest reply used to survive; the transcript must
#: keep the whole dialog, bounded like the feed window).
REPLIES_MAX: Final[int] = 200


class ApprovalItem(BaseModel):
    """One operator-facing approval row (the facade projection of §7.3).

    Built by :meth:`SessionView.pending_approvals` so panels never see the
    internal queue types — only this Pydantic model (D9 boundary).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    interrupt_id: str
    tool: str
    args_digest: str
    rule_or_profile: str
    origin: str


class TodoItem(BaseModel):
    """One orchestrator todo (the L0 state projection for Progress & Plans)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    status: str


class UiSubscription:
    """Stop-handle for a facade subscription (bus types stay internal)."""

    __slots__ = ("_stop",)

    def __init__(self, stop: Callable[[], None]) -> None:
        """Bind the unsubscribe callable captured from the bus handle."""
        self._stop = stop

    def unsubscribe(self) -> None:
        """Cancel this subscription; no further events are delivered."""
        self._stop()


def _require(component: _T | None) -> _T:
    """Non-null view of a composed component (types flow from ``Session``).

    The concrete classes stay unimported here on purpose (arch §2.5 allow-
    list): the annotations of :class:`~swarmy.core.session.Session` carry
    them, so inference types every call site without a single import.
    """
    if component is None:  # pragma: no cover - composed sessions have all
        raise RuntimeError("session component accessed before composition")
    return component


class SessionView:
    """Read-only facade over one open :class:`~swarmy.core.session.Session`.

    The console reads memory/statuses through this object only; the operator
    actions (chat message, HITL decision, close) route through the platform
    so every write is journaled exactly like a headless step (arch §10.3).
    """

    def __init__(self, session: Session) -> None:
        """Bind the open session (composition stays with open/resume)."""
        self._session = session

    @property
    def session(self) -> Session:
        """The underlying session (lifecycle ownership for the CLI/tests)."""
        return self._session

    # ---- subscriptions / masking ----

    def subscribe(
        self,
        handler: Callable[[EventEnvelope], Awaitable[None]],
        types: set[str] | None = None,
    ) -> UiSubscription:
        """Subscribe a UI handler to the session bus (arch §5.3 fan-out)."""
        bus: EventBus | None = _require(self._session.bus)
        subscription = bus.subscribe(handler, types)
        return UiSubscription(subscription.unsubscribe)

    def mask(self, text: str) -> str:
        """Project one display text through the §6.8 sanitizer (masked feeds)."""
        return _require(self._session.projector).project(text)

    # ---- read-only memory queries (raw values — finding cards, §6.8) ----

    async def endpoints(self) -> list[Endpoint]:
        """All endpoints (raw), ascending by id."""
        return await _require(self._session.memory).list_endpoints()

    async def findings(self) -> list[Finding]:
        """All findings (raw), ascending by id."""
        return await _require(self._session.memory).list_findings()

    async def finding(self, finding_id: int) -> Finding:
        """One finding (raw) by id; ``KeyError`` when missing."""
        found = await _require(self._session.memory).get(EntityType.FINDING, finding_id)
        return cast("Finding", found)

    async def evidence(self, evidence_refs: Sequence[int]) -> list[Evidence]:
        """Evidence rows (raw pointers) for the given refs, in ref order."""
        memory = _require(self._session.memory)
        rows: list[Evidence] = []
        for ref in evidence_refs:
            rows.append(cast("Evidence", await memory.get(EntityType.EVIDENCE, ref)))
        return rows

    async def evidence_paths(self, evidence_refs: Sequence[int]) -> list[str]:
        """Absolute paths of the raw evidence files (cards open them)."""
        session_dir: Path = self._session.session_dir
        return [
            str(session_dir / relative)
            for row in await self.evidence(evidence_refs)
            for relative in row.session_paths
        ]

    async def attack_nodes(self) -> list[AttackNode]:
        """All attack-tree nodes (raw), ascending by id."""
        return await _require(self._session.memory).list_attack_nodes()

    async def attack_edges(self) -> list[AttackEdge]:
        """All attack-tree edges (raw), ascending by id."""
        return await _require(self._session.memory).list_attack_edges()

    async def journal_tail(self, n: int = 200) -> list[EventEnvelope]:
        """The last ``n`` journal envelopes, ascending (session open)."""
        return await _require(self._session.reader).tail(n)

    # ---- HITL (§10.3) ----

    def pending_approvals(self) -> tuple[ApprovalItem, ...]:
        """The visible FIFO of approval requests awaiting a decision."""
        queue = _require(self._session.approvals)
        return tuple(
            ApprovalItem(
                request_id=request.request_id,
                interrupt_id=request.interrupt_id,
                tool=request.tool,
                args_digest=request.args_digest,
                rule_or_profile=request.rule_or_profile,
                origin=str(request.origin),
            )
            for request in queue.pending()
        )

    async def submit_decision(
        self,
        request_id: str,
        decision: ApprovalChoice,
        edited_args: Mapping[str, object] | None = None,
    ) -> object:
        """Serve one operator decision through the queue/runtime (§7.3-§7.4).

        The queue journals the ``OperatorDecision``; interrupt-backed
        requests resume their graph interrupt (the swarm's other work is not
        blocked — the single-writer lock merely serializes graph calls).
        """
        return await _require(self._session.runtime).submit_decision(
            request_id, decision, edited_args
        )

    # ---- operator actions / session loop (arch §9.2, §10.3) ----

    async def send_operator_message(self, text: str) -> None:
        """Journal an ``OperatorMessage`` and queue it for the next step."""
        await _require(self._session.runtime).deliver_operator_message(text)

    async def run_step(self) -> object:
        """One orchestrator step (drains queued injections first)."""
        return await _require(self._session.runtime).run_step()

    def pending_injections(self) -> int:
        """Queued notifications/messages awaiting the next step."""
        return _require(self._session.runtime).pending_injections()

    async def close(self) -> None:
        """Checkpoint the WAL and release the session (idempotent)."""
        await self._session.close()

    def profile_label(self) -> str:
        """The strictness profile + autonomy mode label for the header."""
        config = self._session.config
        return f"profile={config.profile} mode={config.mode}"


class TuiState:
    """Single owner of the UI state (arch §10.2).

    One bus subscription feeds a coalescing queue: the producer (the bus
    dispatcher) appends envelopes and sets a wake event; the single consumer
    (:meth:`wait_batch`) swaps out the whole pending list at once. Events are
    never dropped — only the extra redraws collapse into one refresh.
    """

    def __init__(self, view: SessionView, tail_size: int = 200, feed_max: int = FEED_MAX) -> None:
        """Create empty state over the facade; ``tail_size`` bounds preload.

        ``feed_max`` bounds the live feed window: oldest envelopes are
        dropped beyond it, while :attr:`event_count` keeps the session total
        for the statistics panel (Issue #33).
        """
        self.view = view
        self.tail_size = tail_size
        self.feed: deque[EventEnvelope] = deque(maxlen=feed_max)
        self.event_count: int = 0
        self.system_errors: deque[str] = deque(maxlen=SYSTEM_ERRORS_MAX)
        self.approvals: tuple[ApprovalItem, ...] = ()
        self.endpoints: list[Endpoint] = []
        self.findings: list[Finding] = []
        self.attack_nodes: list[AttackNode] = []
        self.attack_edges: list[AttackEdge] = []
        self.todos: list[TodoItem] = []
        self.last_reply: str = ""
        self.replies: deque[str] = deque(maxlen=REPLIES_MAX)
        self.subagent_transcripts: dict[str, list[str]] = {}
        self._pending: list[EventEnvelope] = []
        self._dirty: set[str] = set()
        self._wake = asyncio.Event()
        self._subscription: UiSubscription | None = None

    # ---- subscription lifecycle ----

    def start(self) -> None:
        """Subscribe the coalescing handler to the session bus."""
        if self._subscription is None:
            self._subscription = self.view.subscribe(self._on_event)

    def stop(self) -> None:
        """Unsubscribe (no further deliveries; state stays readable)."""
        if self._subscription is not None:
            self._subscription.unsubscribe()
            self._subscription = None

    async def _on_event(self, envelope: EventEnvelope) -> None:
        """Bus handler: buffer the envelope, request one coalesced wake."""
        self._pending.append(envelope)
        self._dirty.add(envelope.type)
        self._wake.set()

    # ---- coalesced consumption ----

    async def wait_batch(self, poll_after: float | None = None) -> list[EventEnvelope]:
        """Wait for pending events and return them as ONE batch.

        Coalescing: every buffered envelope is returned exactly once, no
        matter how many arrived during the wait; ``poll_after`` (seconds)
        returns an empty batch on expiry — the poll tick for the app loop
        (``None`` waits unboundedly).

        Raises:
            asyncio.CancelledError: propagated on app shutdown.
        """
        if not self._pending:
            try:
                async with asyncio.timeout(poll_after):
                    await self._wake.wait()
            except TimeoutError:
                return []
            self._wake.clear()
            if not self._pending:  # pragma: no cover - append-before-set ordering
                return []
        batch = self._pending[:]
        self._pending.clear()
        return batch

    def kick(self) -> None:
        """Wake the consumer immediately (operator action side effects)."""
        self._wake.set()

    def drain_pending(self) -> list[EventEnvelope]:
        """Non-blocking drain: every envelope buffered so far, as one batch.

        Used while an orchestrator step runs (arch §10.1): the loop must keep
        folding the events the bus dispatcher delivers mid-step into the feed
        without waiting — ``wait_batch`` would block for the step's duration
        and the panels would freeze behind it.
        """
        batch = self._pending[:]
        self._pending.clear()
        self._wake.clear()
        return batch

    # ---- bounded feed window (Issue #33) ----

    def extend_feed(self, batch: Sequence[EventEnvelope]) -> None:
        """Append one coalesced batch, dropping the oldest beyond the window.

        ``event_count`` keeps the session total (the statistics panel shows
        it), so bounding the window never changes reported numbers.
        """
        self.feed.extend(batch)
        self.event_count += len(batch)

    def recent_feed(self, limit: int) -> list[EventEnvelope]:
        """The newest ``limit`` envelopes of the bounded window, in order."""
        if len(self.feed) <= limit:
            return list(self.feed)
        return list(self.feed)[-limit:]

    def report_error(self, message: str) -> None:
        """Record one UI/system error line (bounded; rendered by the chat).

        The Issue #28 degradation path: a failed worker iteration or decision
        surfaces here and in the operator log instead of exiting the app.
        """
        self.system_errors.append(message)

    def take_dirty(self) -> set[str]:
        """Consume the dirty-type set accumulated since the last call."""
        dirty, self._dirty = self._dirty, set()
        return dirty

    def needs_snapshot(self, dirty: set[str]) -> bool:
        """Whether any dirty type invalidates the memory snapshots."""
        return bool(dirty & _SNAPSHOT_TYPES)

    # ---- snapshots ----

    async def preload(self) -> None:
        """Initial fill: journal tail + one snapshot pull (session open)."""
        self.extend_feed(await self.view.journal_tail(self.tail_size))
        await self.refresh()

    async def refresh(self) -> None:
        """Re-pull every snapshot cache through the facade."""
        self.approvals = self.view.pending_approvals()
        self.endpoints = await self.view.endpoints()
        self.findings = await self.view.findings()
        self.attack_nodes = await self.view.attack_nodes()
        self.attack_edges = await self.view.attack_edges()

    def absorb(self, result: object) -> None:
        """Fold one graph-step result into the state (todos/reply/transcripts).

        Duck-typed on purpose: the result is an L0 state mapping and the TUI
        must not import the L0 stack (arch §2.5).
        """
        reply = orchestrator_reply(result)
        self.last_reply = reply or self.last_reply
        if reply and (not self.replies or reply != self.replies[-1]):
            # Issue #47: keep the whole reply history (bounded), not just
            # the latest line — the chat panel renders the full dialog.
            # A step without fresh prose (delegation turns, HITL pauses)
            # still returns the last non-empty AI text of the WHOLE
            # accumulated history, so an unchanged reply means "no new
            # prose this step": appending it would re-append the previous
            # turn — the same per-step-delta flaw the #14 snapshot
            # semantics solved for delegation transcripts.
            self.replies.append(reply)
        todos = orchestrator_todos(result)
        if todos:
            self.todos = todos
        transcripts = delegation_transcripts(result)
        if transcripts:
            # Snapshot semantics (Issue #14): the step result carries the
            # FULL message history (langgraph accumulates ``messages``), so
            # the re-paired transcripts are the complete set — replace, do
            # not extend (extending re-added every historical delegation on
            # each delegation-bearing step).
            self.subagent_transcripts = transcripts


# ---------------------------------------------------------------------------
# Duck-typed graph-result readers (L0-free, arch §2.5).
# ---------------------------------------------------------------------------


def _message_texts(content: object) -> str:
    """Render one duck-typed message ``content`` (str or text-part list)."""
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence):
        parts: list[str] = []
        for part in content:
            if isinstance(part, Mapping):
                parts.append(str(part.get("text", "")))
            elif isinstance(part, str):
                parts.append(part)
        return "".join(parts)
    return str(content)


def orchestrator_reply(result: object) -> str:
    """The last assistant text of one graph step (``""`` when absent).

    Structural contract: ``result`` is a mapping with a ``messages``
    sequence whose entries expose ``type`` and ``content`` attributes.
    """
    if not isinstance(result, Mapping):
        return ""
    messages = result.get("messages")
    if not isinstance(messages, Sequence):
        return ""
    reply = ""
    for message in messages:
        if getattr(message, "type", None) != "ai":
            continue
        text = _message_texts(getattr(message, "content", "")).strip()
        if text:
            reply = text
    return reply


def orchestrator_todos(result: object) -> list[TodoItem]:
    """The orchestrator todos of one graph step (``[]`` when absent)."""
    if not isinstance(result, Mapping):
        return []
    raw = result.get("todos")
    if not isinstance(raw, Sequence):
        return []
    todos: list[TodoItem] = []
    for item in raw:
        if isinstance(item, Mapping):
            todos.append(
                TodoItem(
                    content=str(item.get("content", "")),
                    status=str(item.get("status", "pending")),
                )
            )
    return todos


def delegation_transcripts(result: object) -> dict[str, list[str]]:
    """Per-subagent transcript entries of one step (sanitization at render).

    Pairs ``task()`` tool calls (``args.subagent_type`` + description) with
    their result messages by call id — the checkpointed parent-thread view
    of each delegation (arch §10.1, v0.1 simplification: per-subagent thread
    namespaces are an L0 internal, so the snapshot rides the parent state).
    """
    if not isinstance(result, Mapping):
        return {}
    messages = result.get("messages")
    if not isinstance(messages, Sequence):
        return {}
    task_calls: dict[str, tuple[str, str]] = {}
    for message in messages:
        for call in getattr(message, "tool_calls", None) or ():
            if not isinstance(call, Mapping) or call.get("name") != "task":
                continue
            args = call.get("args")
            if not isinstance(args, Mapping):
                continue
            call_id = str(call.get("id", ""))
            subagent = str(args.get("subagent_type", "unknown"))
            description = str(args.get("description", ""))
            task_calls[call_id] = (subagent, description)
    transcripts: dict[str, list[str]] = {}
    for message in messages:
        if getattr(message, "type", None) != "tool":
            continue
        call_id = str(getattr(message, "tool_call_id", ""))
        matched = task_calls.get(call_id)
        if matched is None:
            continue
        subagent, description = matched
        entries = transcripts.setdefault(subagent, [])
        if description:
            entries.append(f"task: {description}")
        entries.append(_message_texts(getattr(message, "content", "")))
    return transcripts


__all__ = [
    "FEED_MAX",
    "REPLIES_MAX",
    "ApprovalChoice",
    "ApprovalItem",
    "SessionView",
    "TodoItem",
    "TuiState",
    "UiSubscription",
    "delegation_transcripts",
    "orchestrator_reply",
    "orchestrator_todos",
]
