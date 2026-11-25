"""OrchestratorRuntime: single-writer graph execution, event policies and
delegation correlation (arch §9.2-§9.4, roadmap T3.2.1-T3.2.4).

Three concerns of the execution layer live here:

* **Event policies** (T3.2.2, arch §9.3): the declarative
  ``event → reaction`` pipeline. :func:`resolve_policies` activates the
  built-in defaults when the config section is absent; :meth:`OrchestratorRuntime.
  _handle_envelope` matches an envelope against the policies and renders the
  notification via :func:`render_notification`. A policy **only injects a
  notification** — it never calls tools or ``task()`` itself (arch §9.3/§17;
  enforced by the architecture test).
* **Correlation** (T3.2.3, arch §9.4): :class:`CorrelationMiddleware` wraps
  the L0 ``task()`` tool calls on the orchestrator graph; at delegation
  entry it assigns a fresh ``correlation_id``, sets the module contextvar
  (read by ``emit_event`` and the HTTP client through
  :func:`current_correlation_id`), and journals ``TaskRequested`` /
  ``TaskCompleted`` around the delegation. Parallel ``task()`` calls run as
  separate asyncio tasks, so each contextvar assignment is isolated (D19).
* **Runtime** (T3.2.1, AD-8): owns graph execution under the single-writer
  discipline — at most one ``ainvoke``/``astream`` against the orchestrator
  graph at any moment (``asyncio.Lock``); parallelism comes from subagents
  inside one graph step. The reactive contour (bus → policy → notification →
  queue → injection at the step boundary) and the interactive contour
  (operator message → queue → injection) meet in :meth:`run_step`; the
  proactive contour is the orchestrator's own todos (L0). Resume restores
  the checkpointed state, re-reads the journal tail and re-enqueues
  interrupted approvals (T3.2.4, arch §13.1).

Injected notification texts pass through the session ``ContextProjector``
(§6.8: secret masking, byte budget, verbatim untrusted markers) before they
enter the graph — target-derived quotes inside a digest are marked as
untrusted data (arch §9.2).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextvars import ContextVar
from typing import TYPE_CHECKING, Final, Literal, NamedTuple, TypeAlias

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.runnables import RunnableConfig

from swarmy.core.prompts import GENERIC_NOTIFICATION_TEMPLATE, render_notification
from swarmy.events.models import EventEnvelope, JsonValue, OperatorMessagePayload

if TYPE_CHECKING:
    from langchain_core.messages import ToolMessage
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.prebuilt.tool_node import ToolCallRequest
    from langgraph.types import Command

    from swarmy.core.config import PolicySpec
    from swarmy.core.hitl import ApprovalQueue
    from swarmy.tools.projector import ContextProjector

#: The delegation context (arch §9.4): the correlation id of the innermost
#: running delegation, or ``""`` outside any delegation chain (T1.3.4).
_correlation_id: ContextVar[str] = ContextVar("swarmy_correlation_id", default="")


def current_correlation_id() -> str:
    """Read the delegation correlation context (arch §9.4, T3.2.3).

    The provider injected into ``make_emit_tool``/``SwarmyHttpClient``: every
    event, evidence record and HTTP request issued inside a delegation
    carries its ``correlation_id``; outside a chain the value is ``""``.
    """
    return _correlation_id.get()


#: Platform callable publishing one envelope (journal-first, then bus):
#: the ``make_emit_tool`` API (arch §5.2). The runtime publishes
#: ``OperatorMessage`` and the correlation contour's ``Task*`` events
#: through it — the source is platform-side, never agent-forged.
PlatformEmit: TypeAlias = Callable[[str, Mapping[str, JsonValue]], Awaitable[str]]


class CorrelationMiddleware(AgentMiddleware):
    """Delegation correlation around L0 ``task()`` calls (arch §9.4, T3.2.3).

    Installed on the orchestrator graph by the session wiring. For every
    ``task`` tool call it assigns a fresh ``correlation_id``, sets the
    module contextvar for the duration of the call (the awaited subagent
    graph inherits it — every emitted event of that delegation carries the
    id), and journals ``TaskRequested`` before / ``TaskCompleted`` after,
    with the subagent's result digest. Non-``task`` calls pass through
    untouched; the token-scoped contextvar reset keeps sequential calls
    clean. Parallel ``task()`` calls execute in separate asyncio tasks, so
    their contexts cannot cross (D19).
    """

    __slots__ = ("_emit",)

    def __init__(self, emit: PlatformEmit) -> None:
        """Bind the platform event publisher (journal+bus wiring)."""
        self._emit = emit

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[object]]],
    ) -> ToolMessage | Command[object]:
        """Wrap ``task()`` calls with the correlation context and events."""
        tool_call = request.tool_call
        if str(tool_call.get("name", "")) != "task":
            return await handler(request)
        raw_args = tool_call.get("args", {})
        args: Mapping[str, object] = raw_args if isinstance(raw_args, Mapping) else {}
        subagent = str(args.get("subagent_type", "unknown"))
        description_digest = str(args.get("description", ""))[:256]
        correlation_id = f"task-{uuid.uuid4().hex[:12]}"
        # The contextvar is set BEFORE the TaskRequested emit: the request
        # and completion envelopes themselves carry the correlation id (the
        # journal-first ``emit`` reads it through the provider), and the
        # awaited subagent graph inherits it for everything it emits.
        token = _correlation_id.set(correlation_id)
        try:
            await self._emit(
                "TaskRequested",
                {
                    "correlation_id": correlation_id,
                    "subagent": subagent,
                    "status": "requested",
                    "summary_digest": description_digest,
                },
            )
            result = await handler(request)
            content = getattr(result, "content", result)
            summary = content if isinstance(content, str) else str(content)
            await self._emit(
                "TaskCompleted",
                {
                    "correlation_id": correlation_id,
                    "subagent": subagent,
                    "status": "completed",
                    "summary_digest": summary[:256],
                },
            )
        finally:
            _correlation_id.reset(token)
        return result

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[object]],
    ) -> ToolMessage | Command[object]:
        """Fail closed: the synchronous path would bypass the async contour."""
        raise RuntimeError(
            "CorrelationMiddleware enforces awrap_tool_call only; swarmy agents "
            "run asynchronously"
        )


# ---------------------------------------------------------------------------
# Event policies (arch §9.3, T3.2.2).
# ---------------------------------------------------------------------------

#: Reaction classes of a policy (arch §9.3). ``notify_tui`` is matched but
#: its delivery target (the TUI feed) lands with milestone M4; the M3
#: headless runtime counts it in :attr:`OrchestratorRuntime.tui_notifications`.
PolicyAction: TypeAlias = Literal["notify_orchestrator", "notify_tui", "ignore"]


class ResolvedPolicy(NamedTuple):
    """One resolved ``event → reaction`` declaration (arch §9.3)."""

    on: frozenset[str]
    action: PolicyAction
    template: str


def default_policies() -> tuple[ResolvedPolicy, ...]:
    """The built-in defaults (arch §9.3), active without a ``policies`` section."""
    return _DEFAULT_POLICIES


_DEFAULT_POLICIES: Final[tuple[ResolvedPolicy, ...]] = (
    ResolvedPolicy(frozenset({"FindingCandidate"}), "notify_orchestrator", "verify_finding"),
    ResolvedPolicy(
        frozenset({"FindingVerified", "FindingRejected"}), "notify_orchestrator", "tree_proposal"
    ),
    ResolvedPolicy(frozenset({"GuardrailBlocked"}), "notify_orchestrator", "generic"),
    ResolvedPolicy(frozenset({"ScopeChanged"}), "notify_orchestrator", "generic"),
    ResolvedPolicy(
        frozenset({"AttackTreeUpdated", "TaskRequested", "TaskCompleted"}),
        "notify_tui",
        "generic",
    ),
)


def resolve_policies(
    configured: Sequence[PolicySpec] | None,
) -> tuple[ResolvedPolicy, ...]:
    """Resolve the config ``policies`` section (arch §9.3).

    An absent or empty section activates the built-in defaults; a non-empty
    section replaces them wholesale (the operator chose an explicit policy
    set). ``on`` accepts one type name or a list.

    Args:
        configured: the resolved config section (``None`` = absent).

    Returns:
        The effective policy list.
    """
    if not configured:
        return default_policies()
    return tuple(
        ResolvedPolicy(
            on=frozenset([spec.on] if isinstance(spec.on, str) else list(spec.on)),
            action=spec.action,
            template=spec.template if spec.template is not None else "generic",
        )
        for spec in configured
    )


def match_policy(
    policies: Sequence[ResolvedPolicy], event_type: str
) -> ResolvedPolicy | None:
    """The first policy whose ``on`` covers ``event_type`` (arch §9.3)."""
    for policy in policies:
        if event_type in policy.on:
            return policy
    return None


def render_policy_notification(policy: ResolvedPolicy, envelope: EventEnvelope) -> str:
    """Render the notification text for one envelope (arch §9.3).

    The template receives the envelope fields (``id``, ``event_type``) plus
    every payload field; a template referencing an unknown field falls back
    to the generic digest form — a config typo degrades the notification,
    it never drops the event. Target-derived payload content is *not*
    trusted: the runtime projects the rendered text through the
    ``ContextProjector`` before injection (the untrusted markers are added
    there, arch §9.2).
    """
    payload: dict[str, object] = envelope.payload.model_dump(mode="json")
    fields: dict[str, object] = {
        "id": envelope.id,
        "event_type": envelope.type,
        "digest": json.dumps(payload, sort_keys=True, default=str)[:512],
        **payload,
    }
    try:
        return render_notification(policy.template, fields)
    except (KeyError, IndexError):
        return GENERIC_NOTIFICATION_TEMPLATE.format(**{
            "id": envelope.id,
            "event_type": envelope.type,
            "digest": fields["digest"],
        })


# ---------------------------------------------------------------------------
# OrchestratorRuntime (arch §9.2, AD-8).
# ---------------------------------------------------------------------------


class _InterruptView(NamedTuple):
    """The subset of a snapshot interrupt the runtime needs."""

    interrupt_id: str
    tool: str
    args: dict[str, object]


def _read_interrupts(snapshot: object) -> tuple[_InterruptView, ...]:
    """Extract ``(interrupt_id, tool, args)`` views from a state snapshot.

    Mirrors :func:`swarmy.core.hitl._tool_and_args` shape handling (per-call
    and batched HITL requests); unknown shapes degrade to ``("unknown", {})``
    so the operator keeps an answerable entry. A snapshot without
    ``interrupts`` (mock graphs) yields no views.
    """
    if not isinstance(snapshot, object) or not hasattr(snapshot, "interrupts"):
        return ()
    raw = snapshot.interrupts
    views: list[_InterruptView] = []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    for interrupt in raw:
            interrupt_id = str(getattr(interrupt, "id", "") or "")
            value = getattr(interrupt, "value", None)
            if isinstance(value, Mapping):
                name = value.get("name")
                args = value.get("args")
                tool = name if isinstance(name, str) else "unknown"
                args_map: dict[str, object] = (
                    {str(k): v for k, v in args.items()} if isinstance(args, Mapping) else {}
                )
                views.append(_InterruptView(interrupt_id, tool, args_map))
            else:
                views.append(_InterruptView(interrupt_id, "unknown", {}))
    return tuple(views)


class OrchestratorRuntime:
    """Single-writer execution of the orchestrator graph (arch §9.2, AD-8).

    * **Single writer**: :attr:`_graph_lock` serializes every
      ``ainvoke``/``astream`` — at most one active call against the thread's
      checkpointed state at any moment (AD-8; the ≤1 invariant is observable
      via :attr:`active_calls` and asserted by the T3.2.1 monitor test).
    * **Reactive contour**: a bus subscription routes envelopes through the
      resolved policies; ``notify_orchestrator`` reactions are rendered,
      projected (§6.8) and queued for injection at the next step boundary.
    * **Interactive contour**: :meth:`deliver_operator_message` journals the
      ``OperatorMessage`` event and queues the human message.
    * **Proactive contour**: the orchestrator's own todos/tools (L0) — the
      runtime only guarantees the single-writer envelope around each step.
    * **HITL**: after every step the runtime polls ``snapshot.interrupts``
      into the :class:`ApprovalQueue`; :meth:`submit_decision` journals the
      decision and resumes exactly the addressed interrupt (arch §7.3).
    * **Resume** (T3.2.4): :meth:`restore` re-reads the checkpointed state,
      re-enqueues pending interrupts and drains the journal tail through the
      policy pipeline, so events that fired while the process was down are
      not lost.

    Queue entries wait for the *next* step boundary — the runtime never
    re-enters the graph from a bus handler (arch §9.2, single-writer).
    """

    def __init__(
        self,
        *,
        graph: CompiledStateGraph,
        emit: PlatformEmit,
        policies: Sequence[ResolvedPolicy],
        projector: ContextProjector,
        approvals: ApprovalQueue,
        thread_id: str = "orchestrator",
        notify_tui_sink: Callable[[EventEnvelope, ResolvedPolicy], None] | None = None,
    ) -> None:
        """Assemble the runtime over its collaborators.

        Args:
            graph: the compiled orchestrator graph (engine-provided; mock in
                unit tests).
            emit: the platform event publisher (``OperatorMessage``).
            policies: the effective policy set (:func:`resolve_policies`).
            projector: the §6.8 projector applied to injected notifications.
            approvals: the HITL FIFO (shared with the session).
            thread_id: the LangGraph thread of this session's orchestrator.
            notify_tui_sink: delivery hook for ``notify_tui`` reactions (M4
                wiring); ``None`` counts them without delivery.
        """
        self._graph = graph
        self._emit = emit
        self._policies = tuple(policies)
        self._projector = projector
        self._approvals = approvals
        self._thread_id = thread_id
        self._notify_tui_sink = notify_tui_sink
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._graph_lock = asyncio.Lock()
        self._active_calls = 0
        self._max_observed_calls = 0
        self._last_event_id = 0
        self.orchestrator_notifications = 0
        self.tui_notifications = 0
        self.ignored_notifications = 0

    # ---- contours ----

    def subscribe(self, bus_subscribe: Callable[..., object]) -> object:
        """Subscribe the reactive contour to the bus (arch §9.2).

        Args:
            bus_subscribe: ``EventBus.subscribe``; the runtime requests all
                event types — policy matching decides the reaction.

        Returns:
            The bus subscription handle (kept by the session).
        """
        return bus_subscribe(self._on_envelope, None)

    async def deliver_operator_message(self, text: str) -> None:
        """Interactive contour: journal and queue an operator chat message."""
        await self._emit(
            "OperatorMessage",
            OperatorMessagePayload(text_digest=text[:512]).model_dump(mode="json"),
        )
        self._queue.put_nowait(text)

    async def _on_envelope(self, envelope: EventEnvelope) -> None:
        """Reactive contour: policy match → reaction (arch §9.3)."""
        self._handle_envelope(envelope)

    def _handle_envelope(self, envelope: EventEnvelope) -> None:
        """Apply the policy pipeline to one envelope (shared by bus and resume).

        Idempotent on the journal watermark: envelopes at or before
        :attr:`_last_event_id` are skipped, so a resume tail-replay cannot
        double-inject a notification the live bus already delivered.
        """
        if envelope.id <= self._last_event_id:
            return
        self._last_event_id = envelope.id
        policy = match_policy(self._policies, envelope.type)
        if policy is None or policy.action == "ignore":
            self.ignored_notifications += 1
            return
        if policy.action == "notify_tui":
            self.tui_notifications += 1
            if self._notify_tui_sink is not None:
                self._notify_tui_sink(envelope, policy)
            return
        rendered = render_policy_notification(policy, envelope)
        injected = self._projector.project(rendered)
        self._queue.put_nowait(injected)
        self.orchestrator_notifications += 1

    # ---- graph execution (single-writer, AD-8) ----

    @property
    def config(self) -> RunnableConfig:
        """The LangGraph invocation config of this session's thread."""
        return RunnableConfig(configurable={"thread_id": self._thread_id})

    @property
    def active_calls(self) -> int:
        """Currently active graph invocations (the AD-8 invariant: ≤ 1)."""
        return self._active_calls

    @property
    def max_observed_calls(self) -> int:
        """High-water mark of concurrent graph calls (monitor-test probe)."""
        return self._max_observed_calls

    def pending_injections(self) -> int:
        """Number of queued notifications/messages awaiting the next step."""
        return self._queue.qsize()

    async def run_step(self, user_text: str | None = None) -> object:
        """One orchestrator step: drain injections, then invoke the graph.

        The queued notifications and the optional direct operator message
        are injected together as human messages on the step boundary (arch
        §9.2). The invocation happens under the single-writer lock; after
        the step the runtime polls the checkpointed interrupts into the
        approval queue (arch §7.1-§7.3).

        Args:
            user_text: direct operator input for this step (the chat path);
                ``None`` when the step only serves queued injections.

        Returns:
            Whatever the graph returns (final state / message).
        """
        messages: list[BaseMessage] = []
        while not self._queue.empty():
            messages.append(HumanMessage(content=self._queue.get_nowait()))
        if user_text is not None:
            messages.append(HumanMessage(content=user_text))
        if not messages:
            return None
        return await self._invoke_locked({"messages": messages})

    async def _invoke_locked(self, value: object) -> object:
        """Invoke the graph under the lock; keep the monitor counters honest."""
        async with self._graph_lock:
            self._active_calls += 1
            self._max_observed_calls = max(self._max_observed_calls, self._active_calls)
            try:
                result = await self._graph.ainvoke(value, self.config)
            finally:
                self._active_calls -= 1
        await self._refresh_approvals()
        return result

    async def _refresh_approvals(self) -> None:
        """Pull the checkpointed interrupts into the approval FIFO (arch §7.3)."""
        snapshot = await self._graph.aget_state(self.config)
        self._approvals.refresh(snapshot)

    # ---- HITL decisions (arch §7.3) ----

    async def submit_decision(
        self,
        request_id: str,
        decision: Literal["approve", "edit", "reject"],
        edited_args: Mapping[str, object] | None = None,
    ) -> object:
        """Serve one approval decision and resume its interrupt (arch §7.3-§7.4).

        The queue journals the ``OperatorDecision`` first; when the decision
        addresses a real graph interrupt, the returned ``Command(resume=...)``
        is invoked under the single-writer lock. Judge-escalation requests
        carry an empty resume mapping — nothing to invoke, the registry
        resolution happened in the queue.

        Returns:
            The graph result (``None`` when no resume was needed).
        """
        command = await self._approvals.submit_decision(request_id, decision, edited_args)
        resume = getattr(command, "resume", None)
        if not resume:
            return None
        return await self._invoke_locked(command)

    # ---- resume (T3.2.4, arch §13.1) ----

    def swap_graph(self, graph: CompiledStateGraph) -> None:
        """Install a recompiled graph (engine ``recompile``, arch §7.2/§9.5).

        Mode/profile switches rebuild the orchestrator graph on the same
        checkpointer; the runtime continues on the new graph object with the
        same thread id, so checkpointed state and pending interrupts carry
        over.
        """
        self._graph = graph

    async def restore(
        self,
        journal_tail: Callable[[int], Awaitable[Sequence[EventEnvelope]]],
    ) -> int:
        """Restore the contours after a process restart (arch §9.2, §13.1).

        Re-reads the checkpointed state (the graph itself restores from the
        SQLite checkpointer on the next invocation), re-enqueues the pending
        interrupts into the approval FIFO, and drains the journal tail
        (``range(from_id)``) through the policy pipeline so offline events
        still produce their notifications.

        Args:
            journal_tail: ``JournalReader.range``-shaped tail reader.

        Returns:
            The number of replayed journal events.
        """
        await self._refresh_approvals()
        replayed = await journal_tail(self._last_event_id)
        for envelope in replayed:
            self._handle_envelope(envelope)
        return len(replayed)


__all__ = [
    "CorrelationMiddleware",
    "OrchestratorRuntime",
    "ResolvedPolicy",
    "current_correlation_id",
    "default_policies",
    "match_policy",
    "render_policy_notification",
    "resolve_policies",
]
