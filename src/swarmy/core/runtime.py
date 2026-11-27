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
import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextvars import ContextVar
from typing import TYPE_CHECKING, Final, Literal, NamedTuple, TypeAlias

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.errors import GraphInterrupt

from swarmy.core.prompts import GENERIC_NOTIFICATION_TEMPLATE, render_notification
from swarmy.events.models import EventEnvelope, JsonValue, OperatorMessagePayload
from swarmy.tools.projector import ContextProjector

if TYPE_CHECKING:
    from langchain_core.messages import ToolMessage
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.prebuilt.tool_node import ToolCallRequest
    from langgraph.types import Command, StateSnapshot

    from swarmy.core.config import PolicySpec
    from swarmy.core.hitl import ApprovalQueue

#: Module logger (resume-failure diagnostics, Issue #26).
LOG = logging.getLogger(__name__)

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


#: Fallback projector for the correlation digests: built-in masking
#: detectors + the conservative §6.8 default budget, **without** untrusted
#: wrapping — these digests are journal-bound (arch §5.5: masking/объём),
#: never injected into a model context, and the TUI display layer adds its
#: own markers when rendering them; a marker-carrying digest would be
#: double-wrapped and defused there. The session wiring passes the session
#: projector's secret rules via a non-marking instance for the same reason.
_FALLBACK_PROJECTOR: Final[ContextProjector] = ContextProjector(mark_untrusted=False)


#: Platform callable publishing one envelope (journal-first, then bus):
#: the ``make_emit_tool`` API (arch §5.2). The runtime publishes
#: ``OperatorMessage`` and the correlation contour's ``Task*`` events
#: through it — the source is platform-side, never agent-forged.
PlatformEmit: TypeAlias = Callable[[str, Mapping[str, JsonValue]], Awaitable[str]]


def _delivered_operator_texts(snapshot: object) -> frozenset[str]:
    """Projected operator texts present in the checkpointed state (Issue #46).

    The runtime injects operator messages and notifications as
    ``HumanMessage``s; once the step that carried them commits, the L0
    checkpointer stores them in the thread state. A text found here was
    therefore **delivered**; a journal ``OperatorMessage`` missing from the
    set was queued but never drained — the resume re-queues it. This is the
    delivery record: journal-side ack events or a metadata table would need
    a new registered type or a schema migration (both out of v0.1 scope).

    Known limitation (documented honestly): matching is content-based, so two
    identical operator texts cannot be told apart, and a history-compaction
    middleware could let an old delivered message re-enter the queue — v0.1
    runs no such middleware.
    """
    values = getattr(snapshot, "values", None)
    if not isinstance(values, Mapping):
        return frozenset()
    messages = values.get("messages")
    if not isinstance(messages, Sequence) or isinstance(messages, (str, bytes)):
        return frozenset()
    texts: set[str] = set()
    for message in messages:
        if isinstance(message, HumanMessage) and isinstance(message.content, str):
            texts.add(message.content)
    return frozenset(texts)


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

    __slots__ = ("_emit", "_projector")

    def __init__(
        self, emit: PlatformEmit, projector: ContextProjector | None = None
    ) -> None:
        """Bind the platform event publisher and the digest projector.

        Args:
            emit: the platform event publisher (journal+bus wiring).
            projector: the session projector (§6.8) routed through the
                ``summary_digest`` fields before they are journaled (arch
                §5.5: ``*_digest`` always via ``ContextProjector``, Issue
                #55). ``None`` uses the conservative fallback (built-in
                detectors, default budget).
        """
        self._emit = emit
        self._projector = projector if projector is not None else _FALLBACK_PROJECTOR

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
        description_digest = self._projector.project(str(args.get("description", "")))
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
            result: ToolMessage | Command[object]
            try:
                result = await handler(request)
            except GraphInterrupt:
                # A paused delegation is not a failure: the interrupt rides
                # the checkpoint (HITL resume, arch §7.1) and the journal
                # keeps the honest dangling TaskRequested until the resume.
                raise
            except Exception as error:
                # Issue #32: a failed delegation must not leave a dangling
                # TaskRequested — the journal keeps the honest pair and the
                # Activity panel resolves the row. Cancellation (BaseException
                # outside Exception) stays unjournaled: the delegation was
                # interrupted, not failed.
                await self._emit(
                    "TaskCompleted",
                    {
                        "correlation_id": correlation_id,
                        "subagent": subagent,
                        "status": "failed",
                        "summary_digest": self._projector.project(
                            f"{type(error).__name__}: {error}"
                        ),
                    },
                )
                raise
            content = getattr(result, "content", result)
            summary = content if isinstance(content, str) else str(content)
            await self._emit(
                "TaskCompleted",
                {
                    "correlation_id": correlation_id,
                    "subagent": subagent,
                    "status": "completed",
                    "summary_digest": self._projector.project(summary),
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
      re-enqueues pending interrupts and scans the journal through
      :meth:`_replay_envelope`: the notification watermark is seeded by the
      scan (no stale-notification flood after a restart, Issue #27) and
      undelivered operator messages are re-queued (Issue #46).

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
        reload_skills: bool = False,
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
            reload_skills: merge the documented L0 reload trigger
                (``skills_metadata: None``) into the **first** step's input.
                The L0 ``SkillsMiddleware`` loads the skill index once and
                keeps it checkpointed, so a resumed thread would otherwise
                never see skills added to the container between runs (arch
                §8.6); the session sets this whenever skills are wired.
        """
        self._graph = graph
        self._emit = emit
        self._policies = tuple(policies)
        self._projector = projector
        self._approvals = approvals
        self._thread_id = thread_id
        self._notify_tui_sink = notify_tui_sink
        self._reload_skills = reload_skills
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
        """Interactive contour: journal and queue an operator chat message.

        The text passes through the session ``ContextProjector`` before both
        surfaces (arch §5.5 + §16.4, Issue #36 ↔ F-22): the journal row
        carries the projected ``text_digest`` (masking, budget,
        normalization — a pasted credential becomes ``<masked:name>``), and
        the same projection is queued for injection as the ``HumanMessage``.
        """
        projected = self._projector.project(text)
        await self._emit(
            "OperatorMessage",
            OperatorMessagePayload(text_digest=projected).model_dump(mode="json"),
        )
        self._queue.put_nowait(projected)

    async def _on_envelope(self, envelope: EventEnvelope) -> None:
        """Reactive contour: policy match → reaction (arch §9.3)."""
        self._handle_envelope(envelope)

    def _handle_envelope(self, envelope: EventEnvelope) -> None:
        """Apply the policy pipeline to one envelope (shared by bus and resume).

        Idempotent on the journal watermark: envelopes at or before
        :attr:`_last_event_id` are skipped, so a resume tail-replay cannot
        double-inject a notification the live bus already delivered. The
        watermark itself is seeded by the resume scan (see
        :meth:`_replay_envelope`) — it no longer starts at 0 after a process
        restart (Issue #27).
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

    def _replay_envelope(self, envelope: EventEnvelope, delivered: frozenset[str]) -> None:
        """Resume-scan replay of one journal envelope (Issues #27/#46).

        Advances the watermark **without** re-injecting notifications: a
        restart must not flood the orchestrator with stale events the
        pre-restart process already reacted to (the TUI history is served
        from the journal directly, and the live bus carries everything from
        now on — arch §13.1). ``OperatorMessage`` envelopes are re-queued
        only when the checkpointed message history proves they were never
        delivered (see :func:`_delivered_operator_texts`) — an operator
        message the process died before draining is steering input that must
        not be silently lost across the restart.
        """
        if envelope.id <= self._last_event_id:
            return
        self._last_event_id = envelope.id
        if envelope.type != "OperatorMessage":
            return
        payload = envelope.payload
        text = payload.text_digest if isinstance(payload, OperatorMessagePayload) else None
        if text is not None and text not in delivered:
            self._queue.put_nowait(text)

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
                ``None`` when the step only serves queued injections. The
                text passes through the session projector (§16.4) exactly
                like :meth:`deliver_operator_message` — production callers
                go through the chat contour; this direct seam must not
                bypass the §6.8 pipeline either. Unlike queued injections,
                a failed step does not re-queue the direct text (the caller
                owns it).

        Returns:
            Whatever the graph returns (final state / message).
        """
        injections: list[str] = []
        while not self._queue.empty():
            injections.append(self._queue.get_nowait())
        messages: list[BaseMessage] = [HumanMessage(content=text) for text in injections]
        if user_text is not None:
            messages.append(HumanMessage(content=self._projector.project(user_text)))
        if not messages:
            return None
        state: dict[str, object] = {"messages": messages}
        if self._reload_skills:
            # The documented L0 reload trigger (arch §8.6): the middleware
            # re-lists the skills sources instead of reusing the checkpointed
            # index of a previous run.
            state["skills_metadata"] = None
        try:
            result = await self._invoke_locked(state)
        except BaseException:
            # A failure *after* the input superstep committed (AsyncSqliteSaver
            # persists the injected HumanMessages before the failing node
            # runs) must not re-queue them: the checkpointed history already
            # carries that steering, and a blind re-queue would duplicate it.
            # Snapshot the post-failure state and re-queue only the texts the
            # checkpoint does not prove delivered — a failure before any
            # commit keeps every drained injection (operator messages and
            # policy notifications share this content-matched contour).
            try:
                delivered = _delivered_operator_texts(await self._graph.aget_state(self.config))
            except Exception:
                # The snapshot itself failed (checkpointer I/O): fall back to
                # the never-drop behaviour, at the cost of a possible
                # duplicate — silently losing steering input is the worse
                # failure mode (Issue #46 semantics preserved).
                LOG.exception(
                    "post-failure state snapshot failed; re-queueing every "
                    "drained injection (a committed text may re-inject)"
                )
                delivered = frozenset()
            for text in injections:
                if text not in delivered:
                    self._queue.put_nowait(text)
            raise
        # A committed step served the reload; a failed step keeps the flag
        # so the next one retries it (a repeated trigger is idempotent).
        self._reload_skills = False
        return result

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

    async def _refresh_approvals(self) -> StateSnapshot:
        """Pull the checkpointed interrupts into the approval FIFO (arch §7.3).

        Returns:
            The fetched state snapshot (the resume path reads the delivered
            operator texts out of its checkpointed message history).
        """
        snapshot = await self._graph.aget_state(self.config)
        self._approvals.refresh(snapshot)
        return snapshot

    # ---- HITL decisions (arch §7.3) ----

    async def submit_decision(
        self,
        request_id: str,
        decision: Literal["approve", "edit", "reject"],
        edited_args: Mapping[str, object] | None = None,
    ) -> object:
        """Serve one approval decision and resume its interrupt (arch §7.3-§7.4).

        The queue journals the ``OperatorDecision`` first; when the decision
        completes a real graph interrupt's decision group, the returned
        ``Command(resume=...)`` is invoked under the single-writer lock.
        Judge-escalation requests carry an empty resume mapping — nothing to
        invoke, the registry resolution happened in the queue. A failed
        resume invocation re-enqueues the retired requests
        (:meth:`ApprovalQueue.reinstate`, Issue #26) before re-raising: the
        interrupt stays answerable instead of silently orphaning the queue.

        Returns:
            The graph result (``None`` when no resume was needed).
        """
        command = await self._approvals.submit_decision(request_id, decision, edited_args)
        resume = getattr(command, "resume", None)
        if not resume:
            return None
        try:
            result = await self._invoke_locked(command)
        except Exception:
            LOG.exception(
                "resume invocation of request %s failed; the approval request "
                "is reinstated for a retry",
                request_id,
            )
            self._approvals.reinstate(request_id)
            raise
        self._approvals.acknowledge_resume(request_id)
        return result

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
        interrupts into the approval FIFO, then scans the journal **from the
        beginning** through :meth:`_replay_envelope` (Issues #27/#46): the
        dispatch watermark is seeded by the scan itself — notifications are
        not re-injected (the pre-restart process already reacted to them and
        the TUI reads history from the journal), while operator messages the
        checkpoint proves undelivered are re-queued, so operator steering
        survives the restart.

        Args:
            journal_tail: ``JournalReader.range``-shaped reader
                (``range(0)`` returns the full journal).

        Returns:
            The number of replayed journal events.
        """
        snapshot = await self._refresh_approvals()
        delivered = _delivered_operator_texts(snapshot)
        replayed = await journal_tail(0)
        for envelope in replayed:
            self._replay_envelope(envelope, delivered)
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
