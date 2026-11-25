"""HITL strictness profiles → ``interrupt_on`` config and the approval queue
(arch §7.1-§7.4, roadmap T3.3.1/T3.3.2).

Two responsibilities of the human-in-the-loop subsystem live here:

* :func:`build_interrupt_config` renders the arch §7.2 "risk class x profile"
  matrix over a tool registry into the L0 ``interrupt_on`` mapping consumed by
  ``create_deep_agent`` (``dict[str, bool | InterruptOnConfig]``). Autonomy
  modes layer on top (arch §7.2, spec §5.5): ``interactive`` adds gates on
  designated significant-fork tools, ``mission`` keeps profile gates only.
  :func:`merge_interrupt_config` applies explicit module ``interrupt_on``
  entries over profile entries with the L0 replacement semantics.
* :class:`ApprovalQueue` polls ``snapshot.interrupts`` (L0 resume cycle,
  arch §7.1), maintains the FIFO of :class:`ApprovalRequest` visible to the
  TUI (arch §7.3), and turns operator decisions into
  ``Command(resume={interrupt_id: decision})`` — journaling every step as an
  ``OperatorDecision`` event (arch §7.3) without blocking the rest of the
  swarm (spec §9.2).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Final, Literal, TypeAlias

from langgraph.types import Command
from pydantic import BaseModel, ConfigDict

from swarmy.events.models import EventSource, OperatorDecisionPayload
from swarmy.guardrails.models import RiskClass

if TYPE_CHECKING:
    from langchain.agents.middleware import InterruptOnConfig
    from langgraph.types import StateSnapshot

    from swarmy.events.emit import EmitEventTool
    from swarmy.events.journal import JournalWriter

#: Strictness profiles (arch §7.2, D5).
StrictnessProfile: TypeAlias = Literal["paranoid", "normal", "yolo"]

#: Orchestrator autonomy modes (arch §7.2, spec §5.5).
AutonomyMode: TypeAlias = Literal["interactive", "mission"]

#: Decisions an operator can submit through the approval queue (arch §7.2).
ApprovalDecision: TypeAlias = Literal["approve", "edit", "reject"]

#: Which layer produced a gate (arch §7.3): the strictness profile, an explicit
#: module override, the interactive-mode significant forks, or the LLM judge
#: escalations of T3.4.x.
ApprovalOrigin: TypeAlias = Literal["profile", "module", "judge", "mode"]

#: The L0 decision vocabulary of ``InterruptOnConfig.allowed_decisions``
#: (``langchain.agents.middleware.human_in_the_loop.DecisionType`` — a private
#: re-export, mirrored here structurally).
DecisionType: TypeAlias = Literal["approve", "edit", "reject", "respond"]

#: Decisions offered on every swarmy gate (arch §7.2): the L0 ``respond``
#: decision is deliberately not offered — operator feedback reaches the agent
#: through ``reject``/``edit`` payloads, never through a synthetic answer.
ALLOWED_DECISIONS: Final[list[DecisionType]] = ["approve", "edit", "reject"]

#: Tools the ``interactive`` autonomy mode gates as significant forks
#: regardless of their risk class (arch §7.2, spec §5.5: launching a
#: vulnerability-class test run, verification, scope changes). ``mission``
#: keeps profile gates only. Extensible by session wiring (T3.3.4).
SIGNIFICANT_FORK_TOOLS: Final[frozenset[str]] = frozenset({"update_finding_status"})

#: arch §7.2 matrix: the risk classes each strictness profile gates with HITL
#: approvals. ``passive`` tools are never gated by a profile (D5).
_PROFILE_GATES: Final[Mapping[StrictnessProfile, frozenset[RiskClass]]] = {
    "paranoid": frozenset({RiskClass.NETWORK_WRITE, RiskClass.VERIFY, RiskClass.DESTRUCTIVE}),
    "normal": frozenset({RiskClass.VERIFY, RiskClass.DESTRUCTIVE}),
    "yolo": frozenset({RiskClass.DESTRUCTIVE}),
}

#: Byte-safe length cap of the default args digest (§6.8 conservative default).
_DIGEST_LIMIT: Final[int] = 512

#: Feedback the agent receives on ``reject``: the L0 middleware wraps the
#: message into ``User rejected the tool call for `<tool>` with reason: ...``
#: (a ``ToolMessage`` with ``status="error"``) — human_in_the_loop.py
#: ``_answer_message``.
_REJECT_MESSAGE: Final[str] = (
    "Rejected by the operator: this tool call was denied and was not executed."
)


def build_interrupt_config(
    profile: StrictnessProfile,
    risk_classes: Mapping[str, RiskClass],
    *,
    mode: AutonomyMode = "interactive",
    significant_tools: Iterable[str] = (),
    module_overrides: Mapping[str, bool | InterruptOnConfig] | None = None,
    allowed_decisions: Sequence[DecisionType] = ALLOWED_DECISIONS,
) -> dict[str, bool | InterruptOnConfig]:
    """Render the arch §7.2 "class x profile" matrix over a tool registry.

    Every registered tool name gets exactly one entry: ``False`` when the
    profile leaves its risk class ungated (``passive`` is never gated), or an
    ``InterruptOnConfig`` literal offering :data:`ALLOWED_DECISIONS` (arch
    §7.2: ``approve``/``edit``/``reject`` — L0 ``respond`` is not used).
    ``mode="interactive"`` additionally gates the designated significant-fork
    tools regardless of their risk class (arch §7.2, spec §5.5: launching a
    vulnerability-class test run, verification, scope changes);
    ``mode="mission"`` keeps profile gates only. ``module_overrides`` replace
    the entries of the tools they name (L0 semantics, see
    :func:`merge_interrupt_config`).

    The result feeds ``create_deep_agent(interrupt_on=...)`` directly (the L0
    parameter type is ``dict[str, bool | InterruptOnConfig]``; user entries
    win over generated filesystem-permission gates). Rebuilding with another
    profile/mode and recompiling the graph is the documented L0 operation for
    on-the-fly strictness changes (arch §7.2, T3.3.4).

    Args:
        profile: strictness profile (arch §7.2).
        risk_classes: registered tool name → declared risk class (AD-7: the
            class is authored with the tool, never inferred).
        mode: autonomy mode; ``interactive`` layers significant-fork gates
            over the profile (default), ``mission`` keeps profile gates only.
        significant_tools: tool names ``interactive`` gates as significant
            forks (e.g. ``update_finding_status``, verification HTTP calls);
            injectable so call sites stay in control; ignored by ``mission``.
        module_overrides: explicit module ``interrupt_on`` entries replacing
            profile entries (arch §7.1).
        allowed_decisions: decisions offered on each gate; defaults to
            :data:`ALLOWED_DECISIONS`.

    Returns:
        The ``interrupt_on`` mapping covering every registered tool name.

    Raises:
        ValueError: ``profile`` is not a known strictness profile.
    """
    gates = _PROFILE_GATES.get(profile)
    if gates is None:
        known = ", ".join(sorted(_PROFILE_GATES))
        msg = f"unknown strictness profile {profile!r}; known profiles: {known}"
        raise ValueError(msg)
    significant = frozenset(significant_tools)
    config: dict[str, bool | InterruptOnConfig] = {}
    for tool_name, risk in risk_classes.items():
        profile_gated = risk in gates
        if not profile_gated and not (mode == "interactive" and tool_name in significant):
            config[tool_name] = False
            continue
        reason = "risk class" if profile_gated else "significant fork of"
        description = (
            f"Tool {tool_name!r} ({reason} {risk.value}) requires operator approval "
            f"(profile {profile!r}, mode {mode!r})."
        )
        entry: InterruptOnConfig = {
            "allowed_decisions": list(allowed_decisions),
            "description": description,
        }
        config[tool_name] = entry
    if module_overrides is not None:
        config = merge_interrupt_config(config, module_overrides)
    return config


def merge_interrupt_config(
    base: Mapping[str, bool | InterruptOnConfig],
    module_overrides: Mapping[str, bool | InterruptOnConfig],
) -> dict[str, bool | InterruptOnConfig]:
    """Overlay module ``interrupt_on`` entries onto profile gates (arch §7.1).

    L0 semantics (``HumanInTheLoopMiddleware`` consumes the mapping as built):
    entries are merged with ``dict.update`` — an explicit module entry (``True``/
    ``False`` or a full ``InterruptOnConfig``) completely replaces the entry the
    profile produced for that tool, including its allowed decisions; tools the
    module does not name keep their profile gate.

    Args:
        base: profile-built config (every tool → ``False`` or a config entry).
        module_overrides: the module manifest's ``interrupt_on`` entries.

    Returns:
        A new mapping; ``base`` is not mutated.
    """
    merged: dict[str, bool | InterruptOnConfig] = dict(base)
    merged.update(module_overrides)
    return merged


def default_args_digest(args: Mapping[str, object]) -> str:
    """Compact deterministic projection of tool-call arguments (arch §7.3).

    The default performs no secret masking — sessions needing the §6.8
    guarantees inject :class:`ApprovalQueue` with the ContextProjector
    sanitizer; the queue only requires a ``Mapping -> str`` callable.

    Args:
        args: raw tool-call arguments of the interrupted call.

    Returns:
        Sorted compact JSON, truncated past :data:`_DIGEST_LIMIT`.
    """
    try:
        text = json.dumps(args, sort_keys=True, default=repr)
    except (TypeError, ValueError):  # pragma: no cover - defensive: cyclic args
        text = repr(dict(args))
    if len(text) > _DIGEST_LIMIT:
        return f"{text[:_DIGEST_LIMIT]} [truncated {len(text) - _DIGEST_LIMIT} chars]"
    return text


def _tool_and_args(value: object) -> tuple[str, dict[str, object]]:
    """Read ``(tool, args)`` out of one L0 interrupt value (arch §7.3).

    ``per_call`` interrupts carry the ``ToolApprovalRequest`` TypedDict
    (``name``/``args`` — human_in_the_loop.py); ``batched`` interrupts carry a
    ``HITLRequest`` whose ``action_requests`` list is flattened for display,
    because the queue addresses one interrupt per request. Unknown shapes
    degrade to ``("unknown", {})`` instead of raising — an operator must stay
    able to see and answer a request even if L0 changes its payload.

    Args:
        value: the ``Interrupt.value`` payload from the L0 state snapshot.

    Returns:
        Tool name (joined names for a batched request) and its arguments.
    """
    if not isinstance(value, Mapping):
        return "unknown", {}
    name = value.get("name")
    args = value.get("args")
    if isinstance(name, str) and isinstance(args, Mapping):
        return name, {str(key): item for key, item in args.items()}
    requests = value.get("action_requests")
    if isinstance(requests, Sequence):
        names: list[str] = []
        first_args: dict[str, object] = {}
        for request in requests:
            if not isinstance(request, Mapping):
                continue
            request_name = request.get("name")
            if isinstance(request_name, str):
                names.append(request_name)
            if not first_args and isinstance(request.get("args"), Mapping):
                request_args: Mapping[object, object] = request["args"]
                first_args = {str(key): item for key, item in request_args.items()}
        if names:
            return ", ".join(names), first_args
    return "unknown", {}


def _resume_payload(
    tool: str,
    decision: ApprovalDecision,
    edited_args: Mapping[str, object] | None,
) -> dict[str, object]:
    """Build one L0 decision object (the per-call and per-action shape).

    Contract verified against ``langchain/agents/middleware/human_in_the_loop.py``:
    approve → ``{"type": "approve"}``; edit → ``{"type": "edit",
    "edited_action": {"name": <tool>, "args": ...}}`` (``name`` is pinned to
    the interrupted tool — an edit cannot switch tools); reject →
    ``{"type": "reject", "message": ...}``, which the middleware converts
    into the ToolMessage the agent sees.
    """
    if decision == "approve":
        return {"type": "approve"}
    if decision == "reject":
        return {"type": "reject", "message": _REJECT_MESSAGE}
    if edited_args is None:
        msg = "decision 'edit' requires edited_args"
        raise ValueError(msg)
    return {"type": "edit", "edited_action": {"name": tool, "args": dict(edited_args)}}


def _resume_value(
    interrupt_value: object,
    decision: ApprovalDecision,
    edited_args: Mapping[str, object] | None,
) -> dict[str, object]:
    """Build the ``Command(resume={interrupt_id: ...})`` value for one interrupt.

    Two L0 shapes exist (``interrupt_mode`` of the HITL middleware): a
    *batched* interrupt (``HITLRequest`` with an ``action_requests`` list) is
    answered with ``{"decisions": [...]}`` — one decision per action request,
    in order; a *per-call* interrupt (``ToolApprovalRequest`` with
    ``name``/``args``) is answered with the bare decision object. Unknown
    shapes fall back to the bare object (fail-loud downstream, never silent).
    """
    if isinstance(interrupt_value, Mapping):
        requests = interrupt_value.get("action_requests")
        if isinstance(requests, Sequence):
            decisions = []
            for request in requests:
                name = (
                    str(request.get("name"))
                    if isinstance(request, Mapping) and request.get("name")
                    else "unknown"
                )
                decisions.append(_resume_payload(name, decision, edited_args))
            return {"decisions": decisions}
    name = interrupt_value.get("name") if isinstance(interrupt_value, Mapping) else None
    return _resume_payload(name if isinstance(name, str) else "unknown", decision, edited_args)


class ApprovalRequest(BaseModel):
    """One operator-facing approval entry (arch §7.3).

    ``args_digest`` is the sanitized projection of the interrupted call's
    arguments — what the operator actually sees (§6.8 shape). ``rule_or_profile``
    names the rule or strictness profile behind the gate. ``origin`` says which
    layer produced it: ``profile`` (strictness matrix), ``module`` (explicit
    module ``interrupt_on``), ``mode`` (interactive significant fork) or
    ``judge`` (LLM-judge escalation, T3.4.x).
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str
    interrupt_id: str
    tool: str
    args_digest: str
    rule_or_profile: str
    origin: ApprovalOrigin


class ApprovalQueue:
    """FIFO of pending approvals and operator decisions (arch §7.3, T3.3.2).

    Pure in-memory structure: :meth:`refresh` polls the L0 state snapshot and
    appends every *new* interrupt (already-known ids are skipped, so re-polling
    and resume are idempotent); :meth:`pending` hands the ordered view to the
    TUI's HITL Approvals panel; :meth:`submit_decision` turns one operator
    decision into the ``Command(resume={interrupt_id: decision})`` that
    continues exactly that interruption — the modal decision blocks its
    subagent only, other delegations keep running (arch §7.3, spec §9.2).

    Journaling (arch §7.3): every submitted step is appended as an
    ``OperatorDecision`` event — preferably through the injected platform
    ``emit`` callable (the ``make_emit_tool`` API: journal-first, then bus
    fan-out); when only a ``journal`` writer is injected, the envelope is
    appended directly without fan-out. With neither, decisions proceed
    unjournaled (headless unit tests).

    ``submit_decision`` is async because the journaling API is async; a lock
    serializes the journal+retire critical section so concurrent submissions
    keep FIFO decision order.
    """

    # arch §7.2 names this builder on the queue; it is the module function.
    build_interrupt_config = staticmethod(build_interrupt_config)

    def __init__(
        self,
        journal: JournalWriter | None = None,
        emit: EmitEventTool | None = None,
        sanitizer: Callable[[Mapping[str, object]], str] | None = None,
        *,
        origin: ApprovalOrigin = "profile",
        rule_or_profile: str = "profile",
    ) -> None:
        """Create an empty queue.

        Args:
            journal: session journal writer — direct-append fallback when no
                ``emit`` callable is available (no bus fan-out).
            emit: platform ``emit_event`` callable (``make_emit_tool`` API);
                the preferred journaling path (journal-first + fan-out).
            sanitizer: ``args → digest`` projection (§6.8); defaults to
                :func:`default_args_digest` (no secret masking).
            origin: origin stamped on refreshed requests without a per-tool
                override.
            rule_or_profile: rule/profile label stamped likewise.
        """
        self._journal = journal
        self._emit = emit
        self._digest = sanitizer if sanitizer is not None else default_args_digest
        self._origin = origin
        self._rule_or_profile = rule_or_profile
        self._pending: list[ApprovalRequest] = []
        self._by_request_id: dict[str, ApprovalRequest] = {}
        self._known_interrupt_ids: set[str] = set()
        self._interrupt_values: dict[str, object] = {}
        self._resolvers: dict[str, Callable[[ApprovalDecision], Awaitable[None]]] = {}
        self._counter = 0
        self._lock = asyncio.Lock()

    async def enqueue_external(
        self,
        tool: str,
        args_digest: str,
        *,
        origin: ApprovalOrigin = "judge",
        rule_or_profile: str = "judge",
        resolver: Callable[[ApprovalDecision], Awaitable[None]] | None = None,
    ) -> ApprovalRequest:
        """Enqueue a request that is not backed by a graph interrupt (arch §7.3).

        Judge escalations (T3.4.x) surface here with ``origin="judge"``:
        the triggering call was skipped by the judge band, and the request
        stays FIFO-ordered with the graph interrupts. Deciding such a
        request journals the ``OperatorDecision`` and runs the injected
        ``resolver`` (the escalation-registry resolution) — there is no
        ``Command(resume=...)`` for it (:meth:`submit_decision` returns an
        empty resume mapping and the runtime skips the graph invocation).

        Args:
            tool: the tool (or risk class) the escalation concerns.
            args_digest: sanitized projection for the operator.
            origin: the gate origin (``"judge"`` in v0.1).
            rule_or_profile: the judge rule label.
            resolver: async decision handler (removes the class gate).

        Returns:
            The enqueued request (FIFO tail).
        """
        self._counter += 1
        request = ApprovalRequest(
            request_id=f"apr-{self._counter:04d}",
            interrupt_id="",  # not interrupt-backed: no Command(resume) is built
            tool=tool,
            args_digest=args_digest,
            rule_or_profile=rule_or_profile,
            origin=origin,
        )
        self._pending.append(request)
        self._by_request_id[request.request_id] = request
        if resolver is not None:
            self._resolvers[request.request_id] = resolver
        return request

    def refresh(
        self,
        snapshot: StateSnapshot,
        *,
        origins: Mapping[str, ApprovalOrigin] | None = None,
        rules: Mapping[str, str] | None = None,
    ) -> None:
        """Pull ``snapshot.interrupts`` into the FIFO (arch §7.1, §7.3).

        Interrupts already seen (pending or answered) are skipped, so polling
        the same snapshot repeatedly is idempotent and a resume does not
        re-enqueue answered requests. ``origins``/``rules`` optionally map a
        tool name to the origin/label of its gate — the runtime derives them
        from the effective config it built (profile vs module override vs mode
        gate); tools without an entry fall back to the constructor defaults.

        Args:
            snapshot: L0 state snapshot (``graph.aget_state(config)`` result).
            origins: per-tool origin overrides (e.g. module-overridden tools
                → ``"module"``).
            rules: per-tool ``rule_or_profile`` labels.
        """
        origin_map: Mapping[str, ApprovalOrigin] = origins if origins is not None else {}
        rules_map: Mapping[str, str] = rules if rules is not None else {}
        for interrupt in snapshot.interrupts:
            if interrupt.id in self._known_interrupt_ids:
                continue
            self._known_interrupt_ids.add(interrupt.id)
            self._interrupt_values[interrupt.id] = interrupt.value
            tool, args = _tool_and_args(interrupt.value)
            self._counter += 1
            request = ApprovalRequest(
                request_id=f"apr-{self._counter:04d}",
                interrupt_id=interrupt.id,
                tool=tool,
                args_digest=self._digest(args),
                rule_or_profile=rules_map.get(tool, self._rule_or_profile),
                origin=origin_map.get(tool, self._origin),
            )
            self._pending.append(request)
            self._by_request_id[request.request_id] = request

    def pending(self) -> tuple[ApprovalRequest, ...]:
        """FIFO view of the requests awaiting an operator decision."""
        return tuple(self._pending)

    async def submit_decision(
        self,
        request_id: str,
        decision: ApprovalDecision,
        edited_args: Mapping[str, object] | None = None,
    ) -> Command[str]:
        """Apply one operator decision and resume its interrupt (arch §7.3-7.4).

        Builds the L0 resume payload, journals the step as ``OperatorDecision``
        *before* returning the resume command (journal-first discipline — a
        failed append leaves the request pending and retriable), then retires
        the request. The runtime invokes the returned command
        (``graph.ainvoke(Command(resume=...), config)``) to continue exactly
        the addressed interruption; approve does not cancel guardrails — the
        resumed tool call passes the same ``GuardrailPipeline`` (arch §7.4).

        Resume payload contract: see :func:`_resume_payload` (verified against
        the langchain ``human_in_the_loop`` middleware source — per-call
        decisions are TypedDict-shaped objects keyed by interrupt id, not
        booleans/strings).

        Args:
            request_id: id of the pending :class:`ApprovalRequest`.
            decision: the operator's decision.
            edited_args: replacement arguments — required for ``edit``; their
                digest is journaled as ``edited_args_digest``.

        Returns:
            ``Command(resume={interrupt_id: decision_payload})`` addressing
            exactly the interrupted tool call.

        Raises:
            ValueError: unknown ``request_id``, or ``edit`` without
                ``edited_args`` (the request stays pending and retriable).
        """
        request = self._by_request_id.get(request_id)
        if request is None:
            msg = (
                f"unknown request_id {request_id!r}: no pending approval request "
                f"(pending: {len(self._pending)})"
            )
            raise ValueError(msg)
        payload = (
            _resume_value(
                self._interrupt_values.get(request.interrupt_id),
                decision,
                edited_args,
            )
            if request.interrupt_id
            else {}
        )
        edited_digest = (
            self._digest(edited_args) if decision == "edit" and edited_args is not None else None
        )
        async with self._lock:
            await self._journal_decision(request, decision, edited_digest)
            self._pending.remove(request)
            self._by_request_id.pop(request_id, None)
            resolver = self._resolvers.pop(request_id, None)
        if resolver is not None:
            await resolver(decision)
        # N subscripted explicitly: the ``resume`` mapping does not constrain
        # Command's TypeVar, and the runtime resume state here is graph state.
        return Command[str](resume={request.interrupt_id: payload} if request.interrupt_id else {})

    async def _journal_decision(
        self,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        edited_digest: str | None,
    ) -> None:
        """Append the ``OperatorDecision`` envelope for one submitted step."""
        payload = OperatorDecisionPayload(
            request_id=request.request_id,
            decision=decision,
            edited_args_digest=edited_digest,
        )
        if self._emit is not None:
            await self._emit("OperatorDecision", payload.model_dump())
        elif self._journal is not None:
            await self._journal.append(
                type="OperatorDecision",
                source=EventSource.PLATFORM,
                source_detail="core.hitl",
                correlation_id="",
                payload=payload,
            )


__all__ = [
    "ALLOWED_DECISIONS",
    "ApprovalDecision",
    "ApprovalOrigin",
    "ApprovalQueue",
    "ApprovalRequest",
    "AutonomyMode",
    "DecisionType",
    "StrictnessProfile",
    "build_interrupt_config",
    "default_args_digest",
    "merge_interrupt_config",
]
