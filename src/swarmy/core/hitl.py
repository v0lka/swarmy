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
* :func:`build_session_interrupt_config` composes the session-wide views:
  the orchestrator's own gates plus, per named subagent module, the profile
  gates merged with that module's explicit ``interrupt_on`` overrides
  (arch §7.1) as a frozen :class:`InterruptConfig`.
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
from typing import TYPE_CHECKING, Final, Literal, NamedTuple, TypeAlias

from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field

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

#: Duck-typed graph state accessor (arch §7.1): an async
#: ``thread_config → snapshot`` callable — the ``graph.aget_state(config)``
#: seam of the L0 resume cycle. The queue never imports or holds a graph.
StateReader: TypeAlias = Callable[[object], Awaitable["StateSnapshot"]]

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

#: The verify/destructive floor the ``interactive`` mode gates regardless of
#: the profile (arch §7.2 bottom, spec §5.5: significant forks are launching a
#: vulnerability-class test run and verification). A ``yolo`` *mission* run
#: stays destructive-only; a ``yolo`` *interactive* **orchestrator** still
#: gates verify-class calls and the designated decision points.
#:
#: Reach (Issue #51, documented limitation): the floor is layered into the
#: *orchestrator-graph* gate matrix only — the loader builds each subagent's
#: ``interrupt_on`` from the profile gates plus module entries and has no
#: mode parameter, so a ``yolo`` interactive run does NOT extend the floor
#: into subagent graphs. No shipped tool declares ``verify``/``destructive``
#: risk classes in v0.1, so nothing binds today; revisit when a module does.
_INTERACTIVE_CLASS_FLOOR: Final[frozenset[RiskClass]] = frozenset(
    {RiskClass.VERIFY, RiskClass.DESTRUCTIVE}
)

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
    gates leave its risk class ungated (``passive`` is never gated), or an
    ``InterruptOnConfig`` literal offering :data:`ALLOWED_DECISIONS` (arch
    §7.2: ``approve``/``edit``/``reject`` — L0 ``respond`` is not used).
    Non-gated tools keep an explicit ``False`` entry — chosen over absence so
    the mapping stays total over the registry; for the L0 middleware an
    absent key and a ``False`` entry are equivalent (not gated).

    ``mode="interactive"`` layers the arch §7.2 significant forks over the
    profile (spec §5.5): the verify/destructive class floor
    (:data:`_INTERACTIVE_CLASS_FLOOR`) is gated regardless of the profile,
    and every ``significant_tools`` name (the decision-point markers) is
    gated regardless of its risk class. ``mode="mission"`` keeps the pure
    profile matrix. The default follows the documented session default
    (``interactive`` — config.py, arch §9.5; Issue #23): an omitted ``mode``
    must not silently select the *less* restrictive gate matrix.
    ``module_overrides`` replace the entries of the tools they name (L0
    semantics, see :func:`merge_interrupt_config`).

    The result feeds ``create_deep_agent(interrupt_on=...)`` directly (the L0
    parameter type is ``dict[str, bool | InterruptOnConfig]``; user entries
    win over generated filesystem-permission gates). Rebuilding with another
    profile/mode and recompiling the graph is the documented L0 operation for
    on-the-fly strictness changes (arch §7.2, T3.3.4).

    Args:
        profile: strictness profile (arch §7.2).
        risk_classes: registered tool name → declared risk class (AD-7: the
            class is authored with the tool, never inferred).
        mode: autonomy mode; ``interactive`` layers the class floor and the
            significant-fork decision points over the profile, ``mission``
            keeps profile gates only. Defaults to the documented session
            default ``interactive`` (Issue #23: the previous ``"mission"``
            default was the fail-open direction).
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
    if mode == "interactive":
        gates = gates | _INTERACTIVE_CLASS_FLOOR
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


class InterruptConfig(BaseModel):
    """Session-wide ``interrupt_on`` views (arch §7.1-§7.2, T3.3.1).

    ``orchestrator`` holds the gate mapping for the orchestrator's own tools;
    ``per_module`` carries, per named subagent module, the profile gates
    merged with that module's explicit ``interrupt_on`` overrides (arch
    §7.1: module entries replace profile entries per tool). Modules without
    overrides get no ``per_module`` entry — they inherit the orchestrator
    view as-is. Entries are plain dicts (``False`` or an
    ``InterruptOnConfig``-shaped mapping); rebuild the config on a
    profile/mode change and recompile the graph (documented L0 operation).
    """

    model_config = ConfigDict(frozen=True)

    orchestrator: dict[str, bool | dict[str, object]]
    per_module: dict[str, dict[str, bool | dict[str, object]]] = Field(default_factory=dict)


def _plain_gate_view(
    gates: Mapping[str, bool | InterruptOnConfig],
) -> dict[str, bool | dict[str, object]]:
    """Copy a gate mapping into the plain-dict entry shape of InterruptConfig."""
    view: dict[str, bool | dict[str, object]] = {}
    for tool_name, entry in gates.items():
        view[tool_name] = False if isinstance(entry, bool) else dict(entry)
    return view


def build_session_interrupt_config(
    profile: StrictnessProfile,
    tool_risk_classes: Mapping[str, RiskClass],
    *,
    mode: AutonomyMode = "interactive",
    significant_tools: Iterable[str] = (),
    module_overrides: Mapping[str, Mapping[str, bool | InterruptOnConfig]] | None = None,
    allowed_decisions: Sequence[DecisionType] = ALLOWED_DECISIONS,
) -> InterruptConfig:
    """Build the session-wide orchestrator and per-module gate views (T3.3.1).

    The orchestrator view is :func:`build_interrupt_config` over the whole
    tool registry. Each module named in ``module_overrides`` gets the same
    profile gates with its explicit entries overlaid per tool (arch §7.1 —
    an explicit module entry fully replaces the profile entry for that tool,
    including its allowed decisions; L0 replacement semantics). Modules
    absent from ``module_overrides`` get no ``per_module`` entry and inherit
    the orchestrator view unchanged.

    Args:
        profile: strictness profile (arch §7.2).
        tool_risk_classes: registered tool name → declared risk class (AD-7).
        mode: autonomy mode (arch §7.2): ``mission`` keeps the pure profile
            matrix; ``interactive`` additionally gates the verify/destructive
            class floor and the ``significant_tools`` decision points
            regardless of the profile. Defaults to the documented session
            default ``interactive`` (Issue #23).
        significant_tools: decision-point tool names ``interactive`` gates
            (e.g. vulnerability-class test runs, verification, scope
            changes); ignored by ``mission``.
        module_overrides: per-module ``interrupt_on`` entries replacing the
            profile entries of the tools they name.
        allowed_decisions: decisions offered on each generated gate;
            defaults to :data:`ALLOWED_DECISIONS`.

    Returns:
        A frozen :class:`InterruptConfig` (orchestrator + per-module views).
    """
    orchestrator = build_interrupt_config(
        profile,
        tool_risk_classes,
        mode=mode,
        significant_tools=significant_tools,
        allowed_decisions=allowed_decisions,
    )
    per_module: dict[str, dict[str, bool | dict[str, object]]] = {}
    if module_overrides is not None:
        for module_name, overrides in module_overrides.items():
            per_module[module_name] = _plain_gate_view(
                merge_interrupt_config(orchestrator, overrides)
            )
    return InterruptConfig(
        orchestrator=_plain_gate_view(orchestrator),
        per_module=per_module,
    )


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


class _ActionRecord(NamedTuple):
    """One gated call of an interrupt with its display facts (arch §7.3)."""

    tool: str
    args_digest: str
    origin: ApprovalOrigin
    rule_or_profile: str


class _InterruptGroup:
    """Per-action decision bookkeeping of one L0 interrupt (arch §7.3).

    The L0 HITL middleware runs in its default ``batched`` mode (deepagents
    0.7.x constructs ``HumanInTheLoopMiddleware`` without ``interrupt_mode``,
    so one assistant turn with N gated calls raises ONE interrupt whose value
    is a ``HITLRequest`` with N ``action_requests`` — verified against the
    pinned langchain source). The queue surfaces each action as its own
    :class:`ApprovalRequest` (per-call digests/origins, Issue #25) and builds
    the L0 resume value ``{"decisions": [...]}`` — one decision per action,
    in action order — once every action of the group is decided. A group with
    a single action (the ``per_call``/``ToolApprovalRequest`` shape) resumes
    immediately on its one decision.
    """

    __slots__ = ("actions", "decisions", "interrupt_id")

    def __init__(self, interrupt_id: str, actions: list[_ActionRecord]) -> None:
        self.interrupt_id = interrupt_id
        self.actions = actions
        self.decisions: dict[int, tuple[ApprovalDecision, Mapping[str, object] | None]] = {}


def _group_resume_value(group: _InterruptGroup, interrupt_value: object) -> object:
    """Build the L0 resume value from the recorded per-action decisions.

    Contract verified against the pinned langchain source: a *batched*
    interrupt (``HITLRequest`` with an ``action_requests`` list) is answered
    with ``{"decisions": [...]}`` — one decision object per action request,
    in action order (the middleware validates the count and consumes
    decisions positionally; a single-action batched interrupt still demands
    the decisions list). A *per-call* interrupt (``ToolApprovalRequest`` with
    ``name``/``args``) is answered with the bare decision object. Each
    decision carries its own action's tool name and edited args — an operator
    edit can no longer rewrite a sibling call with foreign arguments
    (Issue #25). The shape is read from the saved interrupt value, not from
    the action count: both shapes exist with a single action.
    """
    batched = (
        isinstance(interrupt_value, Mapping)
        and isinstance(interrupt_value.get("action_requests"), Sequence)
    )
    if not batched:
        decision, edited = group.decisions[0]
        return _resume_payload(group.actions[0].tool, decision, edited)
    decisions: list[dict[str, object]] = []
    for index, action in enumerate(group.actions):
        decision, edited = group.decisions[index]
        decisions.append(_resume_payload(action.tool, decision, edited))
    return {"decisions": decisions}


def _action_views(value: object) -> list[tuple[str, dict[str, object]]]:
    """Split one L0 interrupt value into ``(tool, args)`` per gated call.

    A *per-call* interrupt (``ToolApprovalRequest`` TypedDict with
    ``name``/``args``) yields one view; a *batched* interrupt (``HITLRequest``
    with ``action_requests``) yields one view per action request. Unknown
    shapes degrade to a single ``("unknown", {})`` view instead of raising —
    an operator must stay able to see and answer a request even if L0 changes
    its payload.

    Args:
        value: the ``Interrupt.value`` payload from the L0 state snapshot.

    Returns:
        ``(tool, args)`` pairs, one per gated call of the interrupt.
    """
    if not isinstance(value, Mapping):
        return [("unknown", {})]
    name = value.get("name")
    args = value.get("args")
    if isinstance(name, str) and isinstance(args, Mapping):
        return [(name, {str(key): item for key, item in args.items()})]
    requests = value.get("action_requests")
    if isinstance(requests, Sequence):
        views: list[tuple[str, dict[str, object]]] = []
        for request in requests:
            if not isinstance(request, Mapping):
                views.append(("unknown", {}))
                continue
            request_name = request.get("name")
            request_args = request.get("args")
            if isinstance(request_name, str) and isinstance(request_args, Mapping):
                views.append(
                    (request_name, {str(key): item for key, item in request_args.items()})
                )
            else:
                views.append(("unknown", {}))
        if views:
            return views
    return [("unknown", {})]


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


class ApprovalRequest(BaseModel):
    """One operator-facing approval entry (arch §7.3).

    ``args_digest`` is the sanitized projection of the interrupted call's
    arguments — what the operator actually sees (§6.8 shape). ``rule_or_profile``
    names the rule or strictness profile behind the gate. ``origin`` says which
    layer produced it: ``profile`` (strictness matrix), ``module`` (explicit
    module ``interrupt_on``), ``mode`` (interactive significant fork) or
    ``judge`` (LLM-judge escalation, T3.4.x).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    interrupt_id: str
    tool: str
    args_digest: str
    rule_or_profile: str
    origin: ApprovalOrigin = "profile"


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

    Polling (arch §7.1): the caller may pass ``snapshot.interrupts``
    directly to :meth:`refresh` (the committed runtime path), or the queue
    is built with a ``state_reader`` and polls itself through
    :meth:`refresh_from_config` — the duck-typed ``graph.aget_state`` seam;
    both merges are idempotent on interrupt ids.

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
        state_reader: StateReader | None = None,
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
            state_reader: duck-typed graph accessor — async
                ``thread_config → snapshot`` (the ``graph.aget_state`` API,
                arch §7.1); enables :meth:`refresh_from_config` polling.
            origin: origin stamped on refreshed requests without a per-tool
                override.
            rule_or_profile: rule/profile label stamped likewise.
        """
        self._journal = journal
        self._emit = emit
        self._state_reader = state_reader
        self._digest = sanitizer if sanitizer is not None else default_args_digest
        self._origin = origin
        self._rule_or_profile = rule_or_profile
        self._pending: list[ApprovalRequest] = []
        self._by_request_id: dict[str, ApprovalRequest] = {}
        self._known_interrupt_ids: set[str] = set()
        self._interrupt_values: dict[str, object] = {}
        self._resolvers: dict[str, Callable[[ApprovalDecision], Awaitable[None]]] = {}
        # Issue #25: batched interrupts expand into one request per action;
        # the group tracks per-action decisions until all of them are decided.
        self._groups: dict[str, _InterruptGroup] = {}
        # Completed groups kept for Issue #26 recovery: a failed resume
        # invocation re-enqueues them via :meth:`reinstate`; a successful one
        # drops them via :meth:`acknowledge_resume`.
        self._completed_groups: dict[str, _InterruptGroup] = {}
        self._request_group: dict[str, _InterruptGroup] = {}
        self._request_action: dict[str, int] = {}
        self._request_interrupt: dict[str, str] = {}
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
        re-enqueue answered requests. A batched interrupt (``HITLRequest``
        with several ``action_requests``) is expanded into one
        :class:`ApprovalRequest` **per action** (Issue #25): each carries its
        own digest, origin and label, and the group's resume value is built
        once every action is decided. ``origins``/``rules`` optionally map a
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
            # Issue #25: a batched L0 interrupt (one assistant turn with N
            # gated calls) expands into one request per action — per-call
            # digests/origins/labels instead of one joined-name entry.
            actions = [
                _ActionRecord(
                    tool=tool,
                    args_digest=self._digest(args),
                    origin=origin_map.get(tool, self._origin),
                    rule_or_profile=rules_map.get(tool, self._rule_or_profile),
                )
                for tool, args in _action_views(interrupt.value)
            ]
            group = _InterruptGroup(interrupt.id, actions)
            self._groups[interrupt.id] = group
            for index, action in enumerate(actions):
                self._counter += 1
                request = ApprovalRequest(
                    request_id=f"apr-{self._counter:04d}",
                    interrupt_id=interrupt.id,
                    tool=action.tool,
                    args_digest=action.args_digest,
                    rule_or_profile=action.rule_or_profile,
                    origin=action.origin,
                )
                self._pending.append(request)
                self._by_request_id[request.request_id] = request
                self._request_group[request.request_id] = group
                self._request_action[request.request_id] = index
                self._request_interrupt[request.request_id] = interrupt.id

    async def refresh_from_config(self, thread_config: object) -> list[ApprovalRequest]:
        """Poll the graph through the injected ``state_reader`` (arch §7.1).

        The delegation-shaped polling entry: fetches
        ``state_reader(thread_config)`` — the ``graph.aget_state(config)``
        seam — then runs the same idempotent :meth:`refresh` merge and
        returns the FIFO. Deliberately *not* named ``refresh``: the committed
        runtime polls snapshots directly through the synchronous
        :meth:`refresh`, and an un-awaited coroutine of a same-named async
        replacement would silently no-op those call sites.

        Args:
            thread_config: langgraph thread config (``{"configurable":
                {"thread_id": ...}}``); passed to the state reader verbatim.

        Returns:
            The pending requests in FIFO order after the poll.

        Raises:
            TypeError: the queue was built without a ``state_reader``.
        """
        if self._state_reader is None:
            msg = "refresh_from_config requires a state_reader (constructor argument)"
            raise TypeError(msg)
        snapshot = await self._state_reader(thread_config)
        self.refresh(snapshot)
        return list(self.pending())

    def pending(self) -> tuple[ApprovalRequest, ...]:
        """FIFO view of the requests awaiting an operator decision."""
        return tuple(self._pending)

    async def submit_decision(
        self,
        request_id: str,
        decision: ApprovalDecision,
        edited_args: Mapping[str, object] | None = None,
        *,
        graph_runner: Callable[[Command[str]], Awaitable[object]] | None = None,
    ) -> Command[str]:
        """Apply one operator decision and resume its interrupt (arch §7.3-7.4).

        Journals the step as an ``OperatorDecision`` *before* any state change
        (journal-first discipline — a failed append leaves the request pending
        and retriable), then retires the request and records the per-action
        decision in its group (Issue #25). A batched interrupt resumes only
        once **every** action of its group is decided; the built resume value
        then carries one decision object per action, in action order, each
        with its own tool name and edited args (verified against the langchain
        ``human_in_the_loop`` middleware source). A single-action (per-call)
        interrupt resumes immediately, exactly as before.

        The runtime invokes the returned command
        (``graph.ainvoke(Command(resume=...), config)``) to continue exactly
        the addressed interruption; approve does not cancel guardrails — the
        resumed tool call passes the same ``GuardrailPipeline`` (arch §7.4).

        Args:
            request_id: id of the pending :class:`ApprovalRequest`.
            decision: the operator's decision.
            edited_args: replacement arguments — required for ``edit``; their
                digest is journaled as ``edited_args_digest``.
            graph_runner: optional async sink for the built command (the
                runtime's ``graph.ainvoke(command, config)`` seam, arch
                §7.1). The queue never invokes the graph itself; when the
                runner is injected and the group is complete, the command is
                handed to it after journaling and retirement. A runner
                failure re-enqueues the group (:meth:`reinstate`, Issue #26)
                before re-raising — the interrupt stays answerable.

        Returns:
            ``Command(resume={interrupt_id: decision_payload})`` addressing
            exactly the interrupted call — for a batched group, the L0
            ``{"decisions": [...]}`` value over the recorded per-action
            decisions. An empty resume mapping is returned for external judge
            requests and for partially-decided groups (the remaining actions
            are still pending). The same command is handed to
            ``graph_runner`` when one is injected.

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
        if decision == "edit" and edited_args is None:
            # Refused before any journaling or retirement: the request stays
            # pending and retriable (same contract as the per-call era).
            msg = "decision 'edit' requires edited_args"
            raise ValueError(msg)
        group = self._request_group.get(request_id)
        action_index = self._request_action.get(request_id)
        edited_digest = (
            self._digest(edited_args) if decision == "edit" and edited_args is not None else None
        )
        complete = False
        async with self._lock:
            await self._journal_decision(request, decision, edited_digest)
            self._pending.remove(request)
            self._by_request_id.pop(request_id, None)
            resolver = self._resolvers.pop(request_id, None)
            if group is not None and action_index is not None:
                # Record the per-action decision (Issue #25): the L0 resume
                # value is built only once every action of the group is
                # decided, each with its own tool name and edited args.
                group.decisions[action_index] = (decision, edited_args)
                complete = len(group.decisions) == len(group.actions)
                if complete:
                    self._groups.pop(group.interrupt_id, None)
                    self._completed_groups[group.interrupt_id] = group
        if resolver is not None:
            await resolver(decision)
        if group is None or not complete:
            # External judge request (no group) or a partially-decided batched
            # interrupt: nothing to resume yet — the remaining actions keep
            # their FIFO entries and the last decision triggers the resume.
            return Command[str](resume={})
        # N subscripted explicitly: the ``resume`` mapping does not constrain
        # Command's TypeVar, and the runtime resume state here is graph state.
        resume = {
            group.interrupt_id: _group_resume_value(
                group, self._interrupt_values.get(group.interrupt_id)
            )
        }
        command = Command[str](resume=resume)
        if graph_runner is not None:
            try:
                await graph_runner(command)
            except Exception:
                # Issue #26: the interrupt is still live in the checkpointed
                # graph — retire-before-invoke must not orphan it. Re-enqueue
                # the group so the operator can retry (the journaled decisions
                # of the failed attempt stay: an honest audit trail).
                self.reinstate(request_id)
                raise
        return command

    def reinstate(self, request_id: str) -> tuple[ApprovalRequest, ...]:
        """Re-enqueue the decided actions of an interrupt (arch §7.3, #26).

        Recovery path for a failed resume invocation: the request group was
        retired when its last action was decided, but the interrupt is still
        live in the checkpointed graph — without this, the operator would face
        an empty approvals queue and no supported way to answer the interrupt
        again. Every action of the group is re-enqueued with a **fresh**
        request id (the retired ids stay in the journal's ``OperatorDecision``
        rows — the retry is a new, honestly-audited attempt), the recorded
        decisions are discarded, and the group returns to the pending state.
        A later successful resume must call :meth:`acknowledge_resume` so a
        consumed interrupt cannot be resurrected.

        Args:
            request_id: any request id of the group (pending or already
                retired — the lookup survives retirement).

        Returns:
            The freshly enqueued requests, in action order.

        Raises:
            ValueError: the request id is unknown or its group was already
                acknowledged (the resume succeeded — nothing to reinstate).
        """
        interrupt_id = self._request_interrupt.get(request_id)
        group = self._completed_groups.pop(interrupt_id, None) if interrupt_id else None
        if group is None:
            msg = (
                f"request {request_id!r} has no reinstatable interrupt: either the id "
                f"is unknown, the group is still pending, or the resume already succeeded"
            )
            raise ValueError(msg)
        group.decisions = {}
        reinstated: list[ApprovalRequest] = []
        for index, action in enumerate(group.actions):
            self._counter += 1
            request = ApprovalRequest(
                request_id=f"apr-{self._counter:04d}",
                interrupt_id=group.interrupt_id,
                tool=action.tool,
                args_digest=action.args_digest,
                rule_or_profile=action.rule_or_profile,
                origin=action.origin,
            )
            self._pending.append(request)
            self._by_request_id[request.request_id] = request
            self._request_group[request.request_id] = group
            self._request_action[request.request_id] = index
            self._request_interrupt[request.request_id] = group.interrupt_id
            reinstated.append(request)
        self._groups[group.interrupt_id] = group
        return tuple(reinstated)

    def acknowledge_resume(self, request_id: str) -> None:
        """Drop the completed group record after a successful resume (#26).

        Called by the runtime when the resume invocation returned: the
        interrupt is consumed, so :meth:`reinstate` must no longer resurrect
        it. No-op when the request carries no group record (external judge
        requests, already-acked groups).
        """
        interrupt_id = self._request_interrupt.get(request_id)
        if interrupt_id is not None:
            self._completed_groups.pop(interrupt_id, None)

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
    "InterruptConfig",
    "StateReader",
    "StrictnessProfile",
    "build_interrupt_config",
    "build_session_interrupt_config",
    "default_args_digest",
    "merge_interrupt_config",
]
