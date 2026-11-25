"""``GuardrailPipeline`` + ``GuardrailMiddleware``: the pre-tool-call gate (arch §6.5, T1.4.5).

AND-composition of three deterministic layers (spec §8.2, D11): a deny from
*any* layer denies the operation; allowing requires every layer to allow.
Evaluation order is fixed — layer 1 invariants → layer 2 engine rules →
layer 3 the module's own rules for its own tools — and the first denial
becomes the agent feedback, so reports are deterministic.

The LLM judge band (arch §6.7, P3.4/RD-2) is consulted **only after** layers
1-3 allowed the call (T3.4.1 spy-AC); it can flag a call for the record or
escalate it to HITL, never unblock a deterministic deny (D11), and no LLM
sits in the critical path of a denial (arch §17).

Violation semantics (spec §8.5): a blocked call is **not executed**. The
pipeline hands the ``GuardrailBlockedPayload`` to the wiring-provided sink —
the sink appends it to the journal *before* any bus fan-out (arch §5.3,
invariant 2) and the middleware returns a textual feedback (rule id, layer,
reason) to the agent instead of the tool result. Forced override is
operator-only via HITL.

``tool_args_digest`` routes the deterministic JSON serialization of the
arguments through the ``ContextProjector`` (T2.3.2, RD-4 closed): operator
secrets are masked and the §6.8 budget/normalization steps run before the
digest is stored, so the journal never carries a verbatim secret.

Assembly (arch §6.5): each ``GuardrailMiddleware`` instance carries the full
layer set of its agent — subagent: invariants + engine + the module's own
rules; orchestrator: invariants + engine (``module_guardrails=None``).

L0 extension point (arch §2.1 table, §19.1): verified against the pinned
deepagents 0.7.41 stack — the hook is ``AgentMiddleware.awrap_tool_call``
(langchain 1.5.2) receiving a ``langgraph.prebuilt.tool_node.ToolCallRequest``
whose ``tool_call`` dict carries ``name``/``args``/``id``; returning a
``ToolMessage`` skips the handler, i.e. skips the tool. The synchronous
``wrap_tool_call`` is deliberately fail-closed: swarmy runs agents
asynchronously only.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, NamedTuple, Protocol

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from pydantic import BaseModel, ConfigDict

from swarmy.events.models import GuardrailBlockedPayload
from swarmy.guardrails.engine_rules import default_engine_rules
from swarmy.guardrails.invariants import InvariantLayer, default_invariants
from swarmy.guardrails.models import (
    BlockedFeedback,
    GuardrailLayer,
    GuardrailRule,
    ModuleGuardrails,
    Verdict,
    feedback_text,
)
from swarmy.tools.projector import ContextProjector

if TYPE_CHECKING:
    from langgraph.prebuilt.tool_node import ToolCallRequest
    from langgraph.types import Command

#: Payload sink invoked on a denial (arch §6.5): the wiring binds it to the
#: session journal + bus with journal-append *before* bus fan-out (§5.3).
#: ``None`` (tests, pure evaluation) skips violation recording.
BlockedSink = Callable[[GuardrailBlockedPayload], Awaitable[None]]


class JudgeBand(Protocol):
    """The judge-slot contract (arch §6.7, P3.4/RD-2).

    Implemented over :class:`~swarmy.guardrails.judge.LlmJudge` by the
    session wiring; consulted by :meth:`GuardrailPipeline.check_and_report`
    **only after** layers 1-3 allowed the call (T3.4.1 spy-AC) — the band
    journals its own notes and never unblocks a deterministic deny (D11).
    """

    def gate_for(self, tool_name: str) -> tuple[Verdict, BlockedFeedback | None] | None:
        """Standing class verdict for the tool (deny / pending escalation) or ``None``."""
        ...

    async def precall(
        self, tool_name: str, tool_args: Mapping[str, object], args_digest: str
    ) -> tuple[Verdict, BlockedFeedback | None] | None:
        """Judge one deterministically-allowed call.

        Returns ``None`` when the band does not apply to the tool (not
        judged); otherwise the ``(verdict, feedback)`` outcome.
        """
        ...

#: Projector used when a pipeline is built without an explicit one (tests,
#: pure evaluation): default conservative budgets, built-in masking
#: detectors, no injected operator secrets (they arrive with the session
#: wiring, T3.1.1). Untrusted marking stays on — arguments may echo
#: target-derived content.
_DIGEST_PROJECTOR = ContextProjector()

#: Argument keys that carry the request URL of an HTTP tool.
_URL_ARG_KEYS: frozenset[str] = frozenset({"url", "base_url"})

#: Argument keys that carry the request body of an HTTP tool.
_BODY_ARG_KEYS: frozenset[str] = frozenset({"body", "data", "json"})

#: Argument keys that carry request headers of an HTTP tool.
_HEADER_ARG_KEYS: frozenset[str] = frozenset({"headers"})


class EvaluationResult(BaseModel):
    """Outcome of a pipeline evaluation (arch §6.5).

    ``feedback`` is set exactly when the verdict is a denial.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    feedback: BlockedFeedback | None = None


def tool_args_digest(
    tool_args: Mapping[str, object], projector: ContextProjector | None = None
) -> str:
    """Build the sanitized arguments digest of a blocked call (arch §5.1, §6.8).

    The deterministic JSON serialization (stringified leaves, sorted keys)
    is routed through the ``ContextProjector`` (T2.3.2, RD-4 closed): secret
    masking runs *before* the digest enters the journal, so an operator
    secret echoed in the arguments can never surface verbatim in journal or
    model contexts. Serialization and projection are pure — the same
    arguments always produce the same digest.

    Args:
        tool_args: the blocked call's arguments.
        projector: projector carrying the session's secret rules; ``None``
            uses the module default (built-in detectors, default budget).

    Returns:
        The projected digest string.
    """
    try:
        raw = json.dumps(tool_args, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        raw = repr(tool_args)
    active = projector if projector is not None else _DIGEST_PROJECTOR
    return active.project(raw)


def blocked_feedback_text(feedback: BlockedFeedback) -> str:
    """Render the agent-facing textual feedback of a deny (spec §8.5).

    Delegates to the canonical renderer of :mod:`swarmy.guardrails.models`
    (single wording source shared with ``GuardrailBlocked.agent_text``).

    Args:
        feedback: the structured denial.

    Returns:
        The feedback text returned to the agent in place of the tool result.
    """
    return feedback_text(feedback)


def _string_leaves(value: object) -> Iterator[str]:
    """Yield every string leaf of an (untrusted) argument tree."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _string_leaves(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _string_leaves(item)


def _values_under(tool_args: Mapping[str, object], keys: frozenset[str]) -> list[str]:
    """String leaves of the arguments stored under ``keys``."""
    found: list[str] = []
    for key in keys:
        value = tool_args.get(key)
        if value is not None:
            found.extend(_string_leaves(value))
    return found


def _serialized_size(value: object) -> int:
    """UTF-8 byte size of the JSON serialization of one argument value.

    Deliberately the raw size, not a projected digest: ``body_size_above``
    predicates must measure the call the guardrails judge (the pre-tool-call
    gate sees raw arguments; projection is a model-bound concern, arch §6.8).
    """
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return len(repr(value).encode("utf-8"))


def _body_size(tool_args: Mapping[str, object]) -> int:
    """Serialized byte size of the largest body-shaped argument (arch §6.6)."""
    sizes = [0]
    for key in _BODY_ARG_KEYS:
        value = tool_args.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            sizes.append(len(value.encode("utf-8")))
        elif isinstance(value, (bytes, bytearray)):
            sizes.append(len(value))
        else:
            sizes.append(_serialized_size(value))
    return max(sizes)


def _regex_hits(pattern: re.Pattern[str], values: Iterable[str]) -> bool:
    """True when the pattern matches any of the values (disjunction)."""
    return any(pattern.search(value) is not None for value in values)


class _CompiledRule(NamedTuple):
    """A rule with its regex predicates compiled once (fail-fast at build)."""

    rule: GuardrailRule
    any_param_re: re.Pattern[str] | None
    url_re: re.Pattern[str] | None
    header_re: re.Pattern[str] | None

    @classmethod
    def compile(cls, rule: GuardrailRule) -> _CompiledRule:
        """Compile the rule's regexes; a bad pattern raises immediately.

        Raises:
            re.error: when a predicate is not a valid Python regex (module
                rules are pre-validated by ``dsl.py``; engine rules are code).
        """

        def _one(pattern: str | None) -> re.Pattern[str] | None:
            return re.compile(pattern) if pattern is not None else None

        condition = rule.condition
        return cls(
            rule=rule,
            any_param_re=_one(condition.any_param_matches),
            url_re=_one(condition.url_matches),
            header_re=_one(condition.header_matches),
        )


def evaluate_rule(compiled: _CompiledRule, tool_name: str, tool_args: Mapping[str, object]) -> bool:
    """Evaluate one compiled rule against a tool call (arch §6.6).

    Conjunction across predicates: the rule fires only when *every* set
    predicate holds (``any_param_matches`` is a regex whose internal
    alternation is the disjunction, spec §8.3).

    Args:
        compiled: the rule with precompiled regexes.
        tool_name: name of the tool being called.
        tool_args: arguments of the call.

    Returns:
        ``True`` when the rule denies the call.
    """
    rule = compiled.rule
    if tool_name not in rule.applies_to:
        return False
    condition = rule.condition
    if condition.tool_in is not None and tool_name not in condition.tool_in:
        return False
    if compiled.any_param_re is not None and not _regex_hits(
        compiled.any_param_re, _string_leaves(tool_args)
    ):
        return False
    if compiled.url_re is not None and not _regex_hits(
        compiled.url_re, _values_under(tool_args, _URL_ARG_KEYS)
    ):
        return False
    if compiled.header_re is not None and not _regex_hits(
        compiled.header_re, _values_under(tool_args, _HEADER_ARG_KEYS)
    ):
        return False
    if (
        condition.body_size_above is not None
        and _body_size(tool_args) <= condition.body_size_above
    ):
        return False
    return True


def _first_denial(
    rules: Sequence[_CompiledRule],
    layer: GuardrailLayer,
    tool_name: str,
    tool_args: Mapping[str, object],
) -> BlockedFeedback | None:
    """Feedback of the first denying rule of one layer (deterministic order)."""
    for compiled in rules:
        if evaluate_rule(compiled, tool_name, tool_args):
            return BlockedFeedback(
                rule_id=compiled.rule.id, layer=layer, reason=compiled.rule.message
            )
    return None


class GuardrailPipeline:
    """Three-layer AND-composition evaluator (arch §6.5, spec §8.2).

    A deny of any layer denies; allow requires all layers (D11). The judge
    slot is reserved for P3.4 (RD-2) and empty in v0.1.
    """

    __slots__ = (
        "_engine_enabled",
        "_engine_rules",
        "_invariants",
        "_judge_band",
        "_module_rules",
        "_projector",
        "_sink",
    )

    def __init__(
        self,
        *,
        invariants: InvariantLayer | None = None,
        engine_rules: Sequence[GuardrailRule] | None = None,
        engine_rules_enabled: bool = True,
        module_guardrails: ModuleGuardrails | None = None,
        blocked_sink: BlockedSink | None = None,
        projector: ContextProjector | None = None,
        judge_band: JudgeBand | None = None,
    ) -> None:
        """Assemble the layer set of one agent (arch §6.5).

        Defaults build the canonical stacks: the platform invariant layer,
        the shipped engine rules (disableable) and — for subagents — the
        module's own ``guardrails.yaml`` rules; the orchestrator passes
        ``module_guardrails=None``.

        Args:
            invariants: the layer-1 set (defaults to
                :func:`~swarmy.guardrails.invariants.default_invariants`).
            engine_rules: the layer-2 set (defaults to
                :func:`~swarmy.guardrails.engine_rules.default_engine_rules`).
            engine_rules_enabled: the whole-set disable flag (config key
                ``guardrails.engine_rules`` is read only from T3.1.1).
            module_guardrails: the agent's own module rules (layer 3) —
                ``None`` for the orchestrator.
            blocked_sink: violation recorder (journal-before-bus, arch §5.3);
                ``None`` skips recording (pure evaluation).
            projector: the session projector supplying secret rules for
                ``tool_args_digest`` (arch §6.8, T2.3.2); ``None`` uses the
                module default until the session wiring lands (T3.1.1).
            judge_band: the LLM-judge band (arch §6.7, P3.4/RD-2) consulted
                only after layers 1-3 allowed the call; ``None`` keeps the
                reserved slot empty (deterministic-only pipeline).
        """
        layer = invariants if invariants is not None else InvariantLayer(default_invariants())
        rules = default_engine_rules() if engine_rules is None else engine_rules
        self._invariants = layer
        self._engine_enabled = engine_rules_enabled
        self._engine_rules = (
            tuple(_CompiledRule.compile(rule) for rule in rules) if engine_rules_enabled else ()
        )
        self._module_rules = tuple(
            _CompiledRule.compile(rule)
            for rule in (module_guardrails.rules if module_guardrails is not None else ())
        )
        self._sink = blocked_sink
        self._projector = projector if projector is not None else _DIGEST_PROJECTOR
        self._judge_band = judge_band

    def evaluate(self, tool_name: str, tool_args: Mapping[str, object]) -> EvaluationResult:
        """Evaluate the call against layers 1→2→3 (no side effects).

        Args:
            tool_name: name of the tool being called.
            tool_args: arguments of the call.

        Returns:
            ``Verdict.ALLOW`` or ``Verdict.BLOCK`` with the denying layer's
            feedback (judge verdicts arrive with P3.4, RD-2).
        """
        feedback = self._invariants.evaluate(tool_name, tool_args)  # layer 1
        if feedback is None and self._engine_enabled:  # layer 2
            feedback = _first_denial(self._engine_rules, "engine", tool_name, tool_args)
        if feedback is None:  # layer 3: the module's rules for its own tools
            feedback = _first_denial(self._module_rules, "module", tool_name, tool_args)
        if feedback is not None:
            return EvaluationResult(verdict=Verdict.BLOCK, feedback=feedback)
        return EvaluationResult(verdict=Verdict.ALLOW)

    async def check_and_report(
        self, tool_name: str, tool_args: Mapping[str, object]
    ) -> EvaluationResult:
        """Evaluate, and on a deny record the violation via the sink.

        Flow: layers 1-3 (deterministic, AND-composition) — a deterministic
        deny is recorded via the sink and never reaches the judge (T3.4.1
        spy-AC, D11). When the layers allow and a judge band is installed,
        the band produces the final verdict: its outcomes (flag notes,
        escalations) are journaled by the band's own sink, so this method
        does *not* pass them through ``blocked_sink`` again.

        The sink (session wiring) appends ``GuardrailBlocked`` to the journal
        *before* the bus fan-out (arch §5.3 invariant 2); the call itself is
        never executed on a deny/escalation (spec §8.5).

        Args:
            tool_name: name of the tool being called.
            tool_args: arguments of the call.

        Returns:
            The evaluation result the middleware acts on.
        """
        result = self.evaluate(tool_name, tool_args)
        deterministic_deny = result.verdict is Verdict.BLOCK
        if not deterministic_deny and self._judge_band is not None:
            standing = self._judge_band.gate_for(tool_name)
            if standing is not None:
                result = EvaluationResult(verdict=standing[0], feedback=standing[1])
            else:
                outcome = await self._judge_band.precall(
                    tool_name, tool_args, tool_args_digest(tool_args, self._projector)
                )
                if outcome is not None:
                    verdict, feedback = outcome
                    result = EvaluationResult(verdict=verdict, feedback=feedback)
        if (
            deterministic_deny
            and result.feedback is not None
            and self._sink is not None
        ):
            await self._sink(
                GuardrailBlockedPayload(
                    tool_name=tool_name,
                    rule_id=result.feedback.rule_id,
                    layer=result.feedback.layer,
                    reason=result.feedback.reason,
                    tool_args_digest=tool_args_digest(tool_args, self._projector),
                )
            )
        return result


class GuardrailMiddleware(AgentMiddleware):
    """L0 pre-tool-call middleware wrapping the pipeline (arch §6.5).

    Built on the documented deepagents/langchain middleware extension point
    (pinned sources, arch §19.1): ``AgentMiddleware.awrap_tool_call`` with a
    ``ToolCallRequest``; returning a ``ToolMessage`` without calling the
    handler skips the tool — exactly the violation semantics of spec §8.5.
    """

    __slots__ = ("_pipeline",)

    def __init__(self, pipeline: GuardrailPipeline) -> None:
        """Bind the pipeline carrying this agent's full layer set."""
        self._pipeline = pipeline

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[object]]],
    ) -> ToolMessage | Command[object]:
        """Gate one tool call; on a deny return feedback instead of executing.

        Args:
            request: the L0 tool-call request (``tool_call``: name/args/id).
            handler: the L0 continuation that would execute the tool.

        Returns:
            The tool result when allowed, otherwise the guardrail feedback
            message addressed to the agent (spec §8.5).
        """
        tool_call = request.tool_call
        tool_name = str(tool_call.get("name", ""))
        raw_args = tool_call.get("args", {})
        tool_args: Mapping[str, object] = raw_args if isinstance(raw_args, Mapping) else {}
        result = await self._pipeline.check_and_report(tool_name, tool_args)
        if (
            result.verdict in (Verdict.BLOCK, Verdict.ESCALATE_HITL)
            and result.feedback is not None
        ):
            return ToolMessage(
                content=blocked_feedback_text(result.feedback),
                tool_call_id=str(tool_call.get("id", "")),
            )
        return await handler(request)

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[object]],
    ) -> ToolMessage | Command[object]:
        """Fail closed: the synchronous hook is never the guardrail path.

        swarmy runs agents asynchronously only (aiosqlite, Textual, async
        engine); a synchronous execution path would silently bypass the
        async pipeline, so it is rejected instead of being left ungated.

        Args:
            request: the L0 tool-call request.
            handler: the L0 continuation.

        Raises:
            RuntimeError: always — guards against an ungated sync path.
        """
        raise RuntimeError(
            "GuardrailMiddleware enforces awrap_tool_call only; swarmy agents "
            "run asynchronously (a synchronous tool path would bypass the "
            "guardrail pipeline)"
        )


__all__ = [
    "BlockedSink",
    "EvaluationResult",
    "GuardrailMiddleware",
    "GuardrailPipeline",
    "JudgeBand",
    "blocked_feedback_text",
    "evaluate_rule",
    "tool_args_digest",
]
