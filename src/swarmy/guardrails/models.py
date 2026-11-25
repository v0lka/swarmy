"""Guardrail rule models: risk classes, DSL rule shapes, verdicts (arch §6.6, T1.4.1).

This module is the *type vocabulary* of the three-layer guardrail pipeline
(arch §6.5):

* layer 1 — platform invariants (``invariants.py``, non-configurable);
* layer 2 — shipped engine rules (``engine_rules.py``, disableable);
* layer 3 — module rules (``guardrails.yaml`` via ``dsl.py``);
* layer 4 (reserved) — LLM judge, P3.4 (RD-2): ``Verdict.escalate_hitl`` /
  ``Verdict.flag`` exist so the pipeline contract is stable, but v0.1 has no
  judge logic (D11: the judge may only escalate/flag, never unblock).

``RiskClass`` lives here (not in ``swarmy.tools``) so that ``swarmy.tools.*``
can import it without an import cycle (arch §2.5, AD-7): this module imports
only pydantic and the stdlib — no other swarmy package, no L0.

Rule-condition semantics (arch §6.6): the five v0.1 predicates are a
*conjunction* — every predicate that is set must hold for the rule to fire;
inside ``any_param_matches`` the alternation of the regex itself is the
*disjunction* (spec §8.3).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

#: The pipeline layers that can deny an operation (arch §5.1, §6.5).
GuardrailLayer = Literal["invariant", "engine", "module", "judge"]


class RiskClass(StrEnum):
    """Declarative risk class of a tool (arch §7.2, AD-7).

    Drives the HITL strictness profiles; declared by the tool author, never
    inferred by the platform (determinism of the approval gates).
    """

    PASSIVE = "passive"
    NETWORK_WRITE = "network-write"
    VERIFY = "verify"
    DESTRUCTIVE = "destructive"


class RuleCondition(BaseModel):
    """Deterministic pre-tool-call predicates of one rule (arch §6.6).

    Fields are optional so any subset may be combined; set fields form a
    conjunction. ``None`` (the default) means "predicate not used".

    Evaluation is against the tool-call arguments *before* any network
    activity (spec §8.3): ``any_param_matches``/``url_matches``/
    ``header_matches`` are regexes searched over the matching argument
    values, ``body_size_above`` compares the serialized body size in bytes,
    ``tool_in`` tests the tool name.
    """

    model_config = ConfigDict(extra="forbid")

    any_param_matches: str | None = None  # regex over parameter values (disjunction inside)
    url_matches: str | None = None  # regex over URL-shaped arguments
    header_matches: str | None = None  # regex over header values
    body_size_above: int | None = Field(default=None, ge=0)  # serialized body bytes
    tool_in: list[str] | None = None  # tool-name membership


class GuardrailRule(BaseModel):
    """One declarative guardrail rule (arch §6.6; action block-only in v0.1).

    ``applies_to`` names the tools the rule guards (non-empty); ``condition``
    is the conjunction of predicates; ``message`` is the human-readable
    reason returned to the agent on a block (spec §8.5).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)  # unique within its file/layer
    applies_to: list[str] = Field(min_length=1)  # tool names (arch §6.6)
    condition: RuleCondition
    action: Literal["block"]  # v0.1: only block (review/allow — later phase)
    severity: Literal["low", "medium", "high"]
    message: str = Field(min_length=1)


class ModuleGuardrails(BaseModel):
    """Parsed ``guardrails.yaml`` of one module (arch §6.6).

    ``tool_classes`` optionally declares the risk class of the module's own
    tools; ``rules`` are the module's layer-3 rules.
    """

    model_config = ConfigDict(extra="forbid")

    tool_classes: dict[str, RiskClass] = Field(default_factory=dict)
    rules: list[GuardrailRule] = Field(default_factory=list)


class Verdict(StrEnum):
    """Pipeline verdict for one tool call (arch §6.5, §6.7).

    ``escalate_hitl``/``flag`` are produced only by the LLM judge (P3.4,
    RD-2) and never unblock a deterministic deny (D11).
    """

    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE_HITL = "escalate_hitl"
    FLAG = "flag"


class BlockedFeedback(BaseModel):
    """What the agent is told about a deny (spec §8.5, arch §6.5).

    The middleware renders this into the textual tool feedback; the same
    triple goes into the ``GuardrailBlocked`` journal event payload.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    layer: GuardrailLayer
    reason: str


def feedback_text(feedback: BlockedFeedback) -> str:
    """Render the canonical agent-facing textual feedback of a deny (spec §8.5).

    The single wording source of the platform: the middleware
    (:func:`swarmy.guardrails.pipeline.blocked_feedback_text`) and the HTTP
    client (:class:`GuardrailBlocked.agent_text`) both delegate here, so the
    (layer, rule, reason) triple renders identically everywhere.
    """
    return (
        f"Tool call blocked by the {feedback.layer} guardrail layer "
        f"(rule {feedback.rule_id}): {feedback.reason} The call was NOT executed. "
        "Adjust your plan; only the operator can override a deny (HITL)."
    )


class GuardrailBlocked(Exception):
    """In-process signal of a guardrail deny (spec §8.5, arch §6.2).

    Raised by platform components after the ``GuardrailBlocked`` journal
    event has been published through the wiring (journal-first, arch §5.3):
    ``SwarmyHttpClient`` raises it when a redirect hop fails the scope/
    limits re-check or when the limiter refuses the call. The exception
    carries the structured :class:`BlockedFeedback`; tool wrappers catch it
    and return :attr:`agent_text` to the agent in place of a result.
    """

    def __init__(self, feedback: BlockedFeedback) -> None:
        """Build the exception from its structured denial."""
        self.feedback = feedback
        super().__init__(feedback_text(feedback))

    @property
    def agent_text(self) -> str:
        """The agent-facing feedback text (spec §8.5)."""
        return feedback_text(self.feedback)


__all__ = [
    "BlockedFeedback",
    "GuardrailBlocked",
    "GuardrailLayer",
    "GuardrailRule",
    "ModuleGuardrails",
    "RiskClass",
    "RuleCondition",
    "Verdict",
    "feedback_text",
]
