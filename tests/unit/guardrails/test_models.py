"""Tests of the guardrail rule models (arch §6.6, T1.4.1).

The models are the type vocabulary shared by the pipeline layers; these
tests pin the shapes of arch §6.6 — exact predicate names, block-only
actions, the severity scale and the four risk classes of arch §7.2.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from swarmy.guardrails.models import (
    BlockedFeedback,
    GuardrailRule,
    ModuleGuardrails,
    RiskClass,
    RuleCondition,
    Verdict,
)


def test_risk_class_members_match_arch_7_2() -> None:
    """RiskClass carries exactly the four arch §7.2 classes, exact names."""
    assert {member.value for member in RiskClass} == {
        "passive",
        "network-write",
        "verify",
        "destructive",
    }


def test_verdict_carries_the_reserved_judge_verdicts() -> None:
    """Verdict has allow/block plus the judge verdicts (P3.4 slot, RD-2)."""
    assert {member.value for member in Verdict} == {
        "allow",
        "block",
        "escalate_hitl",
        "flag",
    }


def test_rule_condition_all_predicates_optional_by_default() -> None:
    """A fresh condition has every arch §6.6 predicate unset."""
    condition = RuleCondition()
    assert condition.any_param_matches is None
    assert condition.url_matches is None
    assert condition.header_matches is None
    assert condition.body_size_above is None
    assert condition.tool_in is None


def test_guardrail_rule_accepts_the_canonical_shape() -> None:
    """The arch §6.6 rule shape validates as declared."""
    rule = GuardrailRule(
        id="probe-rule",
        applies_to=["http_get"],
        condition=RuleCondition(any_param_matches="1=1"),
        action="block",
        severity="high",
        message="denied",
    )
    assert rule.action == "block"
    assert rule.severity == "high"
    assert rule.applies_to == ["http_get"]


@pytest.mark.parametrize(
    "field_overrides",
    [
        {"action": "allow"},  # v0.1 is block-only (arch §6.6)
        {"severity": "critical"},  # not on the low/medium/high scale
        {"applies_to": []},  # a rule guarding nothing is an author error
        {"message": ""},  # empty feedback text is an author error
        {"id": ""},  # empty ids break journal/attribution
        {"condition": {"body_size_above": -1}},  # negative byte threshold
        {"unknown_field": 1},  # extra keys are rejected (fail-fast DSL)
    ],
    ids=[
        "action-allow",
        "severity-off-scale",
        "empty-applies-to",
        "empty-message",
        "empty-id",
        "negative-body-size",
        "extra-field",
    ],
)
def test_guardrail_rule_rejects_invalid_shapes(field_overrides: dict[str, object]) -> None:
    """Every malformed rule variant is a ValidationError."""
    base: dict[str, object] = {
        "id": "probe-rule",
        "applies_to": ["http_get"],
        "condition": {"any_param_matches": "1=1"},
        "action": "block",
        "severity": "high",
        "message": "denied",
    }
    base.update(field_overrides)
    with pytest.raises(ValidationError):
        GuardrailRule.model_validate(base)


def test_module_guardrails_defaults_to_empty_collections() -> None:
    """A module may ship tool classes or rules only — both default empty."""
    empty = ModuleGuardrails()
    assert empty.tool_classes == {}
    assert empty.rules == []
    full = ModuleGuardrails.model_validate(
        {
            "tool_classes": {"probe_tool": "verify"},
            "rules": [
                {
                    "id": "r",
                    "applies_to": ["probe_tool"],
                    "condition": {"tool_in": ["probe_tool"]},
                    "action": "block",
                    "severity": "low",
                    "message": "m",
                }
            ],
        }
    )
    assert full.tool_classes == {"probe_tool": RiskClass.VERIFY}
    assert full.rules[0].condition.tool_in == ["probe_tool"]


def test_blocked_feedback_shape_is_exact() -> None:
    """BlockedFeedback carries rule id, layer and reason (spec §8.5)."""
    feedback = BlockedFeedback(
        rule_id="no-true-based-sqli", layer="engine", reason="TRUE-construction"
    )
    assert feedback.rule_id == "no-true-based-sqli"
    assert feedback.layer == "engine"
    assert feedback.reason == "TRUE-construction"
    with pytest.raises(ValidationError):
        BlockedFeedback.model_validate(
            {"rule_id": "x", "layer": "unknown-layer", "reason": "r"}
        )
