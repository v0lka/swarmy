"""Tests of guardrail layer 2 — the shipped engine rules (arch §6.6, T1.4.4).

The default set (``no-true-based-sqli``, destructive payloads) is exercised
through the pipeline on the HTTP tools, parameterized after the spec §8.3
payloads; the whole-set disable flag must flip the verdict. The former
``block-trace-connect-methods`` rule is gone (review #59): the platform tool
surface carries fixed methods, so no rule can observe a method value and a
whole-value ``trace``/``connect`` parameter is a legitimate probe.
"""

from __future__ import annotations

import pytest

from swarmy.guardrails.engine_rules import (
    block_destructive_payloads_rule,
    default_engine_rules,
    no_true_based_sqli_rule,
)
from swarmy.guardrails.models import Verdict
from swarmy.guardrails.pipeline import GuardrailPipeline

#: http_get/http_post are platform tools, so layer 1 never interferes here.
_HTTP_GET_ARGS = {"url": "http://target.example.com/items"}


def _pipeline(engine_rules_enabled: bool = True) -> GuardrailPipeline:
    """Build the canonical pipeline with the default engine set."""
    return GuardrailPipeline(engine_rules_enabled=engine_rules_enabled)


@pytest.mark.parametrize(
    ("tool_name", "tool_args"),
    [
        ("http_get", {"url": "http://t.example.com/", "params": {"id": "1 OR 1=1"}}),
        ("http_get", {"url": "http://t.example.com/?q=1=1"}),
        ("http_get", {"url": "http://t.example.com/", "q": "true="}),
        ("http_post", {"url": "http://t.example.com/login", "body": "name=x' OR ''='"}),
        ("http_post", {"url": "http://t.example.com/login", "body": "name=x' AND ''='"}),
    ],
    ids=["param-or-1-eq-1", "url-1-eq-1", "param-true-eq", "body-or-empty-eq", "body-and-empty-eq"],
)
def test_true_constructions_blocked_on_http_tools(
    tool_name: str, tool_args: dict[str, object]
) -> None:
    """Spec §8.3 TRUE-constructions deny http_get and http_post calls (AC)."""
    result = _pipeline().evaluate(tool_name, tool_args)
    assert result.verdict is Verdict.BLOCK
    assert result.feedback is not None
    assert result.feedback.rule_id == "no-true-based-sqli"
    assert result.feedback.layer == "engine"


@pytest.mark.parametrize(
    "tool_args",
    [
        {"url": "http://t.example.com/items", "params": {"id": "42"}},
        {"url": "http://t.example.com/?q=python+sqlite"},
    ],
    ids=["benign-param", "benign-url"],
)
def test_benign_http_calls_pass_engine_rules(tool_args: dict[str, object]) -> None:
    """Ordinary probing parameters stay allowed."""
    result = _pipeline().evaluate("http_get", tool_args)
    assert result.verdict is Verdict.ALLOW


@pytest.mark.parametrize(
    "value",
    ["trace", "connect", "TRACE"],
    ids=["trace", "connect", "TRACE-upper"],
)
def test_probe_values_named_trace_connect_pass(value: str) -> None:
    """Whole-value ``trace``/``connect`` parameters are legitimate probes (#59).

    The removed ``block-trace-connect-methods`` rule denied any argument
    leaf exactly equal to trace/connect although the platform HTTP tools
    carry no method argument at all; ordinary probing must pass.
    """
    result = _pipeline().evaluate(
        "http_get", {"url": "http://t.example.com/", "query": {"action": value}}
    )
    assert result.verdict is Verdict.ALLOW


@pytest.mark.parametrize(
    ("payload", "blocked"),
    [
        ("'; DROP TABLE users;--", True),
        ("TRUNCATE TABLE sessions", True),
        ("DELETE FROM logs", True),
        ("rm -rf /tmp/target", True),
        ("shutdown now", True),
        ("select * from users where name = 'admin'", False),
        ("alert(document.domain)", False),
    ],
    ids=["drop-table", "truncate-table", "delete-from", "rm-rf", "shutdown", "plain-select", "xss-probe"],
)
def test_destructive_payloads_blocked(payload: str, blocked: bool) -> None:
    """Destructive payloads deny; ordinary probes (xss/sql reads) pass."""
    result = _pipeline().evaluate("http_post", {"url": "http://t/", "body": payload})
    assert (result.verdict is Verdict.BLOCK) is blocked
    if blocked:
        assert result.feedback is not None
        assert result.feedback.rule_id == "block-destructive-payloads"


def test_true_sqli_pattern_is_step_capped() -> None:
    """The quote-gap quantifier is bounded (review F-10).

    Typical SQLi TRUE-constructions stay denied, while a payload whose
    quote gap exceeds the bounded window no longer drives quadratic regex
    backtracking over a hostile multi-hundred-KB argument on every call.
    """
    typical = _pipeline().evaluate("http_get", {"url": "http://t/", "q": "' OR ''='"})
    assert typical.verdict is Verdict.BLOCK
    assert typical.feedback is not None
    assert typical.feedback.rule_id == "no-true-based-sqli"
    long_gap = "'" + "x" * 300 + "'='"
    oversized = _pipeline().evaluate("http_get", {"url": "http://t/", "q": long_gap})
    assert oversized.verdict is Verdict.ALLOW


def test_engine_rules_toggle_flips_the_verdict() -> None:
    """Disabling the engine set turns the same call from deny to allow (AC)."""
    sqli_args = {"url": "http://t.example.com/", "q": "1 OR 1=1"}
    enabled = _pipeline(engine_rules_enabled=True).evaluate("http_get", sqli_args)
    disabled = _pipeline(engine_rules_enabled=False).evaluate("http_get", sqli_args)
    assert enabled.verdict is Verdict.BLOCK
    assert disabled.verdict is Verdict.ALLOW


def test_disabled_engine_layer_skips_all_rules() -> None:
    """With the set off, even the destructive payloads pass layer 2."""
    pipeline = _pipeline(engine_rules_enabled=False)
    result = pipeline.evaluate("http_post", {"url": "http://t/", "body": "DROP TABLE users"})
    assert result.verdict is Verdict.ALLOW


def test_default_engine_rules_have_expected_ids() -> None:
    """The shipped set is exactly the two arch §6.6 rules (#59)."""
    assert [rule.id for rule in default_engine_rules()] == [
        "no-true-based-sqli",
        "block-destructive-payloads",
    ]
    for rule in default_engine_rules():
        assert rule.action == "block"
        assert rule.severity in ("low", "medium", "high")
        assert rule.message


def test_rule_builders_match_the_default_set() -> None:
    """Each builder produces one member of the default set (code constants)."""
    rules = default_engine_rules()
    assert no_true_based_sqli_rule() == rules[0]
    assert block_destructive_payloads_rule() == rules[1]
