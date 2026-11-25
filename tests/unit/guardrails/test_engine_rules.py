"""Tests of guardrail layer 2 — the shipped engine rules (arch §6.6, T1.4.4).

The default set (``no-true-based-sqli``, ``TRACE``/``CONNECT`` methods,
destructive payloads) is exercised through the pipeline on the HTTP tools,
parameterized after the spec §8.3 payloads; the whole-set disable flag must
flip the verdict.
"""

from __future__ import annotations

import pytest

from swarmy.guardrails.engine_rules import (
    block_destructive_payloads_rule,
    block_trace_connect_methods_rule,
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
    ("method", "blocked"),
    [("TRACE", True), ("CONNECT", True), ("trace", True), ("GET", False), ("POST", False)],
    ids=["TRACE", "CONNECT", "trace-lower", "GET", "POST"],
)
def test_trace_and_connect_methods_blocked(method: str, blocked: bool) -> None:
    """TRACE/CONNECT are denied regardless of case; usual methods pass (AC)."""
    result = _pipeline().evaluate(
        "http_get", {"url": "http://t.example.com/", "method": method}
    )
    assert (result.verdict is Verdict.BLOCK) is blocked
    if blocked:
        assert result.feedback is not None
        assert result.feedback.rule_id == "block-trace-connect-methods"


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
    """The shipped set is exactly the three arch §6.6 rules."""
    assert [rule.id for rule in default_engine_rules()] == [
        "no-true-based-sqli",
        "block-trace-connect-methods",
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
    assert block_trace_connect_methods_rule() == rules[1]
    assert block_destructive_payloads_rule() == rules[2]
