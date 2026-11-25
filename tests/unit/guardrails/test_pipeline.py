"""Tests of the pipeline and the L0 middleware (arch §6.5, spec §8.5, T1.4.5).

Covers the composition matrix (each layer denies independently; allow
requires all three), the violation semantics (call not executed; spy tool
uncalled; ``GuardrailBlocked`` journal-before-bus; textual feedback with
rule id/layer), the M1 digest truncation and the real L0 middleware hook
against a mock ``ToolCallRequest`` — no network, no LLM anywhere.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest

from swarmy.events.models import GuardrailBlockedPayload
from swarmy.guardrails.models import (
    BlockedFeedback,
    GuardrailLayer,
    GuardrailRule,
    ModuleGuardrails,
    RuleCondition,
    Verdict,
)
from swarmy.guardrails.pipeline import (
    GuardrailMiddleware,
    GuardrailPipeline,
    blocked_feedback_text,
    tool_args_digest,
)
from swarmy.tools.projector import ContextProjector

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from tests.unit.guardrails.conftest import RecordingSink

    from swarmy.events.bus import Subscription


class ToolSpy:
    """Spy handler standing in for the L0 tool execution (no network)."""

    def __init__(self) -> None:
        self.calls: list[object] = []

    async def __call__(self, request: object) -> object:
        """Record the call and return the tool's would-be result."""
        self.calls.append(request)
        return "tool-was-executed"


def _make_request(
    tool_name: str, tool_args: dict[str, object], call_id: str = "call-1"
) -> ToolCallRequest:
    """Build a mock L0 tool-call request (outside a graph: runtime None)."""
    return ToolCallRequest(
        tool_call={"name": tool_name, "args": tool_args, "id": call_id},
        tool=None,
        state=None,
        runtime=None,
    )


#: Layer-3 module rule used by the matrix: guards one offline tool.
_MODULE_DROP_TABLE = GuardrailRule(
    id="module-guard-drop-table",
    applies_to=["memory_add_note"],
    condition=RuleCondition(any_param_matches=r"(?i)drop\s+table"),
    action="block",
    severity="medium",
    message="no destructive SQL against the memory of the target",
)

#: Layer-3 rule applying to a *network* tool (loses to layer 1 on purpose).
_MODULE_ON_RAW_FETCH = GuardrailRule(
    id="module-guard-raw-fetch",
    applies_to=["raw_fetch"],
    condition=RuleCondition(any_param_matches=r"1\s*=\s*1"),
    action="block",
    severity="high",
    message="module-level 1=1 guard",
)


def _pipeline(
    module_rule: GuardrailRule | None = None,
    *,
    blocked_sink: Callable[[GuardrailBlockedPayload], Awaitable[None]] | None = None,
) -> GuardrailPipeline:
    """Assemble the canonical subagent stack (invariants + engine + module)."""
    module = ModuleGuardrails(rules=[module_rule]) if module_rule is not None else None
    return GuardrailPipeline(module_guardrails=module, blocked_sink=blocked_sink)


@pytest.mark.parametrize(
    ("tool_name", "tool_args", "module_rule", "expected"),
    [
        pytest.param(
            "raw_fetch",
            {"url": "http://t.example.com/"},
            None,
            ("block", "invariant", "invariant:platform-http"),
            id="layer1-alone",
        ),
        pytest.param(
            "http_get",
            {"url": "http://t.example.com/", "q": "1 OR 1=1"},
            None,
            ("block", "engine", "no-true-based-sqli"),
            id="layer2-alone",
        ),
        pytest.param(
            "memory_add_note",
            {"text": "please DROP TABLE users"},
            _MODULE_DROP_TABLE,
            ("block", "module", "module-guard-drop-table"),
            id="layer3-alone",
        ),
        pytest.param(
            "memory_add_note",
            {"text": "benign note about the login form"},
            _MODULE_DROP_TABLE,
            ("allow", None, None),
            id="all-layers-pass",
        ),
        pytest.param(
            "raw_fetch",
            {"url": "http://t.example.com/", "q": "1=1"},
            _MODULE_ON_RAW_FETCH,
            ("block", "invariant", "invariant:platform-http"),
            id="layer1-wins-over-module",
        ),
    ],
)
def test_composition_matrix(
    tool_name: str,
    tool_args: dict[str, object],
    module_rule: GuardrailRule | None,
    expected: tuple[str, str | None, str | None],
) -> None:
    """Every layer denies independently; allow requires all three (AC, D11)."""
    expected_verdict, expected_layer, expected_rule = expected
    result = _pipeline(module_rule).evaluate(tool_name, tool_args)
    assert result.verdict.value == expected_verdict
    if expected_layer is None:
        assert result.feedback is None
    else:
        assert result.feedback is not None
        assert result.feedback.layer == expected_layer
        assert result.feedback.rule_id == expected_rule


async def test_blocked_sink_can_be_omitted_for_pure_evaluation() -> None:
    """check_and_report works without a sink (evaluation-only usage)."""
    result = await _pipeline().check_and_report("raw_fetch", {"url": "http://t/"})
    assert result.verdict is Verdict.BLOCK
    assert result.feedback is not None
    assert result.feedback.layer == "invariant"


async def test_allow_skips_the_sink(
    guardrails_env: tuple[object, object, object, RecordingSink, object, Subscription],
) -> None:
    """An allowed call records nothing (no GuardrailBlocked anywhere)."""
    _writer, _reader, _bus, sink, _probe, _subscription = guardrails_env
    result = await _pipeline(blocked_sink=sink).check_and_report(
        "memory_add_note", {"text": "benign"}
    )
    assert result.verdict is Verdict.ALLOW
    assert sink.envelopes == []


async def test_block_violation_semantics_journal_before_bus(
    guardrails_env: tuple[object, object, object, RecordingSink, object, Subscription],
) -> None:
    """On a block: spy uncalled, journal-first event, feedback with ids (AC)."""
    writer, reader, _bus, sink, probe, subscription = guardrails_env
    middleware = GuardrailMiddleware(_pipeline(blocked_sink=sink))
    spy = ToolSpy()
    request = _make_request("raw_fetch", {"url": "http://t.example.com/", "q": "big"})

    outcome = await middleware.awrap_tool_call(request, spy)  # type: ignore[arg-type]

    # 1. The tool call was NOT executed (spec §8.5).
    assert spy.calls == []
    # 2. The agent receives a ToolMessage feedback, not the tool result.
    assert isinstance(outcome, ToolMessage)
    assert outcome.tool_call_id == "call-1"
    feedback_text = str(outcome.content)
    assert "invariant:platform-http" in feedback_text  # rule id
    assert "invariant" in feedback_text  # layer
    assert "platform HTTP client" in feedback_text  # reason fragment
    # 3. Deterministic drain of the bus subscriber queue.
    await subscription.queue.join()
    # 4. The event was already durable when delivery happened (arch §5.3).
    assert probe.in_journal_at_delivery == [True]
    assert sink.in_journal_at_publish == [True]
    # 5. Journal read models see exactly one GuardrailBlocked with the payload.
    journal_events = await reader.by_type("GuardrailBlocked")
    assert [envelope.id for envelope in journal_events] == [sink.envelopes[0].id]
    payload = journal_events[0].payload
    assert isinstance(payload, GuardrailBlockedPayload)
    assert payload.tool_name == "raw_fetch"
    assert payload.rule_id == "invariant:platform-http"
    assert payload.layer == "invariant"
    assert "platform HTTP client" in payload.reason
    assert '"url"' in payload.tool_args_digest
    assert writer.append is not None  # the sink went through the journal writer


async def test_blocked_digest_masks_operator_secrets_rd4() -> None:
    """Regression RD-4: secrets in blocked args never enter the digest raw.

    ``GuardrailBlocked.tool_args_digest`` is serialized through the session
    ``ContextProjector`` (arch §6.8, T2.3.2), so an operator secret passed in
    the tool arguments appears only as ``<masked:name>``.
    """

    async def sink(payload: GuardrailBlockedPayload) -> None:
        captured.append(payload)

    captured: list[GuardrailBlockedPayload] = []
    projector = ContextProjector(secrets={"api_key": "s3cr3t-value"}, mark_untrusted=False)
    pipeline = GuardrailPipeline(projector=projector, blocked_sink=sink)
    result = await pipeline.check_and_report(
        "raw_fetch", {"url": "http://t.example.com/", "key": "s3cr3t-value"}
    )

    assert result.verdict is Verdict.BLOCK  # blocked by invariant:platform-http
    assert len(captured) == 1
    digest = captured[0].tool_args_digest
    assert "s3cr3t-value" not in digest
    assert "<masked:api_key>" in digest


async def test_allow_path_calls_the_handler(
    guardrails_env: tuple[object, object, object, RecordingSink, object, Subscription],
) -> None:
    """An allowed call executes the tool and records nothing."""
    _writer, reader, _bus, sink, probe, subscription = guardrails_env
    middleware = GuardrailMiddleware(_pipeline(blocked_sink=sink))
    spy = ToolSpy()
    outcome = await middleware.awrap_tool_call(
        _make_request("http_get", {"url": "http://t.example.com/items"}), spy
    )
    assert outcome == "tool-was-executed"
    assert len(spy.calls) == 1
    await subscription.queue.join()
    assert probe.delivered == []
    assert await reader.by_type("GuardrailBlocked") == []


def test_middleware_is_an_l0_agent_middleware() -> None:
    """The middleware subclasses the documented L0 base (arch §2.1, §19.1)."""
    assert isinstance(GuardrailMiddleware(_pipeline()), AgentMiddleware)


def test_sync_tool_hook_is_fail_closed() -> None:
    """The synchronous hook refuses to run ungated (async-only runtime)."""
    middleware = GuardrailMiddleware(_pipeline())
    with pytest.raises(RuntimeError, match="awrap_tool_call"):
        middleware.wrap_tool_call(
            _make_request("http_get", {}), lambda _req: None  # type: ignore[arg-type,return-value]
        )


def test_blocked_feedback_text_carries_rule_id_layer_reason() -> None:
    """The agent feedback contains rule id, layer and reason (spec §8.5)."""
    feedback = BlockedFeedback(
        rule_id="no-true-based-sqli", layer="engine", reason="TRUE-construction denied"
    )
    text = blocked_feedback_text(feedback)
    assert "no-true-based-sqli" in text
    assert "engine" in text
    assert "TRUE-construction denied" in text
    assert "NOT executed" in text


def test_digest_short_args_verbatim() -> None:
    """Small argument sets serialize deterministically as sorted JSON."""
    digest = tool_args_digest({"b": 2, "a": "x"}, ContextProjector(mark_untrusted=False))
    assert json.loads(digest) == {"a": "x", "b": 2}
    assert digest.index('"a"') < digest.index('"b"')


def test_digest_wraps_untrusted_markers_by_default() -> None:
    """The digest is model-bound content: the default projection marks it."""
    digest = tool_args_digest({"a": "x"})
    assert digest.startswith("[untrusted-target-content begin]")
    assert digest.endswith("[untrusted-target-content end]")


def test_digest_truncates_long_args_with_marker() -> None:
    """Long argument sets are truncated to the projector budget (RD-4)."""
    digest = tool_args_digest({"blob": "x" * 5000})
    assert digest.startswith("[untrusted-target-content begin]")
    assert "[truncated" in digest
    assert "bytes]" in digest
    assert len(digest) < 4500


def test_digest_stringifies_non_json_values() -> None:
    """Non-JSON-serializable leaves are stringified deterministically."""
    assert "object" in tool_args_digest({"obj": object()})


def test_digest_falls_back_to_repr_on_circular_args() -> None:
    """A circular structure cannot be JSON-serialized: repr fallback fires."""
    circular: dict[str, object] = {"a": 1}
    circular["self"] = circular
    digest = tool_args_digest(circular)
    assert "a" in digest
    assert "self" in digest


def test_all_predicate_types_evaluate_as_conjunction() -> None:
    """url/header/body/tool_in predicates fire only when every one holds."""
    rule = GuardrailRule(
        id="admin-probe-guard",
        applies_to=["http_get", "http_post"],
        condition=RuleCondition(
            url_matches=r"/admin",
            header_matches=r"^internal$",
            body_size_above=10,
            tool_in=["http_post"],
        ),
        action="block",
        severity="high",
        message="admin probing needs a deliberate body",
    )
    pipeline = GuardrailPipeline(
        module_guardrails=ModuleGuardrails(rules=[rule]), engine_rules_enabled=False
    )
    full_args = {
        "url": "http://t.example.com/admin",
        "headers": {"X-Scope": "internal"},
        "body": "y" * 64,
    }
    # All predicates hold → deny…
    denied = pipeline.evaluate("http_post", full_args)
    assert denied.verdict is Verdict.BLOCK
    assert denied.feedback is not None
    assert denied.feedback.rule_id == "admin-probe-guard"
    # …wrong tool (tool_in fails) → allow…
    assert pipeline.evaluate("http_get", full_args).verdict is Verdict.ALLOW
    # …small body (body_size_above fails) → allow…
    small = {**full_args, "body": "y"}
    assert pipeline.evaluate("http_post", small).verdict is Verdict.ALLOW
    # …no headers (header_matches fails) → allow…
    shy = {k: v for k, v in full_args.items() if k != "headers"}
    assert pipeline.evaluate("http_post", shy).verdict is Verdict.ALLOW
    # …and a non-matching URL fails too.
    other = {**full_args, "url": "http://t.example.com/items"}
    assert pipeline.evaluate("http_post", other).verdict is Verdict.ALLOW


def test_body_size_counts_nested_structures() -> None:
    """A structured body is measured by its serialized size."""
    rule = GuardrailRule(
        id="big-form-guard",
        applies_to=["http_post"],
        condition=RuleCondition(body_size_above=20),
        action="block",
        severity="low",
        message="form too large",
    )
    pipeline = GuardrailPipeline(
        module_guardrails=ModuleGuardrails(rules=[rule]), engine_rules_enabled=False
    )
    small = pipeline.evaluate("http_post", {"url": "http://t/", "body": {"a": 1}})
    large = pipeline.evaluate("http_post", {"url": "http://t/", "body": {"a": "x" * 64}})
    assert small.verdict is Verdict.ALLOW
    assert large.verdict is Verdict.BLOCK


def test_guardrail_layer_alias_matches_feedback_values() -> None:
    """The layer alias is the exact arch §5.1 vocabulary."""
    assert GuardrailLayer.__args__ == ("invariant", "engine", "module", "judge")  # type: ignore[attr-defined]
