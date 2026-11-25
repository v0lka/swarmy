"""``ProjectorMiddleware`` tests (roadmap T2.3.2, arch §6.8) + RD-4 regression.

Acceptance criteria under test:

* the middleware subclasses the documented L0 base and projects *every* tool
  result through the ``ContextProjector`` — on the async hook and, since the
  projector is pure/synchronous, on the sync hook alike;
* budget truncation renders the verbatim ``[truncated N bytes]`` marker,
  operator secrets are masked as ``<masked:secret-name>``, and the untrusted
  markers wrap projected content (arch §6.8 order: budget → masking →
  marking → normalization);
* a projection failure is fail-closed: a short safe feedback message is
  returned, never the raw tool output;
* RD-4 regression: the digest stored in ``GuardrailBlocked`` masks operator
  secrets — no raw secret value can reach the journal payload — and digests
  are deterministic for identical arguments.

The full end-to-end scenario (large body + secret through the real HTTP
client) lands in T2.4.2; here a fake tool drives the middleware directly.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from swarmy.guardrails.models import GuardrailRule, RuleCondition, Verdict
from swarmy.guardrails.pipeline import GuardrailPipeline, tool_args_digest
from swarmy.tools.projector import (
    DEFAULT_BUDGET_BYTES,
    UNTRUSTED_BEGIN,
    UNTRUSTED_END,
    ContextProjector,
    ProjectorMiddleware,
    make_projector_middleware,
    mask_reference,
    truncation_marker,
)

if TYPE_CHECKING:
    from swarmy.events.models import GuardrailBlockedPayload

#: Operator secret injected through the projector constructor (the
#: ``secrets.yaml`` loader wires the real values in, T3.1.1).
_SECRET = "sw-op-secret-9f3ab77cda42"

#: Projector carrying that one injected secret.
_SECRET_PROJECTOR = ContextProjector(secrets={"api_key": _SECRET})


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


class _ExplodingProjector(ContextProjector):
    """Projector whose ``project`` always fails (fail-closed path probe)."""

    def project(self, text: str, *, tool_class: str | None = None) -> str:
        """Simulate a sanitizer crash — the raw text is never returned."""
        raise RuntimeError("projection exploded")


# ---- L0 identity and hook coverage ----


def test_middleware_is_an_l0_agent_middleware() -> None:
    """The middleware subclasses the documented L0 base (arch §2.1, §19.1)."""
    middleware = make_projector_middleware()
    assert isinstance(middleware, AgentMiddleware)
    assert isinstance(middleware, ProjectorMiddleware)


async def test_async_hook_truncates_large_result_with_marker() -> None:
    """An oversized tool result is budget-truncated with the §6.8 marker."""
    projector = ContextProjector(budgets={"http_preview_bytes": 100}, mark_untrusted=False)
    middleware = make_projector_middleware(projector, tool_classes={"http_get": "http_preview"})

    async def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(
            content="x" * 500, tool_call_id=str(request.tool_call.get("id", ""))
        )

    outcome = await middleware.awrap_tool_call(_make_request("http_get", {}), handler)
    assert isinstance(outcome, ToolMessage)
    assert outcome.content == "x" * 100 + "\n" + truncation_marker(400)
    assert outcome.tool_call_id == "call-1"


async def test_async_hook_masks_secret_and_marks_untrusted() -> None:
    """An injected secret never survives projection; untrusted markers wrap."""
    middleware = make_projector_middleware(_SECRET_PROJECTOR)

    async def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(
            content=f"Authorization: Bearer {_SECRET}",
            tool_call_id=str(request.tool_call.get("id", "")),
        )

    outcome = await middleware.awrap_tool_call(_make_request("probe", {}), handler)
    assert isinstance(outcome, ToolMessage)
    content = outcome.content
    assert isinstance(content, str)
    assert _SECRET not in content
    assert mask_reference("api_key") in content
    assert content.startswith(UNTRUSTED_BEGIN)
    assert content.endswith(UNTRUSTED_END)


def test_sync_hook_truncates_large_result_with_marker() -> None:
    """The synchronous hook performs the same projection (pure projector)."""
    projector = ContextProjector(budgets={"http_preview_bytes": 50}, mark_untrusted=False)
    middleware = make_projector_middleware(projector, tool_classes={"fetch": "http_preview"})

    def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(content="y" * 200, tool_call_id=str(request.tool_call.get("id", "")))

    outcome = middleware.wrap_tool_call(_make_request("fetch", {}), handler)
    assert isinstance(outcome, ToolMessage)
    assert outcome.content == "y" * 50 + "\n" + truncation_marker(150)


def test_sync_hook_masks_secret() -> None:
    """The synchronous hook masks operator secrets exactly like the async one."""
    middleware = make_projector_middleware(_SECRET_PROJECTOR)

    def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(
            content=f"leaked value {_SECRET}",
            tool_call_id=str(request.tool_call.get("id", "")),
        )

    outcome = middleware.wrap_tool_call(_make_request("probe", {}), handler)
    assert isinstance(outcome, ToolMessage)
    content = outcome.content
    assert isinstance(content, str)
    assert _SECRET not in content
    assert mask_reference("api_key") in content


async def test_async_hook_projects_tool_messages_in_command_update() -> None:
    """Command-shaped results are projected inside ``update["messages"]``."""
    middleware = make_projector_middleware(_SECRET_PROJECTOR)

    async def handler(request: ToolCallRequest) -> Command[object]:
        return Command(
            update={
                "messages": [
                    ToolMessage(
                        content=f"leak {_SECRET}",
                        tool_call_id=str(request.tool_call.get("id", "")),
                    )
                ],
                "evidence_id": 42,
            }
        )

    outcome = await middleware.awrap_tool_call(_make_request("probe", {}), handler)
    assert isinstance(outcome, Command)
    update = outcome.update
    assert isinstance(update, Mapping)
    messages = update["messages"]
    assert isinstance(messages, list)
    message = messages[0]
    assert isinstance(message, ToolMessage)
    content = message.content
    assert isinstance(content, str)
    assert _SECRET not in content
    assert mask_reference("api_key") in content
    assert update["evidence_id"] == 42  # non-message state stays untouched


async def test_unknown_tool_uses_default_budget() -> None:
    """A tool without a mapping entry still gets the conservative budget."""
    middleware = make_projector_middleware(ContextProjector(mark_untrusted=False))

    async def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(
            content="z" * (DEFAULT_BUDGET_BYTES + 200),
            tool_call_id=str(request.tool_call.get("id", "")),
        )

    outcome = await middleware.awrap_tool_call(_make_request("unmapped_tool", {}), handler)
    assert isinstance(outcome, ToolMessage)
    assert outcome.content == "z" * DEFAULT_BUDGET_BYTES + "\n" + truncation_marker(200)


# ---- fail-closed projection ----


async def test_projection_failure_returns_safe_feedback_never_raw() -> None:
    """A projection error replaces the result with safe feedback (no leak)."""
    middleware = make_projector_middleware(_ExplodingProjector())
    raw = f"raw body with {_SECRET} inside"

    async def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(content=raw, tool_call_id=str(request.tool_call.get("id", "")))

    outcome = await middleware.awrap_tool_call(_make_request("probe", {}), handler)
    assert isinstance(outcome, ToolMessage)
    content = outcome.content
    assert isinstance(content, str)
    assert "[projection failed]" in content
    assert _SECRET not in content
    assert raw not in content
    assert outcome.tool_call_id == "call-1"


def test_sync_projection_failure_returns_safe_feedback_never_raw() -> None:
    """The synchronous hook is fail-closed too."""
    middleware = make_projector_middleware(_ExplodingProjector())
    raw = "raw body that must not leak"

    def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(content=raw, tool_call_id=str(request.tool_call.get("id", "")))

    outcome = middleware.wrap_tool_call(_make_request("probe", {}), handler)
    assert isinstance(outcome, ToolMessage)
    content = outcome.content
    assert isinstance(content, str)
    assert "[projection failed]" in content
    assert raw not in content


# ---- integration-level scenario (fake tool; real HTTP lands in T2.4.2) ----


async def test_large_body_with_secret_is_projected() -> None:
    """Large body + secret through the middleware: masked, truncated, marked."""
    projector = ContextProjector(
        budgets={"http_preview_bytes": 200},
        secrets={"api_key": _SECRET},
    )
    middleware = make_projector_middleware(projector, tool_classes={"http_get": "http_preview"})
    body = f"token={_SECRET}\n" + "A" * 300

    async def handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(content=body, tool_call_id=str(request.tool_call.get("id", "")))

    outcome = await middleware.awrap_tool_call(_make_request("http_get", {}), handler)
    assert isinstance(outcome, ToolMessage)
    content = outcome.content
    assert isinstance(content, str)
    assert _SECRET not in content
    assert mask_reference("api_key") in content
    assert "[truncated" in content
    assert content.startswith(UNTRUSTED_BEGIN)
    assert content.endswith(UNTRUSTED_END)


# ---- RD-4 regression: digests route through the projector ----


async def test_blocked_digest_masks_operator_secret_rd4() -> None:
    """A blocked call's ``GuardrailBlocked`` digest never carries the secret."""
    captured: list[GuardrailBlockedPayload] = []

    async def sink(payload: GuardrailBlockedPayload) -> None:
        captured.append(payload)

    deny_rule = GuardrailRule(
        id="test-deny-probe",
        applies_to=["probe"],
        condition=RuleCondition(tool_in=["probe"]),
        action="block",
        severity="low",
        message="probe tool denied",
    )
    pipeline = GuardrailPipeline(
        engine_rules=[deny_rule],
        blocked_sink=sink,
        projector=_SECRET_PROJECTOR,
    )
    result = await pipeline.check_and_report(
        "probe", {"query": f"lookup {_SECRET}", "count": 3}
    )
    assert result.verdict is Verdict.BLOCK
    assert len(captured) == 1
    digest = captured[0].tool_args_digest
    assert _SECRET not in digest
    assert mask_reference("api_key") in digest
    assert digest.startswith(UNTRUSTED_BEGIN)


def test_digest_masks_secret_in_args_directly() -> None:
    """``tool_args_digest`` masks an injected secret present in arguments."""
    digest = tool_args_digest({"token": _SECRET}, _SECRET_PROJECTOR)
    assert _SECRET not in digest
    assert mask_reference("api_key") in digest


def test_digest_is_deterministic() -> None:
    """Identical arguments always produce the identical digest."""
    args: dict[str, object] = {
        "url": "http://t.example.com/",
        "headers": {"Authorization": f"Bearer {_SECRET}"},
    }
    first = tool_args_digest(args, _SECRET_PROJECTOR)
    second = tool_args_digest(args, _SECRET_PROJECTOR)
    assert first == second
    assert _SECRET not in first
    assert mask_reference("api_key") in first


async def test_default_pipeline_digest_masks_builtin_detectors() -> None:
    """Without injected secrets, the built-in bearer detector still masks."""
    captured: list[GuardrailBlockedPayload] = []

    async def sink(payload: GuardrailBlockedPayload) -> None:
        captured.append(payload)

    deny_rule = GuardrailRule(
        id="test-deny-probe-default",
        applies_to=["probe"],
        condition=RuleCondition(tool_in=["probe"]),
        action="block",
        severity="low",
        message="probe tool denied",
    )
    pipeline = GuardrailPipeline(engine_rules=[deny_rule], blocked_sink=sink)
    token = "abcdef1234567890"
    result = await pipeline.check_and_report(
        "probe", {"headers": {"Authorization": f"Bearer {token}"}}
    )
    assert result.verdict is Verdict.BLOCK
    digest = captured[0].tool_args_digest
    assert token not in digest
    assert mask_reference("bearer") in digest
