"""``ToolErrorFeedbackMiddleware`` tests.

Acceptance criteria under test:

* the middleware subclasses the documented L0 base and passes successful
  tool results through unchanged (``ToolMessage`` and ``Command`` alike);
* a tool-body exception becomes an error ``ToolMessage`` addressed to the
  exact tool call, carrying the exception's own agent-addressable message
  (the platform tools document the accepted values there) plus a retry
  hint — instead of the exception aborting the whole agent run;
* control flow is never converted: ``GraphBubbleUp`` (HITL interrupts) and
  ``asyncio.CancelledError`` propagate unchanged;
* the synchronous hook fails closed like ``GuardrailMiddleware`` (swarmy
  agents run asynchronously only).

The end-to-end effect (a wrong ``memory_search`` enum no longer kills the
session) is exercised by the demo driver; here a fake handler drives the
middleware directly, mirroring ``test_projector_middleware.py``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TypeAlias

import pytest
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.errors import GraphInterrupt
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from swarmy.tools.errors import ToolErrorFeedbackMiddleware

Handler: TypeAlias = Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[object]]]


def _make_request(
    tool_name: str = "memory_get",
    tool_args: dict[str, object] | None = None,
    call_id: str = "call-1",
) -> ToolCallRequest:
    """Build a mock L0 tool-call request (outside a graph: runtime None)."""
    return ToolCallRequest(
        tool_call={"name": tool_name, "args": tool_args or {}, "id": call_id},
        tool=None,
        state=None,
        runtime=None,
    )


def _ok_handler(result: ToolMessage | Command[object]) -> Handler:
    """Handler that executes successfully and returns ``result``."""

    async def handler(_request: ToolCallRequest) -> ToolMessage | Command[object]:
        return result

    return handler


def _raising_handler(exc: BaseException) -> Handler:
    """Handler whose execution raises ``exc`` (a tool-body failure)."""

    async def handler(_request: ToolCallRequest) -> ToolMessage | Command[object]:
        raise exc

    return handler


# ---- L0 identity and pass-through ----


def test_middleware_is_an_l0_agent_middleware() -> None:
    """The middleware subclasses the documented L0 base (arch §2.1)."""
    assert isinstance(ToolErrorFeedbackMiddleware(), AgentMiddleware)


async def test_successful_tool_message_passes_through_unchanged() -> None:
    """A successful result is returned exactly as the tool produced it."""
    middleware = ToolErrorFeedbackMiddleware()
    result = ToolMessage(content="[]", tool_call_id="call-1")
    outcome = await middleware.awrap_tool_call(_make_request(), _ok_handler(result))
    assert outcome is result


async def test_successful_command_passes_through_unchanged() -> None:
    """``Command`` results (delegation returns) pass through untouched."""
    middleware = ToolErrorFeedbackMiddleware()
    command: Command[object] = Command(update={"messages": []})
    outcome = await middleware.awrap_tool_call(_make_request(), _ok_handler(command))
    assert outcome is command


# ---- failure conversion ----


async def test_value_error_becomes_error_feedback_with_retry_hint() -> None:
    """The run-1 crash shape: an invalid enum becomes feedback, not death."""
    middleware = ToolErrorFeedbackMiddleware()
    outcome = await middleware.awrap_tool_call(
        _make_request(
            tool_name="memory_get",
            tool_args={"entity_type": "facts", "id": 3},
            call_id="call-abc",
        ),
        _raising_handler(ValueError("entity_type must be one of ['target', 'fact'], got 'facts'")),
    )
    assert isinstance(outcome, ToolMessage)
    assert outcome.tool_call_id == "call-abc"
    assert outcome.name == "memory_get"
    assert outcome.status == "error"
    assert "got 'facts'" in str(outcome.content)
    assert "retry" in str(outcome.content).lower()


async def test_any_tool_body_exception_is_converted(caplog: pytest.LogCaptureFixture) -> None:
    """Non-value errors (engine bugs in a tool) are logged and converted."""
    middleware = ToolErrorFeedbackMiddleware()
    with caplog.at_level(logging.ERROR, logger="swarmy.tools.errors"):
        outcome = await middleware.awrap_tool_call(
            _make_request(tool_name="http_get"),
            _raising_handler(RuntimeError("connection exploded")),
        )
    assert isinstance(outcome, ToolMessage)
    assert outcome.status == "error"
    assert "connection exploded" in str(outcome.content)
    assert any("http_get" in record.message for record in caplog.records)


# ---- control flow is never converted ----


async def test_graph_interrupt_bubbles_up() -> None:
    """HITL interrupts must keep bubbling (arch §7): never feedback."""
    middleware = ToolErrorFeedbackMiddleware()
    with pytest.raises(GraphInterrupt):
        await middleware.awrap_tool_call(_make_request(), _raising_handler(GraphInterrupt()))


async def test_cancellation_bubbles_up() -> None:
    """``CancelledError`` is BaseException: the conversion must not see it."""
    middleware = ToolErrorFeedbackMiddleware()
    with pytest.raises(asyncio.CancelledError):
        await middleware.awrap_tool_call(
            _make_request(), _raising_handler(asyncio.CancelledError())
        )


# ---- sync hook fails closed ----


def test_sync_hook_is_rejected() -> None:
    """A synchronous tool path would silently lose the conversion."""
    middleware = ToolErrorFeedbackMiddleware()
    with pytest.raises(RuntimeError, match="asynchron"):
        middleware.wrap_tool_call(_make_request(), _ok_handler(None))  # type: ignore[arg-type]
