"""Tool-error feedback middleware: tool-body failures become model feedback.

LangGraph's ``ToolNode`` re-raises every exception raised from inside a tool
body (its default handler converts only its own ``ToolInvocationError``
argument-validation wrapper), so a single invalid argument — a wrong enum
value passed to ``memory_get``/``memory_search``, for instance — used to
abort the whole agent run. The platform tools deliberately raise
``ValueError`` with agent-addressable messages (the accepted values are
spelled out in the message and the tool docstrings); this middleware
completes that design: it converts tool-body failures into error
``ToolMessage`` feedback so the model can read the message, correct its
arguments and retry, instead of the session dying (arch §16.4 spirit: the
report-generation pipeline must survive recoverable agent mistakes).

Built on the same documented L0 middleware extension point as the
guardrail (arch §6.5) and projector (arch §6.8) middlewares. It is the
innermost swarmy middleware: guardrail deny feedback and projector
fail-closed behavior are untouched; only exceptions escaping the inner
handler (the actual tool execution) are converted.

Control-flow exceptions are never converted: ``GraphBubbleUp`` (HITL
interrupts and graph control, arch §7) propagates unchanged, and
``asyncio.CancelledError`` is a ``BaseException`` that the ``except
Exception`` clause does not see.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.errors import GraphBubbleUp

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from langgraph.prebuilt.tool_node import ToolCallRequest
    from langgraph.types import Command

LOG = logging.getLogger(__name__)

#: Agent-facing feedback template. The first line carries the exception's
#: own message — for the platform tools that is exactly the agent-addressable
#: enumeration the docstrings promise; the second line nudges a retry.
_FEEDBACK_TEMPLATE = "Error: {error}\nFix the tool call arguments and retry."


class ToolErrorFeedbackMiddleware(AgentMiddleware):
    """Convert tool-body exceptions into error ``ToolMessage`` feedback.

    Without it, one recoverable tool misuse (an invalid enum argument, a
    bad id) crashes the entire session: LangGraph treats exceptions raised
    by a tool body as unrecoverable bugs and re-raises them through the
    graph. With it, the failure reaches the model as feedback and the
    mission continues.
    """

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[object]]],
    ) -> ToolMessage | Command[object]:
        """Run one tool call; on failure return feedback addressed to the agent.

        Args:
            request: the L0 tool-call request (``tool_call``: name/args/id).
            handler: the L0 continuation that executes the tool.

        Returns:
            The tool result, or an error ``ToolMessage`` carrying the
            exception's own agent-addressable message.
        """
        try:
            return await handler(request)
        except GraphBubbleUp:
            # HITL interrupts and graph control flow must keep bubbling
            # (arch §7): converting them would swallow approval gates.
            raise
        except Exception as exc:
            tool_name = str(request.tool_call.get("name", ""))
            LOG.exception("tool %r failed; returning feedback to the agent", tool_name)
            return ToolMessage(
                content=_FEEDBACK_TEMPLATE.format(error=exc),
                name=tool_name,
                tool_call_id=str(request.tool_call.get("id", "")),
                status="error",
            )

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[object]],
    ) -> ToolMessage | Command[object]:
        """Fail closed: the synchronous hook is never the swarmy path.

        swarmy runs agents asynchronously only (aiosqlite, Textual, async
        engine), exactly like ``GuardrailMiddleware``; a synchronous tool
        path would silently lose the feedback conversion, so it is
        rejected instead.

        Args:
            request: the L0 tool-call request.
            handler: the L0 continuation.

        Raises:
            RuntimeError: always — guards against an ungated sync path.
        """
        raise RuntimeError(
            "ToolErrorFeedbackMiddleware enforces awrap_tool_call only; "
            "swarmy agents run asynchronously"
        )


__all__ = ["ToolErrorFeedbackMiddleware"]
