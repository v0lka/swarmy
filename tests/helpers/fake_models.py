"""Scripted chat-model doubles for the headless M3 integration tests.

The orchestrator and the subagent graphs are driven by a **routing fake
model**: one ``BaseChatModel`` that inspects the system message of every
request and consumes the scripted ``AIMessage`` sequence of the matching
agent. This keeps interleaved orchestrator/subagent execution deterministic
without any network or API key (headless F3 acceptance).
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult


class ScriptedChatModel(BaseChatModel):
    """Consumes per-agent AIMessage scripts keyed by a system-prompt marker.

    Args:
        scripts: mapping ``marker → iterable of AIMessage``; the model scans
            the system message of each request for the markers and takes the
            next scripted answer of that agent. A marker matched by a longer
            key wins (so ``crawler`` does not shadow ``crawler_slow``).

    Raises:
        StopIteration: when an agent's script is exhausted (a hard test
            failure — the script must cover every call).
    """

    # ``Any`` on purpose: the scripts hold per-agent AIMessage iterables, and
    # a pydantic-resolvable annotation keeps ``ScriptedChatModel`` fully
    # defined without importing typing machinery at runtime (tests/**: ANN401
    # ignored).
    scripts: dict[str, Any]
    fallback_reply: str = "done"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._iters: dict[str, Any] = {}  # marker -> iterator of AIMessage
        self._system_prompts: list[str] = []  # every request's system text (context probes)

    @property
    def system_prompts(self) -> list[str]:
        """The system message text of every request, in arrival order."""
        return list(self._system_prompts)

    @property
    def _llm_type(self) -> str:
        return "scripted-fake"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedChatModel:
        """Ignore the tool schema: the scripts already carry the tool calls."""
        return self

    def _marker_for(self, messages: list[BaseMessage]) -> str | None:
        """The longest script marker present in the request's system message."""
        system_text = "\n".join(
            str(message.content) for message in messages if message.type == "system"
        )
        matches = [marker for marker in self.scripts if marker in system_text]
        return max(matches, key=len) if matches else None

    def _generate(self, messages: list[BaseMessage], stop: Any = None, **kwargs: Any) -> ChatResult:
        system_text = "\n".join(
            str(message.content) for message in messages if message.type == "system"
        )
        self._system_prompts.append(system_text)
        marker = self._marker_for(messages)
        if marker is None:
            return ChatResult(generations=[ChatGeneration(message=AIMessage(self.fallback_reply))])
        iterators = self._iters
        if marker not in iterators:
            iterators[marker] = iter(list(self.scripts[marker]))
        try:
            answer = next(iterators[marker])
        except StopIteration as exc:
            # StopIteration inside a coroutine silently terminates async
            # tasks — turn script exhaustion into a loud, named failure.
            msg = f"script exhausted for marker {marker!r}"
            raise AssertionError(msg) from exc
        return ChatResult(generations=[ChatGeneration(message=answer)])

    async def _agenerate(
        self, messages: list[BaseMessage], stop: Any = None, **kwargs: Any
    ) -> ChatResult:
        return self._generate(messages, stop=stop, **kwargs)


def one_shot_model(reply: str = "done") -> ScriptedChatModel:
    """A model whose every (unmatched) call answers ``reply`` — compile smoke."""
    return ScriptedChatModel(scripts={}, fallback_reply=reply)


def task_call(description: str, subagent_type: str, call_id: str) -> AIMessage:
    """An ``AIMessage`` issuing one L0 ``task()`` tool call."""
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "task",
                "args": {"description": description, "subagent_type": subagent_type},
                "id": call_id,
                "type": "tool_call",
            }
        ],
    )


def tool_reply(name: str, call_id: str, content: str = "ok") -> AIMessage:
    """An ``AIMessage`` invoking one tool by name (single call)."""
    return AIMessage(
        content="",
        tool_calls=[{"name": name, "args": {}, "id": call_id, "type": "tool_call"}],
    )


def final_reply(text: str) -> AIMessage:
    """A plain final answer (no tool calls)."""
    return AIMessage(content=text)
