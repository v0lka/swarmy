"""T3.4.3 acceptance criteria: the judge escalation path against the queue.

Roadmap T3.4.3: a mock judge returns ``escalate_hitl`` → the call is skipped
and an approval request with ``origin="judge"`` appears in the FIFO → the
operator decision removes the class gate → the next call of the class passes
(judge says ``ok``); the journal holds the ``judge:<verdict>`` chain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from swarmy.guardrails.models import Verdict
from tests.helpers.agent_modules import make_module
from tests.helpers.fake_models import ScriptedChatModel, final_reply

pytestmark = pytest.mark.integration


class ScriptedJudge(BaseChatModel):
    """A judge chat model returning scripted JSON verdicts in order."""

    verdicts: list[str]
    _index: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted-judge"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedJudge:
        return self

    def _next(self) -> str:
        verdict = self.verdicts[min(self._index, len(self.verdicts) - 1)]
        object.__setattr__(self, "_index", self._index + 1)
        return verdict

    def _generate(self, messages: Any, stop: Any = None, **kwargs: Any) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self._next()))])

    async def _agenerate(self, messages: Any, **kwargs: Any) -> ChatResult:
        return self._generate(messages)


def _post_call(call_id: str) -> dict[str, object]:
    return {
        "name": "http_post",
        "args": {"url": "http://127.0.0.1:9/form", "body": "x=1"},
        "id": call_id,
        "type": "tool_call",
    }


@pytest.fixture
async def judged_session(tmp_path: Path, echo_server: Any) -> Session:
    """A session with a judge band on ``network-write`` (mock judge model)."""
    agents = tmp_path / "agents"
    make_module(
        agents, "poster", description="Posting fixture module.",
        prompt="You are poster: call the platform `http_post` tool once, then report.",
        risk="passive",  # the module has no own tools; the gate is the judge's
    )
    orchestrator = ScriptedChatModel(
        scripts={
            "orchestrator": [
                AIMessage(content="", tool_calls=[{  # type: ignore[list-item]
                    "name": "task",
                    "args": {"description": "post the form", "subagent_type": "poster"},
                    "id": "call-p", "type": "tool_call",
                }]),
                final_reply("posted"),
                final_reply("posted"),
            ],
            "poster": [
                AIMessage(content="", tool_calls=[_post_call("p1")]),  # type: ignore[list-item]
                final_reply("post done"),
                AIMessage(content="", tool_calls=[_post_call("p2")]),  # type: ignore[list-item]
                final_reply("post done"),
            ],
        },
        fallback_reply="done",
    )
    judge = ScriptedJudge(verdicts=[
        '{"verdict": "escalate_hitl", "confidence": 0.95, "reason": "suspicious write"}',
        '{"verdict": "ok", "confidence": 0.9, "reason": "fine"}',
    ])
    config = SessionConfig(
        target=TargetConfig(base_url=f"http://127.0.0.1:{echo_server.port}/"),
        scope=ScopeEntries(
            ip_subnets=["127.0.0.1/32"], ports=[echo_server.port], schemes=["http"]
        ),
        agents_dirs=[str(agents)],
        profile="yolo",  # no profile gates: the judge is the only contour here
        judge={
            "tools": ["network-write"],
            "model": "stub:scripted",
            "confidence_threshold": 0.7,
            "timeout_s": 15.0,
        },
    )
    session = await Session.open(
        config=config, session_dir=tmp_path / "s", model=orchestrator, judge_model=judge
    )
    assert session.judge is not None
    try:
        yield session
    finally:
        await session.close()


class TestJudgeEscalationPath:
    """AC: escalation → queue → decision → gate removal, integration-green."""

    async def test_escalation_to_queue_to_decision(self, judged_session: Session) -> None:
        session = judged_session
        await session.runtime.run_step("post the form")

        # 1. The escalation is in the queue with origin="judge"…
        pending = session.approvals.pending()
        assert len(pending) == 1
        request = pending[0]
        assert request.origin == "judge"
        assert request.rule_or_profile == "judge:escalate_hitl"

        # …the class gate is closed: the second http_post was skipped too…
        blocked = await session.reader.by_type("GuardrailBlocked")
        escalations = [
            envelope
            for envelope in blocked
            if envelope.payload.rule_id == "judge:escalate_hitl"  # type: ignore[union-attr]
        ]
        assert len(escalations) >= 1
        # …and no request reached the network while escalated.
        assert session.limiter.budget_used == 0

        # 2. The operator approves: the registry gate opens.
        await session.runtime.submit_decision(request.request_id, "approve")
        assert session.approvals.pending() == ()

        # 3. Gate removal is observable on the live judge: the same call
        # would now consult the judge again (scripted verdict: ok → allow).
        verdict, feedback = await session.judge.precall(
            "http_post", "network-write", '{"url": "http://127.0.0.1:9/form"}'
        )
        assert verdict is Verdict.ALLOW
        assert feedback is None
        assert session.judge.gate_for("network-write") is None

        # 4. The journal holds the judge:<verdict> chain (T3.4.3 AC).
        chain = await session.reader.by_type("GuardrailBlocked")
        rule_ids = [envelope.payload.rule_id for envelope in chain]  # type: ignore[union-attr]
        assert "judge:escalate_hitl" in rule_ids
        decisions = await session.reader.by_type("OperatorDecision")
        assert decisions[-1].payload.decision == "approve"  # type: ignore[union-attr]
