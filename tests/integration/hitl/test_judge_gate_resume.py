"""F-18 acceptance: judge escalations and standing denies survive a restart.

The escalation registry is in-process, so the durable outcome of an operator
decision lives in the ``judge_class_gate`` facts ledger (session wiring):
a **reject** re-establishes the standing class deny on resume (the judge
must not re-evaluate a class the operator denied), and an escalation that
was never answered is **re-enqueued** into the approval queue so the
operator can still decide it — the gate never silently evaporates.
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
from swarmy.memory.models import FactDraft
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


_ESCALATE = '{"verdict": "escalate_hitl", "confidence": 0.95, "reason": "suspicious"}'
_OK = '{"verdict": "ok", "confidence": 0.9, "reason": "fine"}'


def _post_call(call_id: str) -> dict[str, object]:
    return {
        "name": "http_post",
        "args": {"url": "http://127.0.0.1:9/form", "body": "x=1"},
        "id": call_id,
        "type": "tool_call",
    }


@pytest.fixture
async def judged_dirs(tmp_path: Path, echo_server: Any) -> tuple[Path, Path]:
    """The agents folder of the ``poster`` fixture module + the session dir."""
    agents = tmp_path / "agents"
    make_module(
        agents, "poster", description="Posting fixture module.",
        prompt="You are poster: call the platform `http_post` tool once, then report.",
        risk="passive",
    )
    return agents, tmp_path / "s"


def _config(tmp_path: Path, agents: Path, echo_server: Any) -> SessionConfig:
    return SessionConfig(
        target=TargetConfig(base_url=f"http://127.0.0.1:{echo_server.port}/"),
        scope=ScopeEntries(
            ip_subnets=["127.0.0.1/32"], ports=[echo_server.port], schemes=["http"]
        ),
        agents_dirs=[str(agents)],
        profile="yolo",  # no profile gates: the judge is the only contour
        judge={
            "tools": ["network-write"],
            "model": "stub:scripted",
            "confidence_threshold": 0.7,
            "timeout_s": 15.0,
        },
    )


def _orchestrator() -> ScriptedChatModel:
    return ScriptedChatModel(
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
            ],
        },
        fallback_reply="done",
    )


class TestJudgeGateResume:
    """F-18: operator decisions on judge escalations survive restarts."""

    async def test_reject_reestablishes_the_standing_deny(
        self, tmp_path: Path, judged_dirs: tuple[Path, Path], echo_server: Any
    ) -> None:
        agents, session_dir = judged_dirs
        model = _orchestrator()
        session_a = await Session.open(
            config=_config(tmp_path, agents, echo_server),
            session_dir=session_dir,
            model=model,
            judge_model=ScriptedJudge(verdicts=[_ESCALATE]),
        )
        assert session_a.judge is not None
        await session_a.runtime.run_step("post the form")
        pending = session_a.approvals.pending()
        assert len(pending) == 1
        assert pending[0].origin == "judge"

        # The operator rejects: the class gate closes for the rest of the
        # session (asymmetric standing deny — D11)...
        await session_a.runtime.submit_decision(pending[0].request_id, "reject")
        assert session_a.approvals.pending() == ()
        verdict, feedback = session_a.judge.gate_for("network-write") or (None, None)
        assert verdict is Verdict.BLOCK
        assert feedback is not None
        assert feedback.rule_id == "judge:operator_deny"
        await session_a.close()  # "process restart"

        # ...and the deny survives the restart: the resumed registry holds
        # the standing deny WITHOUT consulting the judge model again (the
        # injected model only ever answers "ok").
        session_b = await Session.resume(
            session_dir=session_dir,
            model=model,
            judge_model=ScriptedJudge(verdicts=[_OK]),
        )
        try:
            assert session_b.judge is not None
            assert session_b.approvals.pending() == ()
            verdict, feedback = session_b.judge.gate_for("network-write") or (None, None)
            assert verdict is Verdict.BLOCK
            assert feedback is not None
            assert feedback.rule_id == "judge:operator_deny"
            outcome = await session_b.judge.precall("http_post", "network-write", "digest")
            assert outcome is not None
            assert outcome[0] is Verdict.BLOCK
        finally:
            await session_b.close()

    async def test_unanswered_escalation_is_reenqueued(
        self, tmp_path: Path, judged_dirs: tuple[Path, Path], echo_server: Any
    ) -> None:
        agents, session_dir = judged_dirs
        model = _orchestrator()
        session_a = await Session.open(
            config=_config(tmp_path, agents, echo_server),
            session_dir=session_dir,
            model=model,
            judge_model=ScriptedJudge(verdicts=[_ESCALATE]),
        )
        await session_a.runtime.run_step("post the form")
        assert len(session_a.approvals.pending()) == 1
        await session_a.close()  # restart BEFORE deciding — the gate is open

        session_b = await Session.resume(
            session_dir=session_dir,
            model=model,
            judge_model=ScriptedJudge(verdicts=[_OK]),
        )
        try:
            assert session_b.judge is not None
            # The open escalation is replayed: the class gate is closed again
            # and the request is back in the FIFO for the operator.
            assert session_b.judge.gate_for("network-write") is not None
            pending = session_b.approvals.pending()
            assert len(pending) == 1
            assert pending[0].origin == "judge"
            assert pending[0].rule_or_profile == "judge:escalate_hitl"

            # The operator approves the replayed request: the gate opens and
            # a fresh call is judged again (scripted verdict: ok → allow).
            await session_b.runtime.submit_decision(pending[0].request_id, "approve")
            assert session_b.judge.gate_for("network-write") is None
            verdict, feedback = await session_b.judge.precall(
                "http_post", "network-write", "digest"
            )
            assert verdict is Verdict.ALLOW
            assert feedback is None
        finally:
            await session_b.close()

    async def test_ledger_beyond_search_limit_preserves_the_standing_deny(
        self, tmp_path: Path, judged_dirs: tuple[Path, Path], echo_server: Any
    ) -> None:
        """A ledger longer than any bounded search window replays whole.

        The replay reads the ``judge_class_gate`` ledger in row order
        (``MemoryStore.list_facts``), not through a ranked, limited FTS
        query: once a session accumulates hundreds of gate rows, a
        truncated window would drop the resolution row and either evaporate
        the standing deny or fail the resume outright.
        """
        agents, session_dir = judged_dirs
        model = _orchestrator()
        session_a = await Session.open(
            config=_config(tmp_path, agents, echo_server),
            session_dir=session_dir,
            model=model,
            judge_model=ScriptedJudge(verdicts=[_ESCALATE]),
        )
        await session_a.runtime.run_step("post the form")
        assert len(session_a.approvals.pending()) == 1
        store = session_a.memory
        assert store is not None
        # A long session: hundreds of further escalations (a different
        # class) pile up after the judge escalation and BEFORE the operator
        # decides — the decision row lands far beyond any bounded window.
        for index in range(600):
            await store.add_fact(
                FactDraft(
                    subject="judge_class_gate",
                    predicate="network-read",
                    obj="escalate",
                    tags=[f"gate:bulk-{index}"],
                    source="swarmy/judge",
                )
            )
        await session_a.runtime.submit_decision(
            session_a.approvals.pending()[0].request_id, "reject"
        )
        await session_a.close()  # "process restart"

        session_b = await Session.resume(
            session_dir=session_dir,
            model=model,
            judge_model=ScriptedJudge(verdicts=[_OK]),
        )
        try:
            assert session_b.judge is not None
            # The full ledger replayed: the operator deny (the last row) is
            # re-established WITHOUT consulting the judge model again.
            verdict, feedback = session_b.judge.gate_for("network-write") or (None, None)
            assert verdict is Verdict.BLOCK
            assert feedback is not None
            assert feedback.rule_id == "judge:operator_deny"
            # The bulk escalations replayed too — every undecided ledger row
            # is re-enqueued (dedupe happens per answered decision, not per
            # enqueue): 600 pending requests prove the ledger replayed
            # whole, where a bounded search window would have stopped at
            # ~500 and dropped the trailing resolution row entirely.
            assert session_b.judge.gate_for("network-read") is not None
            assert len(session_b.approvals.pending()) == 600
            assert session_b.approvals.pending()[0].origin == "judge"
        finally:
            await session_b.close()
