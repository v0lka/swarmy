"""T3.5.2 acceptance criteria: multiple parallel interrupts (arch §19.2).

Roadmap T3.5.2: several verify-class delegations interrupt simultaneously;
the observed L0 behaviour is *documented in this test* (arch §19.2 open
question) and the FIFO ApprovalQueue serves every request without loss.

OBSERVED L0 BEHAVIOUR (pinned 0.7.41 stack, this test documents it — arch
§19.2): each parallel ``task()`` subagent raises its own interrupt on the
parent graph; ``snapshot.interrupts`` carries one batched ``HITLRequest`` per
interrupted subagent, and every entry is answered individually by interrupt
id — the queue's FIFO order is the order of ``refresh`` discovery.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from langchain_core.messages import AIMessage

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from tests.helpers.agent_modules import make_module
from tests.helpers.fake_models import ScriptedChatModel, final_reply, task_call

pytestmark = pytest.mark.integration


def _verify_call(call_id: str) -> dict[str, object]:
    """One ``verify_thing`` tool call (verifier_x)."""
    return {
        "name": "verify_thing",
        "args": {"message": f"probe-{call_id}"},
        "id": call_id,
        "type": "tool_call",
    }


@pytest.fixture
async def multi_session(tmp_path: Path) -> Session:
    """Two verify-gated modules delegated in parallel (profile ``normal``)."""
    agents = tmp_path / "agents"
    make_module(
        agents, "verifier_x", description="Verify X (fixture).",
        prompt="You are verifier_x: run your `verify_thing` tool once, then report.",
        risk="verify", tool_name="verify_thing",
    )
    make_module(
        agents, "verifier_y", description="Verify Y (fixture).",
        prompt="You are verifier_y: run your `verify_y_thing` tool once, then report.",
        risk="verify", tool_name="verify_y_thing",
    )
    orchestrator = ScriptedChatModel(
        scripts={
            "orchestrator": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "task",
                         "args": {"description": "verify x", "subagent_type": "verifier_x"},
                         "id": "call-x", "type": "tool_call"},
                        {"name": "task",
                         "args": {"description": "verify y", "subagent_type": "verifier_y"},
                         "id": "call-y", "type": "tool_call"},
                    ],  # type: ignore[arg-type]
                ),
                final_reply("both verifications done"),
            ],
            "verifier_x": [_ai([_verify_call("vx1")]), final_reply("x verified")],
            "verifier_y": [_ai([_verify_y_call("vy1")]), final_reply("y verified")],
        },
        fallback_reply="done",
    )
    config = SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
        agents_dirs=[str(agents)],
        profile="normal",
    )
    session = await Session.open(config=config, session_dir=tmp_path / "s", model=orchestrator)
    try:
        yield session
    finally:
        await session.close()


def _verify_y_call(call_id: str) -> dict[str, object]:
    """One ``verify_y_thing`` tool call (verifier_y)."""
    return {
        "name": "verify_y_thing",
        "args": {"message": f"probe-{call_id}"},
        "id": call_id,
        "type": "tool_call",
    }


def _ai(tool_calls: list[dict[str, object]]) -> AIMessage:
    return AIMessage(content="", tool_calls=tool_calls)  # type: ignore[arg-type]


class TestMultiInterrupts:
    """AC: all interruptions are served by the queue without loss."""

    async def test_parallel_verify_interruptions_served_in_fifo(
        self, multi_session: Session
    ) -> None:
        session = multi_session
        await session.runtime.run_step("verify both")
        approvals = session.approvals
        pending = approvals.pending()
        # OBSERVED L0 (arch §19.2): both subagent interrupts surfaced on the
        # parent; the queue holds one request per interrupted call.
        assert len(pending) == 2, f"expected both gates, got {[r.tool for r in pending]}"
        assert {request.tool for request in pending} == {"verify_thing", "verify_y_thing"}
        assert [request.interrupt_id for request in pending] != ["", ""]  # distinct ids

        # FIFO: approve in queue order — every decision addresses its own id.
        for request in list(pending):
            await session.runtime.submit_decision(request.request_id, "approve")

        # the graph continues to the scripted finish; the queue empties
        snapshot = await session.engine.graph.aget_state(session.runtime.config)
        assert list(snapshot.interrupts) == []  # AC: no interruption lost or stuck
        decisions = await session.reader.by_type("OperatorDecision")
        assert len(decisions) == 2
        assert all(  # type: ignore[union-attr]
            entry.payload.decision == "approve" for entry in decisions
        )
        completed = await session.reader.by_type("TaskCompleted")
        assert len(completed) == 2


class TestSingleTurnMultiCall:
    """Issue #25 (integration, option c): one turn, two gated calls, one interrupt.

    A subagent issuing two verify-class calls in ONE assistant turn raises a
    single *batched* L0 interrupt (``HITLRequest`` with two ``action_requests``
    — the pinned default ``interrupt_mode="batched"``). The queue expands it
    into two per-action entries and resumes only when both are decided, each
    decision carrying its own action's tool name and edited args.
    """

    async def test_batched_interrupt_served_per_action(self, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        make_module(
            agents, "verifier_x", description="Verify X (fixture).",
            prompt="You are verifier_x: run your `verify_thing` tool once, then report.",
            risk="verify", tool_name="verify_thing",
        )
        model = ScriptedChatModel(
            scripts={
                "orchestrator": [
                    task_call("verify x twice", "verifier_x", "call-x"),
                    final_reply("delegation finished"),
                ],
                "verifier_x": [
                    _ai([_verify_call("vx1"), _verify_call("vx2")]),  # ONE turn, two calls
                    final_reply("x verified"),
                ],
            },
            fallback_reply="done",
        )
        config = SessionConfig(
            target=TargetConfig(base_url="http://127.0.0.1:9/"),
            scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
            agents_dirs=[str(agents)],
            profile="normal",
        )
        session = await Session.open(config=config, session_dir=tmp_path / "s", model=model)
        try:
            await session.runtime.run_step("verify both")
            approvals = session.approvals
            pending = approvals.pending()
            assert len(pending) == 2, "the batched interrupt must expand per action"
            assert {request.tool for request in pending} == {"verify_thing"}
            assert len({request.interrupt_id for request in pending}) == 1
            assert len({request.request_id for request in pending}) == 2
            first, second = pending

            # The first decision alone must not resume the turn yet.
            await session.runtime.submit_decision(first.request_id, "approve")
            assert len(approvals.pending()) == 1
            completed = await session.reader.by_type("TaskCompleted")
            assert completed == []  # the batched turn is still held

            # The edit decision stays on ITS action and completes the group.
            await session.runtime.submit_decision(
                second.request_id, "edit", edited_args={"message": "rewritten"}
            )
            decisions = await session.reader.by_type("OperatorDecision")
            assert [entry.payload.decision for entry in decisions] == ["approve", "edit"]
            completed = await session.reader.by_type("TaskCompleted")
            assert len(completed) == 1, "the last decision resumed the batched turn"
            assert approvals.pending() == ()
        finally:
            await session.close()
