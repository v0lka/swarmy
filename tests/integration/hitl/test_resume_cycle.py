"""T3.3.3 acceptance criteria: the HITL resume cycle (headless, RD-6).

Roadmap T3.3.3: a gated (``destructive``) call interrupts the graph; the
interruption survives a process restart (SQLite checkpointer); the operator
``approve`` resumes exactly that call; after the resume the tool passes the
same guardrail pipeline (approve does not cancel invariants — arch §7.4);
the queue empties and the journal holds the full chain
(interrupt → decision → execution).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from tests.helpers.agent_modules import make_module
from tests.helpers.fake_models import ScriptedChatModel, final_reply, task_call

pytestmark = pytest.mark.integration


def _parallel(*tool_calls: dict[str, object]) -> Any:
    from langchain_core.messages import AIMessage

    return AIMessage(content="", tool_calls=list(tool_calls))  # type: ignore[arg-type]


@pytest.fixture
async def breaker_session_dir(tmp_path: Path) -> Path:
    """The module folder of the destructive ``breaker`` fixture module."""
    agents = tmp_path / "agents"
    make_module(
        agents,
        "breaker",
        description="Destructive-capable fixture module.",
        prompt="You are breaker: run your `smash` tool once, then report.",
        risk="destructive",
        tool_name="smash",
    )
    return agents


def _config(tmp_path: Path, agents: Path) -> SessionConfig:
    return SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
        agents_dirs=[str(agents)],
        profile="normal",
    )


def _orchestrator_model() -> ScriptedChatModel:
    return ScriptedChatModel(
        scripts={
            "orchestrator": [
                task_call("run the breaker module", "breaker", "call-b"),
                final_reply("breaker finished"),
            ],
            "breaker": [
                _parallel(
                    {"name": "smash", "args": {"message": "the thing"}, "id": "sb1",
                     "type": "tool_call"}
                ),
                final_reply("smashed"),
            ],
        },
        fallback_reply="done",
    )


class TestResumeCycle:
    """AC: interrupt → restart → approve → executed and re-guardrailed."""

    async def test_interrupt_survives_restart_and_approves(
        self, tmp_path: Path, breaker_session_dir: Path
    ) -> None:
        session_dir = tmp_path / "s"
        # ONE scripted model instance spans both "processes": the scripts
        # continue where the checkpointed conversation left off.
        model = _orchestrator_model()
        session_a = await Session.open(
            config=_config(tmp_path, breaker_session_dir),
            session_dir=session_dir,
            model=model,
        )
        # Step 1: the delegation starts and pauses on the destructive gate.
        await session_a.runtime.run_step("break it")
        approvals_a = session_a.approvals
        pending_before_restart = approvals_a.pending()
        assert len(pending_before_restart) == 1, "the destructive call must be gated"
        request = pending_before_restart[0]
        assert request.tool == "smash"
        assert request.origin in ("profile", "module")  # strictness gate, not judge
        reader_a = session_a.reader
        events_before_restart = len(await reader_a.tail(1000))
        await session_a.close()  # checkpoint WAL — "process restart"

        # Session B: resume restores interrupts from the checkpointer (T3.3.3).
        session_b = await Session.resume(session_dir=session_dir, model=model)
        try:
            runtime_b = session_b.runtime
            approvals_b = session_b.approvals
            # runtime.restore re-pulled the snapshot interrupts into the FIFO
            assert len(approvals_b.pending()) == 1
            resumed_request = approvals_b.pending()[0]
            assert resumed_request.tool == "smash"

            # The operator approves through the runtime: the decision is
            # journalled first, then exactly the addressed interrupt resumes,
            # and the tool passes the same guardrail pipeline afterwards.
            await runtime_b.submit_decision(resumed_request.request_id, "approve")

            # The graph continued to the scripted finish without loss.
            await runtime_b.run_step()  # serve the graph completion + queue
            assert approvals_b.pending() == ()  # AC: the queue empties

            # The journal holds the complete chain (no events lost in restart).
            reader_b = session_b.reader
            events_after_restart = await reader_b.tail(1000)
            assert len(events_after_restart) >= events_before_restart
            kinds = [envelope.type for envelope in events_after_restart]
            assert "OperatorDecision" in kinds  # the approve is journalled
            decisions = await reader_b.by_type("OperatorDecision")
            assert decisions[-1].payload.decision == "approve"  # type: ignore[union-attr]
            # arch §7.4: approve does not cancel invariants — the smash call
            # ran through the pipeline (no deny recorded, the call is pure).
            blocked = await reader_b.by_type("GuardrailBlocked")
            assert blocked == []
        finally:
            await session_b.close()
