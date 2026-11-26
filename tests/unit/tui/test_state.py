"""T4.1.1 acceptance criteria: the SessionView facade and the TuiState.

* the coalescing UI queue never loses events (arch §5.3 contract);
* the facade exposes read-only queries and §7.3/§10.3 operator actions;
* the graph-result readers are L0-free and duck-typed (arch §2.5);
* the tui import set stays inside the facade allowlist (verified by the
  arch test suite; the M3 suite proves it in reverse — importing
  ``swarmy.tui`` here must not import any core internals at runtime).
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from tests.helpers.fake_models import one_shot_model

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from swarmy.events.models import (
    EndpointsDiscoveredPayload,
    EventSource,
    GuardrailBlockedPayload,
)
from swarmy.memory.models import EndpointDraft, FindingDraft, Severity
from swarmy.tui.state import (
    REPLIES_MAX,
    SYSTEM_ERRORS_MAX,
    ApprovalItem,
    SessionView,
    TodoItem,
    TuiState,
    delegation_transcripts,
    orchestrator_reply,
    orchestrator_todos,
)

if TYPE_CHECKING:
    from pathlib import Path

    from swarmy.events.models import EventEnvelope

pytestmark = pytest.mark.unit


def _config(tmp_path: Path) -> SessionConfig:
    """A minimal config over loopback (never contacted in these tests)."""
    return SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
    )


@pytest.fixture
async def session(tmp_path: Path) -> Session:
    """One composed session (no steps run — composition is what matters)."""
    opened = await Session.open(
        config=_config(tmp_path), session_dir=tmp_path / "s", model=one_shot_model()
    )
    return opened


def test_tui_imports_pull_no_core_or_l0() -> None:
    """Importing the console pulls no core internals and no L0 stack (§10.2).

    Runs in a fresh interpreter (this test module composes real sessions).
    The facade imports stay TYPE_CHECKING-only, so ``swarmy.core`` never
    loads; the parent-package re-exports (``swarmy.events``/__init__ → bus,
    ``swarmy.memory``/__init__ → store) are pre-existing L1 side effects and
    stay L0-free — the assertion pins both properties.
    """
    probe = (
        "import json, sys\n"
        "import swarmy.tui.state, swarmy.tui.app  # the whole console\n"
        "loaded = sorted(sys.modules)\n"
        "core = [n for n in loaded if n.startswith('swarmy.core')]\n"
        "l0 = [n for n in loaded if n.split('.')[0] in ('deepagents', 'langchain', 'langgraph')]\n"
        "print(json.dumps({'core': core, 'l0': l0}))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    pulled = json.loads(proc.stdout.strip().splitlines()[-1])
    assert pulled["core"] == [], f"importing the tui pulled core internals: {pulled['core']}"
    assert pulled["l0"] == [], f"importing the tui pulled the L0 stack: {pulled['l0']}"


# ---------------------------------------------------------------------------
# Coalescing (arch §5.3)
# ---------------------------------------------------------------------------


async def test_coalescing_queue_never_loses_events(session: Session) -> None:
    """100 rapid events arrive as ONE batch — every envelope, one redraw."""
    state = TuiState(SessionView(session))
    state.start()
    try:
        envelopes: list[EventEnvelope] = []
        writer = session.journal
        bus = session.bus
        assert writer is not None
        assert bus is not None
        for index in range(100):
            envelopes.append(
                await writer.append(
                    type="GuardrailBlocked",
                    source=EventSource.PLATFORM,
                    source_detail="test",
                    correlation_id="",
                    payload=GuardrailBlockedPayload(
                        tool_name="t",
                        rule_id="r",
                        layer="engine",
                        reason=f"event {index}",
                        tool_args_digest="",
                    ),
                )
            )
            await bus.publish(envelopes[-1])
        # Let the bus dispatcher deliver every event BEFORE the consumer
        # wakes: the coalescing queue then serves all 100 as ONE batch.
        for _ in range(8):
            await asyncio.sleep(0)
        batch = await state.wait_batch(poll_after=1.0)
        assert len(batch) == 100
        assert [envelope.id for envelope in batch] == [envelope.id for envelope in envelopes]
        assert await state.wait_batch(poll_after=0.05) == []  # nothing left behind
    finally:
        state.stop()
        await session.close()


async def test_poll_expiry_returns_empty_batch(session: Session) -> None:
    """The poll tick returns an empty batch when nothing arrived."""
    state = TuiState(SessionView(session))
    assert await state.wait_batch(poll_after=0.01) == []
    await session.close()


async def test_kick_wakes_the_consumer_immediately(session: Session) -> None:
    """``kick`` releases a waiting consumer without any event."""
    state = TuiState(SessionView(session))
    task = asyncio.ensure_future(state.wait_batch())
    await asyncio.sleep(0.01)
    assert not task.done()
    state.kick()
    await asyncio.wait_for(asyncio.shield(task), 0.5)
    assert task.result() == []  # woke with an empty pending list
    await session.close()


async def test_dirty_types_drive_snapshots(session: Session) -> None:
    """Memory-touching types mark snapshots dirty; others do not."""
    state = TuiState(SessionView(session))
    state.start()
    try:
        writer = session.journal
        bus = session.bus
        assert writer is not None
        assert bus is not None
        envelope = await writer.append(
            type="EndpointsDiscovered",
            source=EventSource.PLATFORM,
            source_detail="test",
            correlation_id="",
            payload=EndpointsDiscoveredPayload(endpoints=[], out_of_scope_count=0),
        )
        await bus.publish(envelope)
        await state.wait_batch(poll_after=0.1)
        assert state.needs_snapshot(state.take_dirty())
        assert not state.needs_snapshot(state.take_dirty())
    finally:
        state.stop()
        await session.close()


# ---------------------------------------------------------------------------
# Duck-typed graph-result readers (L0-free)
# ---------------------------------------------------------------------------


def test_orchestrator_reply_takes_last_ai_text() -> None:
    """The last non-empty assistant text wins over tool-call turns."""
    result = {
        "messages": [
            SimpleNamespace(type="human", content="hi"),
            SimpleNamespace(type="ai", content=""),  # tool-call turn
            SimpleNamespace(type="tool", content="ok"),
            SimpleNamespace(type="ai", content="all done"),
        ]
    }
    assert orchestrator_reply(result) == "all done"
    assert orchestrator_reply(None) == ""
    assert orchestrator_reply({"messages": "not-a-sequence"}) == ""


def test_orchestrator_reply_reads_content_part_lists() -> None:
    """Content blocks (list of text parts) concatenate into one text."""
    result = {
        "messages": [
            SimpleNamespace(
                type="ai", content=[{"type": "text", "text": "par"}, {"type": "text", "text": "tial"}]
            )
        ]
    }
    assert orchestrator_reply(result) == "partial"


def test_orchestrator_todos_projection() -> None:
    """Todos fold into TodoItem models; non-mapping entries are skipped."""
    result = {"todos": [{"content": "crawl", "status": "completed"}, "junk", 42]}
    todos = orchestrator_todos(result)
    assert todos == [TodoItem(content="crawl", status="completed")]
    assert orchestrator_todos({"todos": None}) == []


def test_delegation_transcripts_pair_task_calls_with_results() -> None:
    """task() calls pair with their result messages via the call id."""
    result = {
        "messages": [
            SimpleNamespace(
                type="ai",
                tool_calls=[
                    {"name": "task", "args": {"description": "crawl d", "subagent_type": "crawler"},
                     "id": "c1", "type": "tool_call"},
                    {"name": "other_tool", "args": {}, "id": "c2", "type": "tool_call"},
                ],
            ),
            SimpleNamespace(type="tool", tool_call_id="c2", content="unrelated"),
            SimpleNamespace(type="tool", tool_call_id="c1", content="crawl report"),
        ]
    }
    assert delegation_transcripts(result) == {
        "crawler": ["task: crawl d", "crawl report"],
    }
    assert delegation_transcripts({}) == {}


# ---------------------------------------------------------------------------
# SessionView facade
# ---------------------------------------------------------------------------


async def test_facade_read_only_queries(session: Session) -> None:
    """endpoints/findings/attack graphs/journal tail flow through the facade."""
    view = SessionView(session)
    memory = session.memory
    assert memory is not None
    endpoint = await memory.upsert_endpoint(
        EndpointDraft(host="127.0.0.1:9", method="GET", path="/a")
    )
    assert [item.id for item in await view.endpoints()] == [endpoint.id]
    assert await view.attack_nodes() == []
    tail = await view.journal_tail(10)
    assert [envelope.type for envelope in tail][-1] == "TargetSet"
    assert view.profile_label() == "profile=normal mode=interactive"
    await session.close()


async def test_facade_mask_applies_the_projector(tmp_path: Path) -> None:
    """Operator secrets are masked in facade-projected display texts (§6.8)."""
    from swarmy.core.config import SecretsConfig

    session_dir = tmp_path / "s2"
    secrets = SecretsConfig(auth_headers={"X-Token": "hushhush-value"})
    opened = await Session.open(
        config=_config(tmp_path), session_dir=session_dir, secrets=secrets,
        model=one_shot_model(),
    )
    try:
        view = SessionView(opened)
        masked = view.mask("token hushhush-value leaked")
        assert "hushhush-value" not in masked
        assert "<masked:X-Token>" in masked
    finally:
        await opened.close()


async def test_facade_pending_approvals_projection(session: Session) -> None:
    """Judge-origin escalations project into ApprovalItem rows (§7.3)."""
    view = SessionView(session)
    queue = session.approvals
    assert queue is not None
    await queue.enqueue_external(
        tool="verify",
        args_digest="judge says escalate",
        origin="judge",
        rule_or_profile="judge:escalate_hitl",
    )
    pending = view.pending_approvals()
    assert len(pending) == 1
    item = pending[0]
    assert isinstance(item, ApprovalItem)
    assert (item.tool, item.origin, item.rule_or_profile) == (
        "verify", "judge", "judge:escalate_hitl",
    )
    assert item.args_digest == "judge says escalate"
    assert item.interrupt_id == ""  # external request: no graph interrupt
    await session.close()


async def test_facade_submit_decision_journals_operator_decision(session: Session) -> None:
    """Deciding an external request journals OperatorDecision (platform emit)."""
    view = SessionView(session)
    queue = session.approvals
    assert queue is not None
    request = await queue.enqueue_external(
        tool="verify", args_digest="d", origin="judge", rule_or_profile="judge"
    )
    await view.submit_decision(request.request_id, "approve")
    reader = session.reader
    assert reader is not None
    decisions = await reader.by_type("OperatorDecision")
    assert len(decisions) == 1
    await session.close()


async def test_facade_chat_round_trip_queues_operator_message(session: Session) -> None:
    """send_operator_message journals OperatorMessage and queues the step."""
    view = SessionView(session)
    await view.send_operator_message("please continue")
    assert view.pending_injections() == 1
    reader = session.reader
    assert reader is not None
    assert len(await reader.by_type("OperatorMessage")) == 1
    await session.close()


async def test_state_preload_and_refresh(session: Session) -> None:
    """preload pulls the journal tail; refresh snapshots stay consistent."""
    view = SessionView(session)
    state = TuiState(view, tail_size=50)
    state.start()
    try:
        await state.preload()
        assert [envelope.type for envelope in state.feed][-1] == "TargetSet"
        assert state.approvals == ()
        memory = session.memory
        assert memory is not None
        await memory.save_finding(
            FindingDraft(
                type="xss",
                severity=Severity.HIGH,
                title="t",
                description="d",
                created_by="test",
            )
        )
        await state.refresh()
        assert len(state.findings) == 1
        assert state.findings[0].severity is Severity.HIGH
    finally:
        state.stop()
        await session.close()


# ---------------------------------------------------------------------------
# Bounded feed window + system errors + transcript snapshot (#14/#28/#33)
# ---------------------------------------------------------------------------


async def test_feed_window_is_bounded_and_counted(session: Session) -> None:
    """extend_feed drops the oldest beyond the window; the count keeps the total.

    Issue #33: the feed used to grow without bound over a long session; the
    window is capped while the statistics keep reporting the session total.
    """
    state = TuiState(SessionView(session), feed_max=5)
    writer = session.journal
    bus = session.bus
    assert writer is not None
    assert bus is not None
    batch: list[EventEnvelope] = []
    for index in range(8):
        batch.append(
            await writer.append(
                type="GuardrailBlocked",
                source=EventSource.PLATFORM,
                source_detail="test",
                correlation_id="",
                payload=GuardrailBlockedPayload(
                    tool_name="t",
                    rule_id="r",
                    layer="engine",
                    reason=f"event {index}",
                    tool_args_digest="",
                ),
            )
        )
    state.extend_feed(batch)
    assert len(state.feed) == 5
    assert state.event_count == 8
    assert [envelope.id for envelope in state.feed] == [envelope.id for envelope in batch[3:]]
    assert [envelope.id for envelope in state.recent_feed(3)] == [
        envelope.id for envelope in batch[5:]
    ]
    assert len(state.recent_feed(100)) == 5
    await session.close()


async def test_absorb_treats_transcripts_as_snapshot(session: Session) -> None:
    """Issue #14: every step result re-carries the full history — replace it.

    The old ``extend`` semantics re-added every historical delegation on each
    delegation-bearing step, duplicating transcripts ~N times after N steps.
    """
    state = TuiState(SessionView(session))
    call = {
        "name": "task",
        "args": {"description": "crawl d", "subagent_type": "crawler"},
        "id": "c1",
        "type": "tool_call",
    }

    def step() -> dict[str, object]:
        return {
            "messages": [
                SimpleNamespace(type="ai", tool_calls=[call]),
                SimpleNamespace(type="tool", tool_call_id="c1", content="crawl report"),
            ]
        }

    state.absorb(step())
    assert state.subagent_transcripts == {"crawler": ["task: crawl d", "crawl report"]}
    state.absorb(step())  # the next step re-pairs the SAME historical call
    assert state.subagent_transcripts == {"crawler": ["task: crawl d", "crawl report"]}
    await session.close()


async def test_report_error_is_bounded(session: Session) -> None:
    """The system-error buffer (the Issue #28 chat surface) stays bounded."""
    state = TuiState(SessionView(session))
    for index in range(SYSTEM_ERRORS_MAX + 5):
        state.report_error(f"error {index}")
    assert len(state.system_errors) == SYSTEM_ERRORS_MAX
    assert list(state.system_errors)[-1] == f"error {SYSTEM_ERRORS_MAX + 4}"
    await session.close()


async def test_absorb_keeps_the_whole_reply_history(session: Session) -> None:
    """Issue #47: the transcript keeps every orchestrator reply, bounded.

    The old semantics kept only ``last_reply`` — after the second operator
    question the first orchestrator answer disappeared from the dialog.
    """
    state = TuiState(SessionView(session))

    def step(reply: str) -> dict[str, object]:
        return {"messages": [SimpleNamespace(type="ai", content=reply)]}

    state.absorb(step("first answer"))
    state.absorb(step("second answer"))
    assert state.last_reply == "second answer"
    assert list(state.replies) == ["first answer", "second answer"]
    state.absorb(step(""))  # a reply-less step appends nothing
    assert list(state.replies) == ["first answer", "second answer"]
    for index in range(REPLIES_MAX + 10):
        state.absorb(step(f"answer {index}"))
    assert len(state.replies) == REPLIES_MAX
    assert next(iter(state.replies)) == "answer 10"
    assert list(state.replies)[-1] == f"answer {REPLIES_MAX + 9}"
    await session.close()


async def test_absorb_does_not_reappend_the_stale_reply(session: Session) -> None:
    """Prose-less steps must not re-append the previous reply.

    The real accumulated shape: every step result carries the FULL message
    history (langgraph accumulates ``messages``), so a delegation turn or a
    HITL pause still ends with the *earlier* AI prose in history —
    ``orchestrator_reply`` returns it again, and appending per step would
    duplicate the reply (same per-step-delta flaw as the #14 transcripts).
    """
    state = TuiState(SessionView(session))
    call = {
        "name": "task",
        "args": {"description": "crawl d", "subagent_type": "crawler"},
        "id": "c9",
        "type": "tool_call",
    }

    def step() -> dict[str, object]:
        return {
            "messages": [
                # the earlier AI prose of the whole accumulated history …
                SimpleNamespace(type="human", content="go"),
                SimpleNamespace(type="ai", content="the one real answer"),
                # … followed by this step's tool-call/tool pair (no prose)
                SimpleNamespace(type="ai", tool_calls=[call]),
                SimpleNamespace(type="tool", tool_call_id="c9", content="crawl report"),
            ]
        }

    state.absorb(step())
    state.absorb(step())  # delegation turn: history ends with tool pairs, prose unchanged
    state.absorb(step())  # HITL pause turn: still the same stale prose
    assert list(state.replies) == ["the one real answer"]
    await session.close()


async def test_chat_lines_render_the_full_reply_history(session: Session) -> None:
    """Issue #47: the chat panel renders every reply, latest last."""
    from swarmy.tui.panels.chat import ChatPanel

    state = TuiState(SessionView(session))
    state.absorb({"messages": [SimpleNamespace(type="ai", content="first answer")]})
    state.absorb({"messages": [SimpleNamespace(type="ai", content="second answer")]})
    panel = ChatPanel("chat-test", masker=lambda text: text)
    lines = panel._lines(state)
    orchestrator_lines = [text for tag, text in lines if tag == "orchestrator>"]
    assert orchestrator_lines == ["first answer", "second answer"]
    await session.close()
