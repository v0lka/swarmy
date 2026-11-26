"""T3.3.1/T3.3.2 acceptance criteria: the HITL matrix and the ApprovalQueue.

Roadmap T3.3.1: the profile x class matrix matches arch §7.2 (parametrized),
module entries win the merge, rebuilding with another profile or mode changes
the gate set — both on the flat L0 mapping and on the session-wide
``InterruptConfig`` views (orchestrator + per-module merges).
Roadmap T3.3.2: FIFO across several parallel interrupts (through direct
snapshot refresh and through a scripted fake graph behind the queue's
``state_reader`` seam), the decision is delivered to the addressed
``interrupt_id``, ``edit`` swaps the arguments, ``reject`` feeds the agent
an operator-rejection text, the built command reaches the injected
``graph_runner``, and every step lands in the journal as an
``OperatorDecision``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

import pytest
from langgraph.types import Command, Interrupt, StateSnapshot

from swarmy.core.hitl import (
    ALLOWED_DECISIONS,
    ApprovalQueue,
    ApprovalRequest,
    build_interrupt_config,
    build_session_interrupt_config,
    merge_interrupt_config,
)
from swarmy.guardrails.models import RiskClass

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_CLASSES: dict[str, RiskClass] = {
    "http_get": RiskClass.PASSIVE,
    "http_post": RiskClass.NETWORK_WRITE,
    "verify_probe": RiskClass.VERIFY,
    "wipe_form": RiskClass.DESTRUCTIVE,
}


def _snapshot(*interrupt_values: tuple[str, str, dict[str, Any]]) -> StateSnapshot:
    """A state snapshot carrying one interrupt per ``(id, tool, args)`` triple."""
    interrupts = tuple(
        Interrupt(value={"name": tool, "args": args}, id=interrupt_id)
        for interrupt_id, tool, args in interrupt_values
    )
    return StateSnapshot(
        values={},
        next=(),
        config={"configurable": {"thread_id": "t"}},
        metadata=None,
        created_at=None,
        parent_config=None,
        tasks=(),
        interrupts=interrupts,
    )


def _recording_queue(
    sanitizer: Any = None,
    state_reader: Any = None,
) -> tuple[ApprovalQueue, list[tuple[str, Mapping[str, object]]]]:
    """A queue whose OperatorDecision events are captured (no journal/db)."""
    calls: list[tuple[str, Mapping[str, object]]] = []

    async def emit(event_type: str, payload: Mapping[str, object]) -> str:
        calls.append((event_type, payload))
        return f"journalled {event_type}"

    queue = ApprovalQueue(emit=emit, sanitizer=sanitizer, state_reader=state_reader)
    return queue, calls


# ---------------------------------------------------------------------------
# T3.3.1 — the matrix
# ---------------------------------------------------------------------------


class TestProfileMatrix:
    """AC: the matrix matches the arch §7.2 table (parametrized test)."""

    @pytest.mark.parametrize(
        ("profile", "gated"),
        [
            ("paranoid", {"http_post", "verify_probe", "wipe_form"}),
            ("normal", {"verify_probe", "wipe_form"}),
            ("yolo", {"wipe_form"}),
        ],
    )
    def test_matrix(self, profile: str, gated: set[str]) -> None:
        config = build_interrupt_config(profile, _CLASSES, mode="mission")
        for tool_name, risk in _CLASSES.items():
            entry = config[tool_name]
            if tool_name in gated:
                assert entry is not False, f"{risk.value} must be gated by {profile}"
                assert entry["allowed_decisions"] == ALLOWED_DECISIONS  # type: ignore[index]
                assert entry["allowed_decisions"] == ["approve", "edit", "reject"]  # type: ignore[index]
            else:
                assert entry is False, f"{tool_name} must be ungated by {profile}"

    def test_passive_never_gated(self) -> None:
        for profile in ("paranoid", "normal", "yolo"):
            assert build_interrupt_config(profile, _CLASSES, mode="mission")["http_get"] is False

    def test_interactive_adds_significant_forks(self) -> None:
        config = build_interrupt_config(
            "yolo", _CLASSES, mode="interactive", significant_tools={"http_get"}
        )
        assert config["http_get"] is not False  # gated by mode, not by class
        mission = build_interrupt_config("yolo", _CLASSES, mode="mission")
        assert mission["http_get"] is False

    def test_unknown_profile_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown strictness profile"):
            build_interrupt_config("wild-west", _CLASSES)  # type: ignore[arg-type]


class TestMergeAndRebuild:
    """AC: module entries win the merge; another profile rebuilds differently."""

    def test_module_entry_wins(self) -> None:
        base = build_interrupt_config("normal", _CLASSES, mode="mission")
        merged = merge_interrupt_config(
            base,
            {
                "verify_probe": False,  # module explicitly ungates it
                "http_get": {"allowed_decisions": ["approve", "edit", "reject"],
                             "description": "module gate"},
            },
        )
        assert merged["verify_probe"] is False  # module entry replaced the profile gate
        assert isinstance(merged["http_get"], dict)  # module gate added
        assert merged["wipe_form"] == base["wipe_form"]  # untouched tool keeps profile gate

    def test_rebuild_on_another_profile_changes_gates(self) -> None:
        normal = build_interrupt_config("normal", _CLASSES, mode="mission")
        paranoid = build_interrupt_config("paranoid", _CLASSES, mode="mission")
        assert paranoid["http_post"] is not False  # newly gated
        assert normal["http_post"] is False
        assert set(normal) == set(paranoid)  # same tool coverage, different verdicts


class TestSessionInterruptConfig:
    """AC: the session-wide views — orchestrator matrix, per-module merge, rebuild."""

    @pytest.mark.parametrize(
        ("profile", "gated"),
        [
            ("paranoid", {"http_post", "verify_probe", "wipe_form"}),
            ("normal", {"verify_probe", "wipe_form"}),
            ("yolo", {"wipe_form"}),
        ],
    )
    def test_orchestrator_view_matches_matrix(self, profile: str, gated: set[str]) -> None:
        config = build_session_interrupt_config(profile, _CLASSES, mode="mission")
        gated_view = {tool for tool, gate in config.orchestrator.items() if gate is not False}
        assert gated_view == gated

    def test_per_module_merge_replaces_profile_entries(self) -> None:
        config = build_session_interrupt_config(
            "normal",
            _CLASSES,
            mode="mission",
            module_overrides={"crawler": {"verify_probe": False}},
        )
        assert config.orchestrator["verify_probe"] is not False  # orchestrator untouched
        assert config.per_module["crawler"]["verify_probe"] is False  # module entry wins
        module_gate = config.per_module["crawler"]["wipe_form"]
        assert module_gate == config.orchestrator["wipe_form"]  # others keep the profile gate

    def test_module_gate_entry_replaces_whole_config(self) -> None:
        gate = {"allowed_decisions": ["approve", "edit", "reject"], "description": "module gate"}
        config = build_session_interrupt_config(
            "yolo", _CLASSES, mode="mission", module_overrides={"fuzzer": {"http_get": gate}}
        )
        assert config.per_module["fuzzer"]["http_get"] == gate

    def test_modules_without_overrides_inherit_orchestrator(self) -> None:
        config = build_session_interrupt_config(
            "normal", _CLASSES, mode="mission", module_overrides={"crawler": {}}
        )
        assert set(config.per_module) == {"crawler"}  # only named modules get entries
        assert config.per_module["crawler"] == config.orchestrator

    def test_rebuild_on_another_profile_changes_views(self) -> None:
        normal = build_session_interrupt_config("normal", _CLASSES, mode="mission")
        paranoid = build_session_interrupt_config("paranoid", _CLASSES, mode="mission")
        assert paranoid.orchestrator["http_post"] is not False  # newly gated
        assert normal.orchestrator["http_post"] is False
        assert normal != paranoid  # AC: rebuild yields a different gate set

    def test_rebuild_on_another_mode_changes_gates(self) -> None:
        mission = build_session_interrupt_config("yolo", _CLASSES, mode="mission")
        interactive = build_session_interrupt_config(
            "yolo", _CLASSES, mode="interactive", significant_tools={"http_get"}
        )
        assert interactive.orchestrator["verify_probe"] is not False  # verify-class floor
        assert mission.orchestrator["verify_probe"] is False
        assert interactive.orchestrator["http_get"] is not False  # decision point gated
        assert mission.orchestrator["http_get"] is False  # mission: profile gates only
        assert interactive != mission  # AC: mode change → different gate set


# ---------------------------------------------------------------------------
# T3.3.2 — the queue
# ---------------------------------------------------------------------------


class TestFifoAndAddressing:
    """AC: FIFO across parallel interrupts; decisions address their interrupt."""

    async def test_fifo_order_preserved(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(
            _snapshot(
                ("int-a", "verify_probe", {"url": "https://t/1"}),
                ("int-b", "wipe_form", {"url": "https://t/2"}),
                ("int-c", "verify_probe", {"url": "https://t/3"}),
            )
        )
        pending = queue.pending()
        assert [request.interrupt_id for request in pending] == ["int-a", "int-b", "int-c"]
        assert [request.request_id for request in pending] == ["apr-0001", "apr-0002", "apr-0003"]

    async def test_refresh_is_idempotent(self) -> None:
        queue, _calls = _recording_queue()
        snapshot = _snapshot(("int-a", "verify_probe", {}))
        queue.refresh(snapshot)
        queue.refresh(snapshot)
        assert len(queue.pending()) == 1

    async def test_decision_addresses_the_right_interrupt(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(
            _snapshot(
                ("int-a", "verify_probe", {"url": "https://t/1"}),
                ("int-b", "wipe_form", {"url": "https://t/2"}),
            )
        )
        command = await queue.submit_decision("apr-0002", "approve")
        assert isinstance(command, Command)
        assert list(command.resume) == ["int-b"]  # exactly the addressed interrupt
        assert command.resume["int-b"] == {"type": "approve"}
        assert [request.interrupt_id for request in queue.pending()] == ["int-a"]

    async def test_unknown_request_id_rejected_and_request_stays(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(_snapshot(("int-a", "verify_probe", {})))
        with pytest.raises(ValueError, match="unknown request_id"):
            await queue.submit_decision("apr-9999", "approve")
        assert len(queue.pending()) == 1  # retriable


class _FakeGraph:
    """Scripted fake graph: ``aget_state`` replays pre-scripted snapshots."""

    def __init__(self, *snapshots: StateSnapshot) -> None:
        self._snapshots = list(snapshots)
        self._last = snapshots[0]
        self.configs: list[object] = []

    async def aget_state(self, thread_config: object) -> StateSnapshot:
        self.configs.append(thread_config)
        if self._snapshots:
            self._last = self._snapshots.pop(0)
        return self._last


class TestStateReaderPolling:
    """AC (delegation path): the queue polls a scripted fake graph itself."""

    async def test_poll_orders_three_interrupts_fifo(self) -> None:
        graph = _FakeGraph(
            _snapshot(
                ("int-a", "verify_probe", {"url": "https://t/1"}),
                ("int-b", "wipe_form", {"url": "https://t/2"}),
                ("int-c", "http_post", {"url": "https://t/3"}),
            )
        )
        queue, _calls = _recording_queue(state_reader=graph.aget_state)
        thread = {"configurable": {"thread_id": "t"}}
        requests = await queue.refresh_from_config(thread)
        assert graph.configs == [thread]  # the config reached the graph seam
        assert [request.interrupt_id for request in requests] == ["int-a", "int-b", "int-c"]
        again = await queue.refresh_from_config(thread)
        assert [request.interrupt_id for request in again] == ["int-a", "int-b", "int-c"]
        assert again == list(queue.pending())  # idempotent: no duplicates on re-poll

    async def test_poll_requires_state_reader(self) -> None:
        queue, _calls = _recording_queue()
        with pytest.raises(TypeError, match="state_reader"):
            await queue.refresh_from_config({"configurable": {"thread_id": "t"}})

    async def test_decision_flows_to_graph_runner(self) -> None:
        graph = _FakeGraph(_snapshot(("int-a", "http_post", {"url": "https://t/old"})))
        queue, calls = _recording_queue(state_reader=graph.aget_state)
        await queue.refresh_from_config({"configurable": {"thread_id": "t"}})
        handed: list[Command] = []

        async def runner(command: Command) -> object:
            handed.append(command)
            return "resumed"

        command = await queue.submit_decision(
            "apr-0001", "edit", edited_args={"url": "https://t/new"}, graph_runner=runner
        )
        assert handed == [command]  # the exact built command reaches the runtime seam
        assert list(command.resume) == ["int-a"]  # addressed interrupt_id
        payload = command.resume["int-a"]
        assert payload["type"] == "edit"  # edit substitutes the arguments
        assert payload["edited_action"] == {"name": "http_post", "args": {"url": "https://t/new"}}
        decisions = [entry for kind, entry in calls if kind == "OperatorDecision"]
        assert decisions[0]["decision"] == "edit"  # journalled before the runner ran

    async def test_graph_runner_skipped_for_external_request(self) -> None:
        queue, _calls = _recording_queue()
        handed: list[Command] = []

        async def runner(command: Command) -> object:
            handed.append(command)
            return None

        request = await queue.enqueue_external("network-write", "judge escalation")
        await queue.submit_decision(request.request_id, "approve", graph_runner=runner)
        assert handed == []  # not interrupt-backed: the runtime skips the graph
        assert queue.pending() == ()


class TestEditAndReject:
    """AC: ``edit`` substitutes arguments; ``reject`` returns an operator feedback."""

    async def test_edit_replaces_args(self) -> None:
        queue, calls = _recording_queue()
        queue.refresh(_snapshot(("int-a", "http_post", {"url": "https://t/old"})))
        command = await queue.submit_decision(
            "apr-0001", "edit", edited_args={"url": "https://t/new"}
        )
        payload = command.resume["int-a"]
        assert payload["type"] == "edit"
        assert payload["edited_action"] == {"name": "http_post", "args": {"url": "https://t/new"}}
        decision_events = [payload for kind, payload in calls if kind == "OperatorDecision"]
        assert decision_events[0]["decision"] == "edit"
        assert decision_events[0]["edited_args_digest"] is not None

    async def test_edit_without_args_is_refused(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(_snapshot(("int-a", "http_post", {})))
        with pytest.raises(ValueError, match="requires edited_args"):
            await queue.submit_decision("apr-0001", "edit")
        assert len(queue.pending()) == 1

    async def test_reject_carries_feedback_message(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(_snapshot(("int-a", "http_post", {})))
        command = await queue.submit_decision("apr-0001", "reject")
        payload = command.resume["int-a"]
        assert payload["type"] == "reject"
        assert "Rejected by the operator" in payload["message"]
        assert "not executed" in payload["message"]


class TestJournaling:
    """AC: every decision step is journalled as ``OperatorDecision``."""

    async def test_each_step_journalled(self) -> None:
        queue, calls = _recording_queue()
        queue.refresh(
            _snapshot(
                ("int-a", "verify_probe", {}),
                ("int-b", "wipe_form", {}),
            )
        )
        await queue.submit_decision("apr-0002", "reject")
        await queue.submit_decision("apr-0001", "approve")
        decisions = [payload for kind, payload in calls if kind == "OperatorDecision"]
        assert [entry["decision"] for entry in decisions] == ["reject", "approve"]
        assert [entry["request_id"] for entry in decisions] == ["apr-0002", "apr-0001"]

    async def test_digest_sanitized_by_projector(self) -> None:
        captured: dict[str, str] = {}

        def sanitize(args: Mapping[str, object]) -> str:
            captured["digest"] = f"sanitized<{sorted(args)}>"
            return captured["digest"]

        queue, _calls = _recording_queue(sanitizer=sanitize)
        queue.refresh(_snapshot(("int-a", "http_post", {"url": "https://t"})))
        request = queue.pending()[0]
        assert request.args_digest == captured["digest"]


class TestExternalJudgeRequests:
    """Judge escalations enqueue with ``origin='judge'`` and resolve in-queue (T3.4.x)."""

    async def test_enqueue_external_origin_and_resolver(self) -> None:
        queue, calls = _recording_queue()
        resolved: list[str] = []

        async def resolver(decision: str) -> None:
            resolved.append(decision)

        request = await queue.enqueue_external(
            "network-write",
            "judge flagged the call",
            origin="judge",
            rule_or_profile="judge:escalate_hitl",
            resolver=resolver,
        )
        assert request.origin == "judge"
        assert request.interrupt_id == ""  # not interrupt-backed
        assert isinstance(request, ApprovalRequest)
        command = await queue.submit_decision(request.request_id, "approve")
        assert command.resume == {}  # nothing to resume in the graph
        assert resolved == ["approve"]  # the registry resolution ran
        assert queue.pending() == ()
        decisions = [payload for kind, payload in calls if kind == "OperatorDecision"]
        assert decisions[0]["decision"] == "approve"


# ---------------------------------------------------------------------------
# Issue #25 — batched L0 interrupts expand into per-action requests.
# ---------------------------------------------------------------------------


def _batched_snapshot() -> StateSnapshot:
    """A snapshot carrying ONE batched interrupt with two action requests."""
    value = {
        "action_requests": [
            {"name": "http_get", "args": {"url": "https://t/a"}},
            {"name": "http_post", "args": {"url": "https://t/b"}},
        ],
        "review_configs": [],
    }
    return StateSnapshot(
        values={},
        next=(),
        config={"configurable": {"thread_id": "t"}},
        metadata=None,
        created_at=None,
        parent_config=None,
        tasks=(),
        interrupts=(Interrupt(value=value, id="int-batch"),),
    )


class TestBatchedInterrupts:
    """One assistant turn with several gated calls = ONE batched L0 interrupt.

    The queue expands it into one request per action (per-call digests,
    origins and labels), and the resume value is built from the per-action
    decisions — an operator edit can no longer rewrite a sibling call with
    foreign arguments (Issue #25).
    """

    async def test_batched_interrupt_expands_to_per_action_requests(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(
            _batched_snapshot(),
            origins={"http_post": "module"},
            rules={"http_post": "module gate"},
        )
        pending = queue.pending()
        assert [request.tool for request in pending] == ["http_get", "http_post"]
        assert [request.interrupt_id for request in pending] == ["int-batch", "int-batch"]
        assert {request.args_digest for request in pending} == {
            '{"url": "https://t/a"}',
            '{"url": "https://t/b"}',
        }
        assert {request.tool: request.origin for request in pending} == {
            "http_get": "profile",  # per-tool lookup, not the joined-name fallback
            "http_post": "module",
        }
        assert {request.tool: request.rule_or_profile for request in pending} == {
            "http_get": "profile",
            "http_post": "module gate",
        }

    async def test_partial_decision_builds_no_resume(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(_batched_snapshot())
        first, second = queue.pending()
        command = await queue.submit_decision(first.request_id, "approve")
        assert command.resume == {}  # the sibling action is still pending
        assert [request.request_id for request in queue.pending()] == [second.request_id]

    async def test_last_decision_resumes_with_per_action_decisions(self) -> None:
        queue, calls = _recording_queue()
        queue.refresh(_batched_snapshot())
        first, second = queue.pending()
        await queue.submit_decision(first.request_id, "approve")
        command = await queue.submit_decision(
            second.request_id, "edit", edited_args={"url": "https://t/edited"}
        )
        payload = command.resume["int-batch"]
        assert payload == {
            "decisions": [
                {"type": "approve"},
                {
                    "type": "edit",
                    "edited_action": {
                        "name": "http_post",  # the edit stays on its own action
                        "args": {"url": "https://t/edited"},
                    },
                },
            ]
        }
        decisions = [entry for kind, entry in calls if kind == "OperatorDecision"]
        assert [entry["request_id"] for entry in decisions] == [
            first.request_id,
            second.request_id,
        ]
        assert queue.pending() == ()

    async def test_decision_order_does_not_reorder_the_resume(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(_batched_snapshot())
        first, second = queue.pending()
        await queue.submit_decision(second.request_id, "reject")
        command = await queue.submit_decision(first.request_id, "approve")
        payload = command.resume["int-batch"]
        # decisions follow ACTION order (the L0 middleware consumes positionally)
        assert [decision["type"] for decision in payload["decisions"]] == [
            "approve",
            "reject",
        ]


# ---------------------------------------------------------------------------
# Issue #26 — reinstate/acknowledge lifecycle of a completed group.
# ---------------------------------------------------------------------------


class TestReinstateOnFailedResume:
    """A failed resume invocation keeps the interrupt answerable (Issue #26)."""

    async def test_reinstate_reenqueues_all_actions_with_fresh_ids(self) -> None:
        queue, calls = _recording_queue()
        queue.refresh(_batched_snapshot())
        first, second = queue.pending()
        await queue.submit_decision(first.request_id, "approve")
        await queue.submit_decision(second.request_id, "reject")
        assert queue.pending() == ()
        reinstated = queue.reinstate(first.request_id)  # a retired id still resolves
        assert [request.tool for request in reinstated] == ["http_get", "http_post"]
        assert queue.pending() == reinstated
        assert [request.request_id for request in reinstated] != [first.request_id, second]
        decisions = [entry for kind, entry in calls if kind == "OperatorDecision"]
        assert len(decisions) == 2  # the failed attempt stays in the audit trail
        with pytest.raises(ValueError, match="no reinstatable"):
            queue.reinstate(first.request_id)  # already reinstated

    async def test_acknowledge_resume_drops_the_group(self) -> None:
        queue, _calls = _recording_queue()
        queue.refresh(_batched_snapshot())
        first, second = queue.pending()
        await queue.submit_decision(first.request_id, "approve")
        await queue.submit_decision(second.request_id, "approve")
        queue.acknowledge_resume(first.request_id)
        with pytest.raises(ValueError, match="no reinstatable"):
            queue.reinstate(second.request_id)

    async def test_reinstate_unknown_id_rejected(self) -> None:
        queue, _calls = _recording_queue()
        with pytest.raises(ValueError, match="no reinstatable"):
            queue.reinstate("apr-9999")


# ---------------------------------------------------------------------------
# Issue #23 — the builders default to the documented session mode.
# ---------------------------------------------------------------------------


class TestDefaultMode:
    """An omitted ``mode`` must not select the fail-open direction (Issue #23)."""

    def test_default_mode_is_interactive(self) -> None:
        default = build_interrupt_config("yolo", _CLASSES)
        interactive = build_interrupt_config("yolo", _CLASSES, mode="interactive")
        mission = build_interrupt_config("yolo", _CLASSES, mode="mission")
        assert default == interactive  # the documented session default
        assert default != mission
        assert default["verify_probe"] is not False  # the interactive floor applies
        assert mission["verify_probe"] is False  # mission keeps the profile matrix

    def test_session_view_default_mode_is_interactive(self) -> None:
        default = build_session_interrupt_config("yolo", _CLASSES)
        interactive = build_session_interrupt_config("yolo", _CLASSES, mode="interactive")
        assert default == interactive
        assert default.orchestrator["verify_probe"] is not False
