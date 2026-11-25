"""T3.3.1/T3.3.2 acceptance criteria: the HITL matrix and the ApprovalQueue.

Roadmap T3.3.1: the profile x class matrix matches arch §7.2 (parametrized),
module entries win the merge, rebuilding with another profile changes the
gate set.
Roadmap T3.3.2: FIFO across several parallel interrupts, the decision is
delivered to the addressed ``interrupt_id``, ``edit`` swaps the arguments,
``reject`` feeds the agent an operator-rejection text, and every step lands
in the journal as an ``OperatorDecision``.
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
) -> tuple[ApprovalQueue, list[tuple[str, Mapping[str, object]]]]:
    """A queue whose OperatorDecision events are captured (no journal/db)."""
    calls: list[tuple[str, Mapping[str, object]]] = []

    async def emit(event_type: str, payload: Mapping[str, object]) -> str:
        calls.append((event_type, payload))
        return f"journalled {event_type}"

    queue = ApprovalQueue(emit=emit, sanitizer=sanitizer)
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
