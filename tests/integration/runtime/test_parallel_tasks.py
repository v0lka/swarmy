"""T3.5.1 acceptance criteria: parallel ``task()`` under session-global limits.

Roadmap T3.5.1 (D19): N parallel ``task()`` calls in one graph step run
concurrently against the echo app with small limits; the measured in-flight
peak exceeds 1; the global limiter is never exceeded; every delegation's
events carry its own ``correlation_id``.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from tests.helpers.agent_modules import crawler_prompt, make_module
from tests.helpers.fake_models import ScriptedChatModel, final_reply

pytestmark = pytest.mark.integration


def _task(description: str, subagent_type: str, call_id: str) -> dict[str, object]:
    """One L0 ``task()`` tool call for a scripted AIMessage."""
    return {
        "name": "task",
        "args": {"description": description, "subagent_type": subagent_type},
        "id": call_id,
        "type": "tool_call",
    }


def _get(url: str, call_id: str) -> dict[str, object]:
    """One platform ``http_get`` tool call for a scripted AIMessage."""
    return {"name": "http_get", "args": {"url": url}, "id": call_id, "type": "tool_call"}


def _parallel(*tool_calls: dict[str, object]) -> AIMessage:
    """An AIMessage issuing several tool calls in one step (D19 shape)."""
    return AIMessage(content="", tool_calls=list(tool_calls))  # type: ignore[arg-type]


@pytest.fixture
async def slow_session(
    tmp_path: Path, echo_server: Any, spawn_echo_server: Any
) -> Any:
    """A session with two crawl-capable modules and a loopback-only scope."""
    agents = tmp_path / "agents"
    make_module(agents, "crawl_a", description="Crawler A (fixture).", prompt=crawler_prompt("crawl_a"))
    make_module(agents, "crawl_b", description="Crawler B (fixture).", prompt=crawler_prompt("crawl_b"))
    config = SessionConfig(
        target=TargetConfig(base_url=f"http://127.0.0.1:{echo_server.port}/"),
        scope=ScopeEntries(
            ip_subnets=["127.0.0.1/32"], ports=[echo_server.port], schemes=["http"]
        ),
        agents_dirs=[str(agents)],
        limits={
            "rate_limit": 50,
            "max_concurrent_requests": 8,
            "max_body_bytes": 100_000,
            "max_redirect_depth": 3,
            "total_request_budget": 100,
            "connect_timeout_s": 5,
            "read_timeout_s": 5,
        },
    )
    orchestrator = ScriptedChatModel(
        scripts={
            "orchestrator": [
                _parallel(
                    _task("crawl the slow endpoint with module A", "crawl_a", "call-a"),
                    _task("crawl the slow endpoint with module B", "crawl_b", "call-b"),
                ),
                final_reply("both crawls finished"),
            ],
            "crawl_a": [
                _parallel(_get(f"http://127.0.0.1:{echo_server.port}/slow?ms=250", "ga1")),
                final_reply("crawl A done"),
            ],
            "crawl_b": [
                _parallel(_get(f"http://127.0.0.1:{echo_server.port}/slow?ms=250", "gb1")),
                final_reply("crawl B done"),
            ],
        },
        fallback_reply="done",
    )
    session = await Session.open(config=config, session_dir=tmp_path / "s", model=orchestrator)
    try:
        yield session
    finally:
        await session.close()


class TestParallelTasks:
    """AC: measured concurrency > 1; global limits hold; per-task correlation."""

    async def test_parallel_tasks_concurrency_and_correlation(
        self, slow_session: Session
    ) -> None:
        session = slow_session
        limiter = session.limiter
        assert limiter is not None
        peak_in_flight = 0

        async def poll_peak() -> None:
            nonlocal peak_in_flight
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                peak_in_flight = max(peak_in_flight, limiter.requests_in_flight)
                await asyncio.sleep(0.005)

        poller = asyncio.create_task(poll_peak())
        started = time.monotonic()
        await session.runtime.run_step("crawl both endpoints in parallel")
        duration = time.monotonic() - started
        poller.cancel()

        # AC 1: actual concurrency > 1, measured from the session-global limiter
        assert peak_in_flight >= 2, f"in-flight peak was {peak_in_flight}"
        # two sequential 250ms calls take >= 500ms; concurrency halves the wall
        assert (
            duration < 0.9
        ), f"step took {duration:.2f}s — delegations serialized?"
        # AC 2: the global limiter served exactly the two requests, never more
        assert limiter.budget_used == 2
        max_concurrent = limiter.limits.max_concurrent_requests
        assert peak_in_flight <= max_concurrent
        # AC 3: every delegation carries its own correlation_id in the journal
        reader = session.reader
        assert reader is not None
        requested = await reader.by_type("TaskRequested")
        completed = await reader.by_type("TaskCompleted")
        assert len(requested) == 2
        assert len(completed) == 2
        correlations = {envelope.correlation_id for envelope in requested}
        assert len(correlations) == 2
        assert {envelope.correlation_id for envelope in completed} == correlations
        # the full chain of one delegation is recoverable (arch §9.4)
        chain = await reader.by_correlation(correlations.pop())
        kinds = [envelope.type for envelope in chain]
        assert "TaskRequested" in kinds
        assert "TaskCompleted" in kinds

    async def test_no_guardrail_blocks_fired(self, slow_session: Session) -> None:
        session = slow_session
        await session.runtime.run_step("crawl both endpoints in parallel")
        reader = session.reader
        assert reader is not None
        blocked = await reader.by_type("GuardrailBlocked")
        assert blocked == []  # everything stayed in scope under global limits
