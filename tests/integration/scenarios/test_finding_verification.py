"""T3.5.3 acceptance criteria: the headless «finding → verification» scenario.

Roadmap T3.5.3 (F3 DoD): a crawler-like fixture module discovers an endpoint
(``EndpointsDiscovered``), the declarative policy notifies the orchestrator,
the scripted orchestrator delegates a re-verification (RD-5: a detector
module with safe payloads), the verifier stores the candidate
(``memory_save_finding``) and changes its status through the platform tool
``update_finding_status`` (never directly in the store) — ``FindingVerified``
triggers the ``tree_proposal`` policy. The journal holds the full chain, and
every delegation carries its own ``correlation_id``. No TUI anywhere.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from langchain_core.messages import AIMessage

from swarmy.core.config import PolicySpec, ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from tests.helpers.agent_modules import crawler_prompt, make_module, verifier_prompt
from tests.helpers.fake_models import ScriptedChatModel, final_reply

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


def _tool_call(name: str, args: dict[str, object], call_id: str) -> dict[str, object]:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


def _ai(*tool_calls: dict[str, object]) -> AIMessage:
    return AIMessage(content="", tool_calls=list(tool_calls))  # type: ignore[arg-type]


@pytest.fixture
async def scenario_session(tmp_path: Path, echo_server: Any) -> Session:
    """The headless scenario session: crawler + verifier + explicit policies."""
    agents = tmp_path / "agents"
    make_module(
        agents, "scn_crawler", description="Scenario crawler (fixture).",
        prompt=crawler_prompt("scn_crawler"),
    )
    make_module(
        agents, "scn_verifier", description="Scenario verifier (fixture).",
        prompt=verifier_prompt("scn_verifier"),
    )
    base = f"http://127.0.0.1:{echo_server.port}"
    orchestrator = ScriptedChatModel(
        scripts={
            # One script segment per step boundary: the graph loop keeps
            # calling the model until a tool-less answer, so each delegation
            # turn ends with a final reply and the policy notifications are
            # injected at the NEXT run_step (arch §9.2).
            "orchestrator": [
                _ai(_tool_call("task",
                               {"description": f"crawl {base}/query?q=xss",
                                "subagent_type": "scn_crawler"}, "call-o1")),
                final_reply("crawl finished; awaiting the discovery notification"),
                _ai(_tool_call("task",
                               {"description": "verify the finding", "subagent_type": "scn_verifier"},
                               "call-o2")),
                final_reply("verification delegated; awaiting the candidate"),
                _ai(_tool_call("task",
                               {"description": "re-verify the finding", "subagent_type": "scn_verifier"},
                               "call-o3")),
                final_reply("verification done; awaiting the resolution"),
                final_reply("scenario finished"),
            ],
            "scn_crawler": [
                _ai(
                    _tool_call("http_get",
                               {"url": f"{base}/query?q=<script>alert(1)</script>"}, "c1"),
                    _tool_call("memory_upsert_endpoint",
                               {"host": f"127.0.0.1:{echo_server.port}", "method": "GET",
                                "path": "/query"}, "c2"),
                ),
                final_reply("crawl done"),
            ],
            "scn_verifier": [
                _ai(
                    _tool_call("http_get",
                               {"url": f"{base}/query?q=<script>alert(1)</script>"}, "v1"),
                    _tool_call("memory_save_finding",
                               {"type": "xss", "severity": "high",
                                "title": "reflected XSS in /query",
                                "description": "the q parameter is reflected unescaped",
                                "created_by": "scn_verifier"}, "v2"),
                ),
                final_reply("candidate stored"),
                _ai(_tool_call("update_finding_status",
                               {"finding_id": 1, "status": "verified",
                                "severity": "high",
                                "reason": "re-verified with a safe payload"}, "v3")),
                final_reply("verification done"),
            ],
        },
        fallback_reply="done",
    )
    config = SessionConfig(
        target=TargetConfig(base_url=f"{base}/"),
        scope=ScopeEntries(
            ip_subnets=["127.0.0.1/32"], ports=[echo_server.port], schemes=["http"]
        ),
        agents_dirs=[str(agents)],
        profile="normal",
        policies=[
            PolicySpec(on="EndpointsDiscovered", action="notify_orchestrator",
                       template="generic"),
            PolicySpec(on="FindingCandidate", action="notify_orchestrator",
                       template="verify_finding"),
            PolicySpec(on="FindingVerified", action="notify_orchestrator",
                       template="tree_proposal"),
        ],
    )
    session = await Session.open(config=config, session_dir=tmp_path / "s", model=orchestrator)
    try:
        yield session
    finally:
        await session.close()


class TestFindingVerificationScenario:
    """AC: the F3 event loop runs headless with a full correlation trace."""

    async def test_finding_to_verification_through_events(
        self, scenario_session: Session
    ) -> None:
        session = scenario_session
        runtime = session.runtime
        reader = session.reader

        # Turn 1: crawler discovers the endpoint (→ policy notification).
        await runtime.run_step("probe the target")
        assert (await reader.by_type("EndpointsDiscovered")) != []
        assert runtime.pending_injections() >= 1  # the policy fired

        # Turn 2: the injected notification reaches the graph; the scripted
        # orchestrator delegates the verification (verify_finding policy).
        await runtime.run_step()
        assert (await reader.by_type("FindingCandidate")) != []

        # Turn 3: verify_finding notification → re-verification delegation;
        # the status changes through the platform tool only.
        await runtime.run_step()
        verified = await reader.by_type("FindingVerified")
        assert verified != []

        # AC: the status was changed by the PLATFORM tool, not by the agent
        # writing the store directly — the store shows the final state and
        # the event source is the platform/module contour of the tool.
        finding = await session.memory.get("finding", 1)
        assert finding is not None
        assert finding.status.value == "verified"

        # AC: full correlation chain — every delegation has its own id and
        # the Task*/Guardrail/memory events attach to their delegation.
        requested = await reader.by_type("TaskRequested")
        completed = await reader.by_type("TaskCompleted")
        assert len(requested) == 3
        assert len(completed) == 3
        crawler_chain = await reader.by_correlation(requested[0].correlation_id)
        candidate_chain = await reader.by_correlation(requested[1].correlation_id)
        resolution_chain = await reader.by_correlation(requested[2].correlation_id)
        assert "EndpointsDiscovered" in {envelope.type for envelope in crawler_chain}
        assert "FindingCandidate" in {envelope.type for envelope in candidate_chain}
        assert "FindingVerified" in {envelope.type for envelope in resolution_chain}
        assert len({envelope.correlation_id for envelope in requested}) == 3

        # AC (headless): the whole scenario ran without any TUI involvement —
        # the runtime and memory contours carried everything above.
        decisions = await reader.by_type("OperatorDecision")
        assert decisions == []  # no HITL was needed for the passive probes
        blocked = await reader.by_type("GuardrailBlocked")
        assert blocked == []  # everything stayed in scope
