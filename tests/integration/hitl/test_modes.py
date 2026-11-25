"""T3.3.4 acceptance criteria: autonomy modes over the gate matrix.

Roadmap T3.3.4:
* the gate set differs between ``interactive`` and ``mission`` for the same
  profile (mode x class matrix);
* an on-the-fly switch recompiles the graph with the new gates (documented
  L0 operation) and journals the operator decision.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from tests.helpers.agent_modules import make_module
from tests.helpers.fake_models import ScriptedChatModel

pytestmark = pytest.mark.integration

_TOOL_RISKS = {
    "http_get": "passive",
    "http_post": "network-write",
    "update_finding_status": "verify",
    "smash": "destructive",
}


@pytest.fixture
async def mode_session(tmp_path: Path) -> Session:
    """A ``mission``-mode session whose registry covers all four risk classes."""
    agents = tmp_path / "agents"
    make_module(
        agents, "breaker", description="Destructive-capable fixture module.",
        prompt="You are breaker: run `smash`, then report.",
        risk="destructive", tool_name="smash",
    )
    config = SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
        agents_dirs=[str(agents)],
        profile="normal",
        mode="mission",
    )
    session = await Session.open(
        config=config, session_dir=tmp_path / "s",
        model=ScriptedChatModel(scripts={}, fallback_reply="done"),
    )
    try:
        yield session
    finally:
        await session.close()


def _gated_tools(session: Session) -> set[str]:
    """The tool names currently gated (non-``False`` interrupt entries)."""
    return {
        tool
        for tool, gate in session.engine.interrupt_config.items()
        if gate is not False
    }


class TestModeMatrix:
    """AC: the gate composition differs across modes (mode x class matrix)."""

    def test_mission_keeps_profile_gates_only(self, mode_session: Session) -> None:
        gated = _gated_tools(mode_session)
        # profile normal gates verify + destructive; mission adds nothing
        assert "smash" in gated  # destructive via profile
        assert "update_finding_status" not in gated  # verify class... in normal profile

    async def test_interactive_adds_significant_forks(self, mode_session: Session) -> None:
        mission = _gated_tools(mode_session)
        assert "update_finding_status" not in mission
        # the documented L0 operation: rebuild + recompile on the fly
        await mode_session.set_mode("interactive")
        interactive = _gated_tools(mode_session)
        assert "update_finding_status" in interactive  # significant fork now gated
        assert "smash" in interactive  # profile gates kept
        assert interactive != mission  # AC: the gate set differs per mode

    async def test_switch_back_to_mission_restores_profile_gates(
        self, mode_session: Session
    ) -> None:
        mission = _gated_tools(mode_session)
        await mode_session.set_mode("interactive")
        await mode_session.set_mode("mission")
        assert _gated_tools(mode_session) == mission


class TestSwitchJournaling:
    """AC: the on-the-fly switch journals the operator decision."""

    async def test_mode_switch_journalled(self, tmp_path: Path) -> None:
        agents = tmp_path / "agents"
        make_module(
            agents, "breaker", description="Destructive fixture.",
            prompt="run smash", risk="destructive", tool_name="smash",
        )
        config = SessionConfig(
            target=TargetConfig(base_url="http://127.0.0.1:9/"),
            scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
            agents_dirs=[str(agents)],
            profile="normal",
            mode="mission",
        )
        session = await Session.open(
            config=config, session_dir=tmp_path / "s",
            model=ScriptedChatModel(scripts={}, fallback_reply="done"),
        )
        try:
            before = len(await session.reader.by_type("OperatorDecision"))
            await session.set_mode("interactive")
            decisions = await session.reader.by_type("OperatorDecision")
            assert len(decisions) == before + 1
            payload = decisions[-1].payload
            assert payload.request_id == "mode-switch:interactive"  # type: ignore[union-attr]
        finally:
            await session.close()
