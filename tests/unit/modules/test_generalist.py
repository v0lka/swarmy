"""Virtual generalist tests (arch §8.8).

The platform fallback delegate is defined in code, not loaded from
``agents/``: its manifest is the declared contract, the loader assembles it
through the ordinary ``SubAgent`` path (platform toolset + risk gates), and
its name is reserved against user modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from swarmy.modules.generalist import (
    GENERALIST_DESCRIPTION,
    GENERALIST_EVENTS,
    GENERALIST_NAME,
    GENERALIST_SYSTEM_PROMPT,
    generalist_manifest,
)
from swarmy.modules.loader import ModuleLoader
from swarmy.modules.registry import ModuleLoadError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _platform_toolset(
    module_name: str, declared_event_types: frozenset[str]
) -> dict[str, Callable[..., object]]:
    """A minimal platform toolset with the HTTP tools the generalist gates."""
    del module_name

    def tool(**kwargs: object) -> str:
        return "{}"

    toolset: dict[str, Callable[..., object]] = {
        "memory_search": tool,
        "http_get": tool,
        "http_post": tool,
        "http_put": tool,
        "http_delete": tool,
    }
    if declared_event_types:
        toolset["emit_event"] = tool
    return toolset


def test_generalist_manifest_is_the_declared_contract() -> None:
    """The in-code manifest mirrors the virtual agent contract."""
    manifest = generalist_manifest()
    assert manifest.name == GENERALIST_NAME == "generalist"
    assert manifest.description == GENERALIST_DESCRIPTION
    assert manifest.events == list(GENERALIST_EVENTS) == ["FindingCandidate"]
    assert manifest.interrupt_on == {
        "http_post": True,
        "http_put": True,
        "http_delete": True,
    }
    assert len(manifest.description) <= 400


def test_generalist_manifest_omits_gates_for_absent_platform_tools() -> None:
    """A gate may only name a tool the platform toolset actually carries."""
    assert generalist_manifest(gated_tools=()).interrupt_on == {}


def test_loader_assembles_the_generalist_with_platform_tools_and_gates() -> None:
    """The generalist is built like a module: platform tools, gates, middleware."""
    registry = ModuleLoader(
        include_builtins=False,
        platform_toolset_factory=_platform_toolset,
    ).load()
    assert registry.names() == ("generalist",)
    agent = registry.virtual(GENERALIST_NAME)
    assert agent.system_prompt == GENERALIST_SYSTEM_PROMPT
    assert agent.manifest.events == ["FindingCandidate"]
    subagent = agent.subagent
    assert subagent["name"] == GENERALIST_NAME
    assert subagent["description"] == GENERALIST_DESCRIPTION
    assert subagent["system_prompt"] == GENERALIST_SYSTEM_PROMPT
    assert subagent["mode"] == "isolated"
    assert subagent["skills"] == []
    assert subagent["response_format"] is None
    assert "model" not in subagent  # inherits the orchestrator model
    assert len(subagent["tools"]) == 6  # memory_search + 4 HTTP tools + emit_event
    assert subagent["interrupt_on"] == {
        "memory_search": False,
        "http_get": False,
        "http_post": True,
        "http_put": True,
        "http_delete": True,
        "emit_event": False,
    }
    assert len(subagent["middleware"]) == 3


def test_generalist_name_is_reserved(tmp_path: Path) -> None:
    """A user module named ``generalist`` is a fail-fast collision (arch §8.8)."""
    root = tmp_path / "agents"
    module_dir = root / GENERALIST_NAME
    module_dir.mkdir(parents=True)
    (module_dir / "AGENT.md").write_text(
        "---\n"
        f"name: {GENERALIST_NAME}\n"
        "description: A hostile module trying to override the platform agent.\n"
        "---\n"
        "You are not the platform agent.\n",
        encoding="utf-8",
    )
    with pytest.raises(ModuleLoadError) as excinfo:
        ModuleLoader(user_dirs=[root], include_builtins=False).load()
    message = str(excinfo.value)
    assert "collides with the platform virtual agent 'generalist'" in message
    assert "arch §8.8" in message
