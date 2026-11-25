"""Loader smoke over the ``dummy`` fixture module (roadmap T1.5.5, spec criterion F1).

End-to-end proof of the F1 acceptance criterion: the dummy module loads, lands
in the ``ModuleRegistry``, and its ``SubAgent`` dict is assembled with exactly
the arch §8.3 keys — with no fail-fast errors.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from swarmy.modules.loader import ModuleLoader
from swarmy.modules.registry import ModuleRegistry

if TYPE_CHECKING:
    from collections.abc import Callable

FIXTURE_MODULES = Path(__file__).resolve().parents[2] / "fixtures" / "modules"

EXPECTED_SUBAGENT_KEYS = {
    "name",
    "description",
    "system_prompt",
    "mode",
    "tools",
    "middleware",
    "interrupt_on",
    "skills",
    "response_format",
}
#: ``model`` is NotRequired (T3.1.3 wiring): the key is present only when the
#: manifest declares one — an absent key inherits the orchestrator's model.
CONDITIONAL_SUBAGENT_KEYS = {"model"}


def _platform_toolset_factory(
    module_name: str, declared_event_types: frozenset[str]
) -> dict[str, Callable[..., str]]:
    """Minimal stand-in for the session platform toolset (memory_*/emit_event)."""

    async def memory_probe() -> str:
        """Platform probe standing in for the platform toolset."""
        return f"platform for {module_name} ({sorted(declared_event_types)})"

    async def http_get() -> str:
        """The http_get name the built-in guardrails reference (T5.1.1)."""
        return "{}"

    async def http_post() -> str:
        """The http_post name the built-in guardrails reference (T5.2.1)."""
        return "{}"

    async def http_put() -> str:
        """The http_put name of every production toolset."""
        return "{}"

    async def http_delete() -> str:
        """The http_delete name of every production toolset."""
        return "{}"

    # The HTTP tool names exist in every production toolset; the built-in
    # modules' guardrails.yaml rules reference them (T5.1.1/T5.2.1).
    return {
        "memory_probe": memory_probe,
        "http_get": http_get,
        "http_post": http_post,
        "http_put": http_put,
        "http_delete": http_delete,
    }


@pytest.mark.integration
def test_dummy_module_loads_end_to_end() -> None:
    """AC (T1.5.5): loader build → dummy in registry → SubAgent dict assembled."""
    loader = ModuleLoader(
        user_dirs=[FIXTURE_MODULES],
        platform_toolset_factory=_platform_toolset_factory,
    )
    registry: ModuleRegistry = loader.load()  # ModuleLoadError would fail the test
    assert isinstance(registry, ModuleRegistry)
    assert "dummy" in registry
    module = registry.get("dummy")
    assert module.source == f"module:{FIXTURE_MODULES / 'dummy'}"
    subagent = module.subagent
    assert set(subagent) == EXPECTED_SUBAGENT_KEYS | (
        CONDITIONAL_SUBAGENT_KEYS & set(subagent)
    )
    assert subagent["name"] == "dummy"
    assert subagent["system_prompt"].startswith("You are the dummy module")
    tool_names = {getattr(fn, "__name__", "?") for fn in subagent["tools"]}
    assert tool_names == {"memory_probe", "dummy_ping", "http_get", "http_post", "http_put", "http_delete"}
    # guardrails.yaml tool_classes marks dummy_ping verify → gated under normal (arch §7.2)
    assert subagent["interrupt_on"]["dummy_ping"] is True
    assert all(
        gate is False
        for tool, gate in subagent["interrupt_on"].items()
        if tool != "dummy_ping"
    )  # platform stubs are passive; only tool_classes gate dummy_ping
    assert subagent["mode"] == "isolated"
    assert "model" not in subagent  # undeclared in the manifest → inherit (T3.1.3)
    assert subagent["response_format"] is None
    assert subagent["skills"] == []
    assert len(module.guardrails.rules) == 1
    assert module.guardrails.tool_classes == {"dummy_ping": "verify"}


@pytest.mark.integration
def test_dummy_tool_executes_in_isolation() -> None:
    """The fixture tool itself behaves as documented (template sanity)."""
    tool_path = FIXTURE_MODULES / "dummy" / "tools" / "ping.py"
    spec = importlib.util.spec_from_file_location("_smoke_dummy_ping", tool_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.dummy_ping("hello") == "dummy: hello"


@pytest.mark.integration
def test_dummy_loads_under_yolo_profile_without_gates() -> None:
    """Profile switch changes the gates: yolo leaves ``verify`` tools ungated."""
    registry = ModuleLoader(
        user_dirs=[FIXTURE_MODULES],
        strictness="yolo",
        platform_toolset_factory=_platform_toolset_factory,
    ).load()
    gates = registry.get("dummy").subagent["interrupt_on"]
    assert gates["memory_probe"] is False
    assert gates["dummy_ping"] is False  # verify is gated by normal/paranoid only (arch §7.2)
    assert all(gate is False for gate in gates.values())  # yolo: no gates at all
