"""Built-in module contract tests (arch §8.7, roadmap T5.1.1/T5.2.1).

The two reference modules must load through the real ``ModuleLoader`` with
exactly the arch §8.7 table's tool/event/rule shape, all-passive module
tools, and guardrails whose ``applies_to`` names real platform tools.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from swarmy.modules.registry import ModuleRegistry

import pytest

from swarmy.events.models import EVENT_TYPES
from swarmy.guardrails.models import RiskClass
from swarmy.modules.loader import ModuleLoader
from swarmy.tools.registry import risk_class_of

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from swarmy.modules.registry import LoadedModule

pytestmark = pytest.mark.unit


def _stub_platform_toolset(
    module_name: str, declared_events: frozenset[str]
) -> dict[str, Callable[..., object]]:
    """The minimal platform toolset every built-in module expects.

    Names mirror the production wiring (``core/session.py``): the four HTTP
    tools plus the memory toolset. Stubs are inert — the loader only reads
    names and risk-class attributes here.
    """

    def stub(**kwargs: object) -> str:
        return "{}"

    toolset: dict[str, Callable[..., object]] = {
        "http_get": stub,
        "http_post": stub,
        "http_put": stub,
        "http_delete": stub,
        "memory_search": stub,
        "memory_get": stub,
        "memory_upsert_endpoint": stub,
        "memory_save_finding": stub,
        "memory_link_attack_node": stub,
        "memory_add_fact": stub,
        "memory_add_note": stub,
        "update_finding_status": stub,
    }
    if declared_events:
        toolset["emit_event"] = stub
    return toolset


@pytest.fixture
def builtins() -> ModuleRegistry:
    """The loaded built-in module registry (production platform wiring)."""
    return ModuleLoader(
        strictness="normal",
        platform_toolset_factory=_stub_platform_toolset,
    ).load()


def _module(registry: ModuleRegistry, name: str) -> LoadedModule:
    """Fetch one loaded module by its arch §8.7 name."""
    return registry.get(name)


class TestBuiltinModulesLoad:
    """AC: both reference modules load through the real loader."""

    def test_both_modules_load_as_builtins(self, builtins: ModuleRegistry) -> None:
        """crawler + xss-detector are present with builtin source; generalist is virtual."""
        assert set(builtins.names()) == {"crawler", "xss-detector", "generalist"}
        assert {module.manifest.name for module in builtins.modules()} == {
            "crawler",
            "xss-detector",
        }
        for module in builtins.modules():
            assert module.source == "builtin"
        assert [agent.manifest.name for agent in builtins.virtual_agents()] == ["generalist"]

    def test_manifest_events_match_arch_8_7_and_registry(
        self, builtins: ModuleRegistry
    ) -> None:
        """Declared events are exactly the §8.7 sets and all registered."""
        crawler = _module(builtins, "crawler")
        detector = _module(builtins, "xss-detector")
        assert crawler.manifest.events == ["EndpointsDiscovered", "EndpointUpdated"]
        assert detector.manifest.events == ["FindingCandidate"]
        for event in [*crawler.manifest.events, *detector.manifest.events]:
            assert event in EVENT_TYPES

    def test_module_tools_have_docstrings_and_passive_risk(
        self, builtins: ModuleRegistry
    ) -> None:
        """Every tool is documented and inert (AD-7 passive default)."""
        expected_tools = {
            "crawler": {"parse_robots_txt", "parse_sitemap_xml", "extract_links", "extract_forms"},
            "xss-detector": {"make_marker", "build_probe_url", "plan_payloads", "analyze_reflection", "safe_payload_report"},
        }
        for name, tools in expected_tools.items():
            module = _module(builtins, name)
            assert set(module.tools) == tools
            for tool_name, fn in module.tools.items():
                assert fn.__doc__, f"{tool_name} undocumented"
                assert fn.__doc__.strip(), f"{tool_name} undocumented"
                assert risk_class_of(fn) is RiskClass.PASSIVE, f"{tool_name} not passive"

    def test_subagent_dicts_carry_platform_tools_and_expected_gates(
        self, builtins: ModuleRegistry
    ) -> None:
        """Toolsets merge platform tools; gates follow profile + manifest.

        The crawler is all-passive (no gates); the xss-detector pins the
        manifest gate ``http_post: true`` (arch §8.2): its state-changing
        POST probes always ask the operator, whatever the profile is.
        """
        platform_names = set(_stub_platform_toolset("x", frozenset({"FindingCandidate"})))
        crawler = _module(builtins, "crawler").subagent
        tools: list[object] = crawler["tools"]  # type: ignore[assignment]
        assert len(tools) == len(_module(builtins, "crawler").tools) + len(platform_names)
        crawler_gates: Mapping[str, bool] = crawler["interrupt_on"]  # type: ignore[assignment]
        assert platform_names <= set(crawler_gates)
        assert not any(crawler_gates.values()), "crawler unexpectedly gated"

        detector = _module(builtins, "xss-detector").subagent
        detector_gates: Mapping[str, bool] = detector["interrupt_on"]  # type: ignore[assignment]
        assert detector_gates.get("http_post") is True
        assert not any(
            gate for tool, gate in detector_gates.items() if tool != "http_post"
        ), "detector gated beyond the manifest POST gate"
