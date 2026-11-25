"""README module-tutorial reproducibility (roadmap T5.1.3/T5.5.1 AC).

The tutorial claims are checked against the real code so the README can never
drift from the reference modules: the AD-7 declaration idiom, the loader
frontmatter fields, the guardrails example rule and the platform toolset
names must all exist exactly as documented.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import pytest
from tests.helpers.module_tools import AGENTS_DIR

from swarmy.modules.loader import ModuleLoader

pytestmark = pytest.mark.unit

README: Path = Path(__file__).resolve().parents[3] / "README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _builtin(name: str) -> str:
    return (AGENTS_DIR / name).joinpath("AGENT.md").read_text(encoding="utf-8")


class TestTutorialMatchesCode:
    """Every tutorial claim is verifiable on the reference modules."""

    def test_ad7_declaration_idiom_is_real(self) -> None:
        """The tutorial's `swarmy_risk_class` attribute line matches the code."""
        readme = _readme()
        assert ".swarmy_risk_class = RiskClass.PASSIVE  # AD-7 declaration" in readme
        parsers = (
            AGENTS_DIR / "crawler" / "tools" / "parsers.py"
        ).read_text(encoding="utf-8")
        assert parsers.count(".swarmy_risk_class = RiskClass.PASSIVE") == 4

    def test_guardrails_example_rule_is_real(self) -> None:
        """The tutorial's block rule mirrors the xss-detector's real rule."""
        readme = _readme()
        assert "no-executing-payloads" in readme
        detector_yaml = (
            resources.files("swarmy.agents")
            .joinpath("xss-detector/guardrails.yaml")
            .read_text(encoding="utf-8")
        )
        assert "id: no-executing-payloads" in detector_yaml
        assert 'applies_to: ["http_get", "http_post"]' in detector_yaml
        assert "action: block" in detector_yaml

    def test_frontmatter_fields_documented_and_used(self) -> None:
        """name/description/events are the loader contract the tutorial shows."""
        readme = _readme()
        for field in ("name:", "description:", "events:"):
            assert field in readme
        for module in ("crawler", "xss-detector"):
            frontmatter = _builtin(module).split("---")[1]
            assert "name:" in frontmatter
            assert "description:" in frontmatter
            assert "events:" in frontmatter

    def test_platform_tools_named_in_tutorial_exist(self) -> None:
        """Every platform tool the tutorial lists is a real platform toolset name."""
        loader = ModuleLoader(
            strictness="normal",
            platform_toolset_factory=_production_shape_toolset,
        ).load()
        detector = loader.get("xss-detector").subagent
        toolset_names = set(detector["interrupt_on"])  # type: ignore[arg-type]
        readme = _readme()
        for tool in (
            "memory_search",
            "memory_get",
            "memory_upsert_endpoint",
            "memory_save_finding",
            "memory_link_attack_node",
            "memory_add_fact",
            "memory_add_note",
            "update_finding_status",
            "emit_event",
        ):
            assert f"`{tool}`" in readme, tool
            assert tool in toolset_names, tool

    def test_quickstart_names_the_demo_scenario(self) -> None:
        """The quickstart documents the same chain the F5 test exercises."""
        readme = _readme()
        assert "test_demo_f5.py" in readme
        assert "generate_report" in readme
        assert "report.md" in readme
        assert "--session-dir" in readme


def _production_shape_toolset(
    module_name: str, declared_events: frozenset[str]
) -> dict[str, object]:
    """The platform toolset names of a production session (arch §6.1)."""

    def stub(**kwargs: object) -> str:
        return "{}"

    names = (
        "memory_search",
        "memory_get",
        "memory_upsert_endpoint",
        "memory_save_finding",
        "memory_link_attack_node",
        "memory_add_fact",
        "memory_add_note",
        "update_finding_status",
        "http_get",
        "http_post",
        "http_put",
        "http_delete",
    )
    toolset: dict[str, object] = dict.fromkeys(names, stub)
    if declared_events:
        toolset["emit_event"] = stub
    return toolset
