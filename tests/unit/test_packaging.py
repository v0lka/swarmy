"""Packaging contract for the built-in module directory and the skills container
(arch §3.1/§8.6/§8.7).

The reference modules live in ``<repo>/agents`` and are mapped into the wheel
as ``swarmy/agents`` by hatch's ``force-include``; the orchestrator skills
container ``<repo>/skills`` ships the same way as ``swarmy/skills``; the
sdist carries both directories. These tests pin the build configuration so a
pyproject edit cannot silently drop either directory from the distribution,
and check that the runtime resolvers find them in either layout (editable
checkout or installed wheel).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from swarmy.core.skills import builtin_skills_root
from swarmy.modules.loader import builtin_agents_root

pytestmark = pytest.mark.unit

ROOT: Path = Path(__file__).resolve().parents[2]
PYPROJECT: Path = ROOT / "pyproject.toml"
REFERENCE_MODULES: tuple[str, ...] = ("crawler", "xss-detector")


def _pyproject() -> dict[str, Any]:
    """Parse pyproject.toml (tests may use ``Any``; production code may not)."""
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _build_target(name: str) -> dict[str, Any]:
    """Return one ``[tool.hatch.build.targets.<name>]`` table."""
    data = _pyproject()
    targets = data["tool"]["hatch"]["build"]["targets"]
    assert name in targets, f"missing [tool.hatch.build.targets.{name}]"
    return targets[name]


class TestBuildConfiguration:
    """AC: the wheel and sdist both ship ``agents/`` and ``skills/``."""

    def test_wheel_maps_data_directories_into_the_package(self) -> None:
        """``<repo>/agents`` → ``swarmy/agents`` and ``<repo>/skills`` → ``swarmy/skills``."""
        wheel = _build_target("wheel")
        assert "src/swarmy" in wheel["packages"]
        assert wheel["force-include"] == {
            "agents": "swarmy/agents",
            "skills": "swarmy/skills",
        }

    def test_sdist_includes_data_directories(self) -> None:
        """The source distribution carries the same directories."""
        sdist = _build_target("sdist")
        assert "agents" in sdist["include"]
        assert "skills" in sdist["include"]


class TestRuntimeResolution:
    """AC: the resolvers locate the data directories in either packaging layout."""

    def test_repository_agents_directory_holds_reference_modules(self) -> None:
        """The source of truth contains both contract reference modules."""
        agents = ROOT / "agents"
        for module in REFERENCE_MODULES:
            assert (agents / module / "AGENT.md").is_file(), f"missing {module}/AGENT.md"
            assert (agents / module / "guardrails.yaml").is_file()
            assert (agents / module / "tools").is_dir()

    def test_builtin_agents_root_finds_the_reference_modules(self) -> None:
        """The resolver locates the directory in editable and wheel layouts."""
        root = builtin_agents_root()
        assert root is not None, "built-in agents directory not found"
        for module in REFERENCE_MODULES:
            assert (root / module / "AGENT.md").is_file()

    def test_builtin_skills_root_finds_the_container(self) -> None:
        """The skills resolver locates ``skills/`` with its README in either layout."""
        root = builtin_skills_root()
        assert root is not None, "orchestrator skills container not found"
        assert (root / "README.md").is_file()
