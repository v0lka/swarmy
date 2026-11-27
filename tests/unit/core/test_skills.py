"""Orchestrator skills container (arch §8.6, §9.1).

Acceptance criteria under test:

* ``builtin_skills_root()`` resolves ``<repo>/skills/`` in both packaging
  layouts and returns ``None`` when absent;
* ``load_orchestrator_skills()`` validates every skill fail-fast (SKILL.md
  present, agentskills.io frontmatter limits, name = directory, no symlinks)
  plus the ``skills/**/*.py`` static scan, collecting **all** problems into
  one ``SkillsError``; a container without skills yields ``None``;
* the composite backend mounts the container read-only under ``/skills/``:
  reads work, every mutation is refused, traversal outside the root fails;
* ``SkillsError`` renders the aggregated report.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from swarmy.core import skills as skills_module
from swarmy.core.skills import (
    SKILLS_ROUTE,
    OrchestratorSkills,
    ReadOnlySkillsBackend,
    SkillsError,
    build_skills_backend,
    builtin_skills_root,
    load_orchestrator_skills,
    module_skills_routes,
)
from swarmy.modules.loader import module_skills_route
from swarmy.modules.manifest import AgentModuleManifest
from swarmy.modules.registry import LoadedModule, ModuleRegistry

pytestmark = pytest.mark.unit

ROOT: Path = Path(__file__).resolve().parents[3]

GOOD_SKILL = (
    "---\nname: web-research\ndescription: Map a web target before delegating.\n---\n# Body\n"
)


def _skill(root: Path, name: str, frontmatter: str | None = None, body: str = "# Body\n") -> Path:
    """Write one skill directory under ``root`` and return it."""
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    text = (
        frontmatter
        if frontmatter is not None
        else f"name: {name}\ndescription: Probe skill {name}."
    )
    (skill_dir / "SKILL.md").write_text(f"---\n{text}\n---\n{body}", encoding="utf-8")
    return skill_dir


def _symlink_or_skip(target: Path, link: Path) -> None:
    """Create a symlink or skip where the platform forbids it (Windows CI)."""
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks are not creatable here: {exc}")


@pytest.fixture
def container(tmp_path: Path) -> Path:
    """An empty skills container."""
    root = tmp_path / "skills"
    root.mkdir()
    return root


@pytest.fixture
def packaged_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the packaging anchor at a fake ``<site-packages>/swarmy``."""
    package = tmp_path / "site-packages" / "swarmy"
    package.mkdir(parents=True)
    monkeypatch.setattr(skills_module, "_PACKAGE_ROOT", package)
    return package


class TestBuiltinSkillsRoot:
    """AC: the container is resolved in both packaging layouts."""

    def test_repository_root_holds_the_container(self) -> None:
        """The source of truth is ``<repo>/skills/`` (this checkout)."""
        root = builtin_skills_root()
        assert root is not None
        assert root == (ROOT / "skills").resolve()
        assert (root / "README.md").is_file()

    def test_installed_package_layout_wins(self, packaged_root: Path) -> None:
        """``<site-packages>/swarmy/skills`` is found first."""
        (packaged_root / "skills").mkdir()
        assert builtin_skills_root() == packaged_root / "skills"

    def test_editable_checkout_layout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without the packaged dir, ``<repo>/skills`` (sibling of ``src/``) is used."""
        checkout = tmp_path / "repo"
        (checkout / "skills").mkdir(parents=True)
        package_root = checkout / "src" / "swarmy"
        package_root.mkdir(parents=True)
        monkeypatch.setattr(skills_module, "_PACKAGE_ROOT", package_root)
        assert builtin_skills_root() == checkout / "skills"

    def test_missing_container_is_none(self, packaged_root: Path) -> None:
        """Neither layout present → ``None`` (an optional container)."""
        assert builtin_skills_root() is None


class TestLoadOrchestratorSkills:
    """AC: fail-fast validation of the whole container, collected at once."""

    def test_none_or_missing_root_means_no_skills(self, tmp_path: Path) -> None:
        assert load_orchestrator_skills(None) is None
        assert load_orchestrator_skills(tmp_path / "absent") is None

    def test_container_without_skills_is_none(self, container: Path) -> None:
        """Loose files (README) are not skills; no skill directory → ``None``."""
        (container / "README.md").write_text("not a skill\n", encoding="utf-8")
        (container / "notes.txt").write_text("x", encoding="utf-8")
        assert load_orchestrator_skills(container) is None

    def test_valid_skill_is_loaded(self, container: Path) -> None:
        """The bundle carries the sorted names, the resolved root and the L0 source."""
        _skill(container, "web-research")
        _skill(container, "attack-tree-review")
        (container / "README.md").write_text("not a skill\n", encoding="utf-8")
        bundle = load_orchestrator_skills(container)
        assert isinstance(bundle, OrchestratorSkills)
        assert bundle.names == ("attack-tree-review", "web-research")
        assert bundle.root == container.resolve()
        assert bundle.sources == [SKILLS_ROUTE]

    def test_optional_frontmatter_fields_are_accepted(self, container: Path) -> None:
        """``license``/``compatibility``/``metadata`` and unknown keys pass through."""
        _skill(
            container,
            "reporting",
            frontmatter=(
                "name: reporting\n"
                "description: Reporting conventions.\n"
                "license: MIT\n"
                "compatibility: swarmy >=0.1\n"
                "metadata:\n"
                "  include_tools: ''\n"
                "extra-unknown: value\n"
            ),
        )
        assert load_orchestrator_skills(container) is not None

    @pytest.mark.parametrize(
        ("frontmatter", "fragment"),
        [
            ("description: No name here.", "name"),
            ("name: web-research", "description"),
            ("name: Wrong-Name\ndescription: x", "lowercase alphanumeric"),
            ("name: -leading\ndescription: x", "lowercase alphanumeric"),
            ("name: web--research\ndescription: x", "lowercase alphanumeric"),
            (f"name: {'a' * 65}\ndescription: x", "at most 64"),
            ("name: web-research\ndescription: " + "d" * 1025, "at most 1024"),
            (
                "name: web-research\ndescription: ok\ncompatibility: " + "c" * 501,
                "at most 500",
            ),
            ('name: web-research\ndescription: "   "', "non-empty"),
            ("name: other-name\ndescription: x", "must match the skill directory name"),
        ],
    )
    def test_frontmatter_problems(self, container: Path, frontmatter: str, fragment: str) -> None:
        """Each frontmatter violation names the file, the field and the rule."""
        _skill(container, "web-research", frontmatter=frontmatter)
        with pytest.raises(SkillsError) as excinfo:
            load_orchestrator_skills(container)
        report = str(excinfo.value)
        assert "web-research/SKILL.md" in report
        assert fragment in report

    def test_no_frontmatter_block_is_a_problem(self, container: Path) -> None:
        """A body without the leading ``---`` block cannot be a skill."""
        skill_dir = container / "web-research"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Just a body\n", encoding="utf-8")
        with pytest.raises(SkillsError, match="no YAML frontmatter"):
            load_orchestrator_skills(container)

    def test_invalid_yaml_is_a_problem(self, container: Path) -> None:
        skill_dir = container / "web-research"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: [unclosed\ndesc: x\n---\n", encoding="utf-8"
        )
        with pytest.raises(SkillsError, match="invalid YAML frontmatter"):
            load_orchestrator_skills(container)

    def test_non_mapping_frontmatter_is_a_problem(self, container: Path) -> None:
        skill_dir = container / "web-research"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\n- just\n- a list\n---\n", encoding="utf-8")
        with pytest.raises(SkillsError, match="frontmatter must be a mapping"):
            load_orchestrator_skills(container)

    def test_non_utf8_skill_md_is_a_problem(self, container: Path) -> None:
        skill_dir = container / "web-research"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_bytes(b"---\nname: cp1251\xff\xfe\ndescription: x\n---\n")
        with pytest.raises(SkillsError, match="not valid UTF-8"):
            load_orchestrator_skills(container)

    def test_directory_without_skill_md_is_a_problem(self, container: Path) -> None:
        """L0 would skip it silently; here it is a collected problem."""
        (container / "drafts").mkdir()
        with pytest.raises(SkillsError, match=r"drafts: not a skill"):
            load_orchestrator_skills(container)

    def test_all_problems_are_collected_at_once(self, container: Path) -> None:
        """One broken skill never hides the problems of the others."""
        (container / "no-manifest").mkdir()
        _skill(container, "Bad-Name", frontmatter="name: Bad-Name\ndescription: x")
        _skill(container, "fine")
        with pytest.raises(SkillsError) as excinfo:
            load_orchestrator_skills(container)
        report = str(excinfo.value)
        assert "no-manifest: not a skill" in report
        assert "lowercase alphanumeric" in report
        assert len(excinfo.value.problems) == 2

    def test_symlinked_skill_directory_is_a_problem(self, container: Path, tmp_path: Path) -> None:
        """A symlinked skill directory could point outside the vetted container."""
        outside = tmp_path / "outside"
        _skill(outside, "smuggled")
        _symlink_or_skip(outside / "smuggled", container / "smuggled")
        with pytest.raises(SkillsError, match="smuggled: a skill directory must not be a symlink"):
            load_orchestrator_skills(container)

    def test_symlinked_skill_md_is_a_problem(self, container: Path, tmp_path: Path) -> None:
        """A symlinked SKILL.md inside a real skill directory is rejected too."""
        outside = tmp_path / "outside.md"
        outside.write_text(GOOD_SKILL, encoding="utf-8")
        skill_dir = container / "web-research"
        skill_dir.mkdir()
        _symlink_or_skip(outside, skill_dir / "SKILL.md")
        with pytest.raises(SkillsError, match=r"must not be a symlink"):
            load_orchestrator_skills(container)

    def test_skill_scripts_get_the_static_scan(self, container: Path) -> None:
        """``skills/**/*.py`` with a raw-egress import is a problem (ASI05)."""
        skill_dir = _skill(container, "tooled")
        scripts = skill_dir / "scripts"
        scripts.mkdir()
        (scripts / "helper.py").write_text("import socket\n", encoding="utf-8")
        (skill_dir / "references").mkdir()
        (skill_dir / "references" / "notes.py").write_text(
            "import os\nos.system('x')\n", encoding="utf-8"
        )
        with pytest.raises(SkillsError) as excinfo:
            load_orchestrator_skills(container)
        report = str(excinfo.value)
        assert "helper.py imports 'socket'" in report
        assert "notes.py calls os.system()" in report
        assert len(excinfo.value.problems) == 2

    def test_clean_skill_scripts_pass(self, container: Path) -> None:
        """A script without forbidden shapes is accepted."""
        skill_dir = _skill(container, "tooled")
        (skill_dir / "scripts").mkdir()
        (skill_dir / "scripts" / "helper.py").write_text("print('ok')\n", encoding="utf-8")
        assert load_orchestrator_skills(container) is not None


class TestReadOnlyBackend:
    """AC: the container reaches the agent through a read-only ``/skills/`` route."""

    @pytest.fixture
    def bundle(self, container: Path) -> OrchestratorSkills:
        _skill(container, "web-research")
        loaded = load_orchestrator_skills(container)
        assert loaded is not None
        return loaded

    def test_route_lists_and_reads_the_container(self, bundle: OrchestratorSkills) -> None:
        """``/skills/`` lists the skill directories and downloads their SKILL.md."""
        backend = bundle.backend()
        listing = backend.ls(SKILLS_ROUTE)
        assert listing.error is None
        paths = {entry["path"] for entry in listing.entries or []}
        assert f"{SKILLS_ROUTE}web-research/" in paths
        downloads = backend.download_files([f"{SKILLS_ROUTE}web-research/SKILL.md"])
        assert len(downloads) == 1
        assert downloads[0].error is None
        assert b"name: web-research" in (downloads[0].content or b"")

    def test_every_mutation_is_refused(self, bundle: OrchestratorSkills) -> None:
        """write/edit/delete/upload fail at the backend; the disk is untouched."""
        backend = bundle.backend()
        target = f"{SKILLS_ROUTE}web-research/SKILL.md"
        before = (bundle.root / "web-research" / "SKILL.md").read_text(encoding="utf-8")
        assert backend.write(target, "pwned").error is not None
        assert backend.edit(target, "name", "evil").error is not None
        assert backend.delete(f"{SKILLS_ROUTE}web-research").error is not None
        uploads = backend.upload_files([(f"{SKILLS_ROUTE}new/SKILL.md", b"x")])
        assert len(uploads) == 1
        assert uploads[0].error is not None
        assert (bundle.root / "web-research" / "SKILL.md").read_text(encoding="utf-8") == before
        assert not (bundle.root / "new").exists()

    def test_traversal_outside_the_route_is_rejected(self, bundle: OrchestratorSkills) -> None:
        """The L0 virtual-root guard keeps reads inside the container."""
        backend: ReadOnlySkillsBackend = bundle.backend().routes[SKILLS_ROUTE]  # type: ignore[assignment]
        with pytest.raises(ValueError, match="traversal"):
            backend.read("/skills/../../etc/passwd")

    def test_default_route_stays_the_state_backend(self, bundle: OrchestratorSkills) -> None:
        """Paths outside ``/skills/`` keep the pre-skills L0 default."""
        from deepagents.backends import StateBackend

        assert isinstance(bundle.backend().default, StateBackend)


def _skilled_module(registry: ModuleRegistry, module_dir: Path, name: str, *, skills: bool) -> Path:
    """Register a bare module ``name`` under ``module_dir`` with or without skills."""
    skills_dir = module_dir / "skills"
    if skills:
        (skills_dir / "probe-skill").mkdir(parents=True)
        (skills_dir / "probe-skill" / "SKILL.md").write_text(
            f"---\nname: probe-skill\ndescription: Probe skill of {name}.\n---\n# Body\n",
            encoding="utf-8",
        )
    registry.register(
        LoadedModule(
            manifest=AgentModuleManifest(name=name, description=f"{name} module."),
            system_prompt=f"You are {name}.",
            path=module_dir,
            source=f"module:{module_dir}",
            tools={},
            guardrails=None,
            subagent={"name": name, "skills": [module_skills_route(name)] if skills else []},
        )
    )
    return skills_dir


class TestModuleSkillsRoutes:
    """AC: module ``skills/`` directories are mounted as read-only composite routes.

    L0 builds every subagent's ``SkillsMiddleware`` on the backend the
    orchestrator was compiled with; the loader names the module source as
    ``/module-skills/<name>/`` and the engine mounts the directory there.
    """

    @pytest.fixture
    def registry(self, tmp_path: Path) -> tuple[ModuleRegistry, Path]:
        modules = ModuleRegistry()
        _skilled_module(modules, tmp_path / "plain", "plain", skills=False)
        skills_dir = _skilled_module(modules, tmp_path / "skilled", "skilled", skills=True)
        return modules, skills_dir

    def test_only_skilled_modules_get_a_route(self, registry: tuple[ModuleRegistry, Path]) -> None:
        modules, skills_dir = registry
        assert module_skills_routes(modules) == {"/module-skills/skilled/": skills_dir}

    def test_module_route_lists_and_reads_the_skill(
        self, registry: tuple[ModuleRegistry, Path]
    ) -> None:
        """``ls`` + ``download_files`` — exactly the two calls L0's skill listing makes."""
        modules, _skills_dir = registry
        backend = build_skills_backend(None, module_skills_routes(modules))
        assert backend is not None
        route = module_skills_route("skilled")
        listing = backend.ls(route)
        assert listing.error is None
        assert [entry["path"] for entry in listing.entries or []] == [f"{route}probe-skill/"]
        downloads = backend.download_files([f"{route}probe-skill/SKILL.md"])
        assert downloads[0].error is None
        assert b"name: probe-skill" in (downloads[0].content or b"")

    def test_module_route_is_read_only(self, registry: tuple[ModuleRegistry, Path]) -> None:
        """The module's skills directory is as immutable for the agent as the container."""
        modules, skills_dir = registry
        backend = build_skills_backend(None, module_skills_routes(modules))
        assert backend is not None
        target = f"{module_skills_route('skilled')}probe-skill/SKILL.md"
        before = (skills_dir / "probe-skill" / "SKILL.md").read_text(encoding="utf-8")
        assert backend.write(target, "pwned").error is not None
        assert backend.edit(target, "name", "evil").error is not None
        assert backend.delete(target).error is not None
        assert backend.upload_files([(f"{module_skills_route('skilled')}x/SKILL.md", b"")])[0].error
        assert (skills_dir / "probe-skill" / "SKILL.md").read_text(encoding="utf-8") == before
        assert not (skills_dir / "x").exists()

    def test_module_route_rejects_traversal(self, registry: tuple[ModuleRegistry, Path]) -> None:
        """The L0 virtual-root guard keeps reads inside the module's skills directory."""
        modules, _skills_dir = registry
        backend = build_skills_backend(None, module_skills_routes(modules))
        assert backend is not None
        mounted: ReadOnlySkillsBackend = backend.routes[module_skills_route("skilled")]
        with pytest.raises(ValueError, match="traversal"):
            mounted.read("/../../etc/passwd")

    def test_nothing_to_mount_is_none(self) -> None:
        """No orchestrator container and no module skills → the default L0 backend."""
        assert build_skills_backend(None, {}) is None

    def test_orchestrator_and_module_routes_coexist(
        self, container: Path, registry: tuple[ModuleRegistry, Path]
    ) -> None:
        """Both containers live in one composite under distinct namespaces."""
        _skill(container, "web-research")
        orchestrator = load_orchestrator_skills(container)
        assert orchestrator is not None
        modules, _skills_dir = registry
        backend = build_skills_backend(orchestrator, module_skills_routes(modules))
        assert backend is not None
        assert set(backend.routes) == {SKILLS_ROUTE, "/module-skills/skilled/"}
        # the orchestrator container does not leak the module route and vice versa
        assert [entry["path"] for entry in backend.ls(SKILLS_ROUTE).entries or []] == [
            "/skills/web-research/"
        ]
        assert [
            entry["path"] for entry in backend.ls(module_skills_route("skilled")).entries or []
        ] == ["/module-skills/skilled/probe-skill/"]
        from deepagents.backends import StateBackend

        assert isinstance(backend.default, StateBackend)


class TestSkillsError:
    """AC: the error renders the aggregated report like ModuleLoadError."""

    def test_report_format(self) -> None:
        error = SkillsError(["skills:/x: a: one", "skills:/x: b: two"])
        assert error.problems == ("skills:/x: a: one", "skills:/x: b: two")
        text = str(error)
        assert text.startswith("orchestrator skills loading failed, 2 problem(s):")
        assert "  - skills:/x: a: one" in text
        assert "  - skills:/x: b: two" in text


class TestRealRepositoryContainer:
    """AC: the shipped container is valid and loads without problems."""

    def test_repository_container_loads_clean(self) -> None:
        root = builtin_skills_root()
        assert root is not None
        bundle = load_orchestrator_skills(root)
        # Every shipped skill (none yet) must be well-formed; the container
        # itself must never fail the session start.
        assert bundle is None or all(name for name in bundle.names)
