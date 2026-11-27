"""Orchestrator skills: the repository-root ``skills/`` container (arch §8.6, §9.1).

A skill is model-facing instructions in the agentskills.io format: a
directory holding a ``SKILL.md`` (YAML frontmatter ``name``/``description``
plus a markdown body) and optional ``scripts/``, ``references/`` and
``assets/`` resources. Subagent modules carry their own skills next to
``AGENT.md`` (arch §8.2); the **orchestrator-level** skills live in the
repository-root ``skills/<skill-name>/`` container, which the build ships
inside the wheel as ``swarmy/skills`` (the D40 two-layout resolution) and the
session loads automatically — no config key: every skill found is handed to
the L0 ``SkillsMiddleware`` through ``create_deep_agent(skills=...)``.

L0 behaviour used as is (arch §8.6): progressive disclosure (metadata →
instructions → resources); ``mode="fork"`` subagents inherit the
orchestrator's skills, ``isolated`` ones keep only their module skills.

Two properties are swarmy's own:

* **Fail-fast validation before the first LLM call** (arch §16.9): every
  immediate subdirectory of the container must be a well-formed skill —
  ``SKILL.md`` present, frontmatter ``name`` (agentskills.io naming rules,
  ≤64 characters, equal to the directory name) and ``description``
  (≤1024 characters) — and every ``skills/**/*.py`` script passes the same
  forbidden-import / raw-egress static scan as module skills (ASI05: skill
  scripts execute with operator privileges). L0 itself only warns and skips a
  broken skill; here every problem of the whole container is collected into
  one :class:`SkillsError` and the session start aborts.
* **Read-only route**: the default L0 ``StateBackend`` keeps files in the
  graph state and cannot read disk paths, so the container is mounted through
  a ``CompositeBackend`` under the virtual :data:`SKILLS_ROUTE` prefix; the
  mounted :class:`ReadOnlySkillsBackend` refuses every mutating operation —
  a prompt-injected orchestrator must not be able to rewrite the vetted
  instructions it loads at every session start (ASI01 persistence).
* **Module skills ride the same composite** (arch §8.6, AD-9): L0 builds a
  subagent's ``SkillsMiddleware`` on the *same* backend the orchestrator was
  compiled with, so a module's ``skills/`` directory — named by the loader as
  the virtual ``/module-skills/<name>/`` source — is mounted by
  :func:`build_skills_backend` as one more read-only route next to
  ``/skills/``; the directories themselves never reach L0 as disk paths.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml
from deepagents.backends import CompositeBackend, FilesystemBackend, StateBackend
from deepagents.backends.protocol import (
    DeleteResult,
    EditResult,
    FileUploadResponse,
    WriteResult,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
)

from swarmy.modules.loader import LoadProblem, module_skills_route, scan_skill_scripts
from swarmy.modules.manifest import Utf8Error, read_utf8

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from deepagents.backends.protocol import BackendProtocol

    from swarmy.modules.registry import ModuleRegistry

#: The virtual path the container is mounted under in the orchestrator's L0
#: backend — and the single ``skills`` source handed to ``create_deep_agent``
#: (the L0 middleware lists the route's immediate ``<name>/SKILL.md`` dirs).
SKILLS_ROUTE: Final[str] = "/skills/"

#: agentskills.io frontmatter limits (the pinned L0 ``MAX_SKILL_*`` constants).
MAX_SKILL_NAME_LENGTH: Final[int] = 64
MAX_SKILL_DESCRIPTION_LENGTH: Final[int] = 1024
MAX_SKILL_COMPATIBILITY_LENGTH: Final[int] = 500

#: YAML frontmatter between ``---`` delimiters at the start of a ``SKILL.md``
#: — the pinned L0 ``_FRONTMATTER_PATTERN``, so both readers agree on what a
#: frontmatter block is.
_FRONTMATTER: Final[re.Pattern[str]] = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

#: Root of the installed ``swarmy`` package (``.../swarmy``), derived from this
#: module's location — the same packaging-layout anchor as the module loader.
_PACKAGE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent

_READ_ONLY: Final[str] = (
    "read-only skills route: the orchestrator skills container is "
    "operator-vetted and cannot be modified by the agent ({path})"
)


class SkillsError(Exception):
    """Aggregated fail-fast error over the orchestrator skills container (arch §8.6).

    Carries *every* problem collected across the whole container — one
    problem must not stop collecting the others (spec §4.5). ``str()``
    renders the full report, mirroring
    :class:`swarmy.modules.registry.ModuleLoadError`.
    """

    def __init__(self, problems: Sequence[str]) -> None:
        """Build the error from the collected problems (never empty)."""
        lines = "\n".join(f"  - {problem}" for problem in problems)
        super().__init__(
            f"orchestrator skills loading failed, {len(problems)} problem(s):\n{lines}"
        )
        self.problems: tuple[str, ...] = tuple(problems)


class SkillFrontmatter(BaseModel):
    """The ``SKILL.md`` frontmatter (agentskills.io; arch §8.6).

    Only the specification's fields are typed; unknown keys are ignored the
    way the specification treats frontmatter as extensible. A missing or
    over-long ``name``/``description``/``compatibility`` is a problem — L0
    would truncate or skip silently, here it fails the session start.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    name: str = Field(min_length=1, max_length=MAX_SKILL_NAME_LENGTH)
    description: str = Field(min_length=1, max_length=MAX_SKILL_DESCRIPTION_LENGTH)
    license: str | None = None
    compatibility: str | None = Field(default=None, max_length=MAX_SKILL_COMPATIBILITY_LENGTH)
    metadata: dict[str, str] | None = None

    @field_validator("name", "description", "license", "compatibility")
    @classmethod
    def _stripped_text(cls, value: str | None) -> str | None:
        """Strip surrounding whitespace (L0 reads the fields stripped)."""
        return value.strip() if value is not None else None

    @field_validator("name", "description")
    @classmethod
    def _non_empty_text(cls, value: str, info: ValidationInfo) -> str:
        """Reject whitespace-only required text with a precise message."""
        if not value:
            msg = f"field {info.field_name!r} must be a non-empty string"
            raise ValueError(msg)
        return value


def _skill_name_problem(name: str, directory: str) -> str | None:
    """The agentskills.io naming rules as the pinned L0 ``_validate_skill_name``.

    Lowercase alphanumeric and single hyphens, no leading/trailing hyphen,
    and equal to the directory holding the ``SKILL.md`` (the L0 middleware
    only warns on a mismatch — here it is a problem).
    """
    if len(name) > MAX_SKILL_NAME_LENGTH:
        return f"name exceeds {MAX_SKILL_NAME_LENGTH} characters"
    if name.startswith("-") or name.endswith("-") or "--" in name:
        return "name must be lowercase alphanumeric with single hyphens only"
    for char in name:
        if char != "-" and not ((char.isalpha() and char.islower()) or char.isdigit()):
            return "name must be lowercase alphanumeric with single hyphens only"
    if name != directory:
        return f"name {name!r} must match the skill directory name {directory!r}"
    return None


def _validate_skill(skill_dir: Path, source: str) -> list[LoadProblem]:
    """Validate one ``skills/<name>/`` directory against arch §8.6."""
    skill_md = skill_dir / "SKILL.md"
    label = f"{skill_dir.name}/SKILL.md"
    if skill_md.is_symlink():
        return [LoadProblem(source, f"{label}: must not be a symlink")]
    if not skill_md.is_file():
        return [LoadProblem(source, f"{skill_dir.name}: not a skill — SKILL.md is missing")]
    try:
        text = read_utf8(skill_md)
    except Utf8Error as exc:
        return [LoadProblem(source, str(exc))]
    match = _FRONTMATTER.match(text)
    if match is None:
        return [
            LoadProblem(source, f"{label}: no YAML frontmatter (a '---' block at the first line)")
        ]
    try:
        data: object = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        return [LoadProblem(source, f"{label}: invalid YAML frontmatter: {exc}")]
    if not isinstance(data, dict):
        return [LoadProblem(source, f"{label}: frontmatter must be a mapping")]
    try:
        frontmatter = SkillFrontmatter.model_validate(data)
    except ValidationError as exc:
        problems: list[LoadProblem] = []
        for error in exc.errors():
            field = ".".join(str(part) for part in error["loc"]) or "<frontmatter>"
            problems.append(LoadProblem(source, f"{label}: {field}: {error['msg']}"))
        return problems
    name_problem = _skill_name_problem(frontmatter.name, skill_dir.name)
    if name_problem is not None:
        return [LoadProblem(source, f"{label}: {name_problem}")]
    return []


def builtin_skills_root() -> Path | None:
    """Locate the shipped orchestrator skills container (``<repo>/skills/``).

    The same two-layout resolution as
    :func:`swarmy.modules.loader.builtin_agents_root` (D40): the installed
    package (``<site-packages>/swarmy/skills``) first, then an
    editable/src-layout checkout (``<repo>/skills``, the package root being
    ``<repo>/src/swarmy``).

    Returns:
        The directory, or ``None`` when neither candidate exists — the
        orchestrator then runs without skills (an optional container, unlike
        the mandatory built-in modules).
    """
    packaged = _PACKAGE_ROOT / "skills"
    if packaged.is_dir():
        return packaged
    checkout = _PACKAGE_ROOT.parent.parent / "skills"
    if checkout.is_dir():
        return checkout
    return None


def load_orchestrator_skills(root: Path | None) -> OrchestratorSkills | None:
    """Validate the skills container and return the engine-facing bundle.

    Every immediate subdirectory is a skill (loose files such as a README at
    the container root are not); every ``*.py`` under the container gets the
    module-scan. Problems are collected across the whole container before
    anything is raised (fail-fast, arch §16.9).

    Args:
        root: the container (``builtin_skills_root()``); ``None`` or a missing
            directory means "no orchestrator skills".

    Returns:
        The bundle, or ``None`` when the container holds no skill — the
        engine is then compiled exactly as before (no L0 ``SkillsMiddleware``).

    Raises:
        SkillsError: every problem of the whole container, collected at once.
    """
    if root is None or not root.is_dir():
        return None
    source = f"skills:{root}"
    problems: list[LoadProblem] = []
    names: list[str] = []
    for entry in sorted(root.iterdir()):
        if entry.is_symlink():
            problems.append(
                LoadProblem(source, f"{entry.name}: a skill directory must not be a symlink")
            )
            continue
        if not entry.is_dir():
            continue
        problems.extend(_validate_skill(entry, source))
        names.append(entry.name)
    problems.extend(scan_skill_scripts(root, source))
    if problems:
        raise SkillsError([str(problem) for problem in problems])
    if not names:
        return None
    return OrchestratorSkills(root=root.resolve(), names=tuple(names))


class ReadOnlySkillsBackend(FilesystemBackend):
    """``FilesystemBackend`` over the skills container with every mutation refused.

    ``virtual_mode=True`` confines reads to ``root_dir`` (the documented path
    guard of the L0 backend: traversal and absolute escapes are rejected);
    writes, edits, deletions and uploads return an error result, so the
    agent's ``write_file``/``edit_file`` on ``/skills/...`` fail at the
    backend instead of persisting new instructions on disk (ASI01).
    """

    def __init__(self, root_dir: Path) -> None:
        """Serve ``root_dir`` as the virtual root (read-only)."""
        super().__init__(root_dir=root_dir, virtual_mode=True)

    def write(self, file_path: str, content: str) -> WriteResult:
        """Refuse the write (the container is read-only for the agent)."""
        return WriteResult(error=_READ_ONLY.format(path=file_path))

    def edit(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
    ) -> EditResult:
        """Refuse the edit (the container is read-only for the agent)."""
        return EditResult(error=_READ_ONLY.format(path=file_path))

    def delete(self, file_path: str) -> DeleteResult:
        """Refuse the deletion (the container is read-only for the agent)."""
        return DeleteResult(error=_READ_ONLY.format(path=file_path))

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        """Refuse every upload (the container is read-only for the agent)."""
        return [
            FileUploadResponse(path=path, error=_READ_ONLY.format(path=path)) for path, _ in files
        ]


def module_skills_routes(modules: ModuleRegistry) -> dict[str, Path]:
    """The composite routes of every module carrying a ``skills/`` directory.

    Walks the loaded registry (arch §8.3) and pairs each module's L0 source
    — the virtual :func:`~swarmy.modules.loader.module_skills_route` the
    loader put into its ``SubAgent`` dict — with the on-disk directory the
    read-only route serves. Modules without skills contribute nothing.

    Args:
        modules: the session's loaded module registry.

    Returns:
        ``{"/module-skills/<name>/": <module>/skills}`` for every skilled
        module, ordered by module name (the registry order).
    """
    routes: dict[str, Path] = {}
    for module in modules.modules():
        if module.subagent.get("skills"):
            routes[module_skills_route(module.manifest.name)] = module.path / "skills"
    return routes


def build_skills_backend(
    orchestrator: OrchestratorSkills | None,
    module_routes: Mapping[str, Path],
) -> CompositeBackend | None:
    """The L0 backend carrying every skills container of the session (arch §8.6/§9.1).

    One ``CompositeBackend`` over the default ``StateBackend`` (the
    orchestrator's own file tools stay state-backed exactly as before) with
    one read-only :class:`ReadOnlySkillsBackend` route per container: the
    orchestrator's ``/skills/`` container when present, plus every module
    route built by :func:`module_skills_routes`. L0 hands this same backend
    to the orchestrator's and every subagent's ``SkillsMiddleware``, which
    is what makes the module sources resolvable.

    Args:
        orchestrator: the validated orchestrator container, or ``None``.
        module_routes: ``{route: skills directory}`` of the skilled modules.

    Returns:
        The composite, or ``None`` when there is nothing to mount — the
        engine then passes ``backend=None`` and L0 builds its default
        ``StateBackend`` (the pre-skills assembly, byte for byte).
    """
    routes: dict[str, BackendProtocol] = {}
    if orchestrator is not None:
        routes[SKILLS_ROUTE] = ReadOnlySkillsBackend(root_dir=orchestrator.root)
    for route, skills_dir in module_routes.items():
        routes[route] = ReadOnlySkillsBackend(root_dir=skills_dir)
    if not routes:
        return None
    return CompositeBackend(default=StateBackend(), routes=routes)


class OrchestratorSkills:
    """The validated container as the engine consumes it (arch §9.1).

    Attributes:
        root: the on-disk container the read-only backend serves.
        names: the validated skill directory names (sorted).
    """

    __slots__ = ("names", "root")

    def __init__(self, *, root: Path, names: Sequence[str]) -> None:
        """Bind the container and its validated skill names."""
        self.root = root
        self.names = tuple(names)

    @property
    def sources(self) -> list[str]:
        """The L0 ``create_deep_agent(skills=...)`` list: the mounted route."""
        return [SKILLS_ROUTE]

    def backend(self) -> CompositeBackend:
        """The orchestrator container alone, mounted read-only under :data:`SKILLS_ROUTE`.

        The module routes are added by the engine through
        :func:`build_skills_backend`; this is that composite with an empty
        module map — the orchestrator route alone.
        """
        composite = build_skills_backend(self, {})
        assert composite is not None  # the orchestrator route is always present
        return composite


__all__ = [
    "MAX_SKILL_DESCRIPTION_LENGTH",
    "MAX_SKILL_NAME_LENGTH",
    "SKILLS_ROUTE",
    "OrchestratorSkills",
    "ReadOnlySkillsBackend",
    "SkillFrontmatter",
    "SkillsError",
    "build_skills_backend",
    "builtin_skills_root",
    "load_orchestrator_skills",
    "module_skills_routes",
]
