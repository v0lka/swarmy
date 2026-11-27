"""``ModuleLoader``: scan → import → validate → assemble SubAgent dicts (arch §8.3, T1.5.3).

The loader is the fail-fast front door of the module system (arch §8.3,
spec §4.5): it walks the shipped built-in module directory (``<package>/agents``
in a wheel, ``<repo>/agents`` in an editable checkout) and the operator's user
directories, and for every module directory:

1. parses ``AGENT.md`` (frontmatter → :class:`AgentModuleManifest`, body →
   system prompt; T1.5.2);
2. imports every ``tools/*.py`` through
   ``importlib.util.spec_from_file_location`` — module code is never placed
   on ``sys.path`` (arch §8.3) and runs in-process (D4);
3. validates each exported tool function at runtime: full annotations via
   ``typing.get_type_hints`` (no ``Any`` / ``dict[str, Any]``, no unannotated
   parameter, no unannotated return) and a non-empty LLM-facing docstring
   (arch §8.5, spec §4.3);
4. statically scans the tool files' imports and raw-egress call shapes —
   ``socket``, ``urllib``, ``http.client``, the HTTP-client families
   ``httpx``/``aiohttp``/``requests`` (F-2) and ``subprocess`` are forbidden,
   as are the attribute calls ``os.system``/``os.popen`` and asyncio's raw
   streams ``open_connection``/``start_server``: the platform HTTP client is
   the only network path (arch §8.5, spec §4.3, SECURITY.md ASI02/ASI05);
   ``skills/**/*.py`` scripts get the same static scan;
5. parses ``guardrails.yaml`` into :class:`ModuleGuardrails` (T1.4.2) and
   cross-checks its ``applies_to`` / ``tool_classes`` names against the
   real toolset of this session (platform + module tools);
6. registers the module's event payload models from
   ``tools/event_models.py`` into the ``EventRegistry`` (arch §8.4) and
   verifies that every manifest ``events`` entry is registered; the registry
   is reset to the built-in taxonomy at the start of every ``load()`` so a
   failed or repeated load cannot poison later loads (F-12, #35);
7. collects all module tools for the
   :class:`~swarmy.tools.registry.ToolRegistry` (RD-3) — reserved-prefix
   violations and name collisions are collected there; the registry writes
   happen **once, only when every module loaded clean** (never on the abort
   path), so an aborted load leaves no registered tools behind (#44);
8. resolves the AD-3 ``result`` reference to a Pydantic class and assembles
   the ``SubAgent`` dict with exactly the arch §8.3 keys, merging the
   strictness-profile gates with the manifest ``interrupt_on`` (arch §7.2);
   a module's ``skills/`` directory is named as the virtual
   ``/module-skills/<name>/`` L0 source (:func:`module_skills_route`) — never
   as a disk path, which the default ``StateBackend`` cannot read — and the
   Engine mounts it read-only through the composite backend (arch §8.6).

Every problem of every module is collected into **one**
:class:`~swarmy.modules.registry.ModuleLoadError` — a problem in one module
never stops the collection for the others (spec §4.5); with no problems the
loader returns a populated :class:`~swarmy.modules.registry.ModuleRegistry`.

A user module whose name collides with a built-in module is a load error
without override (AD-4).
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import itertools
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import FunctionType, ModuleType
from typing import (
    TYPE_CHECKING,
    Any,
    Final,
    Literal,
    TypeAlias,
    get_args,
    get_origin,
    get_type_hints,
)

from pydantic import BaseModel

from swarmy.events.models import EVENT_TYPES, EventRegistry
from swarmy.guardrails.dsl import GuardrailsDslError, parse_module_guardrails
from swarmy.guardrails.models import ModuleGuardrails, RiskClass
from swarmy.guardrails.pipeline import GuardrailMiddleware, GuardrailPipeline
from swarmy.modules.generalist import (
    GENERALIST_EVENTS,
    GENERALIST_GATED_TOOLS,
    GENERALIST_NAME,
    GENERALIST_SOURCE,
    GENERALIST_SYSTEM_PROMPT,
    generalist_manifest,
)
from swarmy.modules.manifest import (
    ManifestError,
    Utf8Error,
    parse_agent_module,
    parse_result_spec,
    read_utf8,
)
from swarmy.modules.registry import (
    LoadedModule,
    ModuleLoadError,
    ModuleRegistry,
    VirtualAgent,
)
from swarmy.tools.errors import ToolErrorFeedbackMiddleware
from swarmy.tools.projector import ContextProjector, ProjectorMiddleware
from swarmy.tools.registry import (
    BUILTIN_SOURCE,
    PLATFORM_OWNER,
    RESERVED_TOOL_PREFIXES,
    ToolRegistry,
    ToolRegistryError,
    ToolSpec,
    declared_risk_class,
)

if TYPE_CHECKING:
    from swarmy.guardrails.pipeline import JudgeBand
    from swarmy.modules.manifest import AgentModuleManifest

#: Strictness profiles (arch §7.2): the risk classes each profile gates with
#: HITL approvals. ``passive`` is never gated (paranoid gates the rest).
#: Tool-name → budget-class map wired into every production
#: ``ProjectorMiddleware`` (arch §6.8/§12.1 budgets; Issue #58 ↔ F-6): HTTP
#: tool envelopes (the full ``ResponseRecord`` JSON the middleware
#: projects *after* the client's inner body preview) use the
#: ``http_preview`` budget, the read-model platform tools the
#: ``memory_result`` budget. Entries extend ``DEFAULT_TOOL_CLASSES``
#: (``memory_search``/``memory_get``); unknown tools keep the conservative
#: default budget.
PLATFORM_TOOL_BUDGET_CLASSES: Final[dict[str, str]] = {
    "http_get": "http_preview",
    "http_post": "http_preview",
    "http_put": "http_preview",
    "http_delete": "http_preview",
    "session_info": "memory_result",
    "generate_report": "memory_result",
    "update_finding_status": "memory_result",
}

_PROFILE_GATES: Final[Mapping[str, frozenset[RiskClass]]] = {
    "paranoid": frozenset({RiskClass.NETWORK_WRITE, RiskClass.VERIFY, RiskClass.DESTRUCTIVE}),
    "normal": frozenset({RiskClass.VERIFY, RiskClass.DESTRUCTIVE}),
    "yolo": frozenset({RiskClass.DESTRUCTIVE}),
}

#: Modules that would open raw network paths — forbidden in module tool files
#: (arch §8.5: network is executed only by the platform HTTP client). The
#: HTTP-client families matter because they are installed in the same venv
#: the module tools execute in (F-2): ``httpx`` is a runtime dependency of
#: swarmy itself; ``aiohttp``/``requests`` are the other natural raw-HTTP
#: escapes of this stack.
_FORBIDDEN_NETWORK_ROOTS: Final[tuple[str, ...]] = (
    "socket",
    "urllib",
    "http.client",
    "httpx",
    "aiohttp",
    "requests",
)

#: Process-spawn entry points — forbidden as imports (SECURITY.md ASI05: the
#: loader's forbidden-import scan is the deterministic enforcement point).
#: Bare ``os`` is deliberately NOT banned (it has legitimate non-spawn uses);
#: the ``os.system``/``os.popen`` attribute calls are caught by the AST
#: usage scan instead.
_FORBIDDEN_PROCESS_ROOTS: Final[tuple[str, ...]] = ("subprocess",)

#: ``os`` attribute calls that spawn processes (ASI05) — usage-scanned, not
#: import-banned (bare ``os`` stays legal).
_OS_SPAWN_ATTRS: Final[frozenset[str]] = frozenset({"system", "popen"})

#: asyncio's raw stream APIs — direct TCP sockets bypassing the platform
#: client (F-2). Both the ``asyncio.open_connection(...)`` attribute-call
#: shape and ``from asyncio import open_connection`` are forbidden.
_ASYNCIO_STREAM_ATTRS: Final[frozenset[str]] = frozenset({"open_connection", "start_server"})

#: Files inside ``tools/`` that are not tool modules.
_SKIP_TOOL_FILES: Final[frozenset[str]] = frozenset({"__init__.py", "event_models.py", "result.py"})

_MODULE_COUNTER = itertools.count()


class LoadProblem:
    """One problem found while loading one module directory (arch §8.3)."""

    __slots__ = ("message", "source")

    def __init__(self, source: str, message: str) -> None:
        """Bind the module directory the problem belongs to and its text."""
        self.source = source
        self.message = message

    def __str__(self) -> str:
        """Render ``source: message`` (the aggregated report line format)."""
        return f"{self.source}: {self.message}"


#: A module tool function: fully annotated, docstring-carrying callable.
ModuleTool: TypeAlias = Callable[..., object]

#: The platform toolset handed to every subagent (``memory_*`` + ``emit_event``;
#: produced by the session wiring via ``make_memory_tools``/``make_emit_tool``).
PlatformToolset: TypeAlias = Mapping[str, ModuleTool]

#: Factory the loader calls once per module: ``(module_name, declared_event_types)
#: → platform toolset``. The wiring binds the per-module ``emit_event`` with
#: ``allowed_types=declared_event_types`` (arch §8.4) and ``source_detail=
#: module_name`` (arch §5.2).
PlatformToolsetFactory: TypeAlias = Callable[[str, frozenset[str]], PlatformToolset]

#: Factory the session wiring passes to build the per-module §6.8 projector
#: (config budgets + operator secrets, T3.1.1): ``module_name → projector``.
ProjectorFactory: TypeAlias = Callable[[str], "ContextProjector"]

#: Factory building the module pipeline's judge band (arch §6.7, P3.4/RD-2):
#: ``risk_classes → band`` over the session's shared judge.
JudgeBandFactory: TypeAlias = Callable[[Mapping[str, RiskClass]], "JudgeBand"]

#: HITL strictness profile (arch §7.2).
StrictnessProfile: TypeAlias = Literal["paranoid", "normal", "yolo"]


def _no_platform_tools(module_name: str, declared_event_types: frozenset[str]) -> PlatformToolset:
    """Default platform toolset factory: no platform tools (platform-less loading).

    Production wiring (session composition root) passes a factory built on
    ``make_memory_tools``/``make_emit_tool``; tests of the loader itself use
    this stand-in.
    """
    return {}


@dataclass
class _LoadState:
    """Mutable state shared by the per-module load steps of one ``load()`` run.

    Registry writes are **deferred** (#44): every step only collects
    ``ToolSpec`` batches; ``load()`` flushes them into the ``ToolRegistry``
    once, only after all module problems are clean — an aborted load leaves
    the registry untouched, so a same-process retry cannot hit stale
    duplicate registrations.
    """

    tool_registry: ToolRegistry = field(default_factory=ToolRegistry)
    #: platform tool names are collected once from the first module's toolset
    platform_registered: bool = False
    #: deferred batches: platform specs first, then ``(source, specs)`` per module
    pending_platform_specs: list[ToolSpec] = field(default_factory=list)
    pending_module_specs: list[tuple[str, list[ToolSpec]]] = field(default_factory=list)
    #: ``tool_classes`` overrides (AD-7) consulted by ``_build_subagent`` while
    #: the registry itself is not yet written
    risk_overrides: dict[str, RiskClass] = field(default_factory=dict)


#: Root of the installed ``swarmy`` package (``.../swarmy``), derived from this
#: module's location (``.../swarmy/modules/loader.py``). Used to locate the
#: built-in module directory in both packaging layouts.
_PACKAGE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent


def builtin_agents_root() -> Path | None:
    """Locate the built-in module directory shipped with swarmy.

    The repository keeps the reference modules in ``<repo>/agents``; the wheel
    maps that directory to ``swarmy/agents`` inside the installed package
    (``[tool.hatch.build.targets.wheel] force-include``). Two layouts are
    resolved, in order:

    * the installed package: ``<site-packages>/swarmy/agents``;
    * an editable/src-layout checkout: ``<repo>/agents`` (the package root is
      ``<repo>/src/swarmy``).

    Returns:
        The directory, or ``None`` when neither candidate exists — a broken
        installation (:meth:`ModuleLoader.load` reports it fail-fast).

    """
    packaged = _PACKAGE_ROOT / "agents"
    if packaged.is_dir():
        return packaged
    checkout = _PACKAGE_ROOT.parent.parent / "agents"
    if checkout.is_dir():
        return checkout
    return None


def _builtin_module_dirs(root: Path | None) -> list[Path]:
    """Directories of built-in modules (arch §8.3, §8.7).

    An empty or missing root simply yields no built-ins; the empty case is a
    load problem reported by :meth:`ModuleLoader.load`.
    """
    if root is None or not root.is_dir():
        return []
    return sorted(
        path for path in root.iterdir() if path.is_dir() and (path / "AGENT.md").is_file()
    )


def _user_module_dirs(user_dirs: Sequence[Path]) -> tuple[list[Path], list[LoadProblem]]:
    """Resolve user agents roots into module directories (spec §4.5).

    Every immediate subdirectory of a root that contains an ``AGENT.md`` is a
    module directory; subdirectories without a manifest are not modules and
    are skipped. A missing root is a load problem (fail-fast).
    """
    problems: list[LoadProblem] = []
    dirs: list[Path] = []
    for root_dir in user_dirs:
        if not root_dir.is_dir():
            problems.append(
                LoadProblem(str(root_dir), f"agents root directory does not exist: {root_dir}")
            )
            continue
        dirs.extend(
            sorted(
                path
                for path in root_dir.iterdir()
                if path.is_dir() and (path / "AGENT.md").is_file()
            )
        )
    return dirs, problems


def _unique_module_name(module_dir_name: str, file_stem: str) -> str:
    """Build a collision-free import name for one module file.

    Module directory names may contain characters that are illegal in dotted
    module names (``xss-detector``); they are sanitized and a global counter
    guarantees uniqueness across repeated loads. The name is registered in
    ``sys.modules`` (never ``sys.path``) so that pydantic/``get_type_hints``
    can resolve the loaded classes after the loader returns.
    """
    serial = next(_MODULE_COUNTER)
    base = re.sub(r"\W+", "_", f"{module_dir_name}_{file_stem}")
    return f"_swarmy_module_{base}_{serial}"


def _import_python_file(path: Path, unique_name: str) -> tuple[ModuleType | None, str | None]:
    """Import one module file by path (arch §8.3: ``spec_from_file_location``).

    Returns ``(module, None)`` or ``(None, problem)``. The loaded module is
    kept in ``sys.modules`` under ``unique_name`` (the documented importlib
    pattern) so later ``get_type_hints``/pydantic resolution still works;
    ``sys.path`` is never touched.
    """
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:
        return None, f"importlib cannot build a module spec for {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module  # documented importlib pattern (not sys.path)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # module code is arbitrary; every failure is reported fail-fast
        sys.modules.pop(unique_name, None)
        return None, f"file failed to import: {type(exc).__name__}: {exc}"
    return module, None


def _tool_functions(module: ModuleType, unique_name: str) -> list[tuple[str, FunctionType]]:
    """Public functions *defined in* the loaded file (its exported tools).

    Names starting with ``_`` are private; callables imported from elsewhere
    (``__module__`` differs) are not this file's tools.
    """
    found: list[tuple[str, FunctionType]] = []
    for name, value in vars(module).items():
        if name.startswith("_") or not isinstance(value, FunctionType):
            continue
        if getattr(value, "__module__", None) != unique_name:
            continue
        found.append((name, value))
    return found


def _hint_any_label(hint: object) -> str | None:
    """Human-readable label of an ``Any``-usage inside a resolved hint.

    Returns ``"Any"``, ``"dict[str, Any]"`` or the nested violation kind, or
    ``None`` when the hint is clean.
    """
    if hint is Any:
        return "Any"
    origin = get_origin(hint)
    if origin is None:
        return None
    args = get_args(hint)
    if origin is dict and len(args) == 2 and args[1] is Any:
        return "dict[str, Any]"
    for arg in args:
        nested = _hint_any_label(arg)
        if nested is not None:
            return nested
    return None


def _validate_tool(fn: FunctionType, name: str, source: str) -> list[LoadProblem]:
    """Runtime signature validation of one tool function (arch §8.5, spec §4.3).

    Checks: non-empty docstring (the LLM-facing description), every parameter
    and the return annotated, no ``Any``/``dict[str, Any]`` (or ``Any`` nested
    in a generic) anywhere in the resolved annotations.
    """
    problems: list[LoadProblem] = []
    if not inspect.getdoc(fn):
        problems.append(
            LoadProblem(
                source,
                f"tool {name!r} has no docstring; the docstring is the LLM-facing "
                "description and must be non-empty (arch §8.5)",
            )
        )
    try:
        hints = get_type_hints(fn)
    except Exception as exc:  # unresolvable annotations are a load problem
        problems.append(
            LoadProblem(source, f"tool {name!r}: annotations cannot be resolved: {exc}")
        )
        hints = {}
    for param_name in inspect.signature(fn).parameters:
        if param_name not in hints:
            problems.append(
                LoadProblem(
                    source,
                    f"tool {name!r}: parameter {param_name!r} is not annotated "
                    "(full typing required, spec §4.3)",
                )
            )
    if "return" not in hints:
        problems.append(
            LoadProblem(
                source,
                f"tool {name!r}: return type is not annotated (spec §4.3)",
            )
        )
    for key, hint in hints.items():
        label = "return type" if key == "return" else f"parameter {key!r}"
        found = _hint_any_label(hint)
        if found is not None:
            problems.append(
                LoadProblem(
                    source,
                    f"tool {name!r}: {label} uses {found} — Any and dict[str, Any] are "
                    "forbidden in tool signatures (spec §4.3, G3)",
                )
            )
    return problems


def _forbidden_import_problems(tree: ast.Module, path: Path, source: str) -> list[LoadProblem]:
    """Static import analysis of one Python file (arch §8.5, F-2, ASI05).

    Forbidden: any import of ``socket`` / ``urllib`` / ``http.client`` /
    ``httpx`` / ``aiohttp`` / ``requests`` (including submodules, plain or
    ``from``-style) and of ``subprocess``; ``from os import system/popen``
    and ``from asyncio import open_connection/start_server`` name-for-import
    forms of the usage-scanned calls. Module tools reach the target only
    through the platform HTTP client and never spawn processes.
    """
    problems: list[LoadProblem] = []

    def _network(module_name: str) -> None:
        if any(
            module_name == root or module_name.startswith(f"{root}.")
            for root in _FORBIDDEN_NETWORK_ROOTS
        ):
            problems.append(
                LoadProblem(
                    source,
                    f"{path.name} imports {module_name!r}: module tools must use the "
                    "platform HTTP client; socket/urllib/http.client and the "
                    "httpx/aiohttp/requests families are forbidden (arch §8.5)",
                )
            )

    def _process(module_name: str) -> None:
        if any(
            module_name == root or module_name.startswith(f"{root}.")
            for root in _FORBIDDEN_PROCESS_ROOTS
        ):
            problems.append(
                LoadProblem(
                    source,
                    f"{path.name} imports {module_name!r}: module tools must not spawn "
                    "processes; subprocess is forbidden (SECURITY.md ASI05)",
                )
            )

    def _named_from(module_name: str, names: list[str]) -> None:
        if module_name == "os":
            for alias in names:
                if alias in _OS_SPAWN_ATTRS:
                    problems.append(
                        LoadProblem(
                            source,
                            f"{path.name} imports os.{alias} from os: process spawning "
                            "is forbidden in module tools (SECURITY.md ASI05)",
                        )
                    )
        elif module_name == "asyncio":
            for alias in names:
                if alias in _ASYNCIO_STREAM_ATTRS:
                    problems.append(
                        LoadProblem(
                            source,
                            f"{path.name} imports asyncio.{alias}: raw asyncio streams "
                            "bypass the platform HTTP client and are forbidden (arch §8.5)",
                        )
                    )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _network(alias.name)
                _process(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported = [alias.name for alias in node.names]
            _network(node.module)
            _process(node.module)
            _named_from(node.module, imported)
    return problems


def _forbidden_call_problems(tree: ast.Module, path: Path, source: str) -> list[LoadProblem]:
    """Static usage analysis of one Python file (F-2, ASI05).

    Forbidden call shapes: ``os.system(...)`` / ``os.popen(...)`` (any
    ``ast.Call`` whose function is the attribute ``system``/``popen`` of the
    name ``os``) and ``asyncio.open_connection(...)`` /
    ``asyncio.start_server(...)``. Bare ``os`` imports stay legal — only the
    process-spawning attribute uses are rejected; aliased process escapes
    (``import os as o``) are deliberate evasion, which is D4 module-vetting
    territory, not the careless-author case this scan addresses.
    """
    problems: list[LoadProblem] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        func = node.func
        if not isinstance(func.value, ast.Name):
            continue
        owner = func.value.id
        if owner == "os" and func.attr in _OS_SPAWN_ATTRS:
            problems.append(
                LoadProblem(
                    source,
                    f"{path.name} calls os.{func.attr}(): process spawning is "
                    "forbidden in module tools (SECURITY.md ASI05)",
                )
            )
        elif owner == "asyncio" and func.attr in _ASYNCIO_STREAM_ATTRS:
            problems.append(
                LoadProblem(
                    source,
                    f"{path.name} calls asyncio.{func.attr}(): raw asyncio streams "
                    "bypass the platform HTTP client and are forbidden (arch §8.5)",
                )
            )
    return problems


def _static_scan_problems(tree: ast.Module, path: Path, source: str) -> list[LoadProblem]:
    """The full static scan of one Python file: imports + call shapes."""
    return [
        *_forbidden_import_problems(tree, path, source),
        *_forbidden_call_problems(tree, path, source),
    ]


def scan_skill_scripts(skills_root: Path, source: str) -> list[LoadProblem]:
    """Statically scan every ``skills/**/*.py`` script under ``skills_root``.

    The one implementation of the skill-script scan (F-2 option b, ASI05),
    shared by the two skill containers of the system: a module's
    ``<module>/skills/`` (:meth:`ModuleLoader._scan_skill_scripts`, arch
    §8.5) and the orchestrator's repository-root ``skills/``
    (:mod:`swarmy.core.skills`, arch §8.6). Skill scripts execute with
    operator privileges and are never imported by the loader, so the scan is
    purely static: the same forbidden-import and raw-egress call-shape rules
    as ``tools/*.py`` apply. Non-Python scripts are outside the AST scan's
    reach — the operator vetting rule (SECURITY.md ASI04) covers them; a
    non-UTF-8 or unparsable ``*.py`` script is a collected problem like any
    other module file.

    Args:
        skills_root: the skills container (``<module>/skills`` or ``<repo>/skills``).
        source: the problem-source label of the container's owner.

    Returns:
        The collected problems (empty when the root is absent or clean).
    """
    problems: list[LoadProblem] = []
    if not skills_root.is_dir():
        return problems
    for script in sorted(skills_root.rglob("*.py")):
        try:
            tree = ast.parse(read_utf8(script), filename=str(script))
        except Utf8Error as exc:
            problems.append(LoadProblem(source, str(exc)))
            continue
        except SyntaxError as exc:
            problems.append(LoadProblem(source, f"{script.name}: invalid syntax: {exc}"))
            continue
        problems.extend(_static_scan_problems(tree, script, source))
    return problems


#: The virtual L0 backend route every module's ``skills/`` directory is
#: mounted under (arch §8.6/§9.1): ``/module-skills/<module-name>/``. A
#: separate namespace from the orchestrator's ``/skills/`` container, so a
#: skill named like a module can never shadow the module route. The default
#: L0 ``StateBackend`` cannot read disk paths, so the loader never hands the
#: on-disk directory to L0 — ``Engine`` mounts the directory read-only under
#: this route through the composite backend (:mod:`swarmy.core.skills`).
MODULE_SKILLS_ROUTE_PREFIX: Final[str] = "/module-skills/"

#: A module name that hosts skills doubles as a route segment; it must be a
#: plain path segment (no separators, no ``..``/``~``, no whitespace).
_MODULE_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")


def module_skills_route(module_name: str) -> str:
    """The L0 skills source of a module carrying a ``skills/`` directory.

    The loader puts this virtual path into ``SubAgent["skills"]``; the
    composite backend routes it to the module's read-only ``skills/``
    directory (arch §8.6). Callers ensure the name is a valid segment with
    :func:`skills_route_name_problem` first.

    Args:
        module_name: the manifest ``name`` of the module.

    Returns:
        ``/module-skills/<module-name>/``.
    """
    return f"{MODULE_SKILLS_ROUTE_PREFIX}{module_name}/"


def skills_route_name_problem(module_name: str) -> str | None:
    """Why ``module_name`` cannot host skills, or ``None`` when it can.

    A module with a ``skills/`` directory is mounted under
    :func:`module_skills_route`, so its name must be usable as a single
    path segment. Modules without skills are not subject to the rule.
    """
    if _MODULE_NAME_PATTERN.fullmatch(module_name) is None:
        return (
            f"module name {module_name!r} cannot host skills: it must match "
            f"{_MODULE_NAME_PATTERN.pattern!r} to be a skills route segment "
            f"({MODULE_SKILLS_ROUTE_PREFIX}<name>/, arch §8.6)"
        )
    return None


def _register_event_models(module: ModuleType, unique_name: str, source: str) -> list[LoadProblem]:
    """Register the public payload models of ``tools/event_models.py`` (arch §8.4).

    Every public ``BaseModel`` subclass *defined in the file* registers under
    its class name (``class ModuleProbe(BaseModel)`` → event type
    ``"ModuleProbe"``), exactly like the built-in taxonomy bootstrap.
    Registration collisions (two modules claiming one type) are load problems.
    """
    problems: list[LoadProblem] = []
    for name, value in vars(module).items():
        if name.startswith("_") or not isinstance(value, type):
            continue
        if not issubclass(value, BaseModel):
            continue
        if value.__module__ != unique_name:
            continue
        try:
            EventRegistry.register(name, value)
        except ValueError as exc:
            problems.append(LoadProblem(source, f"event model {name!r}: {exc}"))
    return problems


class ModuleLoader:
    """The P1.5 loading pipeline (arch §8.3): scan → validate → assemble.

    Args:
        user_dirs: root directories whose immediate subdirectories are user
            modules (default scan location per spec §4.5 is ``agents/``).
        strictness: HITL strictness profile (arch §7.2) whose risk-class
            gates seed each ``SubAgent`` dict's ``interrupt_on``; the manifest
            ``interrupt_on`` is merged on top.
        platform_toolset_factory: per-module platform toolset factory (see
            :data:`PlatformToolsetFactory`); platform tools are included in
            every subagent toolset (arch §6.1).
    """

    __slots__ = (
        "_engine_rules_enabled",
        "_include_builtins",
        "_judge_band_factory",
        "_platform_factory",
        "_projector_factory",
        "_strictness",
        "_tool_registry",
        "_user_dirs",
    )

    def __init__(
        self,
        *,
        user_dirs: Sequence[Path] = (),
        strictness: StrictnessProfile = "normal",
        platform_toolset_factory: PlatformToolsetFactory | None = None,
        tool_registry: ToolRegistry | None = None,
        projector_factory: ProjectorFactory | None = None,
        engine_rules_enabled: bool = True,
        judge_band_factory: JudgeBandFactory | None = None,
        include_builtins: bool = True,
    ) -> None:
        """Bind scan roots, the strictness profile and the platform wiring.

        Args:
            user_dirs: root directories whose immediate subdirectories are user
                modules (default scan location per spec §4.5 is ``agents/``).
            strictness: HITL strictness profile (arch §7.2) whose risk-class
                gates seed each ``SubAgent`` dict's ``interrupt_on``; the manifest
                ``interrupt_on`` is merged on top.
            platform_toolset_factory: per-module platform toolset factory (see
                :data:`PlatformToolsetFactory`); platform tools are included in
                every subagent toolset (arch §6.1).
            tool_registry: the session-owned registry (arch §13.1 startup
                order: the registry exists *before* the loader). ``None``
                creates a module-private registry (standalone loader use);
                production sessions pass their own and keep the reference.
            projector_factory: per-module §6.8 projector factory (session
                wiring of T3.1.1: config budgets + operator secrets);
                ``None`` keeps the conservative per-module default from
                T2.3.2.
            engine_rules_enabled: the layer-2 toggle (config key
                ``guardrails.engine_rules`` — read since T3.1.1); layer 1
                invariants are never configurable.
            judge_band_factory: builds the LLM-judge band (P3.4, RD-2) for
                each subagent pipeline over that module's risk-class map;
                ``None`` keeps the judge slot empty.
            include_builtins: scan the shipped built-in module directory
                (``<package>/agents``, arch §8.3) for the reference modules.
                ``False`` loads user modules only — the AD-4 "explicit choice
                without built-ins" escape hatch, used by tests and operators
                who want a bespoke roster. The platform virtual ``generalist``
                (arch §8.8) is not a module and is loaded either way.
        """
        self._user_dirs = tuple(user_dirs)
        self._strictness: StrictnessProfile = strictness
        self._include_builtins = include_builtins
        self._platform_factory: PlatformToolsetFactory = (
            platform_toolset_factory if platform_toolset_factory is not None else _no_platform_tools
        )
        self._tool_registry = tool_registry
        self._projector_factory = projector_factory
        self._engine_rules_enabled = engine_rules_enabled
        self._judge_band_factory = judge_band_factory

    def load(self) -> ModuleRegistry:
        """Run the full pipeline (arch §8.3).

        Returns:
            The populated :class:`ModuleRegistry` — every loaded module with
            its assembled ``SubAgent`` dict, plus the platform virtual
            ``generalist`` (arch §8.8; present even when the built-in module
            directory is skipped, because it is not a module).

        Raises:
            ModuleLoadError: with **all** problems of **all** modules when
                anything fails (fail-fast session start, spec §4.5).
        """
        # One load = one taxonomy (F-12, #35): reset the process-global
        # EventRegistry to the built-in types before anything registers, so a
        # failed or repeated load cannot poison later loads with stale module
        # types (retry "already registered" ghosts, cross-session collisions).
        EventRegistry.reset()
        problems: list[LoadProblem] = []
        loaded: list[LoadedModule] = []
        builtin_root = builtin_agents_root() if self._include_builtins else None
        builtin_dirs = _builtin_module_dirs(builtin_root)
        if self._include_builtins and not builtin_dirs:
            # Fail-fast on a broken installation: the reference modules are
            # package data and must ship with swarmy (arch §8.3/§8.7).
            if builtin_root is None:
                detail = (
                    "built-in module directory not found: expected "
                    f"{_PACKAGE_ROOT / 'agents'} or {_PACKAGE_ROOT.parent.parent / 'agents'}; "
                    "the swarmy installation is incomplete — reinstall the package"
                )
            else:
                detail = (
                    f"built-in module directory is empty: {builtin_root} "
                    "(expected at least one <module>/AGENT.md); the swarmy "
                    "installation is incomplete — reinstall the package"
                )
            problems.append(LoadProblem("builtins", detail))
        user_dirs, scan_problems = _user_module_dirs(self._user_dirs)
        problems.extend(scan_problems)
        state = _LoadState(
            tool_registry=self._tool_registry if self._tool_registry is not None else ToolRegistry()
        )
        # name → (source, dir): collision detection incl. AD-4 (built-ins first)
        known_names: dict[str, tuple[str, str]] = {}
        plan: list[tuple[Path, str]] = [(path, BUILTIN_SOURCE) for path in builtin_dirs] + [
            (path, f"module:{path}") for path in user_dirs
        ]
        for module_dir, source in plan:
            module_problems, module_loaded = self._load_module(
                module_dir, source, state, known_names
            )
            problems.extend(module_problems)
            if module_loaded is not None:
                loaded.append(module_loaded)
        if problems:
            # The abort path registers nothing (#44): a failed load leaves the
            # session ToolRegistry exactly as it was before ``load()``.
            raise ModuleLoadError([str(problem) for problem in problems])
        # The platform virtual generalist (arch §8.8) is assembled after a
        # clean module pass but *before* the deferred flush, so its platform
        # tool names reach the ToolRegistry through the same batch mechanics
        # as the modules' (and the judge band keeps seeing every tool).
        generalist_problems, generalist = self._load_generalist(state, known_names)
        problems.extend(generalist_problems)
        if problems:
            raise ModuleLoadError([str(problem) for problem in problems])
        self._flush_tool_registrations(state)
        registry = ModuleRegistry()
        for module in loaded:
            registry.register(module)
        if generalist is not None:
            registry.register_virtual(generalist)
        return registry

    def _flush_tool_registrations(self, state: _LoadState) -> None:
        """Write every deferred batch into the ``ToolRegistry`` (RD-3, #44).

        Runs only on the all-clean success path. Batch problems (reserved
        prefixes, name collisions) still fail the load — aggregated into one
        :class:`ModuleLoadError` with each problem attributed to its source.
        """
        flush_problems: list[LoadProblem] = []
        try:
            state.tool_registry.register_many(state.pending_platform_specs)
        except ToolRegistryError as exc:
            flush_problems.extend(LoadProblem("platform", problem) for problem in exc.problems)
        for source, specs in state.pending_module_specs:
            try:
                state.tool_registry.register_many(specs)
            except ToolRegistryError as exc:
                flush_problems.extend(LoadProblem(source, problem) for problem in exc.problems)
        if flush_problems:
            raise ModuleLoadError([str(problem) for problem in flush_problems])

    def _load_module(
        self,
        module_dir: Path,
        source: str,
        state: _LoadState,
        known_names: dict[str, tuple[str, str]],
    ) -> tuple[list[LoadProblem], LoadedModule | None]:
        """Load one module directory; collect problems, never raise (arch §8.3)."""
        problems: list[LoadProblem] = []
        try:
            parsed = parse_agent_module(module_dir / "AGENT.md")
        except ManifestError as exc:
            return [LoadProblem(source, str(exc))], None
        manifest = parsed.manifest
        name = manifest.name
        if name in known_names:
            other_source, other_dir = known_names[name]
            if other_source == BUILTIN_SOURCE:
                return (
                    [
                        LoadProblem(
                            source,
                            f"module name {name!r} collides with the built-in module at "
                            f"{other_dir}; built-in modules cannot be overridden (AD-4)",
                        )
                    ],
                    None,
                )
            return (
                [
                    LoadProblem(
                        source,
                        f"duplicate module name {name!r} (already provided by {other_dir})",
                    )
                ],
                None,
            )
        known_names[name] = (source, str(module_dir))

        platform_tools = dict(self._platform_factory(name, frozenset(manifest.events)))
        self._register_platform_tools(platform_tools, state)

        tools_dir = module_dir / "tools"
        module_tools = self._import_tools(tools_dir, source, problems)
        self._check_reserved_prefixes(module_tools, source, problems)
        self._load_event_models(tools_dir, source, problems)
        self._check_declared_events(manifest, source, problems)
        self._scan_skill_scripts(module_dir, source, problems)
        self._check_skills_route(module_dir, manifest, source, problems)
        guardrails = self._load_guardrails(module_dir, manifest, source, problems)
        if guardrails is not None:
            self._crosscheck_guardrails(guardrails, platform_tools, module_tools, source, problems)
        self._collect_module_tools(manifest, source, module_tools, guardrails, state)
        response_format = self._resolve_response_format(module_dir, manifest, source, problems)
        if problems:
            return problems, None
        risks = self._resolve_risks(platform_tools, module_tools, state)
        self._check_manifest_gates(manifest, risks, source, problems)
        if problems:
            return problems, None
        skills_dir = module_dir / "skills"
        subagent = self._build_subagent(
            manifest,
            parsed.system_prompt,
            platform_tools,
            module_tools,
            guardrails,
            response_format,
            risks,
            skills=[module_skills_route(manifest.name)] if skills_dir.is_dir() else [],
        )
        module = LoadedModule(
            manifest=manifest,
            system_prompt=parsed.system_prompt,
            path=module_dir,
            source=source,
            tools=module_tools,
            guardrails=guardrails,
            subagent=subagent,
        )
        return [], module

    def _load_generalist(
        self,
        state: _LoadState,
        known_names: Mapping[str, tuple[str, str]],
    ) -> tuple[list[LoadProblem], VirtualAgent | None]:
        """Assemble the platform virtual generalist (arch §8.8).

        The generalist is not a module: there is no directory to scan, so its
        manifest comes from :func:`generalist_manifest` and its system prompt
        from the platform constant. Everything else reuses the ordinary
        ``SubAgent`` assembly — platform toolset, risk-class gates, middleware
        stack — so the fallback delegate has exactly the same guarded surface
        as a loaded module (no privilege beyond the platform tools).

        A user module named ``generalist`` is a fail-fast collision: the
        platform name is reserved and cannot be overridden (the same AD-4
        reasoning as built-ins).

        Args:
            state: the load-run state (deferred platform/tool registrations).
            known_names: module names already accepted in this load.

        Returns:
            ``(problems, agent)`` — problems when the reserved name is taken;
            ``agent`` is ``None`` on any problem.
        """
        problems: list[LoadProblem] = []
        if GENERALIST_NAME in known_names:
            source, _ = known_names[GENERALIST_NAME]
            problems.append(
                LoadProblem(
                    source,
                    f"module name {GENERALIST_NAME!r} collides with the platform virtual "
                    f"agent {GENERALIST_NAME!r} (arch §8.8); the platform name is reserved "
                    "and cannot be overridden — rename the module",
                )
            )
            return problems, None
        platform_tools = dict(
            self._platform_factory(GENERALIST_NAME, frozenset(GENERALIST_EVENTS))
        )
        # The manifest may only name gates for tools the platform toolset
        # actually carries (a gate for a missing tool is a load error).
        manifest = generalist_manifest(
            gated_tools=[tool for tool in GENERALIST_GATED_TOOLS if tool in platform_tools]
        )
        self._register_platform_tools(platform_tools, state)
        # No module tools and no module guardrails: the generalist's only
        # tools are the platform set, whose risk classes the tools declare
        # themselves (http_get → passive, http_post/put/delete → network-write).
        risks = self._resolve_risks(platform_tools, {}, state)
        self._check_manifest_gates(manifest, risks, GENERALIST_SOURCE, problems)
        if problems:
            return problems, None
        subagent = self._build_subagent(
            manifest,
            GENERALIST_SYSTEM_PROMPT,
            platform_tools,
            {},
            None,
            None,
            risks,
            skills=[],
        )
        return [], VirtualAgent(
            manifest=manifest,
            system_prompt=GENERALIST_SYSTEM_PROMPT,
            subagent=subagent,
        )

    def _register_platform_tools(
        self, platform_tools: dict[str, ModuleTool], state: _LoadState
    ) -> None:
        """Collect the platform tool names once per load (arch §6.1, #44).

        The per-module toolset instances differ (each ``emit_event`` is bound
        to its module); the registry records the name-level facts
        (owner ``"platform"``, source ``"builtin"``) from the first set.
        The specs are only *collected* here — ``load()`` writes them after
        every module loaded clean.
        """
        if state.platform_registered:
            return
        state.platform_registered = True
        if not platform_tools:
            return
        state.pending_platform_specs.extend(
            ToolSpec(name=tool_name, fn=fn, owner=PLATFORM_OWNER, source=BUILTIN_SOURCE)
            for tool_name, fn in platform_tools.items()
        )

    def _import_tools(
        self, tools_dir: Path, source: str, problems: list[LoadProblem]
    ) -> dict[str, ModuleTool]:
        """Import and validate ``tools/*.py`` (arch §8.3 steps 2-4)."""
        tools: dict[str, ModuleTool] = {}
        if not tools_dir.is_dir():
            return tools  # tools/ is optional (arch §8.1)
        for py_file in sorted(tools_dir.iterdir()):
            if py_file.suffix != ".py" or py_file.name in _SKIP_TOOL_FILES:
                continue
            unique_name = _unique_module_name(tools_dir.parent.name, py_file.stem)
            module, problem = _import_python_file(py_file, unique_name)
            if problem is not None or module is None:
                problems.append(LoadProblem(source, f"{py_file.name}: {problem}"))
                continue
            try:
                tree = ast.parse(read_utf8(py_file), filename=str(py_file))
            except Utf8Error as exc:
                # Non-UTF-8 tool files are a collected problem, never a raw
                # UnicodeDecodeError escaping the aggregation (#57).
                problems.append(LoadProblem(source, str(exc)))
                continue
            except SyntaxError as exc:
                problems.append(LoadProblem(source, f"{py_file.name}: invalid syntax: {exc}"))
                continue
            problems.extend(_static_scan_problems(tree, py_file, source))
            for tool_name, fn in _tool_functions(module, unique_name):
                problems.extend(_validate_tool(fn, tool_name, source))
                tools[tool_name] = fn
        return tools

    def _load_event_models(self, tools_dir: Path, source: str, problems: list[LoadProblem]) -> None:
        """Register ``tools/event_models.py`` payload models (arch §8.4)."""
        event_models = tools_dir / "event_models.py"
        if not event_models.is_file():
            return
        unique_name = _unique_module_name(tools_dir.parent.name, event_models.stem)
        module, problem = _import_python_file(event_models, unique_name)
        if problem is not None or module is None:
            problems.append(LoadProblem(source, f"event_models.py: {problem}"))
            return
        problems.extend(_register_event_models(module, unique_name, source))

    def _check_declared_events(
        self, manifest: AgentModuleManifest, source: str, problems: list[LoadProblem]
    ) -> None:
        """Every manifest ``events`` entry must be registered (arch §8.4)."""
        for event in manifest.events:
            if event not in EVENT_TYPES:
                problems.append(
                    LoadProblem(
                        source,
                        f"declared event type {event!r} is not registered in the "
                        "EventRegistry (arch §8.4)",
                    )
                )

    def _load_guardrails(
        self,
        module_dir: Path,
        manifest: AgentModuleManifest,
        source: str,
        problems: list[LoadProblem],
    ) -> ModuleGuardrails | None:
        """Parse ``guardrails.yaml`` when present (T1.4.2)."""
        path = module_dir / manifest.guardrails  # default "./guardrails.yaml" (arch §8.2)
        if not path.is_file():
            return None
        try:
            return parse_module_guardrails(read_utf8(path), source=str(path))
        except Utf8Error as exc:
            # Mirror conversion of #57: a non-UTF-8 guardrails file joins the
            # module's problem list instead of aborting the aggregation.
            problems.append(LoadProblem(source, str(exc)))
            return None
        except GuardrailsDslError as exc:
            problems.extend(LoadProblem(source, problem.message) for problem in exc.problems)
            return None

    def _scan_skill_scripts(
        self, module_dir: Path, source: str, problems: list[LoadProblem]
    ) -> None:
        """Statically scan every ``skills/**/*.py`` script of the module (ASI05).

        Delegates to :func:`scan_skill_scripts` — the scan shared with the
        orchestrator skills container (arch §8.5/§8.6).
        """
        problems.extend(scan_skill_scripts(module_dir / "skills", source))

    def _check_skills_route(
        self,
        module_dir: Path,
        manifest: AgentModuleManifest,
        source: str,
        problems: list[LoadProblem],
    ) -> None:
        """A module carrying ``skills/`` must be mountable under its route (arch §8.6).

        The directory is served through the virtual
        :func:`module_skills_route` of the composite backend, so the manifest
        name has to be a valid single path segment; anything else is a
        collected problem (fail-fast) rather than an L0 source that would
        silently resolve to nothing.
        """
        if not (module_dir / "skills").is_dir():
            return
        problem = skills_route_name_problem(manifest.name)
        if problem is not None:
            problems.append(LoadProblem(source, problem))

    def _crosscheck_guardrails(
        self,
        guardrails: ModuleGuardrails,
        platform_tools: dict[str, ModuleTool],
        module_tools: dict[str, ModuleTool],
        source: str,
        problems: list[LoadProblem],
    ) -> None:
        """Check rule/class tool names against the real toolset (T1.4.2 wiring).

        ``applies_to`` must name platform or module tools known to this
        session's :class:`ToolRegistry`; ``tool_classes`` may classify only
        the module's *own* tools (AD-7).
        """
        known = set(platform_tools) | set(module_tools)
        for rule in guardrails.rules:
            for tool_name in rule.applies_to:
                if tool_name not in known:
                    problems.append(
                        LoadProblem(
                            source,
                            f"rule {rule.id!r}: applies_to names unknown tool {tool_name!r} "
                            "(not a platform or module tool of this session; ToolRegistry "
                            "cross-check, T1.4.2)",
                        )
                    )
        for tool_name in guardrails.tool_classes:
            if tool_name not in module_tools:
                problems.append(
                    LoadProblem(
                        source,
                        f"tool_classes declares {tool_name!r} which is not a tool of "
                        "this module (AD-7)",
                    )
                )

    def _check_reserved_prefixes(
        self, module_tools: dict[str, ModuleTool], source: str, problems: list[LoadProblem]
    ) -> None:
        """Check reserved tool-name prefixes at collect time (arch §6.1).

        Uses the registry's exact wording: the flush (where ``register_many``
        would catch them) only runs on the all-clean path, so deferring this
        check would silently drop prefix problems whenever another module
        also failed.
        """
        for tool_name in module_tools:
            for prefix in RESERVED_TOOL_PREFIXES:
                if tool_name.startswith(prefix):
                    problems.append(
                        LoadProblem(
                            source,
                            f"tool name {tool_name!r} uses the reserved platform prefix "
                            f"{prefix!r} (arch §6.1, spec §4.3)",
                        )
                    )

    def _collect_module_tools(
        self,
        manifest: AgentModuleManifest,
        source: str,
        module_tools: dict[str, ModuleTool],
        guardrails: ModuleGuardrails | None,
        state: _LoadState,
    ) -> None:
        """Collect the module's tools for the ToolRegistry (RD-3, arch §6.1, #44).

        ``tool_classes`` from ``guardrails.yaml`` override the attribute risk
        class (AD-7 group marking); the overrides are parked in
        ``state.risk_overrides`` for ``_build_subagent`` and land in the
        registry only when ``load()`` flushes the deferred batches on the
        all-clean path. Prefix/collision problems surface at flush time,
        aggregated per source.
        """
        if not module_tools:
            return
        tool_classes = guardrails.tool_classes if guardrails is not None else {}
        for tool_name, risk in tool_classes.items():
            if tool_name in module_tools:
                state.risk_overrides[tool_name] = risk
        state.pending_module_specs.append(
            (
                source,
                [
                    ToolSpec(
                        name=tool_name,
                        fn=fn,
                        owner=manifest.name,
                        source=source,
                        risk_class=tool_classes.get(tool_name),
                    )
                    for tool_name, fn in module_tools.items()
                ],
            )
        )

    def _resolve_response_format(
        self,
        module_dir: Path,
        manifest: AgentModuleManifest,
        source: str,
        problems: list[LoadProblem],
    ) -> type[BaseModel] | None:
        """Import the AD-3 ``result`` class from ``tools/result.py`` (arch §8.3)."""
        if manifest.result is None:
            return None
        result_spec = parse_result_spec(manifest.result)
        result_path = module_dir / "tools" / "result.py"
        unique_name = _unique_module_name(module_dir.name, "result")
        module, problem = _import_python_file(result_path, unique_name)
        if problem is not None or module is None:
            problems.append(LoadProblem(source, f"result.py: {problem}"))
            return None
        candidate = getattr(module, result_spec.class_name, None)
        if not isinstance(candidate, type) or not issubclass(candidate, BaseModel):
            problems.append(
                LoadProblem(
                    source,
                    f"result class {result_spec.class_name!r} is not found in "
                    f"{result_path} or is not a pydantic BaseModel subclass (AD-3)",
                )
            )
            return None
        return candidate

    def _resolve_risks(
        self,
        platform_tools: dict[str, ModuleTool],
        module_tools: dict[str, ModuleTool],
        state: _LoadState,
    ) -> dict[str, RiskClass]:
        """Resolve ``tool_name → risk class`` for one subagent toolset (AD-7).

        Resolution order: the manifest ``tool_classes`` override, the tool's
        own ``swarmy_risk_class`` attribute, then the ownership-aware default
        (F-3, SECURITY.md ASI02): a module-owned tool whose author forgot the
        declaration defaults to the **most gated** class (``destructive``) so
        the forgotten declaration fails toward operator approval under every
        strictness profile — never toward silent execution; the platform's
        own tools all declare (AD-7) and keep the passive fallback for
        non-gating readers.
        """
        toolset: dict[str, ModuleTool] = {**platform_tools, **module_tools}
        risks: dict[str, RiskClass] = {}
        for tool_name, fn in toolset.items():
            entry_risk: RiskClass | None = state.risk_overrides.get(tool_name)
            declared = declared_risk_class(fn)[0]
            default = RiskClass.PASSIVE if tool_name in platform_tools else RiskClass.DESTRUCTIVE
            risks[tool_name] = (
                entry_risk
                if entry_risk is not None
                else (declared if declared is not None else default)
            )
        return risks

    def _check_manifest_gates(
        self,
        manifest: AgentModuleManifest,
        risks: dict[str, RiskClass],
        source: str,
        problems: list[LoadProblem],
    ) -> None:
        """Enforce operator primacy on the manifest ``interrupt_on`` map (F-4).

        The strictness profile's gates are the **operator's** control
        (SECURITY.md ASI02/ASI09): a module manifest may ADD a gate (``True``
        for a tool the profile leaves passive) but never REMOVE one — a
        ``False`` entry for a profile-gated tool would let the module author
        un-gate its own destructive/verify/network-write calls under
        ``paranoid``, so it fails the load (fail-fast, arch §8.3/§16.9). An
        entry naming a tool outside this subagent's toolset also fails: no
        silent no-ops on the HITL contour. Updates arch §7.1 (the former
        "module entries win" merge) in the same change.
        """
        gates = _PROFILE_GATES[self._strictness]
        for tool_name, wants_gate in manifest.interrupt_on.items():
            if tool_name not in risks:
                problems.append(
                    LoadProblem(
                        source,
                        f"manifest interrupt_on names {tool_name!r}, which is not a tool "
                        "of this module's toolset (platform or module tools)",
                    )
                )
            elif not wants_gate and risks[tool_name] in gates:
                problems.append(
                    LoadProblem(
                        source,
                        f"manifest interrupt_on removes the operator gate for {tool_name!r} "
                        f"(risk class {risks[tool_name].value!r} is gated by the "
                        f"{self._strictness!r} profile); a module may only add gates, "
                        "never remove them (SECURITY.md ASI02/ASI09)",
                    )
                )

    def _build_subagent(
        self,
        manifest: AgentModuleManifest,
        system_prompt: str,
        platform_tools: dict[str, ModuleTool],
        module_tools: dict[str, ModuleTool],
        guardrails: ModuleGuardrails | None,
        response_format: type[BaseModel] | None,
        risks: dict[str, RiskClass],
        *,
        skills: Sequence[str],
    ) -> dict[str, object]:
        """Assemble the ``SubAgent`` dict with exactly the arch §8.3 keys.

        Shared by loaded modules (``skills`` is their module-skills route) and
        the virtual generalist (``skills=[]``, no module directory).
        """
        gates = _PROFILE_GATES[self._strictness]
        toolset: dict[str, ModuleTool] = {**platform_tools, **module_tools}
        interrupt_on: dict[str, bool] = {
            tool_name: risks[tool_name] in gates for tool_name in toolset
        }
        # F-4 (operator primacy): the manifest may only ADD gates — entries
        # for profile-gated tools were validated in ``_check_manifest_gates``
        # (a manifest ``False`` there fails the load), so what merges here is
        # either a gate addition (passive tool → gated) or a no-op refinement
        # of a tool the profile does not gate. Platform-set gates win.
        for tool_name, wants_gate in manifest.interrupt_on.items():
            interrupt_on[tool_name] = wants_gate
        # One projector per subagent: the session wiring (T3.1.1) supplies
        # config budgets + operator secrets via the factory; the conservative
        # §6.8 default stays the fallback for platform-less loading, shared
        # by the pipeline's GuardrailBlocked digests (RD-4) and the
        # post-tool-call result projection (arch §6.8, T2.3.2).
        projector = (
            self._projector_factory(manifest.name)
            if self._projector_factory is not None
            else ContextProjector()
        )
        pipeline = GuardrailPipeline(
            module_guardrails=guardrails,
            projector=projector,
            engine_rules_enabled=self._engine_rules_enabled,
            judge_band=(
                self._judge_band_factory(risks) if self._judge_band_factory is not None else None
            ),
        )
        # Module skills (arch §8.6): the on-disk directory is mounted by the
        # Engine under a read-only composite route; the L0 source is that
        # virtual path — the default ``StateBackend`` cannot read disk paths.
        subagent: dict[str, object] = {
            "name": manifest.name,  # ← arch §8.3
            "description": manifest.description,
            "system_prompt": system_prompt,
            "mode": manifest.mode,
            "tools": list(toolset.values()),  # platform + module tools (arch §6.1)
            # The session projector also sanitizes the deny feedback inside
            # GuardrailMiddleware (the deny bypasses the inner projector,
            # Issue #39); the tool-class map applies the §6.8 budgets to
            # HTTP tool envelopes (Issue #58 ↔ F-6).
            "middleware": [
                GuardrailMiddleware(pipeline, projector=projector),
                ProjectorMiddleware(projector, tool_classes=PLATFORM_TOOL_BUDGET_CLASSES),
                # Innermost: recoverable tool-body failures reach the model
                # as error feedback instead of aborting the run (see
                # swarmy.tools.errors).
                ToolErrorFeedbackMiddleware(),
            ],
            "interrupt_on": interrupt_on,
            "skills": list(skills),
            "response_format": response_format,
        }
        if manifest.model is not None:
            # ``model`` is NotRequired in the L0 SubAgent dict: an absent key
            # inherits the orchestrator's model; an explicit None would break
            # that inheritance (deepagents subagents.py ``spec.get("model",
            # model)`` semantics — a present None is NOT the default).
            subagent["model"] = manifest.model
        return subagent


__all__ = [
    "MODULE_SKILLS_ROUTE_PREFIX",
    "PLATFORM_TOOL_BUDGET_CLASSES",
    "LoadProblem",
    "ModuleLoader",
    "ModuleTool",
    "PlatformToolset",
    "PlatformToolsetFactory",
    "StrictnessProfile",
    "builtin_agents_root",
    "module_skills_route",
    "scan_skill_scripts",
    "skills_route_name_problem",
]
