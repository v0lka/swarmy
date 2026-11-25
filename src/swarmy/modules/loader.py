"""``ModuleLoader``: scan → import → validate → assemble SubAgent dicts (arch §8.3, T1.5.3).

The loader is the fail-fast front door of the module system (arch §8.3,
spec §4.5): it walks the built-in module package
(``importlib.resources(swarmy.agents)``) and the operator's user directories,
and for every module directory:

1. parses ``AGENT.md`` (frontmatter → :class:`AgentModuleManifest`, body →
   system prompt; T1.5.2);
2. imports every ``tools/*.py`` through
   ``importlib.util.spec_from_file_location`` — module code is never placed
   on ``sys.path`` (arch §8.3) and runs in-process (D4);
3. validates each exported tool function at runtime: full annotations via
   ``typing.get_type_hints`` (no ``Any`` / ``dict[str, Any]``, no unannotated
   parameter, no unannotated return) and a non-empty LLM-facing docstring
   (arch §8.5, spec §4.3);
4. statically scans the tool files' imports — ``socket``, ``urllib`` and
   ``http.client`` (and their submodules) are forbidden: the platform HTTP
   client is the only network path (arch §8.5, spec §4.3);
5. parses ``guardrails.yaml`` into :class:`ModuleGuardrails` (T1.4.2) and
   cross-checks its ``applies_to`` / ``tool_classes`` names against the
   real toolset of this session (platform + module tools);
6. registers the module's event payload models from
   ``tools/event_models.py`` into the ``EventRegistry`` (arch §8.4) and
   verifies that every manifest ``events`` entry is registered;
7. registers all module tools in the :class:`~swarmy.tools.registry.ToolRegistry`
   (RD-3) — reserved-prefix violations and name collisions are collected
   there;
8. resolves the AD-3 ``result`` reference to a Pydantic class and assembles
   the ``SubAgent`` dict with exactly the arch §8.3 keys, merging the
   strictness-profile gates with the manifest ``interrupt_on`` (arch §7.2).

Every problem of every module is collected into **one**
:class:`~swarmy.modules.registry.ModuleLoadError` — a problem in one module
never stops the collection for the others (spec §4.5); with no problems the
loader returns a populated :class:`~swarmy.modules.registry.ModuleRegistry`.

A user module whose name collides with a built-in module is a load error
without override (AD-4).
"""

from __future__ import annotations

import ast
import importlib.resources
import importlib.util
import inspect
import itertools
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
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
from swarmy.modules.manifest import (
    ManifestError,
    ParsedAgentModule,
    parse_agent_module,
    parse_result_spec,
)
from swarmy.modules.registry import LoadedModule, ModuleLoadError, ModuleRegistry
from swarmy.tools.projector import ContextProjector, ProjectorMiddleware
from swarmy.tools.registry import (
    BUILTIN_SOURCE,
    PLATFORM_OWNER,
    ToolRegistry,
    ToolRegistryError,
    ToolSpec,
    declared_risk_class,
)

if TYPE_CHECKING:
    from pathlib import Path

    from swarmy.guardrails.pipeline import JudgeBand
    from swarmy.modules.manifest import AgentModuleManifest

#: Strictness profiles (arch §7.2): the risk classes each profile gates with
#: HITL approvals. ``passive`` is never gated (paranoid gates the rest).
_PROFILE_GATES: Final[Mapping[str, frozenset[RiskClass]]] = {
    "paranoid": frozenset({RiskClass.NETWORK_WRITE, RiskClass.VERIFY, RiskClass.DESTRUCTIVE}),
    "normal": frozenset({RiskClass.VERIFY, RiskClass.DESTRUCTIVE}),
    "yolo": frozenset({RiskClass.DESTRUCTIVE}),
}

#: Modules that would open raw network paths — forbidden in module tool files
#: (arch §8.5: network is executed only by the platform HTTP client).
_FORBIDDEN_NETWORK_ROOTS: Final[tuple[str, ...]] = ("socket", "urllib", "http.client")

#: Files inside ``tools/`` that are not tool modules.
_SKIP_TOOL_FILES: Final[frozenset[str]] = frozenset(
    {"__init__.py", "event_models.py", "result.py"}
)

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
JudgeBandFactory: TypeAlias = Callable[
    [Mapping[str, RiskClass]], "JudgeBand"
]

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
    """Mutable state shared by the per-module load steps of one ``load()`` run."""

    tool_registry: ToolRegistry = field(default_factory=ToolRegistry)
    #: platform tool names are registered once from the first module's toolset
    platform_registered: bool = False


def _builtin_module_dirs(stack: ExitStack) -> list[Path]:
    """Directories of built-in modules (arch §8.3, §8.7).

    ``swarmy.agents`` is scanned via ``importlib.resources``; ``as_file`` keeps
    a real filesystem path alive for the whole load. An empty or missing
    package simply yields no built-ins.
    """
    try:
        traversable = importlib.resources.files("swarmy.agents")
    except ModuleNotFoundError:
        return []
    if not traversable.is_dir():
        return []
    root = stack.enter_context(importlib.resources.as_file(traversable))
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
                path for path in root_dir.iterdir() if path.is_dir() and (path / "AGENT.md").is_file()
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
    """Static import analysis of one tool file (arch §8.5).

    Any import of ``socket`` / ``urllib`` / ``http.client`` (including
    submodules, plain or ``from``-style) is a load problem: module tools reach
    the target only through the platform HTTP client.
    """
    problems: list[LoadProblem] = []

    def _check(module_name: str) -> None:
        if any(
            module_name == root or module_name.startswith(f"{root}.")
            for root in _FORBIDDEN_NETWORK_ROOTS
        ):
            problems.append(
                LoadProblem(
                    source,
                    f"{path.name} imports {module_name!r}: module tools must use the "
                    "platform HTTP client; socket/urllib/http.client are forbidden (arch §8.5)",
                )
            )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            _check(node.module)
    return problems


def _register_event_models(
    module: ModuleType, unique_name: str, source: str
) -> list[LoadProblem]:
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
            include_builtins: scan the installed ``swarmy.agents`` package for
                built-in modules (arch §8.3). ``False`` loads user modules
                only — the AD-4 "explicit choice without built-ins" escape
                hatch, used by tests and operators who want a bespoke roster.
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
            The populated :class:`ModuleRegistry` (each module carrying its
            assembled ``SubAgent`` dict).

        Raises:
            ModuleLoadError: with **all** problems of **all** modules when
                anything fails (fail-fast session start, spec §4.5).
        """
        problems: list[LoadProblem] = []
        loaded: list[LoadedModule] = []
        with ExitStack() as stack:
            builtin_dirs = (
                _builtin_module_dirs(stack) if self._include_builtins else []
            )
            user_dirs, scan_problems = _user_module_dirs(self._user_dirs)
            problems.extend(scan_problems)
            state = _LoadState(
                tool_registry=self._tool_registry
                if self._tool_registry is not None
                else ToolRegistry()
            )
            # name → (source, dir): collision detection incl. AD-4 (built-ins first)
            known_names: dict[str, tuple[str, str]] = {}
            plan: list[tuple[Path, str]] = [
                (path, BUILTIN_SOURCE) for path in builtin_dirs
            ] + [(path, f"module:{path}") for path in user_dirs]
            for module_dir, source in plan:
                module_problems, module_loaded = self._load_module(
                    module_dir, source, state, known_names
                )
                problems.extend(module_problems)
                if module_loaded is not None:
                    loaded.append(module_loaded)
        if problems:
            raise ModuleLoadError([str(problem) for problem in problems])
        registry = ModuleRegistry()
        for module in loaded:
            registry.register(module)
        return registry

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

        platform_tools = dict(
            self._platform_factory(name, frozenset(manifest.events))
        )
        self._register_platform_tools(platform_tools, state, problems)

        tools_dir = module_dir / "tools"
        module_tools = self._import_tools(tools_dir, source, problems)
        self._load_event_models(tools_dir, source, problems)
        self._check_declared_events(manifest, source, problems)
        guardrails = self._load_guardrails(module_dir, manifest, source, problems)
        if guardrails is not None:
            self._crosscheck_guardrails(guardrails, platform_tools, module_tools, source, problems)
        self._register_module_tools(manifest, source, module_tools, guardrails, state, problems)
        response_format = self._resolve_response_format(module_dir, manifest, source, problems)
        if problems:
            return problems, None
        subagent = self._build_subagent(
            module_dir, manifest, parsed, platform_tools, module_tools, guardrails,
            response_format, state,
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

    def _register_platform_tools(
        self, platform_tools: dict[str, ModuleTool], state: _LoadState, problems: list[LoadProblem]
    ) -> None:
        """Register the platform tool names once per load (arch §6.1).

        The per-module toolset instances differ (each ``emit_event`` is bound
        to its module); the registry records the name-level facts
        (owner ``"platform"``, source ``"builtin"``) from the first set.
        """
        if state.platform_registered:
            return
        state.platform_registered = True
        if not platform_tools:
            return
        try:
            state.tool_registry.register_many(
                [
                    ToolSpec(name=tool_name, fn=fn, owner=PLATFORM_OWNER, source=BUILTIN_SOURCE)
                    for tool_name, fn in platform_tools.items()
                ]
            )
        except ToolRegistryError as exc:
            problems.extend(LoadProblem("platform", problem) for problem in exc.problems)

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
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            except SyntaxError as exc:
                problems.append(LoadProblem(source, f"{py_file.name}: invalid syntax: {exc}"))
                continue
            problems.extend(_forbidden_import_problems(tree, py_file, source))
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
            return parse_module_guardrails(
                path.read_text(encoding="utf-8"), source=str(path)
            )
        except GuardrailsDslError as exc:
            problems.extend(
                LoadProblem(source, problem.message) for problem in exc.problems
            )
            return None

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

    def _register_module_tools(
        self,
        manifest: AgentModuleManifest,
        source: str,
        module_tools: dict[str, ModuleTool],
        guardrails: ModuleGuardrails | None,
        state: _LoadState,
        problems: list[LoadProblem],
    ) -> None:
        """Register the module's tools in the ToolRegistry (RD-3, arch §6.1).

        ``tool_classes`` from ``guardrails.yaml`` override the attribute risk
        class (AD-7 group marking); the registry aggregates prefix and
        collision problems.
        """
        if not module_tools:
            return
        tool_classes = guardrails.tool_classes if guardrails is not None else {}
        try:
            state.tool_registry.register_many(
                [
                    ToolSpec(
                        name=tool_name,
                        fn=fn,
                        owner=manifest.name,
                        source=source,
                        risk_class=tool_classes.get(tool_name),
                    )
                    for tool_name, fn in module_tools.items()
                ]
            )
        except ToolRegistryError as exc:
            problems.extend(LoadProblem(source, problem) for problem in exc.problems)

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

    def _build_subagent(
        self,
        module_dir: Path,
        manifest: AgentModuleManifest,
        parsed: ParsedAgentModule,
        platform_tools: dict[str, ModuleTool],
        module_tools: dict[str, ModuleTool],
        guardrails: ModuleGuardrails | None,
        response_format: type[BaseModel] | None,
        state: _LoadState,
    ) -> dict[str, object]:
        """Assemble the ``SubAgent`` dict with exactly the arch §8.3 keys."""
        gates = _PROFILE_GATES[self._strictness]
        toolset: dict[str, ModuleTool] = {**platform_tools, **module_tools}
        risks: dict[str, RiskClass] = {}
        for tool_name, fn in toolset.items():
            entry_risk: RiskClass | None = None
            if tool_name in state.tool_registry:  # registry holds the tool_classes override
                entry_risk = state.tool_registry.entry(tool_name).risk_class
            declared = declared_risk_class(fn)[0]  # AD-7 attribute, then passive default
            risks[tool_name] = (
                entry_risk
                if entry_risk is not None
                else (declared if declared is not None else RiskClass.PASSIVE)
            )
        interrupt_on: dict[str, bool] = {
            tool_name: risks[tool_name] in gates for tool_name in toolset
        }
        interrupt_on.update(manifest.interrupt_on)  # manifest merges on top (arch §7.2)
        skills_dir = module_dir / "skills"
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
        subagent: dict[str, object] = {
            "name": manifest.name,  # ← arch §8.3
            "description": manifest.description,
            "system_prompt": parsed.system_prompt,
            "mode": manifest.mode,
            "tools": list(toolset.values()),  # platform + module tools (arch §6.1)
            "middleware": [GuardrailMiddleware(pipeline), ProjectorMiddleware(projector)],
            "interrupt_on": interrupt_on,
            "skills": [str(skills_dir)] if skills_dir.is_dir() else [],
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
    "LoadProblem",
    "ModuleLoader",
    "ModuleTool",
    "PlatformToolset",
    "PlatformToolsetFactory",
    "StrictnessProfile",
]
