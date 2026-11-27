"""``ModuleRegistry``: loaded modules, virtual agents, event cross-check (arch §8.4, T1.5.4).

The registry maps the subagent name to its record — a :class:`LoadedModule`
loaded from a module directory, or a :class:`VirtualAgent` defined by the
platform in code (the ``generalist``, arch §8.8). Both carry the assembled
``SubAgent`` dict (arch §8.3) and obey the same §8.4 event contract:

* a manifest ``events`` entry that is **not registered** in the
  ``EventRegistry`` (neither a v0.1 built-in type nor a type the module's
  ``tools/event_models.py`` added at load time) is a *load error*;
* at runtime, emitting an event type **not declared** in the manifest is a
  tool error addressed to the agent — enforced by the ``allowed_types``
  binding of :func:`~swarmy.events.emit.make_emit_tool` which the session
  wiring feeds with ``manifest.events`` (junction with T1.3.4).

``modules()`` stays the on-disk module roster (the skills composite is built
from it); ``names()``/``subagent_dicts()``/``__len__``/``__contains__`` cover
modules **and** virtual agents, so the orchestrator roster and the L0
``subagents`` list see one delegation surface.

:class:`ModuleLoadError` is the aggregated fail-fast report of the module
loading pipeline (arch §8.3): every problem of every module, one error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from swarmy.events.models import EVENT_TYPES

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from swarmy.guardrails.models import ModuleGuardrails
    from swarmy.modules.manifest import AgentModuleManifest


class ModuleLoadError(Exception):
    """Aggregated fail-fast error over all loaded modules (arch §8.3).

    Carries *every* problem collected across *all* module directories — a
    problem in one module must not stop collecting the problems of the
    others (spec §4.5). ``str(exception)`` renders the full report.
    """

    def __init__(self, problems: Sequence[str]) -> None:
        """Build the error from the collected problems (never empty)."""
        lines = "\n".join(f"  - {problem}" for problem in problems)
        super().__init__(f"module loading failed, {len(problems)} problem(s):\n{lines}")
        self.problems: tuple[str, ...] = tuple(problems)


@dataclass(frozen=True)
class LoadedModule:
    """One loaded subagent module (arch §8.3): the loader's output record.

    ``source`` is ``"builtin"`` or ``"module:<dir>"`` (arch §6.1); ``tools``
    are the module's *own* tool functions (platform tools live in the
    ``SubAgent`` dict's ``tools`` list); ``subagent`` is the L0 ``SubAgent``
    dict handed to ``create_deep_agent(subagents=...)``.
    """

    manifest: AgentModuleManifest
    system_prompt: str
    path: Path
    source: str
    tools: dict[str, Callable[..., object]]
    guardrails: ModuleGuardrails | None
    subagent: dict[str, object]


@dataclass(frozen=True)
class VirtualAgent:
    """A platform-defined subagent with no module directory (arch §8.8).

    The ``generalist`` is the virtual agent: its manifest and system prompt are
    code constants, not an ``AGENT.md``; it has no ``tools/``, ``skills/`` or
    ``guardrails.yaml`` of its own (its toolset is the platform set assembled by
    the loader). The ``SubAgent`` dict is the same L0 shape a loaded module
    produces, so the orchestrator delegates to it through the ordinary
    ``task()`` surface.
    """

    manifest: AgentModuleManifest
    system_prompt: str
    subagent: dict[str, object]


class ModuleRegistry:
    """Registry of loaded modules and platform virtual agents (arch §8.4/§8.8).

    ``register``/``register_virtual`` re-check the §8.4 event contract
    independently of the loader (defence in depth): declared-but-unregistered
    event types are a load error, as are duplicate subagent names — a module
    cannot shadow a virtual agent and vice versa.
    """

    __slots__ = ("_modules", "_virtual")

    def __init__(self) -> None:
        """Create an empty registry."""
        self._modules: dict[str, LoadedModule] = {}
        self._virtual: dict[str, VirtualAgent] = {}

    @staticmethod
    def _event_problems(manifest: AgentModuleManifest, subject: str) -> list[str]:
        """The §8.4 cross-check of one manifest's ``events`` declaration."""
        return [
            f"{subject}: declared event type {event!r} is not registered "
            "in the EventRegistry (arch §8.4)"
            for event in manifest.events
            if event not in EVENT_TYPES
        ]

    def register(self, module: LoadedModule) -> None:
        """Add one loaded module after the §8.4 cross-checks.

        Raises:
            ModuleLoadError: when the name is already registered (as a module
                or a platform virtual agent) or any manifest ``events`` entry
                is missing from the ``EventRegistry`` (arch §8.4: declared =
                registered).
        """
        problems: list[str] = []
        name = module.manifest.name
        if name in self._modules:
            problems.append(
                f"duplicate module name {name!r} (already loaded from {self._modules[name].path})"
            )
        if name in self._virtual:
            problems.append(
                f"duplicate subagent name {name!r} (already provided by the "
                "platform virtual agent of the same name)"
            )
        problems.extend(self._event_problems(module.manifest, f"module {name!r}"))
        if problems:
            raise ModuleLoadError(problems)
        self._modules[name] = module

    def register_virtual(self, agent: VirtualAgent) -> None:
        """Add one platform virtual agent after the same cross-checks (arch §8.8).

        Raises:
            ModuleLoadError: when the name is already registered (as a module
                or another virtual agent) or a declared event type is missing
                from the ``EventRegistry`` (arch §8.4).
        """
        problems: list[str] = []
        name = agent.manifest.name
        if name in self._modules:
            problems.append(
                f"duplicate subagent name {name!r} (already loaded from "
                f"{self._modules[name].path}); the platform virtual agent cannot "
                "be overridden"
            )
        if name in self._virtual:
            problems.append(f"duplicate virtual agent name {name!r}")
        problems.extend(self._event_problems(agent.manifest, f"virtual agent {name!r}"))
        if problems:
            raise ModuleLoadError(problems)
        self._virtual[name] = agent

    def get(self, name: str) -> LoadedModule:
        """Return the loaded module ``name`` (virtual agents are not modules).

        Raises:
            KeyError: naming the unknown module and the loaded names.
        """
        try:
            return self._modules[name]
        except KeyError:
            known = ", ".join(sorted(self._modules))
            msg = f"unknown module {name!r}; loaded modules: {known}"
            raise KeyError(msg) from None

    def virtual(self, name: str) -> VirtualAgent:
        """Return the platform virtual agent ``name`` (arch §8.8).

        Raises:
            KeyError: naming the unknown agent and the registered virtual names.
        """
        try:
            return self._virtual[name]
        except KeyError:
            known = ", ".join(sorted(self._virtual))
            msg = f"unknown virtual agent {name!r}; registered virtual agents: {known}"
            raise KeyError(msg) from None

    def names(self) -> tuple[str, ...]:
        """All subagent names (modules + virtual agents), sorted."""
        return tuple(sorted({*self._modules, *self._virtual}))

    def modules(self) -> tuple[LoadedModule, ...]:
        """All loaded modules (on-disk roster only), ordered by name."""
        return tuple(self._modules[name] for name in sorted(self._modules))

    def virtual_agents(self) -> tuple[VirtualAgent, ...]:
        """All platform virtual agents, ordered by name."""
        return tuple(self._virtual[name] for name in sorted(self._virtual))

    def descriptions(self) -> dict[str, str]:
        """All subagent names → manifest descriptions (modules + virtual agents)."""
        return {
            **{module.manifest.name: module.manifest.description for module in self.modules()},
            **{
                agent.manifest.name: agent.manifest.description
                for agent in self.virtual_agents()
            },
        }

    def subagent_dicts(self) -> list[dict[str, object]]:
        """The assembled ``SubAgent`` dicts, for ``create_deep_agent(subagents=...)``.

        Modules and virtual agents in one name-sorted list — the single
        delegation surface handed to L0.
        """
        entries: list[tuple[str, dict[str, object]]] = [
            (module.manifest.name, module.subagent) for module in self.modules()
        ]
        entries.extend(
            (agent.manifest.name, agent.subagent) for agent in self.virtual_agents()
        )
        return [subagent for _, subagent in sorted(entries, key=lambda entry: entry[0])]

    def __contains__(self, name: object) -> bool:
        """``name in registry`` membership over every subagent name."""
        return name in self._modules or name in self._virtual

    def __len__(self) -> int:
        """Number of subagents (modules + virtual agents)."""
        return len(self._modules) + len(self._virtual)


__all__ = ["LoadedModule", "ModuleLoadError", "ModuleRegistry", "VirtualAgent"]
