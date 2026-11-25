"""``ModuleRegistry``: loaded modules, event-declaration cross-check (arch §8.4, T1.5.4).

The registry maps the module name to its :class:`LoadedModule` record — the
manifest, the imported tool functions and the assembled ``SubAgent`` dict
(arch §8.3) — and enforces the arch §8.4 event contract:

* a manifest ``events`` entry that is **not registered** in the
  ``EventRegistry`` (neither a v0.1 built-in type nor a type the module's
  ``tools/event_models.py`` added at load time) is a *load error*;
* at runtime, emitting an event type **not declared** in the manifest is a
  tool error addressed to the agent — enforced by the ``allowed_types``
  binding of :func:`~swarmy.events.emit.make_emit_tool` which the session
  wiring feeds with ``manifest.events`` (junction with T1.3.4).

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


class ModuleRegistry:
    """Registry of loaded modules: ``name → LoadedModule`` (arch §8.4).

    ``register`` re-checks the §8.4 event contract independently of the
    loader (defence in depth): declared-but-unregistered event types are a
    load error, as are duplicate module names.
    """

    __slots__ = ("_modules",)

    def __init__(self) -> None:
        """Create an empty registry."""
        self._modules: dict[str, LoadedModule] = {}

    def register(self, module: LoadedModule) -> None:
        """Add one loaded module after the §8.4 cross-checks.

        Raises:
            ModuleLoadError: when the module name is already registered or
                any manifest ``events`` entry is missing from the
                ``EventRegistry`` (arch §8.4: declared = registered).
        """
        problems: list[str] = []
        name = module.manifest.name
        if name in self._modules:
            problems.append(
                f"duplicate module name {name!r} (already loaded from {self._modules[name].path})"
            )
        for event in module.manifest.events:
            if event not in EVENT_TYPES:
                problems.append(
                    f"module {name!r}: declared event type {event!r} is not registered "
                    "in the EventRegistry (arch §8.4)"
                )
        if problems:
            raise ModuleLoadError(problems)
        self._modules[name] = module

    def get(self, name: str) -> LoadedModule:
        """Return the loaded module ``name``.

        Raises:
            KeyError: naming the unknown module and the loaded names.
        """
        try:
            return self._modules[name]
        except KeyError:
            known = ", ".join(sorted(self._modules))
            msg = f"unknown module {name!r}; loaded modules: {known}"
            raise KeyError(msg) from None

    def names(self) -> tuple[str, ...]:
        """All loaded module names, sorted."""
        return tuple(sorted(self._modules))

    def modules(self) -> tuple[LoadedModule, ...]:
        """All loaded modules, ordered by name."""
        return tuple(self._modules[name] for name in sorted(self._modules))

    def subagent_dicts(self) -> list[dict[str, object]]:
        """The assembled ``SubAgent`` dicts, for ``create_deep_agent(subagents=...)``."""
        return [module.subagent for module in self.modules()]

    def __contains__(self, name: object) -> bool:
        """``name in registry`` membership over loaded module names."""
        return name in self._modules

    def __len__(self) -> int:
        """Number of loaded modules."""
        return len(self._modules)


__all__ = ["LoadedModule", "ModuleLoadError", "ModuleRegistry"]
