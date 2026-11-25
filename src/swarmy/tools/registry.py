"""``ToolRegistry``: names, risk classes, owners, collision fail-fast (arch §6.1, T1.5.1).

The registry is the session-global table ``name → ToolEntry{fn, risk_class,
owner, source}`` (arch §6.1):

* ``owner`` — ``"platform"`` or the owning module name;
* ``source`` — ``"builtin"`` or ``"module:<dir>"``;
* ``risk_class`` — the HITL gate class (arch §7.2, AD-7): read from the tool
  function's ``swarmy_risk_class`` attribute, defaulting to
  :attr:`RiskClass.PASSIVE`; a declarative ``tool_classes`` entry from the
  module's ``guardrails.yaml`` may override the attribute (the override is
  passed in explicitly by the loader, AD-7).

Fail-fast semantics (arch §6.1, spec §4.3): module tools may **not** use the
reserved platform prefixes ``memory_*`` / ``event_*`` / ``session_*`` (the
platform tools themselves keep those prefixes and stay available to every
subagent through the loader-built toolset), and duplicate names collide.
Every problem of a registration call is collected into one
:class:`ToolRegistryError` — the loader (T1.5.3) folds these into the
aggregated ``ModuleLoadError`` report.

The class never computes a risk class from argument content — only from
declarations (AD-7: deterministic approval gates).
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Final, NamedTuple

from swarmy.guardrails.models import RiskClass

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

#: Reserved prefixes of platform tool names (arch §6.1, spec §4.3).
#: Module-owned tools must not use them; platform tools legitimately do.
RESERVED_TOOL_PREFIXES: Final[tuple[str, ...]] = ("memory_", "event_", "session_")

#: Owner value of platform tools (arch §6.1) — every non-platform owner is a
#: module name.
PLATFORM_OWNER: Final[str] = "platform"

#: Source value of built-in tools (arch §6.1) — module tools use
#: ``"module:<dir>"``.
BUILTIN_SOURCE: Final[str] = "builtin"

#: Sentinel for an absent ``swarmy_risk_class`` attribute.
_MISSING = object()


class ToolRegistryError(Exception):
    """Raised when a registration has at least one problem (arch §6.1).

    Carries *all* problems of the call — duplicate names and prefix
    violations are reported together (fail-fast aggregated list, spec §4.3).
    """

    def __init__(self, problems: Sequence[str]) -> None:
        """Build the error from the collected problems (never empty)."""
        lines = "\n".join(f"  - {problem}" for problem in problems)
        super().__init__(f"tool registration rejected, {len(problems)} problem(s):\n{lines}")
        self.problems: tuple[str, ...] = tuple(problems)


class ToolSpec(NamedTuple):
    """One tool offered for registration (arch §6.1).

    ``risk_class`` is an explicit override (e.g. the module's
    ``guardrails.yaml`` ``tool_classes`` entry); ``None`` resolves the class
    from the function's ``swarmy_risk_class`` attribute (AD-7).
    """

    name: str
    fn: Callable[..., object]
    owner: str  # "platform" or the module name (arch §6.1)
    source: str  # "builtin" or "module:<dir>" (arch §6.1)
    risk_class: RiskClass | None = None


class ToolEntry(NamedTuple):
    """One registered tool: the registry's ``name → entry`` row (arch §6.1)."""

    fn: Callable[..., object]
    risk_class: RiskClass
    owner: str
    source: str


def declared_risk_class(fn: Callable[..., object]) -> tuple[RiskClass | None, str | None]:
    """Read the tool's ``swarmy_risk_class`` attribute (AD-7).

    Returns:
        ``(risk_class, problem)``: the declared class with ``None`` problem,
        or ``(None, problem)`` when the attribute is absent (caller applies
        the ``passive`` default) or holds an invalid value.

    """
    value = getattr(fn, "swarmy_risk_class", _MISSING)
    if value is _MISSING:
        return None, None
    if isinstance(value, RiskClass):
        return value, None
    if isinstance(value, str):
        try:
            return RiskClass(value), None
        except ValueError:
            allowed = [item.value for item in RiskClass]
            return None, (
                f"invalid swarmy_risk_class attribute {value!r}; allowed: {allowed} (AD-7)"
            )
    allowed = [item.value for item in RiskClass]
    return None, (
        f"swarmy_risk_class attribute must be a RiskClass or its string value, "
        f"got {type(value).__name__}; allowed: {allowed} (AD-7)"
    )


def risk_class_of(fn: Callable[..., object]) -> RiskClass:
    """Resolve the risk class of a tool function (AD-7).

    The declared ``swarmy_risk_class`` attribute wins; a missing attribute
    defaults to :attr:`RiskClass.PASSIVE` (arch §6.1).

    Raises:
        ToolRegistryError: when the attribute holds an invalid value.
    """
    risk, problem = declared_risk_class(fn)
    if problem is not None:
        raise ToolRegistryError([problem])
    return risk if risk is not None else RiskClass.PASSIVE


class ToolRegistry:
    """Session-global ``name → ToolEntry`` table (arch §6.1).

    Registration is validated as one aggregated batch: every duplicate-name
    and reserved-prefix problem of the call is reported together
    (:class:`ToolRegistryError`), matching the fail-fast report style of the
    rest of the session start (arch §4.5, §8.3).
    """

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        """Create an empty registry."""
        self._entries: dict[str, ToolEntry] = {}

    def register(self, spec: ToolSpec) -> None:
        """Validate and insert one tool (aggregated over its problems).

        Raises:
            ToolRegistryError: with every problem of ``spec`` (duplicate
                name, reserved prefix, invalid risk declaration).
        """
        self.register_many((spec,))

    def register_many(self, specs: Sequence[ToolSpec]) -> None:
        """Validate and insert a batch of tools (arch §6.1 fail-fast).

        Every problem is collected before anything is inserted: a batch with
        at least one problem leaves the registry untouched and raises one
        :class:`ToolRegistryError` listing all problems (duplicates within
        the batch, duplicates against existing entries, reserved prefixes of
        module-owned tools, invalid risk declarations).

        Raises:
            ToolRegistryError: when any spec has a problem.
        """
        problems: list[str] = []
        resolved: list[ToolEntry] = []
        batch_names: set[str] = set()
        for spec in specs:
            if spec.owner != PLATFORM_OWNER:
                for prefix in RESERVED_TOOL_PREFIXES:
                    if spec.name.startswith(prefix):
                        problems.append(
                            f"tool name {spec.name!r} uses the reserved platform prefix "
                            f"{prefix!r} (arch §6.1, spec §4.3)"
                        )
            if spec.name in self._entries:
                owner = self._entries[spec.name].owner
                problems.append(
                    f"duplicate tool name {spec.name!r} (already registered by owner {owner!r})"
                )
            elif spec.name in batch_names:
                problems.append(f"duplicate tool name {spec.name!r} within the batch")
            batch_names.add(spec.name)
            risk, problem = (
                (spec.risk_class, None) if spec.risk_class is not None else declared_risk_class(spec.fn)
            )
            if problem is not None:
                problems.append(f"tool {spec.name!r}: {problem}")
            resolved.append(
                ToolEntry(
                    fn=spec.fn,
                    risk_class=risk if risk is not None else RiskClass.PASSIVE,
                    owner=spec.owner,
                    source=spec.source,
                )
            )
        if problems:
            raise ToolRegistryError(problems)
        for spec, entry in zip(specs, resolved, strict=True):
            self._entries[spec.name] = entry

    def entry(self, name: str) -> ToolEntry:
        """Return the entry registered under ``name``.

        Raises:
            KeyError: naming the unknown tool and the registered names.
        """
        try:
            return self._entries[name]
        except KeyError:
            known = ", ".join(sorted(self._entries))
            msg = f"unknown tool {name!r}; registered tools: {known}"
            raise KeyError(msg) from None

    def entries(self) -> Mapping[str, ToolEntry]:
        """Read-only view of the whole table (arch §6.1)."""
        return MappingProxyType(self._entries)

    def names(self) -> tuple[str, ...]:
        """All registered tool names, sorted."""
        return tuple(sorted(self._entries))

    def risk_classes(self) -> dict[str, RiskClass]:
        """Snapshot ``name → risk_class`` of the registered tools."""
        return {name: item.risk_class for name, item in self._entries.items()}

    def __contains__(self, name: object) -> bool:
        """``name in registry`` membership over registered tool names."""
        return name in self._entries

    def __len__(self) -> int:
        """Number of registered tools."""
        return len(self._entries)


__all__ = [
    "BUILTIN_SOURCE",
    "PLATFORM_OWNER",
    "RESERVED_TOOL_PREFIXES",
    "ToolEntry",
    "ToolRegistry",
    "ToolRegistryError",
    "ToolSpec",
    "declared_risk_class",
    "risk_class_of",
]
