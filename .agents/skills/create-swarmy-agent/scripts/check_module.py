#!/usr/bin/env python
"""Load one swarmy module directory through the real ``ModuleLoader`` (dry run).

Usage (from the swarmy repository root, so the ``swarmy`` package is importable):

    uv run python .agents/skills/create-swarmy-agent/scripts/check_module.py agents/<module-name>
    uv run python .agents/skills/create-swarmy-agent/scripts/check_module.py path/to/<module-name>

A module inside the built-in ``agents/`` directory is loaded together with the
other built-ins (exactly what a session does). A module elsewhere is loaded
through its parent directory as a ``--agents-dir`` root, next to the built-ins,
so a name collision with a built-in is reported too (AD-4).

The platform toolset is a stub carrying the production platform tool names: the
loader validates the module contract (typing, docstrings, forbidden imports,
event declarations, ``applies_to``/``tool_classes`` cross-checks) but never
executes a tool here.

Exit codes: 0 — loads clean; 1 — ``ModuleLoadError`` (aggregated problem list
printed); 2 — usage or path problem.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

from swarmy.modules.loader import ModuleLoader, builtin_agents_root
from swarmy.modules.registry import ModuleLoadError
from swarmy.tools.registry import risk_class_of

if TYPE_CHECKING:
    from collections.abc import Callable

    from swarmy.modules.registry import LoadedModule

#: Platform tool names every production subagent receives (core/session.py
#: wiring); ``emit_event`` is added per module only when it declares events.
PLATFORM_TOOL_NAMES: Final[tuple[str, ...]] = (
    "http_get",
    "http_post",
    "http_put",
    "http_delete",
    "memory_search",
    "memory_get",
    "memory_upsert_endpoint",
    "memory_save_finding",
    "memory_link_attack_node",
    "memory_add_fact",
    "memory_add_note",
    "update_finding_status",
    "session_info",
)


def _stub_platform_toolset(
    module_name: str, declared_event_types: frozenset[str]
) -> dict[str, Callable[..., object]]:
    """Inert platform toolset with the production names (the loader reads names only)."""

    def stub(**kwargs: object) -> str:
        return "{}"

    toolset: dict[str, Callable[..., object]] = dict.fromkeys(PLATFORM_TOOL_NAMES, stub)
    if declared_event_types:
        toolset["emit_event"] = stub
    return toolset


def _user_root(module_dir: Path) -> Path | None:
    """The ``--agents-dir`` root of *module_dir*, or ``None`` when it is a built-in."""
    builtin = builtin_agents_root()
    if builtin is not None and module_dir.parent.resolve() == builtin.resolve():
        return None
    return module_dir.parent


def _describe(module: LoadedModule, profile: str) -> None:
    """Print the loaded shape: tools with risk classes, events, rules, gates."""
    print(f"OK: {module.manifest.name} (source: {module.source})")
    print(f"  path:        {module.path}")
    print(f"  description: {module.manifest.description}")
    own = ", ".join(
        f"{name}[{risk_class_of(fn).value}]" for name, fn in sorted(module.tools.items())
    )
    print(f"  own tools:   {own or '-'}")
    print(f"  events:      {', '.join(module.manifest.events) or '-'}")
    rules = (
        ", ".join(rule.id for rule in module.guardrails.rules)
        if module.guardrails is not None
        else "-"
    )
    print(f"  rules:       {rules}")
    gates = module.subagent.get("interrupt_on")
    gated = (
        ", ".join(sorted(name for name, on in gates.items() if on))
        if isinstance(gates, dict)
        else "-"
    )
    print(f"  gated ({profile}): {gated or '-'}")


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, load the module, print the result; return the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("module_dir", help="module directory (contains AGENT.md)")
    parser.add_argument(
        "--profile",
        choices=("paranoid", "normal", "yolo"),
        default="normal",
        help="HITL strictness profile for the gate preview (default: normal)",
    )
    args = parser.parse_args(argv)
    module_dir = Path(args.module_dir).resolve()
    if not (module_dir / "AGENT.md").is_file():
        print(f"error: {module_dir} is not a module directory (AGENT.md missing)", file=sys.stderr)
        return 2
    user_root = _user_root(module_dir)
    loader = ModuleLoader(
        user_dirs=[user_root] if user_root is not None else [],
        strictness=args.profile,
        platform_toolset_factory=_stub_platform_toolset,
    )
    try:
        registry = loader.load()
    except ModuleLoadError as exc:
        # The loader validates every module of every loaded root — exactly what a
        # session start does — so sibling problems can appear here too. Separate
        # the problems that name the requested module from the rest.
        needle = str(module_dir)
        own = [problem for problem in exc.problems if needle in problem]
        others = [problem for problem in exc.problems if needle not in problem]
        print(f"module loading failed, {len(exc.problems)} problem(s):")
        if own:
            print(f"problems naming the requested module ({module_dir}):")
            for problem in own:
                print(f"  - {problem}")
        if others:
            print(
                "problems of other modules in the loaded roots (a session start "
                "fails on them too; built-in tool problems carry the source "
                "'builtin' without a path):"
            )
            for problem in others:
                print(f"  - {problem}")
        if not own:
            print(
                f"note: no problem names {module_dir} — the requested module may be "
                "clean; fix the siblings or check it in an isolated root."
            )
        return 1
    loaded = [module for module in registry.modules() if module.path.resolve() == module_dir]
    if not loaded:  # pragma: no cover - a clean load always contains the requested dir
        print(f"error: {module_dir} was not loaded", file=sys.stderr)
        return 2
    _describe(loaded[0], args.profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
