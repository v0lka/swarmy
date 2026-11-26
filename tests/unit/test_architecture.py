"""Architecture import-rule tests (arch §2.5, roadmap G6).

Enforced continuously from the first packages onward: every `*.py` under
`src/swarmy` is parsed with `ast` and checked against the dependency table of
architecture §2.5 — allowed/forbidden swarmy imports per package, the
`memory.models` leaf rule, and the ban on direct L0 (deepagents/LangChain)
imports outside `core` and the module loader. The rules are keyed by module
path prefixes, so they stay green as new modules appear and start failing the
moment a package violates a boundary.
"""

from __future__ import annotations

import ast
import importlib
import sys
from dataclasses import dataclass
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "swarmy"

# L0 harness roots (arch §2.1): only core/* and the module loader may touch them.
L0_ROOTS: frozenset[str] = frozenset({"deepagents", "langchain", "langgraph"})


@dataclass(frozen=True)
class Rule:
    """Import rule for one package boundary (arch §2.5 table row)."""

    # module names this rule applies to (exact or "prefix.*")
    matches: tuple[str, ...]
    # swarmy import prefixes explicitly forbidden for these modules
    forbidden_swarmy: tuple[str, ...] = ()
    # when not None — swarmy imports must match one of these prefixes (or be non-swarmy)
    allowed_swarmy: tuple[str, ...] | None = None
    # when True — direct L0 imports are a violation
    forbid_l0: bool = False
    comment: str = ""


RULES: tuple[Rule, ...] = (
    Rule(
        matches=("swarmy.memory.models",),
        allowed_swarmy=(),  # leaf: no swarmy imports at all
        comment="arch §2.5/§4.1: memory.models is the leaf — pydantic + stdlib only",
    ),
    Rule(
        matches=("swarmy.events.models",),
        allowed_swarmy=("swarmy.memory.",),
        forbid_l0=True,
        comment="arch §2.5: events.models may import memory.models only",
    ),
    Rule(
        matches=("swarmy.events.bus", "swarmy.events.journal", "swarmy.events.emit"),
        allowed_swarmy=("swarmy.events.", "swarmy.core.database"),
        forbid_l0=True,
        comment="arch §2.5: events.{bus,journal,emit} → events.models + core.database",
    ),
    Rule(
        matches=("swarmy.memory.store", "swarmy.memory.schema", "swarmy.memory.search"),
        allowed_swarmy=("swarmy.memory.", "swarmy.core.database"),
        forbid_l0=True,
        comment="arch §2.5: memory.{store,schema,search} → memory.models + core.database",
    ),
    Rule(
        matches=("swarmy.memory",),  # memory/__init__ re-exports; same boundary as the trio
        allowed_swarmy=("swarmy.memory.", "swarmy.core.database"),
        forbid_l0=True,
        comment="arch §2.5: the memory package never imports events/tools/tui",
    ),
    Rule(
        matches=("swarmy.tools",),
        forbidden_swarmy=("swarmy.core.", "swarmy.modules.", "swarmy.tui."),
        forbid_l0=True,
        comment="arch §2.5: tools.* → memory.models, events.*, guardrails.models",
    ),
    Rule(
        matches=("swarmy.guardrails.pipeline",),
        forbidden_swarmy=(
            "swarmy.memory.store",
            "swarmy.memory.schema",
            "swarmy.memory.search",
            "swarmy.tui.",
        ),
        forbid_l0=False,
        comment=(
            "arch §2.1 table + §6.5: pipeline.py is the package's single documented "
            "L0 wrapper (GuardrailMiddleware on the middleware extension point)"
        ),
    ),
    Rule(
        matches=("swarmy.guardrails",),
        forbidden_swarmy=(
            "swarmy.memory.store",
            "swarmy.memory.schema",
            "swarmy.memory.search",
            "swarmy.tui.",
        ),
        forbid_l0=True,
        comment="arch §2.5: guardrails may use memory models only (never the store)",
    ),
    Rule(
        matches=("swarmy.modules",),
        forbidden_swarmy=("swarmy.core.engine", "swarmy.tui."),
        comment="arch §2.5: modules.* must not import core.engine or the TUI",
    ),
    Rule(
        matches=("swarmy.core",),
        forbidden_swarmy=("swarmy.tui.", "swarmy.report."),
        comment="arch §2.5: core never imports the interface layer",
    ),
    Rule(
        matches=("swarmy.report",),
        forbidden_swarmy=("swarmy.core.", "swarmy.tools.", "swarmy.tui."),
        forbid_l0=True,
        comment="arch §2.5: report reads memory read-only, no core/tools/tui",
    ),
    Rule(
        matches=("swarmy.tui",),
        allowed_swarmy=(
            "swarmy.core.session",  # the SessionView facade subject (§10.2)
            "swarmy.events.models",  # envelopes + payload models (§10.2)
            "swarmy.memory.models",  # the leaf: domain records for rendering
        ),
        forbid_l0=True,
        comment=(
            "arch §2.5/§10.2 + roadmap T4.1.1: tui reads only through the "
            "SessionView facade and events.models (+ the memory.models leaf); "
            "store/bus/runtime/engine internals and the L0 stack stay out"
        ),
    ),
    Rule(
        matches=("swarmy.cli",),
        forbid_l0=True,
        comment="arch §3.4/T1.1.2: CLI start must not pull the L0 stack",
    ),
)


def _module_name(path: Path) -> str:
    """Map a file under src/swarmy to its dotted module name."""
    rel = path.relative_to(SRC_ROOT)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1] or ["swarmy"]
    return ".".join(["swarmy", *parts[1:]] if parts[0] == "swarmy" else parts)


def _rule_for(module: str) -> Rule | None:
    """Find the first rule whose `matches` hit the module (exact or prefix)."""
    for rule in RULES:
        for pattern in rule.matches:
            if module == pattern or module.startswith(f"{pattern}."):
                return rule
    return None


def _iter_swarmy_sources() -> list[Path]:
    """All Python sources of the package (skips caches)."""
    return sorted(SRC_ROOT.rglob("*.py"))


def _imported_roots(tree: ast.Module, current_package: str) -> list[str]:
    """Dotted names of every imported module (absolute + resolved relative)."""
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                found.append(node.module)
            elif node.level > 0:
                # relative import: resolve against the current module's package
                prefix = current_package.split(".")
                up = node.level
                base = prefix[: len(prefix) - up] if up <= len(prefix) else []
                found.append(".".join([*base, node.module] if node.module else base))
    return found


@dataclass
class Violation:
    """One broken boundary, reported with file and rule comment."""

    file: Path
    module: str
    detail: str
    rule_comment: str = ""


def collect_violations() -> list[Violation]:
    """Parse every source file and return all import-rule violations."""
    violations: list[Violation] = []
    for path in _iter_swarmy_sources():
        module = _module_name(path)
        rule = _rule_for(module)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if rule is None:
            continue
        current_package = "swarmy" if module == "swarmy" else module.rpartition(".")[0]
        for name in _imported_roots(tree, current_package):
            top = name.split(".")[0]
            if top in L0_ROOTS and rule.forbid_l0:
                violations.append(
                    Violation(path, module, f"direct L0 import: {name}", rule.comment)
                )
                continue
            if not name.startswith("swarmy"):
                continue
            if any(name == f or name.startswith(f + ".") for f in rule.forbidden_swarmy):
                violations.append(
                    Violation(path, module, f"forbidden swarmy import: {name}", rule.comment)
                )
                continue
            if rule.allowed_swarmy is not None and not any(
                name == a or name.startswith(a) for a in rule.allowed_swarmy
            ):
                violations.append(
                    Violation(
                        path, module, f"swarmy import outside allowlist: {name}", rule.comment
                    )
                )
    return violations


def test_no_import_rule_violations() -> None:
    """Every swarmy module respects its arch §2.5 boundary."""
    violations = collect_violations()
    assert not violations, "\n".join(
        f"{v.file.name} [{v.module}]: {v.detail} ({v.rule_comment})" for v in violations
    )


def test_package_layout_matches_arch_3_1() -> None:
    """The canonical packages of arch §3.1 exist in the tree."""
    expected = [
        "core",
        "events",
        "memory",
        "tools",
        "guardrails",
        "modules",
        "report",
        "tui",
        "cli.py",
        "__main__.py",
        "__init__.py",
    ]
    for rel in expected:
        assert (SRC_ROOT / rel).exists(), f"missing canonical path: src/swarmy/{rel}"
    # Built-in modules live in the repository-root agents/ directory and ship
    # inside the wheel as swarmy/agents (arch §3.1/§8.7, D40).
    agents_root = SRC_ROOT.parent.parent / "agents"
    for module in ("crawler", "xss-detector"):
        assert (agents_root / module / "AGENT.md").is_file(), (
            f"missing built-in module: agents/{module}/AGENT.md"
        )


def test_tools_may_import_riskclass_without_cycle() -> None:
    """``tools.*`` can import ``RiskClass`` from guardrails.models, no cycle (AC T1.4.1).

    The proof is by fresh import under a ``sys.modules`` snapshot: importing
    ``swarmy.guardrails.models`` must load no other swarmy module (besides
    the two parent packages) and no L0 module at all — therefore an import
    from ``swarmy.tools.*`` cannot close a dependency cycle.
    """
    snapshot = {
        name: sys.modules[name]
        for name in sys.modules
        if name == "swarmy" or name.startswith("swarmy.") or name.split(".")[0] in L0_ROOTS
    }
    for name in [n for n in sys.modules if n == "swarmy" or n.startswith("swarmy.")]:
        del sys.modules[name]
    try:
        models = importlib.import_module("swarmy.guardrails.models")
        loaded_swarmy = sorted(
            name
            for name in sys.modules
            if (name == "swarmy" or name.startswith("swarmy."))
            and sys.modules.get(name) is not snapshot.get(name)
        )
        loaded_l0 = sorted(
            name
            for name in sys.modules
            if name.split(".")[0] in L0_ROOTS and sys.modules.get(name) is not snapshot.get(name)
        )
        assert models.RiskClass("verify") is models.RiskClass.VERIFY
        assert set(loaded_swarmy) == {"swarmy", "swarmy.guardrails", "swarmy.guardrails.models"}, (
            f"guardrails.models must be importable without the rest of swarmy, got {loaded_swarmy}"
        )
        assert not loaded_l0, (
            f"guardrails.models must stay free of the L0 stack, got {sorted(loaded_l0)}"
        )
    finally:
        # Restore the *original* module objects (not fresh re-imports): other
        # modules and already-collected test files hold references to the
        # classes defined in the snapshot modules, so re-importing by name
        # would create duplicate class objects (``isinstance`` false negatives,
        # monkeypatches landing on a module nobody uses).
        for name in [
            n
            for n in sys.modules
            if (n == "swarmy" or n.startswith("swarmy.")) and n not in snapshot
        ]:
            del sys.modules[name]
        for name, module in snapshot.items():
            sys.modules[name] = module
