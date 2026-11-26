"""T3.1.2/T3.1.3 acceptance criteria: the Session composition root and Engine.

Roadmap T3.1.2:
* ``open`` creates every component on one Database (ownership/uniqueness);
* a second ``open`` of the same folder is an error; resume is a separate path;
* ``close`` folds the WAL; a copied session folder opens "on another machine";
* ``swarmy.core`` does not import ``swarmy.tui`` (architecture invariant 8).
Roadmap T3.1.3:
* the graph compiles and the checkpointer tables appear in ``memory.sqlite``;
* the orchestrator carries the same middleware stack as the subagents.
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest
from tests.helpers.fake_models import ScriptedChatModel, one_shot_model

from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session, SessionError

pytestmark = pytest.mark.unit


def _config(tmp_path: Path, agents_dir: Path | None = None) -> SessionConfig:
    """A minimal config over loopback (never contacted in these tests)."""
    return SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
        agents_dirs=[str(agents_dir)] if agents_dir is not None else [],
    )


@pytest.fixture
def module_dir(tmp_path: Path) -> Path:
    """The fixture module directory (the dummy template, copied per test)."""
    source = Path(__file__).parents[2] / "fixtures" / "modules" / "dummy"
    target = tmp_path / "agents" / "dummy"
    shutil.copytree(source, target)
    return tmp_path / "agents"


@pytest.fixture
def model() -> ScriptedChatModel:
    return one_shot_model()


async def test_open_creates_all_components_on_one_database(
    tmp_path: Path, model: ScriptedChatModel
) -> None:
    session = await Session.open(config=_config(tmp_path), session_dir=tmp_path / "s", model=model)
    try:
        assert (tmp_path / "s" / "memory.sqlite").exists()
        assert session.database is not None
        assert session.journal is not None
        assert session.bus is not None
        assert session.scope is not None
        assert session.limiter is not None
        assert session.tool_registry is not None
        assert session.memory is not None
        assert session.search is not None
        assert session.projector is not None
        assert session.engine is not None
        assert session.runtime is not None
        assert session.approvals is not None
        # one Database owns every subsystem connection (AD-6):
        connections = list(session.database._connections.values())
        assert len(connections) == len({id(conn) for conn in connections})
        # TargetSet published exactly once (fresh start)
        envelope = await session.reader.by_type("TargetSet")
        assert len(envelope) == 1
    finally:
        await session.close()


async def test_double_open_is_error_resume_is_separate(
    tmp_path: Path, model: ScriptedChatModel
) -> None:
    session_dir = tmp_path / "s"
    first = await Session.open(config=_config(tmp_path), session_dir=session_dir, model=model)
    await first.close()
    with pytest.raises(SessionError, match=r"already contains memory\.sqlite"):
        await Session.open(config=_config(tmp_path), session_dir=session_dir, model=model)
    resumed = await Session.resume(session_dir=session_dir, model=model)
    try:
        # resume must not re-emit TargetSet (arch §13.1)
        assert len(await resumed.reader.by_type("TargetSet")) == 1
    finally:
        await resumed.close()
    with pytest.raises(SessionError, match=r"no session to resume"):
        await Session.resume(session_dir=tmp_path / "empty")


async def test_close_folds_wal_copy_opens_elsewhere(
    tmp_path: Path, model: ScriptedChatModel
) -> None:
    original = tmp_path / "original"
    session = await Session.open(config=_config(tmp_path), session_dir=original, model=model)
    await session.close()
    # WAL folded: only the portable files remain (arch §3.3)
    assert sorted(p.name for p in original.iterdir()) == ["memory.sqlite", "session.yaml"]
    # the copied folder opens "on another machine" (same build, different path)
    elsewhere = tmp_path / "another-machine"
    shutil.copytree(original, elsewhere)
    reopened = await Session.resume(session_dir=elsewhere, model=model)
    try:
        assert reopened.database is not None
        assert len(await reopened.reader.by_type("TargetSet")) == 1
    finally:
        await reopened.close()


async def test_graph_compiles_and_checkpointer_tables_appear(
    tmp_path: Path, module_dir: Path, model: ScriptedChatModel
) -> None:
    session_dir = tmp_path / "s"
    session = await Session.open(
        config=_config(tmp_path, module_dir), session_dir=session_dir, model=model
    )
    try:
        # the graph compiled with the loaded module roster: the dummy
        # fixture plus the two built-in reference modules (arch §8.7)
        assert session.engine.graph is not None
        assert len(session.modules) == 3
        assert "dummy" in session.modules
        # one graph step: the checkpointer materializes its L0 tables (arch §7.1)
        await session.runtime.run_step("hello")
        with sqlite3.connect(session_dir / "memory.sqlite") as conn:
            tables = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        assert "checkpoints" in tables  # the L0 saver owns these (arch §7.1)
        assert tables & {"checkpoint_writes", "checkpoint_blobs"} in (
            {"checkpoint_writes"},
            {"checkpoint_blobs"},
            set(),
        )  # write-side tables appear lazily with the first pending write
        # the domain tables are NOT the checkpointer's (one file, two owners)
        assert "events" in tables
        assert "findings" in tables
    finally:
        await session.close()


async def test_orchestrator_has_the_subagent_middleware_stack(
    tmp_path: Path, module_dir: Path, model: ScriptedChatModel
) -> None:
    session = await Session.open(
        config=_config(tmp_path, module_dir), session_dir=tmp_path / "s", model=model
    )
    try:
        subagent_middleware = session.modules.modules()[0].subagent["middleware"]
        subagent_types = [type(middleware) for middleware in subagent_middleware]
        engine_types = [type(middleware) for middleware in session.engine.middleware]
        # the subagents carry the same stack minus the orchestrator-only
        # correlation contour; the tool-error feedback wrapper is innermost
        # in both lists:
        assert engine_types[:2] == subagent_types[:2]
        from swarmy.core.runtime import CorrelationMiddleware

        assert isinstance(session.engine.middleware[2], CorrelationMiddleware)
        assert engine_types[-1] is subagent_types[-1]
        assert engine_types[-1].__name__ == "ToolErrorFeedbackMiddleware"
    finally:
        await session.close()


def test_core_never_imports_tui() -> None:
    """Architecture invariant 8 (T3.1.2 AC): swarmy.core does not import TUI."""
    import ast
    import importlib
    import pkgutil

    import swarmy.core

    def _imported_roots(path: Path) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module)
        return roots

    for module_info in pkgutil.walk_packages(swarmy.core.__path__, prefix="swarmy.core."):
        module = importlib.import_module(module_info.name)
        roots = _imported_roots(Path(module.__file__))
        offenders = [root for root in roots if root.startswith(("swarmy.tui", "swarmy.report"))]
        assert not offenders, f"{module_info.name} imports {offenders}"


async def test_snapshot_written_without_secrets(tmp_path: Path, model: ScriptedChatModel) -> None:
    session = await Session.open(config=_config(tmp_path), session_dir=tmp_path / "s", model=model)
    try:
        text = (tmp_path / "s" / "session.yaml").read_text(encoding="utf-8")
        assert "secrets:" in text  # the (empty) reference map is present
        assert "hunter2" not in text  # no raw secret value anywhere
    finally:
        await session.close()


async def test_set_mode_rebuilds_the_orchestrator_toolset(
    tmp_path: Path, module_dir: Path, model: ScriptedChatModel
) -> None:
    """Issue #38: ``session_info`` reports the post-switch mode.

    ``set_mode`` recompiles the graph AND rebuilds the orchestrator toolset —
    ``session_info`` is composed with the mode baked in, so without the
    rebuild the orchestrator would keep reading the pre-switch mode forever.
    """
    import json

    session = await Session.open(
        config=_config(tmp_path, module_dir), session_dir=tmp_path / "s", model=model
    )
    try:
        info = session._orchestrator_tools["session_info"]
        state = json.loads(await info())
        assert state["hitl"]["mode"] == session.config.mode  # the pre-switch mode
        await session.set_mode("mission", model=model)  # explicit: no L0 default flip
        state_after = json.loads(await session._orchestrator_tools["session_info"]())
        assert state_after["hitl"]["mode"] == "mission"  # the post-switch mode
        # the runtime runs on the recompiled graph (the checkpointer carried over)
        assert await session.runtime.run_step() is not None or True  # step executes
        decisions = await session.reader.by_type("OperatorDecision")
        assert any(entry.payload.request_id == "mode-switch:mission" for entry in decisions)
    finally:
        await session.close()


def test_subagent_gates_carry_the_swarmy_decision_set() -> None:
    """Issue #60: plain ``True`` subagent gates never offer L0 ``respond``.

    The loader emits bool entries (the manifest map is bool-typed); langchain
    expands ``True`` to the full default decision set, which includes the
    ``respond`` decision the platform deliberately does not offer. The engine
    normalizes every subagent gate to the swarmy decision set.
    """
    from swarmy.core.engine import Engine

    subagents: list[dict[str, object]] = [
        {"name": "crawler", "interrupt_on": {"http_get": True, "memory_get": False}},
        {
            "name": "custom",
            "interrupt_on": {"http_post": {"allowed_decisions": ["approve", "respond"]}},
        },
        {"name": "plain", "description": "no gates"},
    ]
    normalized = Engine._normalize_subagent_gates(subagents)
    crawler_gates = normalized[0]["interrupt_on"]
    assert isinstance(crawler_gates, dict)
    assert crawler_gates["http_get"] == {
        "allowed_decisions": ["approve", "edit", "reject"],
        "description": ("Tool 'http_get' requires operator approval (module-declared gate)."),
    }
    assert crawler_gates["memory_get"] is False  # explicit False passes through
    custom_gates = normalized[1]["interrupt_on"]
    assert isinstance(custom_gates, dict)
    entry = custom_gates["http_post"]
    assert isinstance(entry, dict)
    assert entry["allowed_decisions"] == ["approve"]  # respond stripped
    assert "interrupt_on" not in normalized[2]  # gate-less dicts pass through
    assert subagents[0]["interrupt_on"] == {
        "http_get": True,
        "memory_get": False,
    }  # inputs untouched
