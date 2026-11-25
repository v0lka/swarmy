"""``ModuleRegistry`` tests (roadmap T1.5.4, arch §8.4) + the T1.3.4 emit junction.

Acceptance criteria under test: a manifest event type that is declared but not
registered in the ``EventRegistry`` is a load error; emitting an event type not
declared in the manifest is a tool error addressed to the agent (enforced by
the ``allowed_types`` binding of ``make_emit_tool``, arch §8.4).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from swarmy.core.database import Database
from swarmy.events import (
    EmitEventTool,
    EventBus,
    EventSource,
    JournalReader,
    JournalWriter,
    make_emit_tool,
)
from swarmy.memory.schema import MIGRATIONS
from swarmy.modules.manifest import AgentModuleManifest
from swarmy.modules.registry import LoadedModule, ModuleLoadError, ModuleRegistry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    import aiosqlite


def _module(
    tmp_path: Path,
    name: str,
    *,
    events: list[str] | None = None,
) -> LoadedModule:
    """Build a ``LoadedModule`` record for registry-level tests."""
    path = tmp_path / name
    path.mkdir(parents=True, exist_ok=True)
    manifest = AgentModuleManifest(
        name=name,
        description=f"Module {name} under test.",
        events=events or [],
    )
    return LoadedModule(
        manifest=manifest,
        system_prompt=f"You are {name}.",
        path=path,
        source=f"module:{path}",
        tools={},
        guardrails=None,
        subagent={"name": name},
    )


def test_declared_but_unregistered_event_is_a_load_error(tmp_path: Path) -> None:
    """AC (T1.5.4): a declared-but-unregistered event type is a load error."""
    registry = ModuleRegistry()
    with pytest.raises(ModuleLoadError) as excinfo:
        registry.register(_module(tmp_path, "ghost", events=["NoSuchType"]))
    message = str(excinfo.value)
    assert "module 'ghost': declared event type 'NoSuchType' is not registered" in message
    assert "EventRegistry (arch §8.4)" in message
    assert len(registry) == 0  # nothing registered on failure


def test_declared_registered_event_passes(tmp_path: Path) -> None:
    """Declaring a built-in registered type (e.g. ``FindingCandidate``) loads."""
    registry = ModuleRegistry()
    module = _module(tmp_path, "clean", events=["FindingCandidate"])
    registry.register(module)
    assert "clean" in registry
    assert registry.get("clean") is module
    assert registry.names() == ("clean",)


def test_duplicate_module_name_is_rejected(tmp_path: Path) -> None:
    """Registering two modules under one name is a load error."""
    registry = ModuleRegistry()
    registry.register(_module(tmp_path, "dup"))
    with pytest.raises(ModuleLoadError, match="duplicate module name 'dup'") as excinfo:
        registry.register(_module(tmp_path, "dup"))
    assert f"already loaded from {tmp_path / 'dup'}" in str(excinfo.value)


def test_registry_lookups_and_aggregation(tmp_path: Path) -> None:
    """``get``/``names``/``modules``/``subagent_dicts`` behave over sorted names."""
    registry = ModuleRegistry()
    for name in ("beta", "alpha"):
        registry.register(_module(tmp_path, name))
    assert registry.names() == ("alpha", "beta")
    assert [m.manifest.name for m in registry.modules()] == ["alpha", "beta"]
    assert registry.subagent_dicts() == [{"name": "alpha"}, {"name": "beta"}]
    with pytest.raises(KeyError, match="unknown module 'nope'") as excinfo:
        registry.get("nope")
    assert "alpha, beta" in str(excinfo.value)


@pytest.fixture
async def emit_env(
    tmp_path: Path,
) -> AsyncIterator[tuple[EmitEventTool, JournalReader, EventBus]]:
    """Real database/journal/bus wired to a manifest-restricted emit tool."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn: aiosqlite.Connection = await db.connection("events")
    writer = JournalWriter(conn)
    reader = JournalReader(conn)
    bus = EventBus()
    # The session wiring binds allowed_types = manifest.events (arch §8.4, T1.5.4).
    emit = make_emit_tool(
        journal=writer,
        bus=bus,
        source=EventSource.MODULE,
        source_detail="dummy",
        allowed_types=frozenset({"FindingCandidate"}),
    )
    yield emit, reader, bus
    await bus.close()
    await db.close()


_CANDIDATE: dict[str, object] = {
    "finding_id": 1,
    "finding_type": "xss",
    "endpoint_ref": None,
    "evidence_refs": [],
}


async def test_emit_of_undeclared_type_is_a_tool_error(
    emit_env: tuple[EmitEventTool, JournalReader, EventBus],
) -> None:
    """AC (T1.5.4): emitting an undeclared type fails as a tool error, appends nothing."""
    emit, reader, _bus = emit_env
    with pytest.raises(ValueError, match="not declared in this agent's manifest") as excinfo:
        await emit("TargetSet", {"target_id": 1, "base_url": "http://example.com"})
    message = str(excinfo.value)
    assert "declared: FindingCandidate" in message
    assert "arch §8.4" in message
    assert (await reader.tail(5)) == []


async def test_emit_of_declared_type_is_accepted(
    emit_env: tuple[EmitEventTool, JournalReader, EventBus],
) -> None:
    """A declared type passes the manifest check and reaches the journal."""
    emit, reader, _bus = emit_env
    confirmation = await emit("FindingCandidate", _CANDIDATE)
    assert "FindingCandidate" in confirmation
    (tail,) = await reader.tail(1)
    assert tail.type == "FindingCandidate"
    assert tail.source_detail == "dummy"
    assert tail.source is EventSource.MODULE


async def test_without_allowed_types_the_whole_registry_is_emittable(tmp_path: Path) -> None:
    """``allowed_types=None`` (platform behaviour) accepts any registered type."""
    db = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await db.open()
    conn: aiosqlite.Connection = await db.connection("events")
    writer = JournalWriter(conn)
    reader = JournalReader(conn)
    bus = EventBus()
    emit = make_emit_tool(
        journal=writer,
        bus=bus,
        source=EventSource.PLATFORM,
        source_detail="platform",
    )
    confirmation = await emit("TargetSet", {"target_id": 1, "base_url": "http://example.com"})
    assert "TargetSet" in confirmation
    await asyncio.sleep(0)
    assert (await reader.tail(1))[0].type == "TargetSet"
    await bus.close()
    await db.close()
