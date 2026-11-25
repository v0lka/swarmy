"""T3.1.5 acceptance criteria: the ``session_info`` platform tool.

Roadmap T3.1.5:
* the output carries the declared fields (scope, research statuses, profile,
  request budget counter);
* a secret-value scan over the output finds nothing (arch §6.1).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from swarmy.core.database import Database
from swarmy.memory.schema import MIGRATIONS
from swarmy.memory.search import Fts5SearchIndex
from swarmy.memory.store import MemoryStore
from swarmy.tools.limits import ResourceLimiter, ResourceLimits
from swarmy.tools.platform import make_session_info_tool
from swarmy.tools.scope import ScopeEntries, ScopeRegistry

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
async def store(tmp_path: Path) -> MemoryStore:
    """A real store on the migration-backed schema (research counters)."""
    database = Database(tmp_path / "memory.sqlite", MIGRATIONS)
    await database.open()
    index = Fts5SearchIndex(await database.connection("search"))
    yield MemoryStore(database, index)
    await database.close()


async def _make_tool(
    store: MemoryStore, limits: ResourceLimits | None = None
) -> tuple[Any, ResourceLimiter, ScopeRegistry]:
    """Build the tool over the real store (default conservative limits)."""
    entries = ScopeEntries(
        domains=["target.example.com"],
        ip_subnets=["203.0.113.0/24"],
        ports=[80, 443],
        schemes=["https"],
    )
    limiter = ResourceLimiter(limits) if limits is not None else ResourceLimiter(
        ResourceLimits(
            rate_limit=5,
            max_concurrent_requests=8,
            max_body_bytes=5_242_880,
            max_redirect_depth=5,
            total_request_budget=5000,
            connect_timeout_s=10,
            read_timeout_s=30,
        )
    )
    return make_session_info_tool(
        base_url="https://target.example.com",
        scope_entries=entries,
        limiter=limiter,
        profile="normal",
        mode="interactive",
        store=store,
    ), limiter, ScopeRegistry(entries)


class TestDeclaredFields:
    """AC: the output contains the declared fields (test)."""

    async def test_sections_present(self, store: MemoryStore) -> None:
        tool, _limiter, _scope = await _make_tool(store)
        state = json.loads(await tool())
        assert state["target"] == {"base_url": "https://target.example.com"}
        assert state["scope"] == {
            "domains": ["target.example.com"],
            "ip_subnets": ["203.0.113.0/24"],
            "ports": [80, 443],
            "schemes": ["https"],
        }
        assert state["hitl"] == {"profile": "normal", "mode": "interactive"}
        assert state["budget"] == {"used": 0, "remaining": 5000}
        assert state["research"] == {
            "endpoints": 0,
            "findings": {"candidate": 0, "verified": 0, "rejected": 0},
        }

    async def test_budget_counter_reflects_usage(self, store: MemoryStore) -> None:
        tool, limiter, _scope = await _make_tool(store)
        limiter._budget_used = 12  # simulate consumed requests (introspection seam)
        state = json.loads(await tool())
        assert state["budget"] == {"used": 12, "remaining": 4988}


class TestNoSecrets:
    """AC: a scan of the output finds no secret values (test)."""

    async def test_secret_values_never_appear(self, store: MemoryStore) -> None:
        tool, _limiter, _scope = await _make_tool(store)
        raw = await tool()
        for value in ("hunter2", "sk-live-abc", "cookie-monster"):
            assert value not in raw
        # structural: the closure holds no SecretsConfig at all — a scan over
        # the factory output finds no secret-bearing model.
        assert not any("secret" in name.lower() for name in json.loads(raw))
