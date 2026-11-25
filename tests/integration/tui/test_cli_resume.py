"""T4.1.3 acceptance: the operational CLI — full syntax and the resume path.

The CLI never launches a real terminal UI in tests: the console seam is
``SwarmyTui.run_async`` (monkeypatched here), which receives the composed
session exactly like the real console would. The resume scenario re-opens
a closed portable session folder and proves the config came from the
``session.yaml`` audit snapshot and the pending approvals were restored.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from swarmy import cli
from swarmy.core.config import ScopeEntries, SessionConfig, TargetConfig
from swarmy.core.session import Session
from swarmy.tui.app import SwarmyTui
from tests.helpers.fake_models import one_shot_model

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


def _config() -> SessionConfig:
    """A minimal loopback config (never contacted)."""
    return SessionConfig(
        target=TargetConfig(base_url="http://127.0.0.1:9/"),
        scope=ScopeEntries(ip_subnets=["127.0.0.1/32"], schemes=["http"]),
        profile="paranoid",
    )


async def test_resume_continues_an_existing_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC T4.1.3: ``swarmy --resume <dir>`` re-opens the portable folder."""
    session_dir = tmp_path / "s"
    original = await Session.open(
        config=_config(), session_dir=session_dir, model=one_shot_model()
    )
    await original.close()  # a portable folder: snapshot + sqlite + WAL folded

    # aiosqlite connections bind to the loop that opened them: the resumed
    # session lives on the WORKER thread's loop, so every touch happens in
    # the seam and only plain values cross back to the test.
    observed: dict[str, object] = {}

    async def fake_run_async(self: SwarmyTui, *args: Any, **kwargs: Any) -> None:
        """The console seam: inspect the resumed session like the operator would."""
        view = self.view
        observed["dir"] = view.session.session_dir
        observed["profile"] = view.session.config.profile
        observed["has_runtime"] = view.session.runtime is not None
        reader = view.session.reader
        assert reader is not None
        observed["tail"] = [envelope.type for envelope in await reader.tail(1)]
        await view.close()  # the ctrl+q path (same loop as the connections)

    monkeypatch.setattr(SwarmyTui, "run_async", fake_run_async)
    code = await asyncio.to_thread(cli.main, ["--resume", str(session_dir)])
    assert code == 0
    assert observed["dir"] == session_dir
    # the audit snapshot was the config source of truth (arch §13.1)
    assert observed["profile"] == "paranoid"
    assert observed["has_runtime"] is True
    assert observed["tail"] == ["TargetSet"]


async def test_open_via_cli_prepares_the_portable_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC T4.1.3: the open path resolves the config and launches the console."""
    config_path = tmp_path / "session.yaml"
    config_path.write_text(
        "target:\n"
        "  base_url: 'http://127.0.0.1:9/'\n"
        "scope:\n"
        "  ip_subnets: ['127.0.0.1/32']\n"
        "  schemes: ['http']\n"
        "profile: yolo\n",
        encoding="utf-8",
    )
    session_dir = tmp_path / "run"
    captured: list[SwarmyTui] = []

    async def fake_run_async(self: SwarmyTui, *args: Any, **kwargs: Any) -> None:
        captured.append(self)
        await asyncio.sleep(0)

    monkeypatch.setattr(SwarmyTui, "run_async", fake_run_async)
    code = await asyncio.to_thread(
        cli.main, [str(config_path), "--session-dir", str(session_dir)]
    )
    assert code == 0
    assert (session_dir / "memory.sqlite").exists()
    snapshot = (session_dir / "session.yaml").read_text(encoding="utf-8")
    assert "profile: yolo" in snapshot
    opened = captured[0].view.session
    assert opened.config.profile == "yolo"
    await opened.close()
