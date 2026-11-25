"""T4.1.3 acceptance: CLI fail-fast behavior — config problems never open the UI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from swarmy import cli
from swarmy.tui.app import SwarmyTui

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


@pytest.fixture
def guard_ui(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Fail the test if the console would launch (config errors must not)."""
    launched: list[bool] = []

    async def fake_run_async(self: SwarmyTui, *args: object, **kwargs: object) -> None:
        launched.append(True)
        raise AssertionError("the UI must not open on a config error")

    monkeypatch.setattr(SwarmyTui, "run_async", fake_run_async)
    return launched


def _write_config(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_config_file_fails_fast(tmp_path: Path, guard_ui: list[bool]) -> None:
    """A missing config path exits 2 with a report; the UI never opens."""
    code = cli.main([str(tmp_path / "absent.yaml")])
    assert code == 2
    assert guard_ui == []


def test_invalid_config_field_fails_fast(tmp_path: Path, guard_ui: list[bool]) -> None:
    """Every validation problem is reported; exit 2 before any UI work."""
    config = _write_config(
        tmp_path / "bad.yaml",
        "target:\n  base_url: 'http://127.0.0.1:9/'\nprofile: reckless\n",
    )
    code = cli.main([str(config)])
    assert code == 2
    assert guard_ui == []


def test_resume_and_config_are_mutually_exclusive(tmp_path: Path) -> None:
    """`--resume` combined with a config path is a usage error (exit 2)."""
    code = cli.main(["--resume", str(tmp_path), str(tmp_path / "x.yaml")])
    assert code == 2


def test_unknown_session_dir_resume_fails_fast(tmp_path: Path, guard_ui: list[bool]) -> None:
    """Resuming an empty folder exits 2 (no memory.sqlite to open)."""
    code = cli.main(["--resume", str(tmp_path / "not-a-session")])
    assert code == 2
    assert guard_ui == []


def test_help_shows_the_full_session_syntax(capsys: pytest.CaptureFixture[str]) -> None:
    """`--help` documents every flag of arch §3.4."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in (
        "--agents-dir",
        "--profile",
        "--mode",
        "--model",
        "--session-dir",
        "--resume",
        "--version",
    ):
        assert flag in out, f"missing {flag} in --help"
