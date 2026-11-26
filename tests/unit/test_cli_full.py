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


# ---------------------------------------------------------------------------
# #30: the CLI renders the closed set of typed start failures (exit 2, no UI).
# ---------------------------------------------------------------------------


def _write_minimal_config(path: Path) -> Path:
    path.write_text(
        "target:\n  base_url: 'https://target.example.com'\n",
        encoding="utf-8",
    )
    return path


def test_broken_module_report_not_traceback(
    tmp_path: Path,
    guard_ui: list[bool],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken module gives the aggregated loader report, exit 2, no UI."""
    from swarmy.modules.registry import ModuleLoadError

    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    _write_minimal_config(tmp_path / "session.yaml")
    monkeypatch.setattr(
        "swarmy.core.session.Session.open",
        _raise_on_open(ModuleLoadError(["  - module loading failed, 1 problem(s):\n  - boom"])),
    )
    code = cli.main(
        [str(tmp_path / "session.yaml"), "--agents-dir", str(agents_dir),
         "--session-dir", str(tmp_path / "s")]
    )
    assert code == 2
    assert guard_ui == []
    err = capsys.readouterr().err
    assert "session could not be opened" in err
    assert "module loading failed" in err


def test_resume_with_corrupt_secrets_is_rendered(
    tmp_path: Path,
    guard_ui: list[bool],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resume surfaces SecretsConfigError through the same fail-fast report (#30)."""
    from swarmy.core.config import SecretsConfigError

    _write_minimal_config(tmp_path / "session.yaml")
    monkeypatch.setattr(
        "swarmy.core.session.Session.resume",
        _raise_on_resume(SecretsConfigError(["secrets file x: not valid UTF-8: evil"])),
    )
    code = cli.main(["--resume", str(tmp_path)])
    assert code == 2
    assert guard_ui == []
    assert "session could not be resumed" in capsys.readouterr().err


def test_tool_registry_failure_is_rendered(
    tmp_path: Path,
    guard_ui: list[bool],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ToolRegistryError from session composition never escapes as a traceback."""
    from swarmy.tools.registry import ToolRegistryError

    _write_minimal_config(tmp_path / "session.yaml")
    monkeypatch.setattr(
        "swarmy.core.session.Session.open",
        _raise_on_open(ToolRegistryError(["duplicate tool name 'probe'"])),
    )
    code = cli.main(
        [str(tmp_path / "session.yaml"), "--session-dir", str(tmp_path / "s")]
    )
    assert code == 2
    assert guard_ui == []
    assert "duplicate tool name" in capsys.readouterr().err


def _raise_on_open(exc: Exception) -> object:
    """Build a ``Session.open`` stand-in raising the given start failure."""

    async def fake_open(**kwargs: object) -> object:
        raise exc

    return staticmethod(fake_open)


def _raise_on_resume(exc: Exception) -> object:
    """Build a ``Session.resume`` stand-in raising the given start failure."""

    async def fake_resume(**kwargs: object) -> object:
        raise exc

    return staticmethod(fake_resume)
