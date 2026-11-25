"""CLI entry-point smoke (roadmap T1.1.2 + T1.1.4, spec criterion F0).

In-process integration check of the installed entry point: ``swarmy --help``
exits 0 and prints usage; ``swarmy --version`` exits 0 with the version line.
Complements the subprocess-based unit tests by pinning the exit-code contract
of :func:`swarmy.cli.main` as the smoke jobs (CI, Py3.15) rely on it.
"""

from __future__ import annotations

import pytest

from swarmy import __version__
from swarmy.cli import build_parser, main


def test_main_prints_help_and_returns_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No arguments -> usage on stdout, process exit code 0 (F0 criterion)."""
    assert main([]) == 0
    assert "usage: swarmy" in capsys.readouterr().out


def test_version_flag_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    """`--version` terminates argparse with exit code 0 and the version line."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"swarmy {__version__}"


def test_parser_prog_and_description() -> None:
    """The parser is built with the arch §3.4 prog name and description."""
    parser = build_parser()
    assert parser.prog == "swarmy"
    assert "authorized web-application penetration testing" in parser.description
