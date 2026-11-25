"""CLI skeleton tests (roadmap T1.1.2): version output and the L0-import guard."""

import json
import subprocess
import sys

from swarmy import __version__


def test_version_flag() -> None:
    """`swarmy --version` reports the package version (F0 criterion)."""
    proc = subprocess.run(
        [sys.executable, "-m", "swarmy", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout.strip() == f"swarmy {__version__}"


def test_help_flag() -> None:
    """`swarmy --help` prints usage (F0 criterion)."""
    proc = subprocess.run(
        [sys.executable, "-m", "swarmy", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "usage: swarmy" in proc.stdout


def test_cli_does_not_import_l0_stack() -> None:
    """Guard (T1.1.2 AC): starting the CLI must not pull deepagents/LangChain in."""
    probe = (
        "import json, sys\n"
        "from swarmy.cli import main\n"
        "main([])\n"
        "roots = ('deepagents', 'langchain', 'langgraph')\n"
        "print(json.dumps(sorted(k for k in sys.modules if k.split('.')[0] in roots)))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=True,
    )
    imported_l0 = json.loads(proc.stdout.strip().splitlines()[-1])
    assert imported_l0 == [], f"CLI start imported L0 modules: {imported_l0}"
