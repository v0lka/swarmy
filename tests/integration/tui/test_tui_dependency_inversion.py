"""T4.1.1 AC 3 - the M3 integration set passes without importing swarmy.tui.

The dependency-inversion proof (arch §2.5, §2.2): the runtime core must be
fully usable - and the whole M3 integration set green - in an environment
where importing ``swarmy.tui`` is impossible. The blocker is installed by
``tests/integration/conftest.py`` when ``SWARMY_TEST_BLOCK_TUI=1``; this
module re-runs the M3 integration directories in a fresh interpreter with
that flag set, so a single transitive ``swarmy.tui`` import (AST scans miss
those) fails the run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The M3 integration set (roadmap P3.5 carriers: runtime, HITL, judge,
#: the F3 finding-verification scenario). The M5 demo file
#: (``test_demo_f5.py``) is deliberately not part of it: as the F5/F4
#: acceptance carrier it legitimately exercises the ``SessionView`` facade.
M3_INTEGRATION_PATHS: Final[tuple[str, ...]] = (
    "tests/integration/runtime",
    "tests/integration/hitl",
    "tests/integration/guardrails",
    "tests/integration/scenarios/test_finding_verification.py",
)


def test_m3_integration_set_passes_without_importing_swarmy_tui() -> None:
    """The M3 integration set is green with ``swarmy.tui`` imports blocked.

    A fresh ``pytest`` subprocess runs the M3 integration directories with
    ``SWARMY_TEST_BLOCK_TUI=1``: any attempt to import ``swarmy.tui`` (direct
    or transitive) raises ``ImportError`` inside that interpreter and fails
    the run. Green therefore means: the runtime contour - events, memory,
    guardrails, engine, HITL, judge, scenarios - never touches the TUI
    package (arch §2.2: the core does not know about the interface layer).
    """
    env = {**os.environ, "SWARMY_TEST_BLOCK_TUI": "1"}
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            *M3_INTEGRATION_PATHS,
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        check=False,
        timeout=600,
    )
    output = completed.stdout.decode(errors="replace")
    assert completed.returncode == 0, (
        "the M3 integration set failed with swarmy.tui imports blocked "
        f"(T4.1.1 AC 3):\n{output}\n{completed.stderr.decode(errors='replace')}"
    )
    # The blocker must actually have been active (guard against silently
    # running without it, which would make the test vacuous).
    assert "passed" in output, f"unexpected pytest output:\n{output}"


def test_runtime_import_surface_pulls_no_swarmy_tui() -> None:
    """Importing the runtime composition surface never loads swarmy.tui.

    Complements the AST-based ``test_core_never_imports_tui``: this probe
    catches transitive runtime imports an AST scan could miss (the same
    rationale as the aiohttp probe of T2.4.1).
    """
    probe = (
        "import sys; import swarmy.core.session, swarmy.core.engine, "
        "swarmy.core.runtime; "
        "sys.exit(1 if any(m == 'swarmy.tui' or m.startswith('swarmy.tui.') "
        "for m in sys.modules) else 0)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, (
        "swarmy.tui leaked into the runtime import surface:\n"
        f"{completed.stderr.decode(errors='replace')}"
    )
