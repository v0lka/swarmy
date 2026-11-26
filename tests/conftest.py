"""Root conftest: assigns D22 suite markers by directory (arch §15.1).

`tests/unit/**` → marker `unit`, `tests/integration/**` → marker `integration`.
The coverage gates run the two suites as separate commands (Makefile / CI), so
the markers must be derivable from the file location without per-test decorators.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterable


def pytest_collection_modifyitems(items: Iterable[pytest.Item]) -> None:
    """Tag every collected test with its suite marker based on its path.

    The path is normalised to POSIX separators first: ``item.fspath`` is
    OS-native (``\\`` on Windows), and the CI matrix includes windows/amd64
    (arch §15.4) — a raw substring check would silently skip every test there.
    """
    for item in items:
        path = Path(str(item.fspath)).as_posix()
        if "/tests/unit/" in path:
            item.add_marker(pytest.mark.unit)
        elif "/tests/integration/" in path:
            item.add_marker(pytest.mark.integration)
