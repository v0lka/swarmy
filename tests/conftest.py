"""Root conftest: assigns D22 suite markers by directory (arch §15.1).

`tests/unit/**` → marker `unit`, `tests/integration/**` → marker `integration`.
The coverage gates run the two suites as separate commands (Makefile / CI), so
the markers must be derivable from the file location without per-test decorators.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterable


def pytest_collection_modifyitems(items: Iterable[pytest.Item]) -> None:
    """Tag every collected test with its suite marker based on its path."""
    for item in items:
        path = str(item.fspath)
        if "/tests/unit/" in path:
            item.add_marker(pytest.mark.unit)
        elif "/tests/integration/" in path:
            item.add_marker(pytest.mark.integration)
