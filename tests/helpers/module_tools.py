"""Loader-faithful import helper for built-in module tool files (arch §8.3).

Module directories (``crawler``, ``xss-detector``) are data folders, not
importable packages — the production loader imports their ``tools/*.py``
via ``importlib.util.spec_from_file_location`` under unique module names
(never ``sys.path``). Tests that exercise those tools directly reuse the
same mechanics through :func:`load_tool_file`, so the code under test is
byte-identical to what a session executes.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import swarmy

if TYPE_CHECKING:
    from types import ModuleType


def _agents_dir() -> Path:
    """The ``agents`` folder inside the installed swarmy package."""
    return Path(swarmy.__file__).resolve().parent / "agents"


#: Source directory of the built-in modules (installed/editable package).
AGENTS_DIR: Final[Path] = _agents_dir()


def load_tool_file(module_dir: str, file_stem: str) -> ModuleType:
    """Import one built-in module tool file exactly like the loader does.

    Args:
        module_dir: the module folder name (e.g. ``"xss-detector"``).
        file_stem: the tool file name without ``.py`` (e.g. ``"marker"``).

    Returns:
        The imported module (registered under a unique ``sys.modules`` name).
    """
    path = AGENTS_DIR / module_dir / "tools" / f"{file_stem}.py"
    unique_name = f"_swarmy_test_{module_dir.replace('-', '_')}_{file_stem}"
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - importlib contract
        msg = f"cannot build import spec for {path}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module  # documented importlib pattern
    spec.loader.exec_module(module)
    return module


__all__ = ["AGENTS_DIR", "load_tool_file"]
