"""Command-line entry point `swarmy` (arch §3.4, roadmap T4.1.3).

    swarmy <session-config.yaml> [--agents-dir PATH]... [--profile paranoid|normal|yolo]
           [--mode interactive|mission] [--model provider:model] [--session-dir PATH]
    swarmy --resume <session-dir>
    swarmy --version

The CLI is a thin wrapper (argparse, no CLI framework — P4): it resolves the
``SessionConfig`` (CLI flags → file → defaults, fail-fast with one report),
prepares the session folder (operator secrets next to the config file are
copied into it as ``secrets.yaml`` mode 600) and launches :class:`SwarmyTui`
— headless mode is out of scope for v0.1. Config problems never open the UI.

The L0-touching imports (``core.session`` → engine → deepagents/LangChain)
are made lazily inside the launch paths: ``main`` with no arguments prints
help without pulling the L0 stack into the process (guard test in
tests/unit/test_cli.py).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING

from swarmy import __version__

if TYPE_CHECKING:
    from swarmy.core.config import SecretsConfig, SessionConfig
    from swarmy.core.session import Session

    #: The resolved-config carrier handed to the launch paths.
    LoadedConfig = tuple[SessionConfig, SecretsConfig | None]

#: Default session folder for a fresh start (arch §3.4: ``--session-dir``).
DEFAULT_SESSION_DIR: Path = Path("swarmy-session")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (arch §3.4)."""
    parser = argparse.ArgumentParser(
        prog="swarmy",
        description=(
            "Extensible agent system for authorized web-application penetration testing."
        ),
    )
    parser.add_argument("--version", action="version", version=f"swarmy {__version__}")
    parser.add_argument(
        "config",
        nargs="?",
        metavar="session-config.yaml",
        help="path to the session config (YAML, arch §12.1); starts a new session",
    )
    parser.add_argument(
        "--agents-dir",
        action="append",
        default=[],
        metavar="PATH",
        help="user module directory (repeatable); overrides the config agents_dirs",
    )
    parser.add_argument(
        "--profile",
        choices=("paranoid", "normal", "yolo"),
        help="HITL strictness profile (arch §7.2); overrides the config profile",
    )
    parser.add_argument(
        "--mode",
        choices=("interactive", "mission"),
        help="orchestrator autonomy mode (arch §9.5); overrides the config mode",
    )
    parser.add_argument(
        "--model",
        metavar="PROVIDER:MODEL",
        help="orchestrator model id (D1); overrides the config model",
    )
    parser.add_argument(
        "--session-dir",
        metavar="PATH",
        help=f"session folder to create (default: {DEFAULT_SESSION_DIR})",
    )
    parser.add_argument(
        "--resume",
        metavar="SESSION_DIR",
        help="resume the session folder created by an earlier run (arch §13.1)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch; return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.resume is not None:
        if args.config is not None:
            print(
                "error: --resume cannot be combined with a session-config path",
                file=sys.stderr,
            )
            return 2
        return _resume(args)
    if args.config is None:
        parser.print_help()
        return 0
    return _open(args)


def _fail(problems: list[str]) -> int:
    """Report one fail-fast problem list (arch §4.5 style) without the UI."""
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 2


def _open(args: Namespace) -> int:
    """Resolve the config (fail-fast) and launch the console on a fresh session."""
    from swarmy.core.config import (
        ConfigError,
        SecretsConfigError,
        SessionConfig,
        load_secrets,
        write_secrets,
    )

    overrides: dict[str, object] = {
        "profile": args.profile,
        "mode": args.mode,
        "model": args.model,
        "agents_dirs": [Path(item) for item in args.agents_dir] or None,
    }
    config_path = Path(args.config)
    try:
        config = SessionConfig.load(cli_overrides=overrides, config_path=config_path)
    except ConfigError as exc:
        return _fail(list(exc.problems))
    session_dir = Path(args.session_dir) if args.session_dir else DEFAULT_SESSION_DIR
    secrets: SecretsConfig | None = None
    candidate = config_path.resolve().parent / "secrets.yaml"
    if candidate.is_file():
        try:
            secrets = load_secrets(candidate)
        except SecretsConfigError as exc:
            return _fail(list(exc.problems))
    if secrets is not None:
        # Persist the operator secrets into the portable folder (mode 600)
        # so `--resume` finds them on another machine (arch §3.3/§12.3).
        session_dir.mkdir(parents=True, exist_ok=True)
        write_secrets(session_dir / "secrets.yaml", secrets)
    return asyncio.run(_launch_fresh(config, session_dir, secrets))


def _resume(args: Namespace) -> int:
    """Resume an existing session folder (arch §13.1) and launch the console."""
    return asyncio.run(_launch_resume(Path(args.resume), args.model))


def _start_error_types() -> tuple[type[Exception], ...]:
    """Build the start-failure catch set (#30, arch §4.5: one report, exit 2, no UI).

    The closed set of aggregated start failures the CLI renders instead of a
    raw traceback: ``SessionError`` (typed session-open/resume failures),
    ``ModuleLoadError`` (the loader's aggregate report), ``SecretsConfigError``
    (unreadable/invalid ``secrets.yaml`` — also on the resume path, which
    loads it after ``Session.resume``), ``ToolRegistryError`` (toolset
    registration inside session composition) and ``DatabaseSchemaError``
    (a session folder written by a newer schema, #30 — the typed successor
    of the bare ``RuntimeError``). Imported lazily beside
    ``Session`` so ``main`` with no arguments still keeps the L0 stack out of
    the process.
    """
    from swarmy.core.config import SecretsConfigError
    from swarmy.core.database import DatabaseSchemaError
    from swarmy.core.session import SessionError
    from swarmy.modules.registry import ModuleLoadError
    from swarmy.tools.registry import ToolRegistryError

    return (
        SessionError,
        ModuleLoadError,
        SecretsConfigError,
        ToolRegistryError,
        DatabaseSchemaError,
    )


async def _launch_fresh(
    config: SessionConfig, session_dir: Path, secrets: SecretsConfig | None
) -> int:
    """Compose the session on the app's event loop and run the console."""
    from swarmy.core.session import Session  # lazy: L0 out of help
    from swarmy.report.generator import make_generate_report_tool

    try:
        session = await Session.open(
            config=config,
            session_dir=session_dir,
            secrets=secrets,
            report_tool_factory=make_generate_report_tool,
        )
    except _start_error_types() as exc:
        return _fail([f"session could not be opened: {exc}"])
    return await _run_console(session)


async def _launch_resume(session_dir: Path, model: str | None) -> int:
    """Resume the session on the app's event loop and run the console."""
    from swarmy.core.session import Session  # lazy: L0 out of help
    from swarmy.report.generator import make_generate_report_tool

    try:
        session = await Session.resume(
            session_dir=session_dir,
            model=model,
            report_tool_factory=make_generate_report_tool,
        )
    except _start_error_types() as exc:
        return _fail([f"session could not be resumed: {exc}"])
    return await _run_console(session)


async def _run_console(session: Session) -> int:
    """Run SwarmyTui on the current loop; guarantee the session release."""
    from swarmy.tui.app import SwarmyTui

    app = SwarmyTui(session)
    try:
        await app.run_async()
    finally:
        await session.close()
    return 0


__all__ = ["build_parser", "main"]
