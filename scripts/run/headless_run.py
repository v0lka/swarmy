"""Headless driver for a swarmy demo (default: ``demos/shop_vault``).

Composes a session from the demo's ``session.yaml`` (``SessionConfig.load``),
drives the orchestrator with the operator goal from a text file, and writes
the markdown report into the session folder at the end — the headless pattern
of the F5 demo integration test
(``tests/integration/scenarios/test_demo_f5.py``) with the scripted model
replaced by the configured chat model (``model: deepseek:deepseek-flash``,
resolved through ``init_chat_model`` by the session wiring).

The shared bash and PowerShell launchers in ``scripts/run`` both call this
driver; it changes no swarmy code and touches only the public composition
surface: ``SessionConfig.load`` → ``Session.open`` (with the report package's
``make_generate_report_tool`` factory, RD-7) →
``runtime.run_step`` / ``runtime.submit_decision`` → the session's
``generate_report`` tool.

Drive loop (mirrors the TUI session worker, arch §10.2): serve pending
HITL gates (auto-approve; not expected under ``profile: yolo`` +
``mode: mission`` but handled defensively — every decision is journaled
by the approval queue as ``OperatorDecision``), then drain queued policy
injections one ``run_step`` at a time, and stop when the orchestrator
graph is idle (no pending nodes), the deadline expires or a step times
out. Each step is bounded by a wall-clock guard: a hung provider call
must not eat the whole mission deadline (the session folder stays
resumable via ``swarmy --resume`` afterwards).

Exit codes: ``0`` — the mission ran to an idle orchestrator and the
report was written; ``1`` — start failure, deadline exhaustion, step
timeout, or a report failure (details are printed).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections.abc import Callable, Coroutine, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, TypeAlias, cast

from swarmy.core.config import ConfigError, SessionConfig

if TYPE_CHECKING:
    from swarmy.core.session import Session

#: Per-``run_step`` / per-decision wall-clock guard in seconds (a hung
#: provider call must not consume the whole mission deadline).
STEP_TIMEOUT_S: Final[float] = 300.0

#: Pause between defensive idle polls (graph mid-superstep without gates).
IDLE_POLL_S: Final[float] = 1.0

#: Default mission wall-clock deadline in minutes (``--deadline-minutes``).
DEFAULT_DEADLINE_MINUTES: Final[float] = 60.0

#: Journal event types reported in the closing summary.
SUMMARY_EVENT_TYPES: Final[tuple[str, ...]] = (
    "EndpointsDiscovered",
    "FindingCandidate",
    "FindingVerified",
    "GuardrailBlocked",
    "AttackTreeUpdated",
)

#: Repository root (``scripts/run/headless_run.py`` → three levels up);
#: computed at import time so ASYNC240 keeps blocking path resolution out of
#: the async paths.
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

#: Default demo served by this shared driver (the ShopVault demo).
DEFAULT_DEMO_DIR: Final[Path] = REPO_ROOT / "demos" / "shop_vault"

#: The zero-argument async ``generate_report`` tool as built by
#: ``make_generate_report_tool`` (swarmy.report.generator).
ReportTool: TypeAlias = Callable[..., Coroutine[object, object, str]]


class DriverError(Exception):
    """A driver-side precondition failed (missing components, bad input)."""


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the driver CLI (shared by the bash and PowerShell twins)."""
    parser = argparse.ArgumentParser(
        prog="swarmy-demo",
        description=(
            "Headless swarmy demo driver: compose a session from the demo's "
            "session.yaml, drive the orchestrator with the operator goal, and "
            "write report.md into the session folder."
        ),
    )
    parser.add_argument(
        "--demo-dir",
        type=Path,
        default=DEFAULT_DEMO_DIR,
        help=(
            "demo directory that owns session.yaml, goal.md and the session "
            "folder; drives the defaults below (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="session YAML to load (default: <demo-dir>/session.yaml)",
    )
    parser.add_argument(
        "--session-dir",
        type=Path,
        help=(
            "portable session folder to create "
            "(default: <demo-dir>/session; must not already hold a session)"
        ),
    )
    parser.add_argument(
        "--goal-file",
        type=Path,
        help="UTF-8 text file with the operator goal (default: <demo-dir>/goal.md)",
    )
    parser.add_argument(
        "--deadline-minutes",
        type=float,
        default=DEFAULT_DEADLINE_MINUTES,
        help="mission wall-clock deadline in minutes (default: %(default)s)",
    )
    return parser.parse_args(argv)


def _remaining(deadline: float) -> float:
    """Seconds left before the mission deadline (never negative)."""
    return max(deadline - time.monotonic(), 0.0)


async def _drive(session: Session, goal_text: str, *, deadline_s: float) -> bool:
    """Run the mission to an idle orchestrator; ``True`` on completion.

    The goal turn is the first step; afterwards the loop serves gates,
    drains injections and polls the graph state exactly like the TUI
    session worker (arch §10.2) until the graph reports no pending nodes.
    """
    runtime = session.runtime
    approvals = session.approvals
    engine = session.engine
    if runtime is None or approvals is None or engine is None:
        raise DriverError("session components are not composed")

    deadline = time.monotonic() + deadline_s
    step = 0

    print(f"[demo] goal: {goal_text.strip().splitlines()[0][:120]!r}", flush=True)
    step += 1
    await asyncio.wait_for(
        runtime.run_step(goal_text), timeout=min(STEP_TIMEOUT_S, _remaining(deadline))
    )
    print(f"[demo] step {step}: goal turn done", flush=True)

    while _remaining(deadline) > 0:
        gates = approvals.pending()
        if gates:
            # Defensive: under profile yolo + mission no gates are expected
            # (only the most destructive risk class can still gate). The
            # approval queue journals every decision as OperatorDecision.
            for gate in gates:
                step += 1
                print(
                    f"[demo] step {step}: auto-approving unexpected gate "
                    f"{gate.tool!r} (origin={gate.origin}, "
                    f"rule={gate.rule_or_profile!r})",
                    flush=True,
                )
                await asyncio.wait_for(
                    runtime.submit_decision(gate.request_id, "approve"),
                    timeout=min(STEP_TIMEOUT_S, _remaining(deadline)),
                )
            continue

        if runtime.pending_injections() > 0:
            step += 1
            await asyncio.wait_for(
                runtime.run_step(), timeout=min(STEP_TIMEOUT_S, _remaining(deadline))
            )
            print(f"[demo] step {step}: served queued notifications", flush=True)
            continue

        snapshot = await engine.graph.aget_state(runtime.config)
        if not snapshot.next:
            print(f"[demo] orchestrator idle after {step} step(s)", flush=True)
            return True
        await asyncio.sleep(IDLE_POLL_S)  # defensive: no gates, graph not idle

    print(
        f"[demo] deadline of {deadline_s:.0f}s exhausted after {step} step(s)",
        flush=True,
    )
    return False


async def _write_report(session: Session) -> Path | None:
    """Trigger the session's ``generate_report`` tool (the F5-test seam).

    The same composition surface the integration test uses
    (``tests/integration/scenarios/test_demo_f5.py``): the tool was built
    by ``make_generate_report_tool`` during ``Session.open`` and writes
    ``<session-dir>/report.md`` deterministically (no LLM, no network).
    """
    tool = cast("ReportTool | None", session._orchestrator_tools.get("generate_report"))
    if tool is None:
        print(
            "[demo] generate_report is missing from the orchestrator toolset",
            file=sys.stderr,
            flush=True,
        )
        return None
    confirmation = await tool()
    print(f"[demo] {confirmation}", flush=True)
    return session.session_dir / "report.md"


async def _print_summary(session: Session) -> None:
    """Print the closing journal statistics (operator-facing convenience)."""
    reader = session.reader
    if reader is None:
        return
    for event_type in SUMMARY_EVENT_TYPES:
        events = await reader.by_type(event_type)
        print(f"[demo] journal: {event_type} x {len(events)}", flush=True)


async def main(argv: Sequence[str] | None = None) -> int:
    """Compose the session, run the mission, write the report; exit code."""
    args = _parse_args(argv)
    demo_dir = args.demo_dir
    config_path = args.config if args.config is not None else demo_dir / "session.yaml"
    session_dir = args.session_dir if args.session_dir is not None else demo_dir / "session"
    goal_file = args.goal_file if args.goal_file is not None else demo_dir / "goal.md"

    try:
        config = SessionConfig.load(config_path=config_path)
    except ConfigError as exc:
        print(f"[demo] session config rejected:\n{exc}", file=sys.stderr, flush=True)
        return 1

    if (
        config.model is not None
        and config.model.startswith("deepseek:")
        and not os.environ.get("DEEPSEEK_API_KEY")
    ):
        print(
            "[demo] DEEPSEEK_API_KEY is not set; the deepseek provider needs it",
            file=sys.stderr,
            flush=True,
        )
        return 1

    try:
        goal_text = goal_file.read_text(encoding="utf-8")
    except OSError as exc:
        print(
            f"[demo] goal file {goal_file} is unreadable: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    if not goal_text.strip():
        print(f"[demo] goal file {goal_file} is empty", file=sys.stderr, flush=True)
        return 1

    # L0/report imports stay lazy so --help does not pay for them (cli.py
    # keeps the same discipline: the L0 stack enters only with a session).
    from swarmy.core.session import Session, SessionError
    from swarmy.report.generator import make_generate_report_tool

    try:
        session = await Session.open(
            config=config,
            session_dir=session_dir,
            report_tool_factory=make_generate_report_tool,
        )
    except SessionError as exc:
        print(
            f"[demo] session could not be opened: {exc}\n"
            "[demo] hint: pass a fresh --session-dir (an existing session "
            "folder is resumed with `swarmy --resume`, not this driver).",
            file=sys.stderr,
            flush=True,
        )
        return 1

    print(
        f"[demo] target {config.target.base_url} "
        f"(profile={config.profile}, mode={config.mode}, model={config.model})",
        flush=True,
    )
    print(f"[demo] session dir: {session_dir}", flush=True)
    try:
        completed = await _drive(session, goal_text, deadline_s=args.deadline_minutes * 60.0)
        report_path = await _write_report(session)  # best-effort on any exit
        await _print_summary(session)
        if not completed:
            print("[demo] FAILED: the mission did not reach an idle orchestrator", flush=True)
            return 1
        if report_path is None or not report_path.is_file():
            print("[demo] FAILED: report.md was not written", flush=True)
            return 1
        print(f"[demo] OK: report at {report_path}", flush=True)
        return 0
    finally:
        await session.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
