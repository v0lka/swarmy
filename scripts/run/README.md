# Shared demo launchers (`scripts/run`)

Reusable launchers for the scenarios under `demos/<name>/`. They build &
start the demo target via docker compose, wait for readiness, run the swarmy
session and archive the report into `<demo>/reports/<run-id>/` together with
the `session.yaml` provenance snapshot.

| File | Purpose |
|---|---|
| `run.sh` | Bash launcher (Linux/macOS/WSL): `scripts/run/run.sh [--tui] [--keep-up] [DEMO_DIR]` |
| `run.ps1` | PowerShell launcher (Windows): `.\scripts\run\run.ps1 [--tui] [--keep-up] [DEMO_DIR]` (also accepts `-Tui` / `-KeepUp`) |
| `headless_run.py` | Shared headless driver: `SessionConfig.load` → `Session.open(report_tool_factory=make_generate_report_tool)` → operator goal via `runtime.run_step(...)` → drain loop (HITL gates auto-approve with journaling, policy injections served one step at a time, overall deadline + per-step timeout) → final `generate_report`. |

## Modes

- **Headless (default)** — runs `headless_run.py`, which drives the mission
  unattended and writes `report.md`. `DEADLINE_MINUTES` applies.
- **TUI (`--tui`)** — opens the interactive swarmy TUI on the demo session
  instead. `goal.md` (or `GOAL_FILE`) is passed to the console as the
  opening goal: the mission starts automatically as soon as the TUI opens;
  without a goal file the operator types the goal in the chat.
  `DEADLINE_MINUTES` is ignored, `run.log` is not written (the TUI owns the
  terminal) and `report.md` is archived only if it was generated during the
  session.

## Demo contract

A demo directory passed as `DEMO_DIR` (default `demos/shop_vault`; relative
paths resolve against the repository root) must contain:

- `session.yaml` — swarmy session config (target, scope, profile, mode, model);
- `goal.md` — operator goal (override with `GOAL_FILE`): required by the
  headless driver; in `--tui` mode the console sends it as the first chat
  message, so the mission starts automatically (without it the operator
  types the goal in the chat);
- `target/docker-compose.yml` — the target under test; it publishes the
  backend on `127.0.0.1:3001` and the frontend on `127.0.0.1:3000`
  (override the readiness endpoints with `BACKEND_URL` / `FRONTEND_URL`).

Run artifacts stay in the demo directory: `session/` and `run.log` are
gitignored, `reports/<run-id>/` is kept.

## Environment overrides

| Variable | Purpose | Default |
|---|---|---|
| `GOAL_FILE` | operator goal text file (both modes; optional for the TUI) | `<demo>/goal.md` |
| `DEADLINE_MINUTES` | mission deadline (headless only) | driver default (60) |
| `WAIT_TIMEOUT_SECS` | readiness polling budget | `300` |
| `BACKEND_URL` | backend readiness endpoint | ShopVault API |
| `FRONTEND_URL` | frontend readiness endpoint | ShopVault SPA |
