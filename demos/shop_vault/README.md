# ShopVault demo

An end-to-end **swarmy** demo against a deliberately vulnerable,
**loopback-only** e-commerce application: the orchestrator deep-agent
receives an operator goal in `mission` mode, explores the ShopVault API
through the built-in `crawler` / `xss-detector` subagents, links verified
findings into attack trees and renders a draft report — headless by
default, or interactively in the TUI with `--tui`.

The shared launchers in [`scripts/run`](../../scripts/run/README.md)
(bash and PowerShell twins of the same lifecycle) drive this demo; the
session shape lives in [`session.yaml`](./session.yaml).

## Layout

| File | Purpose |
|---|---|
| `session.yaml` | Session config: target `http://127.0.0.1:3001/`, scope loopback (`127.0.0.1/32` + `localhost`, ports 3000/3001, http), `profile: yolo`, `mode: mission`, `model: deepseek:deepseek-flash`; the judge band stays off and `limits` keep the conservative code defaults. |
| `goal.md` | The operator goal for the headless driver (a UTF-8 text file; override with `GOAL_FILE`). |
| `target/` | The ShopVault application under test (git submodule): Go backend + React frontend. See `target/README.md` for build details. |
| `session/` | Created by the session: the portable session folder (`session.yaml` audit snapshot, `memory.sqlite`, `evidence/`, `report.md`). |
| `reports/` | Archived reports (one folder per run: `report.md` + the `session.yaml` provenance snapshot). |

## Prerequisites

- Python ≥ 3.11 with [uv](https://docs.astral.sh/uv/) — the deepseek
  provider comes from the optional `demo` dependency group
  (`uv run --group demo ...` below installs/uses it on demand).
- A DeepSeek API key in the environment: `export DEEPSEEK_API_KEY=...`
  (PowerShell: `$env:DEEPSEEK_API_KEY = "..."`).
- The ShopVault target running on `127.0.0.1:3001` (next section).
- An operator goal: a UTF-8 text file (default path `goal.md` in the
  demo directory). The shipped [`goal.md`](./goal.md) is a generic mission
  statement — test every endpoint for all classes of vulnerabilities,
  then build all possible attack trees of maximum depth — that gives
  the swarm no leads about what to look for, where or how: it has to
  work that out from the application itself.

## Starting the target

From this directory (both variants bind loopback only):

```bash
# Variant A: docker compose (frontend :3000, backend API :3001)
docker compose --project-directory target up --build

# Variant B: single self-contained binary (API + embedded SPA on :3001)
# build it once per target/README.md, then:
./target/dist/shopvault-linux-amd64
```

## Running the demo

From the repository root (the launchers build & start the target, wait
for readiness, run the session and archive the report):

```bash
scripts/run/run.sh                 # headless (default)
scripts/run/run.sh --tui           # swarmy TUI instead of the headless driver
scripts/run/run.sh --keep-up       # leave the target running afterwards

# PowerShell twin (Windows)
.\scripts\run\run.ps1 --tui
```

In `--tui` mode the launcher opens the interactive swarmy TUI on the demo
session with the config as-is (`profile: yolo`, `mode: mission`):
`DEADLINE_MINUTES` is ignored, `run.log` is not written (the TUI owns the
terminal) and `report.md` is archived only if it was generated during the
session.

The headless driver can also be invoked directly — the launchers pass the
same arguments:

```bash
uv run --group demo python scripts/run/headless_run.py \
    --demo-dir demos/shop_vault \
    --goal-file demos/shop_vault/goal.md \
    --deadline-minutes 90
```

Driver flags (all optional unless noted):

- `--demo-dir PATH` — demo directory that owns `session.yaml`, `goal.md`
  and the session folder; drives the defaults below (default:
  `demos/shop_vault`).
- `--config PATH` — session YAML (default: `<demo-dir>/session.yaml`).
- `--session-dir PATH` — session folder to create (default:
  `<demo-dir>/session`). An existing session folder is **not**
  reused: start fresh or resume an interrupted one with
  `uv run swarmy --resume <session-dir>`.
- `--goal-file PATH` — operator goal text (default: `goal.md` in the
  demo directory).
- `--deadline-minutes N` — mission wall-clock deadline (default: 60);
  each orchestrator step is additionally capped at 5 minutes so a hung
  provider call cannot stall the run.

Exit code `0` means the orchestrator reached an idle state and the
report was written; `1` means a start failure, deadline/step timeout, or
a report failure. Under `yolo` + `mission` no HITL gates are expected —
if one still appears, the driver auto-approves it and the decision is
journaled as an `OperatorDecision` event.

## Results

- `session/report.md` — the deterministic markdown report. Its first
  line is the draft mark: **the report is a verification aid for a human
  pentester, not a deliverable** (spec §10).
- `session/memory.sqlite` + `session/evidence/` — findings, endpoints,
  attack trees and raw evidence (kept unredacted on disk, spec §8.7).
- The console log mirrors mission progress: steps served, unexpected
  gates, journal counters and the final report path.

## Legal / authorization disclaimer

ShopVault is a **deliberately vulnerable training application** and this
demo is configured strictly for it on loopback. swarmy intentionally has
**no authorization gate** (decision D15): running it against any system
requires the operator's own legal authorization to test that system. You
are responsible for ensuring you have permission to test every target
you point swarmy at — do not point this demo config anywhere else.
