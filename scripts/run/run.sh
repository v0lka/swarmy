#!/usr/bin/env bash
# Shared demo launcher (defaults to the ShopVault demo): builds & starts the
# target via docker compose, waits for readiness, runs the swarmy session —
# the headless driver by default, the TUI with --tui — and archives the
# report into <demo>/reports/<run-id>/ together with the session.yaml
# provenance snapshot.
#
# Bash twin of run.ps1; both drive the shared headless_run.py driver
# (see README.md in this directory).
#
# Usage: run.sh [--tui] [--keep-up] [DEMO_DIR]
#   --tui      open the swarmy TUI instead of running the headless driver
#   --keep-up  leave the target running after the demo (teardown is skipped)
#   DEMO_DIR   demo directory, absolute or relative to the repository root
#              (default: demos/shop_vault)
# Environment overrides:
#   GOAL_FILE           operator goal text file (default: <demo>/goal.md)
#   DEADLINE_MINUTES    mission deadline passed to the driver (headless only)
#   WAIT_TIMEOUT_SECS   readiness polling budget (default: 300)
#   BACKEND_URL         backend readiness endpoint (default: ShopVault API)
#   FRONTEND_URL        frontend readiness endpoint (default: ShopVault SPA)
set -euo pipefail

# Paths are resolved from the script location: the launcher does not
# depend on the directory it is invoked from.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
INVOCATION_DIR="$PWD"

fail() {
    echo "run.sh: error: $*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
usage: run.sh [--tui] [--keep-up] [DEMO_DIR]
  --tui      open the swarmy TUI instead of running the headless driver
  --keep-up  leave the target running after the demo
  DEMO_DIR   demo directory (default: demos/shop_vault)
USAGE
}

TUI=0
KEEP_UP=0
DEMO_DIR=""
for arg in "$@"; do
    case "$arg" in
        --tui) TUI=1 ;;
        --keep-up) KEEP_UP=1 ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*) fail "unknown option: $arg (usage: run.sh [--tui] [--keep-up] [DEMO_DIR])" ;;
        *)
            if [ -n "$DEMO_DIR" ]; then
                fail "unexpected argument: $arg (usage: run.sh [--tui] [--keep-up] [DEMO_DIR])"
            fi
            DEMO_DIR="$arg"
            ;;
    esac
done

if [ -z "$DEMO_DIR" ]; then
    DEMO_DIR="$REPO_ROOT/demos/shop_vault"
elif [ "${DEMO_DIR#/}" = "$DEMO_DIR" ]; then
    # A relative demo path is resolved against the repo root, not the caller's cwd.
    DEMO_DIR="$REPO_ROOT/$DEMO_DIR"
fi
[ -d "$DEMO_DIR" ] || fail "demo directory not found: $DEMO_DIR"

# GOAL_FILE is resolved before the cd below: a relative override stays relative
# to the caller's cwd, not to the repository root.
GOAL_FILE="${GOAL_FILE:-}"
if [ -n "$GOAL_FILE" ] && [ "${GOAL_FILE#/}" = "$GOAL_FILE" ]; then
    GOAL_FILE="$INVOCATION_DIR/$GOAL_FILE"
fi

cd -- "$REPO_ROOT"

# Full console log of the run (gitignored; overwritten on every run). The TUI
# owns the terminal, so the log is captured in headless mode only.
if [ "$TUI" -eq 0 ]; then
    exec > >(tee "$DEMO_DIR/run.log") 2>&1
fi

# --- environment pre-flight (fail fast, before touching docker) ---
if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
    fail "DEEPSEEK_API_KEY is not set; export it first (see the demo README)"
fi
command -v docker >/dev/null 2>&1 || fail "docker CLI not found in PATH"
docker compose version >/dev/null 2>&1 || fail "docker compose plugin not available"
command -v uv >/dev/null 2>&1 || fail "uv not found in PATH (https://docs.astral.sh/uv/)"
command -v curl >/dev/null 2>&1 || fail "curl not found in PATH (used for readiness polling)"

# The operator goal file is a headless-mode input; the TUI takes the goal
# from the chat, so it is not required there.
if [ "$TUI" -eq 0 ]; then
    if [ -z "$GOAL_FILE" ]; then
        GOAL_FILE="$DEMO_DIR/goal.md"
    fi
    if [ ! -r "$GOAL_FILE" ] || [ ! -s "$GOAL_FILE" ]; then
        fail "operator goal file is missing or empty: $GOAL_FILE (create it; see the demo README)"
    fi
fi

SESSION_DIR="$DEMO_DIR/session"
if [ -d "$SESSION_DIR" ] && [ -n "$(ls -A "$SESSION_DIR" 2>/dev/null)" ]; then
    fail "session dir already holds a session: $SESSION_DIR (resume with 'uv run swarmy --resume', or remove it for a fresh run)"
fi

compose() {
    docker compose -f "$DEMO_DIR/target/docker-compose.yml" "$@"
}

TARGET_STARTED=0
cleanup() {
    if [ "$TARGET_STARTED" -eq 1 ]; then
        if [ "$KEEP_UP" -eq 1 ]; then
            echo "run.sh: keeping the target up (--keep-up); stop it later with: docker compose -f $DEMO_DIR/target/docker-compose.yml down"
        else
            echo "run.sh: tearing down the target..."
            compose down --remove-orphans || true
        fi
    fi
}
trap cleanup EXIT

# --- target: build & start (frontend :3000, backend API :3001) ---
echo "run.sh: demo directory: $DEMO_DIR"
echo "run.sh: building & starting the target..."
compose up --build -d || {
    compose down --remove-orphans || true
    fail "docker compose up failed"
}
TARGET_STARTED=1

# --- readiness: backend API first, then the frontend ---
wait_for() {
    local name="$1" url="$2"
    local timeout="${WAIT_TIMEOUT_SECS:-300}"
    local deadline=$(( SECONDS + timeout ))
    echo "run.sh: waiting for $name at $url (up to ${timeout}s)..."
    until curl -fsS -o /dev/null "$url" 2>/dev/null; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            fail "$name not ready after ${timeout}s: $url"
        fi
        sleep 2
    done
    echo "run.sh: $name is ready."
}
BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:3001/api/products}"
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:3000/}"
wait_for "backend API" "$BACKEND_URL"
wait_for "frontend" "$FRONTEND_URL"

# --- session: TUI (--tui) or the headless driver ---
if [ "$TUI" -eq 1 ]; then
    echo "run.sh: starting the swarmy TUI..."
    uv run --group demo swarmy "$DEMO_DIR/session.yaml" --session-dir "$SESSION_DIR" \
        || fail "the swarmy TUI exited with a non-zero code"
else
    echo "run.sh: starting the headless swarmy session..."
    DEADLINE_ARGS=()
    if [ -n "${DEADLINE_MINUTES:-}" ]; then
        DEADLINE_ARGS=(--deadline-minutes "$DEADLINE_MINUTES")
    fi
    uv run --group demo python "$SCRIPT_DIR/headless_run.py" \
        --demo-dir "$DEMO_DIR" \
        --config "$DEMO_DIR/session.yaml" \
        --session-dir "$SESSION_DIR" \
        --goal-file "$GOAL_FILE" \
        ${DEADLINE_ARGS:+"${DEADLINE_ARGS[@]}"} \
        || fail "the headless swarmy session failed"
fi

# --- archive the report (reports/ is kept; session/ stays uncommitted) ---
REPORT_SRC="$SESSION_DIR/report.md"
if [ -f "$REPORT_SRC" ]; then
    RUN_ID="$(date -u +%Y%m%d-%H%M%S)"
    RUN_DIR="$DEMO_DIR/reports/$RUN_ID"
    mkdir -p "$RUN_DIR"
    cp "$REPORT_SRC" "$RUN_DIR/report.md"
    SNAPSHOT="$SESSION_DIR/session.yaml"
    if [ ! -f "$SNAPSHOT" ]; then
        # Resolved config snapshot written by the session (provenance).
        SNAPSHOT="$DEMO_DIR/session.yaml"
    fi
    cp "$SNAPSHOT" "$RUN_DIR/session.yaml"
    echo "run.sh: report archived in $RUN_DIR"
elif [ "$TUI" -eq 1 ]; then
    echo "run.sh: no report.md in the session folder; nothing to archive (generate it in the TUI to keep a copy)"
else
    fail "the driver exited 0 but no report was written: $REPORT_SRC"
fi

echo "run.sh: done."
