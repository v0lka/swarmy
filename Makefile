# =============================================================================
# swarmy — developer Makefile
#
# Implements the quality gates and core codebase operations mandated by the
# design documents (docs/development/):
#   - spec.md         v0.3 — §11 (quality NFRs: ruff, ty/mypy strict, pytest,
#                       D22 coverage thresholds), §12.2 (development tooling),
#                       D18 (pinned deepagents + uv.lock), §12.3 (phases F0–F6)
#   - architecture.md v0.1 — §3.1 (src-layout), §3.2 (pyproject), §3.4 (CLI),
#                       §15.1–§15.4 (tests, static analysis, CI), §16 (invariants)
#   - roadmap.md      v0.1 — T1.1.1–T1.1.5 (uv, ruff, ty/mypy, Py3.15 smoke,
#                       CI matrix), T1.5.6 / T2.4.3 (D22 coverage gates)
#
# `make check` mirrors the CI pipeline (arch §15.4):
#   uv sync → ruff → ty/mypy → unit (≥85%) → integration (≥70%) → smoke.
#
# Note: this Makefile targets the developer machine's make(1) (macOS/Linux/WSL).
# The CI matrix (windows/amd64, macos/arm64, linux/amd64+arm64, arch §15.4) runs
# the same uv/ruff/pytest commands directly and does not depend on make.
# =============================================================================

.DEFAULT_GOAL := help
.NOTPARALLEL:                  # `make check` gates run strictly in CI order (arch §15.4)

# ---- Configuration (overridable from the command line, e.g. `make test-unit UNIT_COVERAGE=0`) ----
# Note: assignments carry no trailing comments — in make, spaces before `#`
# become part of the variable's value.

# Package and directories (arch §3.1: src-layout, tests/unit + tests/integration)
PACKAGE              ?= swarmy
SRC_DIR              ?= src
TESTS_DIR            ?= tests

# Strict type checker — F0 decision (roadmap T1.1.1/T1.1.3): ty primary, mypy fallback
TYPECHECKER          ?= ty

# D22 coverage gates (spec §11): unit ≥ 85% (roadmap T1.5.6), integration ≥ 70% (roadmap T2.4.3)
UNIT_COVERAGE        ?= 85
INTEGRATION_COVERAGE ?= 70

# Smoke runtime target (spec §11); requires-python = ">=3.11,<4.0"
PYTHON_VERSION       ?= 3.15

# Run parameters (arch §3.4): CONFIG — session config file for run/run-debug;
# ARGS — extra CLI arguments, e.g. ARGS="--profile yolo --mode mission";
# BREAKPOINT — PYTHONBREAKPOINT for run-debug (disable with BREAKPOINT=0)
CONFIG               ?=
ARGS                 ?=
BREAKPOINT           ?= pdb.set_trace

UV                   ?= uv
PY                   := $(UV) run python

.PHONY: help sync lock lock-check upgrade-deepagents build install \
        lint lint-ruff lint-format format typecheck \
        test test-unit test-integration test-fast \
        smoke smoke-py315 run run-debug check clean clean-all

# ---- Environment and dependencies: uv + uv.lock (spec §11; D18 — reproducibility, pinned deepagents) ----

sync: ## Create .venv and install the project (editable) + dev dependencies from uv.lock
	$(UV) sync

lock: ## Refresh uv.lock after editing dependencies in pyproject.toml
	$(UV) lock

lock-check: ## Gate (D18): uv.lock is up to date with pyproject.toml
	$(UV) lock --check

upgrade-deepagents: ## D18 procedure: review changelog (manually) → bump lock → full `make check`
	@echo "D18: 1) review the deepagents changelog (pin >=0.7.41,<0.8); 2) bump the lock; 3) full gate run."
	$(UV) lock --upgrade-package deepagents
	$(MAKE) check

# ---- Build (src-layout: arch §3.1–§3.2; F0 criterion — install from sources) ----

build: ## Build sdist and wheel into dist/ (uv build)
	$(UV) build

install: sync ## Set up the dev environment (equivalent of `pip install -e .` + dev group) — F0 criterion

# ---- Linters and typing: gates of arch §15.3, roadmap T1.1.3 ----

lint: lint-ruff typecheck ## Gate: ruff strict (src + tests) + strict type checker (src)

lint-ruff: ## ruff strict (in the spirit of upstream deepagents: no Any/ANN401, I/UP/B)
	$(UV) run ruff check $(SRC_DIR) $(TESTS_DIR)

lint-format: ## ruff format --check — advisory only, not part of the gate (docs mandate `ruff check` only)
	$(UV) run ruff format --check $(SRC_DIR) $(TESTS_DIR)

format: ## ruff format — auto-format src and tests
	$(UV) run ruff format $(SRC_DIR) $(TESTS_DIR)

typecheck: ## Strict type check of src (arch §15.3): ty (default) or mypy (TYPECHECKER=mypy)
ifeq ($(TYPECHECKER),mypy)
	$(UV) run mypy $(SRC_DIR)
else
	$(UV) run ty check $(SRC_DIR)
endif

# ---- Tests and D22 coverage gates (spec §11; arch §15.1; roadmap T1.5.6 / T2.4.3) ----
# Thresholds are enforced PER SUITE — a separate command with --cov-fail-under each (D22):
# one shared threshold for the whole run is forbidden, blanket-omitting whole packages is forbidden.

test: test-unit test-integration ## All tests + both coverage gates (D22)

test-unit: ## Gate: unit suite, coverage ≥ 85% (roadmap T1.5.6)
	$(UV) run pytest $(TESTS_DIR)/unit --cov=$(PACKAGE) --cov-report=term-missing --cov-fail-under=$(UNIT_COVERAGE)

test-integration: ## Integration suite (echo app); coverage ≥ 70% gate ACTIVE since T2.4.3 (G5, D22)
	$(UV) run pytest $(TESTS_DIR)/integration --cov=$(PACKAGE) --cov-report=term-missing --cov-fail-under=$(INTEGRATION_COVERAGE)

test-fast: ## Fast run of all tests without gates (advisory; until gates activate in F1/F2)
	$(UV) run pytest $(TESTS_DIR)/unit $(TESTS_DIR)/integration

# ---- Smoke: F0 criterion and CI step (arch §15.4; roadmap T1.1.4) ----

smoke: ## Run `swarmy --version` and `swarmy --help` (F0 criterion)
	$(PY) -m swarmy --version
	$(PY) -m swarmy --help

smoke-py315: ## Smoke on Python 3.15 — runtime target (spec §11), isolated throwaway environment
	$(UV) run --isolated --python $(PYTHON_VERSION) python -m swarmy --version

# ---- Run and debug (arch §3.4: the CLI builds SessionConfig and brings up the TUI) ----

run: ## Run a session: make run CONFIG=session.yaml [ARGS="--profile normal --mode interactive"]
	@test -n "$(CONFIG)" || { echo "ERROR: specify CONFIG=session.yaml (arch §3.4)"; exit 2; }
	$(PY) -m swarmy $(CONFIG) $(ARGS)

run-debug: ## Debug run: python -X dev (asyncio debug, verbose warnings) + PYTHONBREAKPOINT
	@test -n "$(CONFIG)" || { echo "ERROR: specify CONFIG=session.yaml (arch §3.4)"; exit 2; }
	PYTHONBREAKPOINT=$(BREAKPOINT) $(PY) -X dev -m swarmy $(CONFIG) $(ARGS)

# ---- All gates together: CI parity (arch §15.4: sync → ruff → ty → unit 85 → integration 70 → smoke) ----

check: lock-check sync lint test smoke ## All quality gates in CI order + D18 lock check

# ---- Cleanup ----

clean: ## Remove build/test artifacts (dist/, tool caches, coverage data)
	rm -rf dist build .pytest_cache .ruff_cache .mypy_cache .ty_cache .coverage .coverage.* htmlcov
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	@find . -name '*.egg-info' -type d -prune -exec rm -rf {} +

clean-all: clean ## Same + remove .venv (full reinstall: `make sync`)
	rm -rf .venv

# ---- Help ----

help: ## Show this help
	@echo "swarmy — developer commands (gates from docs/development: spec §11/§12.2, arch §15, roadmap T1.1.x/T1.5.6/T2.4.3)"
	@echo "Usage: make <target> [VARIABLE=value]"
	@echo "Key variables: TYPECHECKER=ty|mypy  UNIT_COVERAGE=85  INTEGRATION_COVERAGE=70  CONFIG=session.yaml  ARGS=...  BREAKPOINT=pdb.set_trace"
	@echo
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z0-9][a-zA-Z0-9_-]*:.*## / { split($$1, t, " "); printf "  %-20s %s\n", t[1], $$2 }' $(MAKEFILE_LIST)
