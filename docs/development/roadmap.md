# swarmy — development roadmap

- **Version:** 0.1
- **Date:** 2026-11-25
- **Basis:** [spec.md](spec.md) v0.3-draft (principles P1–P5, decisions D1–D22,
  phases F0–F6 §12.3) and [architecture.md](architecture.md) v0.1-draft
  (components §2.3, decisions AD-1–AD-8, invariants §16, anti-patterns §17,
  tracing §18)
- **Status:** working planning document. Hierarchy: **milestone → phase →
  atomic task** (What/Where/How/Acceptance Criteria)
- **Languages:** English (documentation, code, identifiers, CLI, UI)

---

## 1. How to read this document

- **Hierarchy:** `M1–M5` — milestones (deliverables, each with its own
  Definition of Done), `P1.1–P5.5` — phases (work areas within a milestone),
  `T#.#.#` — atomic tasks.
- **Mapping to spec:** each phase is tagged with the spec §12.3 phase
  (`F0–F6`); the spec's phase readiness criteria are carried into the phase and
  milestone DoDs and are **not weakened**.
- **Task schema:** **What** — the observable result; **Where** — canonical
  paths from architecture.md §3.1 (divergence of the code from them is a
  defect, arch §1); **How** — the approach and key steps; **Acceptance
  criteria** — binary verifiable criteria (checkboxes).
- **Atomicity:** a task is sized for a single reviewable PR and is verified on
  its own, without the neighboring tasks of the phase.
- **Completion:** a task is closed when all its ACs are checked and CI is
  green; a phase is closed when all its tasks are closed and its DoD is met; a
  milestone is closed per its own DoD (§5.0–§9.0).
- **Order:** tasks within a phase are listed in the recommended execution
  order; dependencies between phases are in §10.
- **Effort estimates and calendar dates are deliberately omitted:** the source
  documents provide no basis for them; the document fixes the composition, the
  order and the readiness criteria.
- **Maintenance:** the document lives together with the implementation.
  Divergence of the code from spec/architecture is a design defect (not a
  "workaround"); new planning decisions are added to the RD journal (§4)
  following the pattern of the spec §13 decision log.

---

## 2. Milestones: overview

| Milestone | Phases | F-spec | Goal | DoD (brief) | Tasks |
|---|---|---|---|---|---|
| **M1 Foundation** | P1.1–P1.5 | F0, F1 | Repository, quality tools, domain core: memory (schema+FTS5), events (bus+journal), guardrails (pipeline+DSL), tool registry + module loader | Installation and `swarmy --help` on all platforms; core under unit tests; unit gate ≥ 85% active; a stub module loads | 29 |
| **M2 Execution perimeter** | P2.1–P2.4 | F2 | Network under control: scope, limits, HTTP client, evidence, LLM-context sanitization | Echo app: out-of-scope is blocked, evidence is written, budgets/masking work; integration gate ≥ 70% active | 13 |
| **M3 Swarm and HITL** | P3.1–P3.5 | F3 | Orchestrator: config/session/engine, runtime + event policies, HITL (profiles, queue), LLM judge, async parallelism of delegations | "finding → verification" scenario via events; parallel `task()` with global limits; the approval queue works | 19 |
| **M4 Operator console** | P4.1–P4.4 | F4 | TUI: 6 panels, chat, HITL modals, attack trees | The full session is driven from the TUI without CLI input | 11 |
| **M5 Reference swarm and release** | P5.1–P5.5 | F5, F6 | Built-in `crawler` and `xss-detector` modules, minimal attack trees, demo session, report, v0.1 release | F5 demo session; `report.md` is generated from the F5 session; v0.1 acceptance (installation from git, D17) | 12 |

Milestones depend linearly (phase composition and exact dependencies are in §10):

```
M1 (foundation: F0+F1)
 │
 ▼
M2 (execution perimeter: F2)
 │
 ▼
M3 (swarm and HITL: F3)
 │
 ▼
M4 (operator console: F4)
 │
 ▼
M5 (reference swarm, report, release: F5+F6)
```

The meaning of the boundaries: after M1 the system has a core without network
and agents; after M2 — controlled access to the target with scope/limits/
evidence guarantees; after M3 — a working swarm with HITL (headless, no TUI);
after M4 — a session driven from the TUI; M5 brings it to the demo scenario
and the v0.1 release.

---

## 3. Global constraints and cross-cutting practices

Apply in all phases; a violation is treated as a defect in the same way as
divergence from spec/architecture.

| # | Constraint | Source |
|---|---|---|
| G1 | Python `>=3.11,<4.0`; runtime target 3.15 (smoke in CI); platforms windows/amd64, macos/arm64, linux/amd64+arm64; no POSIX-only APIs in the core | spec §11; arch §15.4 |
| G2 | L0 = deepagents `>=0.7.41,<0.8`, never forked; only documented extension points (arch §2.1); upgrade is the D18 procedure | D16, D18 |
| G3 | Pydantic v2 for all boundaries; `Any`/`dict[str, Any]` forbidden in domain code; untyped dependencies only through typed wrappers | D9; spec §11 |
| G4 | Runtime dependencies: deepagents, pydantic, httpx, textual, rich, jinja2, aiosqlite, langgraph-checkpoint-sqlite; management — uv + lock file | spec §11; AD-2 |
| G5 | Coverage thresholds (D22): unit ≥ 85%, integration ≥ 70% — **separate** CI commands; activation: unit from T1.5.6, integration from T2.4.3; exceptions are spot (`pragma: no cover`), blanket-omitting whole packages is forbidden | D22 |
| G6 | arch §16 invariants (10 items) and arch §17 anti-patterns are verifiable requirements; architectural tests for the import rules (arch §2.5) are maintained continuously from the moment the packages appear | arch §16–§17 |
| G7 | Fail-fast session start: all config, manifest, guardrail and name-collision problems are detected before the first LLM call | arch §16.10 |
| G8 | Operator secrets: only `secrets.yaml` (chmod 600), masking in LLM context/TUI/journal; raw values only in evidence files | AD-5; D21; arch §12.3 |
| G9 | Every PR passes the CI matrix (G1) and does not lower coverage below the active thresholds (G5) | D22 |
| G10 | The docstring of a tool function is the LLM-facing description (non-empty, typed signature); "← arch §N" traceability comments are welcome | arch §1, §8.5 |

**DoD hierarchy:** task ACs → phase DoD (in the phase heading) → milestone DoD
(§5.0–§9.0). Milestone DoDs inherit the spec §12.3 phase criteria verbatim in
meaning (with the RD-6 caveat for F3/F4).

---

## 4. Roadmap decisions (RD)

Decisions specific to this document: they do not change spec/architecture, but
resolve planning ambiguity where arch §18.3 leaves a phase unassigned or the
execution order needs clarification.

| # | Decision | Rationale |
|---|---|---|
| RD-1 | Milestones group the spec §12.3 phases: M1 = F0+F1; M2 = F2; M3 = F3; M4 = F4; M5 = F5+F6+release. Large spec phases are split into sub-phases (F0 → P1.1; F1 → P1.2–P1.5; F2 → P2.1–P2.4; F3 → P3.1–P3.5; F4 → P4.1–P4.4; F5 → P5.1–P5.3; F6 → P5.4) | A three-level "milestone → phase → task" structure while keeping F0–F6 as the skeleton and their criteria as the DoD |
| RD-2 | The LLM judge (arch §6.7) is assigned to P3.4 (milestone F3); it is not part of F1/F2 | arch §18.3 does not explicitly assign §6.7 to a phase; judge escalations require ApprovalQueue and the "temporary gate" `JudgeEscalationRegistry` — a dependency on HITL |
| RD-3 | ToolRegistry (arch §6.1) is assigned to P1.5 (the loader phase) | arch §18.3 does not assign §6.1; name collisions and risk classes are needed by the loader for fail-fast assembly of SubAgent dicts (§8.3) |
| RD-4 | In M1 the argument digests in `GuardrailBlocked` are trivial truncation; from P2.3 (T2.3.2) they are replaced with ContextProjector | arch §5.5 requires the projector for all digests, but ContextProjector is implemented in F2; in F1 the bus/journal are already needed |
| RD-5 | The "verifier" of the demo scenario — without a new built-in module: a re-delegation of `xss-detector` with safe payloads + the platform `update_finding_status` | spec §4.6 fixes exactly two built-in v0.1 modules; arch §13.4 mentions `task(verifier)` without defining a separate module |
| RD-6 | The F3 criterion "the HITL modal intercepts destructive" is accepted in two steps: queue logic — headless acceptance in P3.3; the UI modal — in P4.3 (final acceptance together with F4) | The TUI is implemented in F4 (spec §12.3); the potential contradiction between the F3 and F4 criteria is resolved by splitting the acceptance |
| RD-7 | `generate_report` is included in the engine tools in P5.4; before that the engine is assembled without it | arch §9.1 lists the tool in the assembly, but the report implementation is F6; no stub is required |
| RD-8 | Migrations of all tables of the single `memory.sqlite` (domain + `events` + FTS) — a single list in `memory/schema.py`; ownership of table semantics stays with the subsystems | arch §4.3 describes a single migrator; the arch §2.5 import rules are not violated (DDL constants are not a cross-import) |
| RD-9 | Acceptance of P4.4 (the Attack Trees panel) — on fixture tree data (a test fixture writes `AttackNode`/`AttackEdge` into memory); live demo data arrives in P5.3 without a reverse dependency P4.4 ← P5.3 | A mutual dependency P4.4 ↔ P5.3 (panel ← demo data; demo ← panel) would form a cycle against the linear milestone order (§2, §10.1); the panel is verified on a fixture in M4, the end-to-end check "the tree reaches the TUI" stays in P5.3 (T5.3.1) |
| RD-10 | The L0 pre-tool-call middleware hooks are confirmed against the pin (deepagents 0.7.41 → langchain 1.5.2): base class — `langchain.agents.middleware.AgentMiddleware`, hooks `wrap_tool_call`/`awrap_tool_call`, request — `langgraph.prebuilt.tool_node.ToolCallRequest` (fields `tool_call{name,args,id}`, `tool`, `state`, `runtime`); block — returning a `ToolMessage` without calling the handler. `GuardrailMiddleware` runs in the asynchronous `awrap_tool_call` variant, the synchronous hook is fail-closed (RuntimeError) | The hook name matched the arch §6.5/§19.1 assumption; swarmy runs only asynchronously (aiosqlite, Textual), so Enforcement is in `awrap_tool_call`, and the synchronous path is deliberately closed so as not to leave a tool without guardrails; `create_deep_agent(middleware=…)` and `SubAgent["middleware"]` accept a list of middleware (verified against the pin's sources, T1.4.5) |

---

## 5. Milestone 1 — "Foundation" (F0 + F1)

**Composition:** P1.1 skeleton and infrastructure · P1.2 shared memory · P1.3
events · P1.4 guardrails (pipeline+DSL) · P1.5 tool registry and module loader.

### M1 · Definition of Done
Inherits the F0 and F1 criteria (spec §12.3):

- [x] `pip install -e .` and `swarmy --help` work on all platforms of the CI matrix (F0)
- [x] smoke on Python 3.15 is green (runtime target, spec §11)
- [x] core unit tests are green; **the unit coverage gate ≥ 85% is active in CI** (D22; T1.5.6)
- [x] **a stub module is loaded** by the loader (F1; T1.5.5)
- [x] the event journal is append-only, delivery to subscribers is journal-first (T1.3.5)
- [x] the guardrail pipeline is deterministic (AND-composition), the DSL is validated fail-fast (T1.4.6)

---

### P1.1 · Phase "Package skeleton and infrastructure" (F0)

**Goal:** the repository builds, installs and is verified on all target platforms; quality tools are configured for D9/D22.
**Dependencies:** none (starting phase).
**Phase DoD:** the spec F0 criterion — installation + `swarmy --help` on all platforms.
**Tasks:** T1.1.1–T1.1.6.

#### T1.1.1 — Package metadata and dependencies
- **What:** `pyproject.toml` as the single source of the build: metadata, runtime/dev dependencies, entry point, tool configurations.
- **Where:** `pyproject.toml`, `uv.lock`.
- **How:** per arch §3.2: `[project] name = "swarmy"`, `license = "MIT"`, `requires-python = ">=3.11,<4.0"`; `[project.scripts] swarmy = "swarmy.cli:main"`; runtime deps: `deepagents>=0.7.41,<0.8` (D18), `pydantic>=2,<3` (D9), `httpx`, `textual`, `rich`, `jinja2>=3.1`, `aiosqlite`, `langgraph-checkpoint-sqlite` (AD-2); dev group: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `ty` (or `mypy` — the choice is fixed by this task), `aiohttp` (for the echo app fixtures). src-layout.
- **Acceptance criteria:**
  - [x] `uv lock` resolves the full graph; `uv.lock` is committed
  - [x] `uv run python -m swarmy --version` responds without importing the L0 stack
  - [x] the type-checker choice (ty or mypy) is fixed in `pyproject.toml` and here (in T1.1.3)

#### T1.1.2 — Package skeleton and CLI stub
- **What:** the `src/swarmy` tree per arch §3.1 with stub packages, `__version__`, `__main__.py` and an argparse CLI (no third-party CLI frameworks — P4).
- **Where:** `src/swarmy/**` (`core/`, `events/`, `memory/`, `tools/`, `guardrails/`, `modules/`, `report/`, `tui/`, `agents/`), `src/swarmy/cli.py`, `src/swarmy/__main__.py`, `agents/` (root — an example user directory).
- **How:** packages are created with docstring stubs; `cli.py` supports only `--version`/`--help` (the full syntax of arch §3.4 is added in T4.1.3).
- **Acceptance criteria:**
  - [x] `swarmy --version` and `--help` work on all platforms of the matrix
  - [x] the package composition matches arch §3.1 (checked against the list)
  - [x] test guard: CLI startup does not import `deepagents`/LangChain

#### T1.1.3 — Quality configuration
- **What:** ruff strict, ty/mypy strict, pytest (asyncio), coverage configuration for the two D22 thresholds.
- **Where:** `pyproject.toml` — sections `[tool.ruff]`, `[tool.ty]`/`[tool.mypy]`, `[tool.pytest.ini_options]`, `[tool.coverage.*]`.
- **How:** ruff — a strict set in the spirit of upstream deepagents: `Any` forbidden (`ANN401`), mandatory annotations, `I`/`UP`/`B`; type checker strict: `disallow_any_explicit`, `disallow_untyped_defs`, `warn_return_any`; pytest: `asyncio_mode = "auto"`, markers `unit`/`integration`; coverage: two sources (`tests/unit` → 85, `tests/integration` → 70), `exclude_lines` — spot only (activation of the CI commands: T1.5.6 and T2.4.3).
- **Acceptance criteria:**
  - [x] `ruff check src tests` and the type checker are clean on the skeleton
  - [x] `uv run pytest -m unit` and `-m integration` run (0 tests is acceptable)
  - [x] the coverage configuration contains both thresholds and the exclusion policy

#### T1.1.4 — Smoke on Python 3.15
- **What:** confirmation of the spec §11 runtime target: installation and launch on Python 3.15.
- **Where:** CI workflow (a separate job), `uv.lock`, `pyproject.toml` (minimum versions).
- **How:** job: `uv sync` under 3.15 → `swarmy --version`; the deepagents classifiers declare up to 3.14 — the smoke confirms actual compatibility (spec §11); the minimum versions of the remaining dependencies are fixed from the result (arch §19.3).
- **Acceptance criteria:**
  - [x] the Py3.15 smoke job is green in CI
  - [x] the minimum versions in `pyproject.toml` match the smoke results
  - [x] if the smoke is red — an issue is filed in §12 of the roadmap (defect procedure)

#### T1.1.5 — Platform CI matrix
- **What:** GitHub Actions: 4 OS/arch combinations + quality steps; the scaffold for the later coverage gates.
- **Where:** `.github/workflows/ci.yml`.
- **How:** matrix `windows/amd64`, `macos/arm64`, `linux/amd64`, `linux/arm64`; steps: `uv sync` → ruff → type checker → `pytest -m unit` → `pytest -m integration` → smoke `swarmy --version`; uv cache; the coverage-gate commands are added by tasks T1.5.6/T2.4.3, the Py3.15 job by task T1.1.4.
- **Acceptance criteria:**
  - [x] CI is green on all four OS/arch combinations
  - [x] the matrix config accepts the T1.1.4/T1.5.6/T2.4.3 jobs without duplicating steps (reusable composite/anchor)

#### T1.1.6 — README and LICENSE
- **What:** MIT license and a public liability disclaimer (D15, spec §8.6).
- **Where:** `README.md`, `LICENSE`.
- **How:** disclaimer: a tool for **authorized** testing, responsibility lies with the operator; a brief project description; a link to `docs/development`; installation from sources (git install is described in P5.5).
- **Acceptance criteria:**
  - [x] `LICENSE` — MIT
  - [x] README contains the disclaimer about responsibility and the legality of testing
  - [x] README describes installation and building from sources

---

### P1.2 · Phase "Shared memory" (F1)

**Goal:** domain models (leaf), the SQLite schema of the single session file, a typed store and full-text search.
**Dependencies:** P1.1 (skeleton; the `core/database` scaffold is created here).
**Phase DoD:** schema+FTS5 and MemoryStore are covered by unit tests (contribution to the unit gate T1.5.6).
**Tasks:** T1.2.1–T1.2.6.

#### T1.2.1 — Domain models (`memory/models.py`)
- **What:** Pydantic v2 models of all domain entities — the single place of domain types, a leaf module (arch §2.5, §4.1).
- **Where:** `src/swarmy/memory/models.py`.
- **How:** enums: `Severity` (mandatory on Finding, D14), `FindingStatus`, `FindingType` (xss/sqli/auth — an open set), `EvidenceKind` (`http_request_response`; `screenshot`/`har`/`grpc_file` are reserved — D20); models: `Target`, `ScopeEntry` (kind/value/origin), `Endpoint` (host:port, method, path, auth_requirements, research_status, out_of_scope, notes), `Parameter`, `Finding` (severity mandatory, cvss optional, endpoint_ref, evidence_refs, reproduction, created_by/at), `Evidence`, `AttackNode` (kind: precondition/finding/goal), `AttackEdge` (requires/enables/leads_to), `Note`, `Fact`; references between entities — `int` ids, no nested graphs (arch §4.2); imports — only pydantic + stdlib.
- **Acceptance criteria:**
  - [x] architectural test: the module does not import other swarmy packages
  - [x] the field composition matches arch §4.2 (checked against the model)
  - [x] `EvidenceKind` contains 4 values; only `http_request_response` is produced in v0.1 (D20)
  - [x] the type checker is clean in strict mode

#### T1.2.2 — DB wrapper (`core/database.py`)
- **What:** `Database` — connection management for the single `memory.sqlite` file, WAL, migrator.
- **Where:** `src/swarmy/core/database.py`.
- **How:** aiosqlite; one connection per subsystem (AD-6), WAL, `busy_timeout = 5000`, `foreign_keys = ON`; migrator: `schema_migrations(version, applied_at)` + a sequential list of `(version, ddl)` pairs, applied in a transaction on `Session.open()` (startup — T3.1.2); a repeated open with the same version is a no-op; resume with a matching version skips migrations (arch §13.1); the L0 checkpointer tables are outside our DDL (created by the checkpointer).
- **Acceptance criteria:**
  - [x] fresh file: WAL/busy_timeout/foreign_keys pragmas are applied (test)
  - [x] migrations are applied in a transaction, the version is recorded; a repeated open is idempotent
  - [x] an attempt to open a session directory with a newer schema — an explicit error (a message about the version)
#### T1.2.3 — SQLite schema (`memory/schema.py`)
- **What:** DDL of all tables of the single memory file: 10 domain tables, `events`, 4 FTS5 + synchronization triggers, `schema_migrations`.
- **Where:** `src/swarmy/memory/schema.py`.
- **How:** arch §4.3 rules: multi-valued fields (`tags`, `examples`, `evidence_refs`) — JSON strings; `events.payload` — JSON of the payload model, `events.ts` — UTC ISO-8601; all domain tables — `id INTEGER PRIMARY KEY AUTOINCREMENT`; FTS5 tables `fts_endpoints/fts_findings/fts_facts/fts_notes` (title/body columns) with `AFTER INSERT/UPDATE` triggers; ownership: domain — MemoryStore, `events` — JournalWriter (append-only), fts — SearchIndex; a single migrator (RD-8).
- **Acceptance criteria:**
  - [x] migrations create all tables from arch §4.3 (checked against the list)
  - [x] triggers: insert/update of Endpoint/Finding/Fact/Note synchronously updates the corresponding fts table (unit test)
  - [x] the DDL does not create L0 checkpointer tables (their owner is the checkpointer)

#### T1.2.4 — Search (`memory/search.py`)
- **What:** the `SearchIndex` interface (Protocol) + the `Fts5SearchIndex` implementation.
- **Where:** `src/swarmy/memory/search.py`.
- **How:** Protocol per arch §4.5 (`index_up`, `search`); FTS5 implementation: bm25 + title match boosting, filter by entity types, `limit`; backend choice — the config key `memory.search_backend` (`vec`/sqlite-vec — phase 2, not implemented, the interface already allows it — P4: two implementations are not required, but the abstraction is in place).
- **Acceptance criteria:**
  - [x] on fixture data the search returns relevant hits; a title match ranks higher (test)
  - [x] the `entity_types` filter works
  - [x] clients use only the Protocol (architectural test: no direct FTS access outside SearchIndex)

#### T1.2.5 — Store (`memory/store.py`)
- **What:** `MemoryStore` — typed CRUD per the API table in arch §4.4.
- **Where:** `src/swarmy/memory/store.py`.
- **How:** methods: `search`, `get`, `upsert_endpoint` (dedup by `(host, method, path)`, parameters are appended), `save_finding` (validation that `evidence_refs` exist), `update_finding_status`, `link_attack_node` (node + edges atomically), `add_fact`, `add_note`, `list_endpoints`, `list_findings`; `SearchHit` = `{entity_type, id, title_snippet, score}`; the store **does not import** events/tools/tui (arch §2.5): platform events (`EndpointsDiscovered`/`EndpointUpdated`) are published by the `tools/platform.py` wrappers (T1.2.6) after a successful mutation — arch §5.2 "the event is created by the platform".
- **Acceptance criteria:**
  - [x] all arch §4.4 methods are implemented with the declared signatures
  - [x] a repeated `upsert_endpoint` updates the record, does not duplicate it (test)
  - [x] `save_finding` with a non-existent `evidence_ref` — a validation error (test)
  - [x] `link_attack_node` creates the node and edges atomically (rollback test on an edge error)
  - [x] architectural test: the store does not import events/tools/tui

#### T1.2.6 — Platform `memory_*` wrappers (`tools/platform.py`)
- **What:** the tools `memory_search/get/upsert_endpoint/save_finding/link_attack_node/add_fact/add_note` and the platform `update_finding_status` (arch §4.4, §6.1).
- **Where:** `src/swarmy/tools/platform.py`.
- **How:** tool functions with full typing and docstring descriptions; argument validation with Pydantic models before the store call (arch §4.4); after a successful mutation — publication of a platform event (payload per arch §5.5); the tools receive `SessionContext` from the factory closure (arch §8.5) — there are no direct imports of the core from tool functions.
- **Acceptance criteria:**
  - [x] every tool validates arguments with models (negative tests)
  - [x] `upsert_endpoint` publishes `EndpointsDiscovered`/`EndpointUpdated` with correct payloads (test)
  - [x] `update_finding_status` publishes `FindingVerified`/`FindingRejected` according to the new status (test)
  - [x] all signatures are fully typed, docstrings are non-empty (checked by the loader validator from T1.5.3)

---

### P1.3 · Phase "Events: models, bus, journal" (F1)

**Goal:** the v0.1 event taxonomy, type registry, append-only journal, bus with journal-first ordering, the `emit_event` factory.
**Dependencies:** P1.2 (payload models reference domain ids; the `events` schema from T1.2.3).
**Phase DoD:** bus/journal are covered by unit tests: ordering, filtering, error isolation, catch-up reading.
**Tasks:** T1.3.1–T1.3.5.

#### T1.3.1 — Envelope, payload models, registry (`events/models.py`)
- **What:** `EventEnvelope`, `EventSource`, payload models of the v0.1 taxonomy and `EventRegistry`.
- **Where:** `src/swarmy/events/models.py`.
- **How:** envelope per arch §5.1: `id` (journal PK), `ts` (UTC), `type`, `source` (platform/orchestrator/module), `source_detail`, `correlation_id` ("" outside chains), `payload` (a typed model); payload models of all 13 §5.5 types (TargetSet, ScopeChanged, EndpointsDiscovered, EndpointUpdated, FindingCandidate, FindingVerified, FindingRejected, AttackTreeUpdated, GuardrailBlocked, TaskRequested, TaskCompleted, OperatorMessage, OperatorDecision) — domain entity identifiers + sanitized digests, no nested domain objects (arch §4.1); `EventRegistry.register/lookup` — the single place for "type name → payload class"; the built-ins are registered on package import. *(v0.1 note: the taxonomy has a 14th built-in type — `OutboundSecretWarn`, added after M2, see D27 in spec §13; the criteria below fix the state as of M2.)*
- **Acceptance criteria:**
  - [x] the registry contains all 13 types; each has a payload class (test)
  - [x] payload models contain no nested domain models (architectural test)
  - [x] re-registering a name — an error (protection against module type collisions)

#### T1.3.2 — Journal (`events/journal.py`)
- **What:** `JournalWriter` (append-only) and `JournalReader` (`tail`, `range`, `by_correlation`, `by_type`).
- **Where:** `src/swarmy/events/journal.py`.
- **How:** writer — INSERT only; `id` is assigned by SQLite (monotonic order is the basis of ordered delivery, arch §5.3); reader — the §5.4 methods; `payload` — JSON (format per arch §4.3); append-only is enforced at the API level (no mutations) + an optional guard trigger on UPDATE/DELETE of the `events` table.
- **Acceptance criteria:**
  - [x] append returns monotonic ids; read order = write order (concurrency test)
  - [x] the API provides no mutations; (if the trigger is introduced) UPDATE/DELETE fails at the DBMS level
  - [x] `by_correlation` reconstructs the chain on synthetic data (test)

#### T1.3.3 — Bus (`events/bus.py`)
- **What:** `EventBus` — an in-memory asyncio pub/sub with journal-first delivery order.
- **Where:** `src/swarmy/events/bus.py`.
- **How:** a queue per subscriber; journal-first: append to `events` before fan-out → delivery in ascending `id` order (arch §5.3); `subscribe(types: set[str] | None)`; handler error isolation (logging, delivery to the others continues); coalescing mode for the UI subscriber (merging updates: redundant redraws are collapsed, events are delivered in full).
- **Acceptance criteria:**
  - [x] under concurrent publication the subscriber receives events in ascending id order (test)
  - [x] an exception in one subscriber's handler does not interfere with the others (test)
  - [x] coalescing: N same-type events in the UI queue → one redraw, counters are correct (test)

#### T1.3.4 — The `emit_event` factory (`events/emit.py`)
- **What:** the `emit_event` tool function, bound to the session (bus, journal, correlation context).
- **Where:** `src/swarmy/events/emit.py`.
- **How:** the mechanics of arch §5.2: the arguments `{type, payload}` are validated by the registry (unknown type / invalid payload → a tool error to the agent); `source`/`source_detail` — on behalf of the calling subagent (the agent cannot forge the source); `correlation_id` — from the delegation context contextvar (filled by the runtime in T3.2.3; before that — ""); publication through the bus after the append to the journal.
- **Acceptance criteria:**
  - [x] an unknown type and an invalid payload are rejected with a clear error message (tests)
  - [x] the tool does not accept `source` from outside — the envelope assembles it itself (test)
  - [x] `correlation_id` is picked up from the contextvar (test with a set context)

#### T1.3.5 — End-to-end test "event → journal → subscribers"
- **What:** an end-to-end test of journal-first ordering and catch-up reading after resume.
- **Where:** `tests/integration/events/test_journal_flow.py`.
- **How:** N concurrent publications → N rows in the journal in id order; subscribers received them in ascending id order; resume simulation: a new reader with `range(from_id)` reads the tail (arch §5.4).
- **Acceptance criteria:**
  - [x] the test is green on real SQLite (not mocks)
  - [x] fixed as the canonical example of the "durability before delivery" property (arch §5.3)

---

### P1.4 · Phase "Guardrails: pipeline and DSL" (F1)

**Goal:** a deterministic pre-tool-call pipeline (3 layers, AND-composition) + the declarative `guardrails.yaml` DSL; the judge slot is reserved (connected in P3.4, RD-2).
**Dependencies:** P1.3 (the `GuardrailBlocked` event), P1.2 (domain models are not needed in predicates, but the pipeline lives on tool arguments).
**Phase DoD:** the guardrail unit set is green (the test scaffold of arch §15.1).
**Tasks:** T1.4.1–T1.4.6.
#### T1.4.1 — Rule types (`guardrails/models.py`)
- **What:** models of rules, verdicts and risk classes.
- **Where:** `src/swarmy/guardrails/models.py`.
- **How:** `RuleCondition` — the 5 v0.1 predicates: `any_param_matches`/`url_matches`/`header_matches`/`body_size_above`/`tool_in` (conjunction of predicates, inside `any_param_matches` — a disjunction, arch §6.6); `GuardrailRule` (id, applies_to, condition, `action: Literal["block"]` — v0.1, severity, message); `ModuleGuardrails` (`tool_classes` + `rules`); `Verdict` (allow/block/escalate_hitl/flag), `BlockedFeedback` (rule_id, layer, reason); `RiskClass` (passive/network-write/verify/destructive) lives here so that `tools.*` imports it without a cycle (arch §2.5, AD-7).
- **Acceptance criteria:**
  - [x] the models match arch §6.6 (checked)
  - [x] architectural test: `tools.*` imports `RiskClass` from guardrails without a dependency cycle
  - [x] the type checker is clean in strict mode

#### T1.4.2 — The `guardrails.yaml` DSL (`guardrails/dsl.py`)
- **What:** parsing and validation of the module rules file.
- **Where:** `src/swarmy/guardrails/dsl.py`.
- **How:** YAML → `ModuleGuardrails` (Pydantic); fail-fast — a list of ALL file problems at once (arch §4.5); compilation of all regexes during validation; id uniqueness check; matching `applies_to` against the ToolRegistry — available from P1.5, before that a structural check of names.
- **Acceptance criteria:**
  - [x] the spec §8.3 example (`no-true-based-sqli`) parses without errors
  - [x] a file with three different errors yields three entries in the report (test)
  - [x] an invalid regex is rejected at the validation stage (test)

#### T1.4.3 — Layer 1: invariants (`guardrails/invariants.py`)
- **What:** platform invariants — the non-disableable pipeline layer.
- **Where:** `src/swarmy/guardrails/invariants.py`.
- **How:** code-constant rules with `invariant:*` identifiers: `platform-http` (network only through the platform client — arch §6.5); stub slots for `scope`/`limits`/`timeout`/`out-of-scope-target`, connected to real checks in P2.1 (T2.1.3); evaluation — on the arguments before the network; the invariants are absent from the config schema.
- **Acceptance criteria:**
  - [x] the invariants are not configurable (the config slot is absent — a config schema test after T3.1.1)
  - [x] the `platform-http` rule fires on a tool outside the platform http set with network behavior (test with a fake "network" tool)
  - [x] the source of all layer rules is the `invariant:` prefix (test)

#### T1.4.4 — Layer 2: basic engine rules (`guardrails/engine_rules.py`)
- **What:** a shipped, disableable set of default rules.
- **Where:** `src/swarmy/guardrails/engine_rules.py`.
- **How:** the default set (arch §6.6): `no-true-based-sqli` (the spec §8.3 example), blocking the `TRACE`/`CONNECT` methods, blocking known dangerous payloads; disabling the set — a pipeline parameter (in the config — the `guardrails.engine_rules` key, read from T3.1.1; before that — an assembly argument).
- **Acceptance criteria:**
  - [x] TRUE constructs are caught on `http_get`/`http_post` (a parameterized test following the spec §8.3 example)
  - [x] `TRACE`/`CONNECT` are blocked (test)
  - [x] the set is disableable by a flag: on/off changes the verdict (test)

#### T1.4.5 — Pipeline (`guardrails/pipeline.py`)
- **What:** `GuardrailPipeline` + `GuardrailMiddleware` — the L0 pre-tool-call extension point.
- **Where:** `src/swarmy/guardrails/pipeline.py`.
- **How:** layers 1→2→3, AND-composition: a deny from any layer denies, an allow requires all (D11, arch §6.5); layer 3 — the module rules for its tools; the judge slot is reserved (P3.4); violation semantics (spec §8.5, arch §6.5): the call is not executed; `GuardrailBlocked` to the journal+bus (payload per arch §5.1 with `tool_args_digest`); the agent receives textual feedback (rule id, layer, reason); for a subagent the middleware = invariants+engine+the rules of its module, for the orchestrator = invariants+engine; the argument digest in M1 is trivial truncation, replaced with ContextProjector in T2.3.2 (RD-4); the L0 middleware hook names are verified against the sources of the 0.7.41 pin (arch §19.1).
- **Acceptance criteria:**
  - [x] composition matrix: each layer blocks independently; an allow requires all (parameterized test)
  - [x] on a block: the tool is not called (spy), `GuardrailBlocked` in the journal and the bus, the agent received feedback with rule_id/layer (test)
  - [x] the actual L0 middleware hook names are confirmed; the divergence is recorded in §12 of the roadmap

#### T1.4.6 — Guardrail unit set
- **What:** the pipeline test scaffold per arch §15.1: DSL, layers, composition, feedback.
- **Where:** `tests/unit/guardrails/`.
- **How:** parameterized composition matrices, negative DSL files, spy checks of the violation semantics; mock tools instead of the network.
- **Acceptance criteria:**
  - [x] the set covers all arch §6.5–§6.6 rules; green; no `xfail` without a ticket
  - [x] contribution to the unit gate ≥ 85% for `guardrails/` (local check with `pytest --cov`)

---

### P1.5 · Phase "Tool registry and module loader" (F1)

**Goal:** fail-fast loading of declarative modules: manifest, tool import, module guardrails, assembly of SubAgent dicts (RD-3: ToolRegistry lives here).
**Dependencies:** P1.4 (GuardrailMiddleware in the subagent dict), P1.3 (EventRegistry for checking `events`), P1.2 (platform `memory_*` in the toolset).
**Phase DoD:** a stub module loads (the F1 criterion); unit gate ≥ 85% active in CI.
**Tasks:** T1.5.1–T1.5.6.

#### T1.5.1 — Tool registry (`tools/registry.py`)
- **What:** `ToolRegistry` — names, risk classes, owners, collisions.
- **Where:** `src/swarmy/tools/registry.py`.
- **How:** `ToolEntry{fn, risk_class, owner, source}`; owner: `platform` | module name; source: `builtin` | `module:<dir>` (arch §6.1); the reserved prefixes `memory_*`/`event_*`/`session_*` are forbidden to modules; platform tools are available to every subagent (the loader includes them in the toolset — arch §6.1); collisions — fail-fast with an aggregated list; risk_class — from the `swarmy_risk_class` attribute (default `passive`, AD-7); auto-classification of http tools — in P2.2 (T2.2.3).
- **Acceptance criteria:**
  - [x] registering a duplicate name and a prefix violation yield an aggregated error (test)
  - [x] risk_class is taken from `swarmy_risk_class`, default passive (AD-7 test)
  - [x] the registry distinguishes owner/source (test)

#### T1.5.2 — Manifest (`modules/manifest.py`)
- **What:** `AgentModuleManifest` + `AGENT.md` parsing.
- **Where:** `src/swarmy/modules/manifest.py`.
- **How:** arch §8.2 fields: `name`, `description` (mandatory), `model`, `mode`, `interrupt_on`, `events`, `guardrails`, `result` (AD-3: the path `"<module>/tools/result.py:Class"` → `response_format`); the body below the frontmatter → `system_prompt`; strict YAML: unknown fields — an error; skills/tools are not declared in the frontmatter (the loader connects the directories automatically).
- **Acceptance criteria:**
  - [x] a minimal manifest (name+description) is valid (test)
  - [x] the `result` field format is recognized (without importing the class — the import happens in the loader)
  - [x] an unknown field / bad type — a precise validation error (test)

#### T1.5.3 — Loader (`modules/loader.py`)
- **What:** `ModuleLoader` — scanning, import, validation, assembly of SubAgent dicts.
- **Where:** `src/swarmy/modules/loader.py`.
- **How:** the arch §8.3 pipeline: scan (user directories + built-in modules: `<package>/agents` in a wheel or `<repo>/agents` in an editable checkout); import of `tools/*.py` via `importlib.util.spec_from_file_location` (not into `sys.path`); runtime type check (`typing.get_type_hints`: `Any`/`dict[str, Any]`/unannotated parameters forbidden, docstring mandatory); parsing `guardrails.yaml` (T1.4.2); registration of module event models from `tools/event_models.py`; fail-fast — a single list of problems across ALL modules → `ModuleLoadError` (session start aborted); dict assembly: `name, description, system_prompt, model, mode, tools=[platform+module], middleware=[GuardrailMiddleware(...)], interrupt_on=merge(profile, manifest), skills=["/module-skills/<name>/"] (the virtual composite route — never a disk path, AD-10/D43), response_format`; static analysis of module imports: `socket`/`urllib`/`http.client` — an error (arch §8.5); a name collision with a built-in — an error without override (AD-4).
- **Acceptance criteria:**
  - [x] a fixture module with valid AGENT.md/tools/guardrails.yaml loads; the dict matches arch §8.3 (keys checked)
  - [x] five kinds of violations (no docstring; `Any` annotation; reserved prefix; network import; unregistered event type) — each yields a precise line in the aggregated error (tests)
  - [x] an error in one module does not interrupt collecting the problem list for the others (test)

#### T1.5.4 — Module registry (`modules/registry.py`)
- **What:** `ModuleRegistry` — module names and verification of event declarations.
- **Where:** `src/swarmy/modules/registry.py`.
- **How:** name → module; the frontmatter `events` are matched against `EventRegistry` (arch §8.4); the runtime check of emit against the registry is already in T1.3.4 — here the "declared = registered" check is connected.
- **Acceptance criteria:**
  - [x] a declared but unregistered type — a load error (test)
  - [x] emitting a type not declared in the manifest — a tool error to the agent (test, interface with T1.3.4)

#### T1.5.5 — Stub module and load smoke
- **What:** a minimal fixture module + a load end-to-end test (the F1 criterion).
- **Where:** `tests/fixtures/modules/dummy/` (AGENT.md + tools/), `tests/integration/modules/test_loader_smoke.py`.
- **How:** dummy: name/description frontmatter + one trivial typed tool; test: loader assembly → dummy in the registry → SubAgent dict assembled → no fail-fast errors; the fixture becomes the template for M3/M5 modules.
- **Acceptance criteria:**
  - [x] the spec F1 criterion "a stub module loads" is met in CI
  - [x] the fixture structure is documented as the user module template (a comment in the fixture)

#### T1.5.6 — Activation of the coverage unit gate (D22)
- **What:** the unit ≥ 85% threshold is enabled in CI as a separate command.
- **Where:** `.github/workflows/ci.yml`, `[tool.coverage.*]`.
- **How:** the command `pytest tests/unit --cov=swarmy --cov-fail-under=85`; exclusions — only spot `pragma: no cover` recorded in `exclude_lines`; blanket-omit is forbidden (D22); the threshold is computed for this set separately (arch §15.1).
- **Acceptance criteria:**
  - [x] CI contains a separate unit run command with `--cov-fail-under=85`
  - [x] the threshold actually works: a local run with a lowered threshold fails (the manual check is recorded in the PR)
  - [x] the current set is ≥ 85% for `src/swarmy`; exclusions are spot and listed in the config

---

## 6. Milestone 2 — "Execution Perimeter" (F2)

**Composition:** P2.1 scope and limits · P2.2 HTTP client and evidence · P2.3 ContextProjector and secrets · P2.4 echo app and the integration loop.

### M2 · Definition of Done

Inherits the F2 criterion (spec §12.3):

- [x] against the echo app: out-of-scope requests are blocked, evidence is written, budgets/masking in `ContextProjector` work
- [x] **the ≥ 70% coverage integration gate is active in CI** (D22; T2.4.3)
- [x] all 10 arch §16 invariants — the perimeter-dependent ones (1, 4, 7) — are confirmed by tests

---

### P2.1 · Phase "Scope and Limits" (F2)

**Goal:** target allowlist and session-global resource limits; wiring the invariants into the pipeline.
**Dependencies:** P1.4 (invariant layer with slots — T1.4.3).
**Phase DoD:** scope matching and limiters are covered by unit tests; invariants block before the network.
**Tasks:** T2.1.1–T2.1.3.

#### T2.1.1 — ScopeRegistry (`tools/scope.py`)
- **What:** scope allowlist and target check for every network hop.
- **Where:** `src/swarmy/tools/scope.py`.
- **How:** the source is the config's `scope_entries`; `check(url) → ScopeVerdict(allowed | denied(reason))`; matching semantics (arch §6.3): domain — exact name or a subordinate subdomain (`example.com` covers `*.example.com`), IP — `ipaddress` subnets, ports — an explicit list (default 80/443 by scheme), schemes — an allowlist; `extend()` — only with `origin = operator` (publishing `ScopeChanged` is the platform HITL loop, integrated in P3.3); memory records with `out_of_scope=True` are not served to network tools (`invariant: out-of-scope-target`).
- **Acceptance criteria:**
  - [x] matching matrix: subdomain yes/no, CIDR, default port, scheme — parameterized tests
  - [x] the `extend()` API requires `origin=operator` (test: programmatic extension without an operator is impossible)
  - [x] a request to an endpoint with `out_of_scope=True` — block `invariant: out-of-scope-target` (test)

#### T2.1.2 — ResourceLimiter (`tools/limits.py`)
- **What:** session-global resource limits.
- **Where:** `src/swarmy/tools/limits.py`.
- **How:** the mechanisms of arch §6.4: token bucket per host (`rate_limit`), a global `asyncio.Semaphore` (`max_concurrent_requests`), `max_body_bytes` truncation on read, a `max_redirect_depth` counter (used by the client), an atomic `total_request_budget` (exhaustion → denial of all network calls + `GuardrailBlocked(invariant: budget)`), connect/read timeouts; `acquire(host, method)` — an async context; the limits are **session-global** — the limiter knows nothing about subagents (D19, arch §16 invariant 7).
- **Acceptance criteria:**
  - [x] rps per host is respected under parallel calls (test with interval measurement)
  - [x] total concurrent requests ≤ `max_concurrent_requests` at any moment (counter test)
  - [x] budget exhaustion blocks new calls and publishes `invariant: budget` (test)
  - [x] waiting for the semaphore/rate does not block the event loop (async test)

#### T2.1.3 — Wiring up the scope/limits invariants
- **What:** layer 1 gets real checks instead of the T1.4.3 slots.
- **Where:** `src/swarmy/guardrails/invariants.py`.
- **How:** the rules `invariant: scope`, `invariant: limits`, `invariant: out-of-scope-target`, `invariant: timeout`; evaluation strictly before the network call (pipeline order per arch §6.2: guardrails → limiter → httpx); events — `layer="invariant"`.
- **Acceptance criteria:**
  - [x] an out-of-scope request is blocked with `layer=invariant` before the connection is opened (unit test on a mock transport)
  - [x] invariants fire before `ResourceLimiter.acquire` (pipeline-order test)

---

### P2.2 · Phase "HTTP client and evidence" (F2)

**Goal:** the single network path with the arch §6.2 pipeline: guardrails → limits → httpx (manual redirects) → evidence → projection.
**Dependencies:** P2.1 (scope/limits in the pipeline), P1.4 (GuardrailPipeline).
**Phase DoD:** the client pipeline is covered by unit tests on a mock transport; integration scenarios are in P2.4.
**Tasks:** T2.2.1–T2.2.4.

#### T2.2.1 — HTTP models (`tools/http/models.py`)
- **What:** `RequestSpec` and `ResponseRecord`.
- **Where:** `src/swarmy/tools/http/models.py`.
- **How:** the fields of arch §6.2: `RequestSpec` — `method: Literal[GET, HEAD, POST, PUT, PATCH, DELETE]`, `url: HttpUrl`, `headers`, `query`, `body`, `evidence: bool = True`, `evidence_depth: Literal[request, request_response]`; `ResponseRecord` — `status`, `reason`, `headers`, `body_preview` (an already sanitized projection), `body_bytes`, `elapsed_ms`, `redirects: list[str]`, `evidence_id`, `request_id` (correlation).
- **Acceptance criteria:**
  - [x] the models match arch §6.2 (cross-check)
  - [x] an invalid method — a Pydantic validation error (test)

#### T2.2.2 — SwarmyHttpClient (`tools/http/client.py`)
- **What:** the pipeline of every network call.
- **Where:** `src/swarmy/tools/http/client.py`.
- **How:** the arch §6.2 pipeline: `GuardrailPipeline.allow?` → `ResourceLimiter.acquire(host, method)` → `httpx.AsyncClient` (`redirects=False`) → **manual redirect loop**: every hop — a repeated pass through scope+limits with a depth counter; a cross-domain redirect outside the scope = `GuardrailBlocked` → `EvidenceRecorder` (if `evidence=True`) → projection (until T2.3.2 — a raw preview truncated by `max_body_bytes`; afterwards — ContextProjector) → `ResponseRecord`; timeouts from the limits; a violation = `TimeoutError` → `GuardrailBlocked(invariant: timeout)` + feedback to the agent; outbound hygiene: a secret detector in headers/body → a warn event + masking in the preview (a warn does **not** block — the operator passed the credentials deliberately).
- **Acceptance criteria:**
  - [x] every redirect hop passes through scope/limits (unit test on a mock chain; integration chains — T2.4.2)
  - [x] a timeout returns feedback to the agent and writes `invariant: timeout` to the journal (test)
  - [x] a secret in outbound traffic → a warn event, the call is not blocked, the preview is masked (test)
  - [x] an out-of-scope call does not open a connection (mock transport, test)

#### T2.2.3 — HTTP tools (`tools/http/tools.py`)
- **What:** the platform `http_get/http_post/http_put/http_delete`.
- **Where:** `src/swarmy/tools/http/tools.py`.
- **How:** thin wrappers over `client.request(RequestSpec)`; automatic risk classification by HTTP method (AD-7): GET/HEAD → `passive`, POST/PUT/PATCH/DELETE → `network-write`; registration in ToolRegistry with `owner=platform`; the client supports all 6 Literal methods, there are four named platform wrappers (arch §6.1).
- **Acceptance criteria:**
  - [x] risk classes are assigned by method (registry test)
  - [x] the tools pass through GuardrailPipeline (out-of-scope block before the network — test)

#### T2.2.4 — EvidenceRecorder (`tools/http/evidence.py`)
- **What:** session evidence files + `Evidence` records.
- **Where:** `src/swarmy/tools/http/evidence.py`.
- **How:** `evidence/<uuid>/request.txt` + `response.txt` — raw, in full (the body up to the `max_body_bytes` threshold, then a truncation marker); an `Evidence` record (`kind=http_request_response`, `session_paths`, metadata: ts, tool, correlation_id); depth `request` | `request_response` — by `evidence_depth` (D20: other kinds are reserved; v0.1 produces only those listed).
- **Acceptance criteria:**
  - [x] evidence files match the traffic byte-for-byte up to the threshold (test)
  - [x] the Evidence record is linked to `ResponseRecord.evidence_id` (test)
  - [x] `depth=request` does not write `response.txt` (test)

---

### P2.3 · Phase "ContextProjector and secrets" (F2)

**Goal:** a sanitized projection of the LLM context (D21) and sealing of secrets (AD-5).
**Dependencies:** P2.2 (HTTP response previews), P1.3 (event digests).
**Phase DoD:** the four projection steps are covered by unit tests; secrets do not leave the session perimeter.
**Tasks:** T2.3.1–T2.3.3.

#### T2.3.1 — ContextProjector (`tools/projector.py`)
- **What:** sanitization of everything returned to the model.
- **Where:** `src/swarmy/tools/projector.py`.
- **How:** the four steps of arch §6.8 in order 1→4: (1) byte budgets by tool class (`context.budgets`) — truncation with the `[truncated N bytes]` marker, the full content stays in evidence; (2) masking of operator secrets — values/patterns from `secrets.yaml` + built-in detectors (Authorization/Cookie-like headers, bearer tokens) → `<masked:secret-name>`; (3) untrusted marking — `[untrusted-target-content begin] ... [untrusted-target-content end]`; (4) normalization of control characters and hidden Unicode (biDi, zero-width).
- **Acceptance criteria:**
  - [x] every step is covered by a unit test; marker formats match arch §6.8 verbatim
  - [x] the steps are applied in the order of §6.8 (chain test)
  - [x] detections: bearer, Cookie, Authorization are masked; ordinary values are not (tests)

#### T2.3.2 — ProjectorMiddleware and digests
- **What:** post-tool-call projection of the results of all agents + moving digests over to the projector.
- **Where:** `src/swarmy/tools/projector.py`, `src/swarmy/guardrails/pipeline.py` (replacing the digest), `src/swarmy/events/` (payload digests).
- **How:** `ProjectorMiddleware` (post-tool-call hook of L0, arch §19.1 — names are verified) for every agent: the orchestrator and subagents; `GuardrailBlocked.tool_args_digest` and journal digests — through ContextProjector (closing RD-4); HTTP response previews — through the projector (replacing the T2.2.2 stub).
- **Acceptance criteria:**
  - [x] the result of any tool goes through projection (integration test: large body + secret)
  - [x] RD-4 regression test: the digest in `GuardrailBlocked` masks secrets
  - [x] the names of the L0 post-tool-call hooks are confirmed; any divergence goes to roadmap §12

#### T2.3.3 — Operator secrets
- **What:** `secrets.yaml` (chmod 600), references by name, non-disclosure guarantees.
- **Where:** `src/swarmy/core/config.py` (loading skeleton — integration with SessionConfig in T3.1.1), `src/swarmy/tools/projector.py`.
- **How:** AD-5/arch §12.3: secrets — a separate file (chmod 600), categories `auth_headers`/`cookies`/`tokens`; in the config and tools — addressed by name; they never get into `session.yaml`; into evidence — as is; into the journal/chat/context — only `<masked:secret-name>`; until T3.1.1 the projector takes patterns explicitly (constructor/tests).
- **Acceptance criteria:**
  - [x] file permissions 600 are set (POSIX test; the Windows limitation is documented)
  - [x] a scan of a test session: the raw value is present only in evidence files (test)
  - [x] the `session.yaml` snapshot contains no secret values (test; final check — T3.1.1)

---

### P2.4 · Phase "Echo app and the integration loop" (F2)

**Goal:** a fixture server and end-to-end perimeter scenarios; activation of the integration gate.
**Dependencies:** P2.1–P2.3 (the full pipeline).
**Phase DoD:** the F2 spec criterion is met; the ≥ 70% integration gate is active.
**Tasks:** T2.4.1–T2.4.3.

#### T2.4.1 — Echo app (`tests/fixtures/echo_app`)
- **What:** a controllable aiohttp server with reproducible behavior.
- **Where:** `tests/fixtures/echo_app/` (dev dependency group).
- **How:** the modes of arch §15.2: parameter echo (reflections for detectors), redirect chains (inside and outside the scope), large bodies, "slow" endpoints (timeouts), forms, sitemap, robots.txt; started on a free localhost port from a pytest fixture; the scope of test sessions points at it.
- **Acceptance criteria:**
  - [x] the fixture starts/stops in pytest without port conflicts (random port)
  - [x] every behavior mode is covered by a fixture smoke test
  - [x] `aiohttp` — dev group only: no runtime import (import test)

#### T2.4.2 — Perimeter integration scenarios
- **What:** end-to-end F2 checks against the echo app.
- **Where:** `tests/integration/http/`.
- **How:** scenarios: blocking of an out-of-scope request (direct + via redirect), byte-for-byte evidence recording, body budget and session budget, rate limit, timeout → `invariant: timeout`, masking in the preview, an `out_of_scope` endpoint is not served.
- **Acceptance criteria:**
  - [x] every scenario — a separate named test; green on the entire CI matrix
  - [x] the F2 criterion: out of scope is blocked, evidence is written, budgets/masking work (verified on the echo app)

#### T2.4.3 — Activating the integration gate (D22)
- **What:** the ≥ 70% integration threshold in CI as a separate command.
- **Where:** `.github/workflows/ci.yml`.
- **How:** `pytest tests/integration --cov=swarmy --cov-fail-under=70`; thresholds are computed per suite separately (D22; arch §15.1).
- **Acceptance criteria:**
  - [x] both CI commands (unit 85%, integration 70%) are green and independent
  - [x] locally removing the threshold makes the corresponding command fail (verified and recorded)

---

## 7. Milestone 3 — "Swarm and HITL" (F3)

**Composition:** P3.1 config, session, engine · P3.2 runtime and policies · P3.3 HITL · P3.4 LLM judge · P3.5 parallel delegations and the verification scenario.

### M3 · Definition of Done

Inherits the F3 criterion (spec §12.3) with the RD-6 caveat:

- [x] the "finding → verification" scenario runs through events (headless; T3.5.3)
- [x] parallel `task()` calls work with **global** session limits (T3.5.1)
- [x] the approval queue intercepts `destructive` calls and serves decisions (headless acceptance, T3.3.3; the UI modal — P4.3, RD-6)
- [x] the resume cycle: restarting the process restores interruptions and continues without losses (T3.3.3)
- [x] arch §16 invariants No. 2, 3, 5, 6, 8, 10 are confirmed by tests

---

### P3.1 · Phase "Config, session, engine" (F3)

**Goal:** the session composition root, YAML config with resolution, assembling the deep-agent (orchestrator) with a checkpointer, the system prompt.
**Dependencies:** P1.5 (loader and SubAgent dicts), P2.4 (perimeter — engine tools), P1.2–P1.3 (memory/events).
**Phase DoD:** `Session.open()` assembles all components on a single Database; the graph compiles and checkpoints.
**Tasks:** T3.1.1–T3.1.5.

#### T3.1.1 — SessionConfig (`core/config.py`)
- **What:** the session config schema, resolution, the `session.yaml` snapshot.
- **Where:** `src/swarmy/core/config.py`.
- **How:** the sections of arch §12.1: `target`, `scope`, `profile`, `mode`, `model`, `limits`, `memory.search_backend`, `context.budgets`, `guardrails.engine_rules`, `judge`, `policies`, `mcp_servers`, `agents_dirs` (AD-1: YAML); resolution per arch §12.2: CLI flags → file → profile → conservative defaults in code; the result — an immutable Pydantic object + a `session.yaml` snapshot in the session directory (for audit); integration of `secrets.yaml` loading (T2.3.3); errors — fail-fast as a list.
- **Acceptance criteria:**
  - [x] the arch §12.1 config example parses in full (test)
  - [x] the resolution priority is verified by tests (CLI beats the file, the file beats defaults)
  - [x] three config errors produce three report entries (fail-fast as a list)
  - [x] the `session.yaml` snapshot matches the applied configuration and contains no secrets (test)

#### T3.1.2 — Session (`core/session.py`)
- **What:** composition root: `open`/`resume`/`close`.
- **Where:** `src/swarmy/core/session.py`.
- **How:** the startup order per arch §13.1: Database → JournalWriter/EventBus/ScopeRegistry/ResourceLimiter/ToolRegistry → MemoryStore+SearchIndex → ModuleLoader → Engine → the `TargetSet` event → SessionView (the TUI facade — T4.1.1); Session owns all components, nobody creates them "on their own" (arch §2.2); resume: skipping migrations when the version matches, reading the journal to the end (`range`), restoring the interrupt queue (T3.3.3); close: checkpoint WAL, closing connections; a session is a portable folder (arch §3.3).
- **Acceptance criteria:**
  - [x] `open` creates all components on a single Database (ownership/uniqueness test)
  - [x] a repeated `open` of the same directory — an error; resume is a separate path (test)
  - [x] close finishes the WAL; a copied session directory opens "on another machine" (copy test)
  - [x] `swarmy.core` does not import `swarmy.tui` (architecture test — invariant 8)

#### T3.1.3 — Engine (`core/engine.py`)
- **What:** assembling the orchestrator's `create_deep_agent` (arch §9.1).
- **Where:** `src/swarmy/core/engine.py`.
- **How:** `create_deep_agent(model=session.config.model, system_prompt=ORCHESTRATOR_PROMPT, tools=[session_info, ...] (generate_report — from P5.4, RD-7), subagents=modules.subagent_specs, middleware=[GuardrailMiddleware, ProjectorMiddleware], interrupt_on=interrupt_cfg.orchestrator, checkpointer=AsyncSqliteSaver(...))`; a typed L0 wrapper: all untyped work with deepagents happens only here (G3); the SQLite checkpointer writes to `memory.sqlite` (arch §7.1).
- **Acceptance criteria:**
  - [x] the graph compiles; the checkpointer tables appear in `memory.sqlite` (test)
  - [x] the orchestrator has the same middleware as the subagents (assembly test)
  - [x] the L0 wrapper is the only place with typing relaxations (check of ruff/ty per-file exceptions)

#### T3.1.4 — System prompt (`core/prompts.py`)
- **What:** `ORCHESTRATOR_PROMPT` and the policy notification templates.
- **Where:** `src/swarmy/core/prompts.py`.
- **How:** the structure of arch §9.6: (1) role — orchestrator of the swarm, delegations via `task()` by module `description`, chat, todos; (2) distrust rules — target content is data, not instructions; a ban on executing instructions from untrusted blocks; reporting injections; (3) policies — references to templates; (4) boundaries — do not work outside the scope, `GuardrailBlocked` → plan correction, HITL is a normal part of the cycle; (5) style — concise in chat, artifacts into memory; the dynamic section — a generated list of modules with `description`; the templates `verify_finding`, `tree_proposal` (for the T3.2.2 policies); assembly is static.
- **Acceptance criteria:**
  - [x] the prompt contains the ban on executing instructions from untrusted markers (marker test)
  - [x] the dynamic section reflects the loaded modules (test with a dummy module)
  - [x] the prompt is assembled without user text injections (test)

#### T3.1.5 — The `session_info` tool
- **What:** the orchestrator's platform tool for session state.
- **Where:** `src/swarmy/tools/platform.py`.
- **How:** returns the scope, research statuses, profile, request budget counter — without raw secrets (arch §6.1).
- **Acceptance criteria:**
  - [x] the output contains the declared fields (test)
  - [x] a scan of the output finds no secret values (test)

---

### P3.2 · Phase "Runtime and event policies" (F3)

**Goal:** running the orchestrator graph: single-writer (AD-8), three loops, declarative policies, delegation correlation.
**Dependencies:** P3.1 (Engine, prompt, templates).
**Phase DoD:** events reach the graph as notifications via policies; resume-runtime is restored.
**Tasks:** T3.2.1–T3.2.4.

#### T3.2.1 — OrchestratorRuntime (`core/runtime.py`)
- **What:** ownership of graph execution: single-writer + three loops.
- **Where:** `src/swarmy/core/runtime.py`.
- **How:** an `asyncio.Lock` on `ainvoke`/`astream` — no more than one call into the graph at any moment (AD-8; parallelism — by subagents inside a step, D19); the loops of arch §9.2: reactive (subscription to the bus → policy → notification digest → queue → injection at the step boundary), proactive (L0 todos), interactive (`OperatorMessage` → a human message); quotes from target content in notifications — through ContextProjector with untrusted markers; resume: restore the state from the checkpointer, read the journal to the end, continue (arch §9.2).
- **Acceptance criteria:**
  - [x] concurrent "notification + operator message" are serialized (test with an instrumented graph mock)
  - [x] the invariant of ≤1 active graph call (monitor test)
  - [x] injections contain untrusted markers for target quotes (test)

#### T3.2.2 — Event policies
- **What:** the declarative "event → reaction" pipeline (arch §9.3).
- **Where:** `src/swarmy/core/runtime.py` (mechanics), `src/swarmy/core/prompts.py` (templates).
- **How:** the `policies` config (`on`, `action: notify_orchestrator | notify_tui | ignore`, `template`); the built-in defaults of arch §9.3: `FindingCandidate → notify_orchestrator(verify_finding)`, `FindingVerified/FindingRejected → notify_orchestrator(tree_proposal)`, `GuardrailBlocked → notify_orchestrator`, `ScopeChanged → notify_orchestrator`, `AttackTreeUpdated/Task* → notify_tui`; a policy only injects a notification — no delegations/tools from code (anti-pattern per arch §17).
- **Acceptance criteria:**
  - [x] `FindingCandidate` produces a notification from the `verify_finding` template (test)
  - [x] the defaults are active when the `policies` section is absent (test)
  - [x] architecture test: policy code does not call tools or `task()` directly

#### T3.2.3 — Delegation correlation
- **What:** `correlation_id` on subagent task chains (arch §9.4).
- **Where:** `src/swarmy/core/runtime.py`, `src/swarmy/events/emit.py` (the contextvar from T1.3.4).
- **How:** the runtime sets `correlation_id` in the contextvar when entering a subagent; events/evidence/metadata carry it; `TaskRequested`/`TaskCompleted` are published by the platform and link the call tree; `JournalReader.by_correlation` restores the trace (the basis of the Swarm Activity panel, arch §10.1).
- **Acceptance criteria:**
  - [x] events from a delegation carry its correlation_id (integration test with a dummy module)
  - [x] the `task()` tree is restored from the journal (`by_correlation` test)

#### T3.2.4 — Runtime resume behavior
- **What:** restoring the loop after a restart.
- **Where:** `src/swarmy/core/runtime.py`.
- **How:** on resume: restore the state from the checkpointer, read the journal to the end (`range(from_id)`), restore the interrupt queue (T3.3.3), continue execution (arch §9.2, §13.1).
- **Acceptance criteria:**
  - [x] integration test: interrupt → "restart" → continuation without losing events (together with T3.3.3)

---

### P3.3 · Phase "HITL: profiles and the approval queue" (F3)

**Goal:** persistent `interrupt_on` gates by tool class, a FIFO decision queue, the resume cycle, interactive/mission modes.
**Dependencies:** P3.2 (runtime), P2.3 (sanitized argument digests).
**Phase DoD:** a destructive call is intercepted by the queue; the decision is delivered to the right addressee; the interruption survives a restart (headless, RD-6).
**Tasks:** T3.3.1–T3.3.4.

#### T3.3.1 — Profiles → interrupt_on (`core/hitl.py`)
- **What:** `build_interrupt_config(profile, module_overrides)` (arch §7.2).
- **Where:** `src/swarmy/core/hitl.py`.
- **How:** the "class × profile" matrix (D5): `paranoid` — gates on everything except `passive`; `normal` (default) — on `verify` and `destructive`; `yolo` — only `destructive`; `allowed_decisions = [approve, edit, reject]` (the L0 `respond` is not used — arch §7.2); merge: a module's explicit `interrupt_on` replaces the profile entries (L0 behavior); changing the profile/mode — rebuilding the config and recompiling the graph (a documented L0 operation).
- **Acceptance criteria:**
  - [x] the matrix matches the arch §7.2 table (parameterized test)
  - [x] merge semantics: the module entry wins over the profile one (test)
  - [x] rebuilding on a different profile changes the set of gates (test)

#### T3.3.2 — ApprovalQueue
- **What:** the interrupt queue and submission of decisions (arch §7.3).
- **Where:** `src/swarmy/core/hitl.py`.
- **How:** polling `snapshot.interrupts` → FIFO `ApprovalRequest{request_id, interrupt_id, tool, args_digest (sanitized), rule/profile, origin}`; judge escalations — with `origin="judge"` (T3.4.x); `submit_decision(request_id, decision, edited_args?)` → `Command(resume={interrupt_id: decision})`; with `edit` — substitution of the modified arguments; the decision is published as `OperatorDecision` and gets into the journal; the queue does not block the other subagents (arch §7.3, spec §9.2).
- **Acceptance criteria:**
  - [x] FIFO with several parallel interruptions (test)
  - [x] the decision is delivered to the specific `interrupt_id` (test)
  - [x] `edit` substitutes the arguments; `reject` returns "rejected by the operator" feedback to the agent (tests)
  - [x] every step is recorded as `OperatorDecision` in the journal (test)

#### T3.3.3 — HITL resume cycle
- **What:** persistence of interruptions and the decision cycle (arch §7.1, §7.4).
- **Where:** `src/swarmy/core/hitl.py`.
- **How:** the proven L0 API: `graph.aget_state(config) → snapshot.interrupts` → `graph.ainvoke(Command(resume={...}))` → repeat until the interruptions are empty; the interrupt state — in the SQLite checkpointer, survives a process restart; the arch §7.4 invariant: after resume the tool goes through **the same** GuardrailPipeline — approve does not cancel invariants.
- **Acceptance criteria:**
  - [x] integration test: a destructive call is interrupted → "restart" → approve → the tool is executed and passes the guardrails again
  - [x] the queue empties; the journal contains the complete chain (interrupt → decision → execution)

#### T3.3.4 — interactive/mission modes
- **What:** mode gates on top of the profile and switching on the fly (arch §7.2, §9.5).
- **Where:** `src/swarmy/core/hitl.py`, `src/swarmy/core/runtime.py`.
- **How:** `interactive` — additional gates on significant forks (running tests of a vulnerability class, verification, scope change) via `interrupt_on`; `mission` — only the profile gates; switching — an operator command in the chat → rebuilding `interrupt_on` → recompiling the graph → an event to the journal.
- **Acceptance criteria:**
  - [x] the set of gates differs by mode (mode × class matrix test)
  - [x] switching on the fly applies the new gates (integration test) and writes an event to the journal

---

### P3.4 · Phase "LLM judge" (F3; RD-2)

**Goal:** an asynchronous "second look" with an asymmetry of authority: the judge adds restrictions and does not lift deterministic bans (D11).
**Dependencies:** P3.3 (HITL queue for escalations), P1.4 (the pipeline's judge slot).
**Phase DoD:** both judge lanes are covered by tests on a mock model; an escalation reaches the operator.
**Tasks:** T3.4.1–T3.4.3.

#### T3.4.1 — Pre-call lane (`guardrails/judge.py`)
- **What:** checking suspicious calls with a separate model before execution.
- **Where:** `src/swarmy/guardrails/judge.py`.
- **How:** the `judge.{tools, model, confidence_threshold, timeout_s}` config (arch §12.1); the call — only after the deterministic layers allow it and only for the classes from `judge.tools`; verdicts: `ok` → execution; `flag` → execution + a note in the journal; `escalate_hitl` (or a timeout — **fail-closed**) → the call is not executed, it is placed in the HITL queue with `origin="judge"`; asymmetry: the judge cannot lift a deterministic ban (arch §6.7, D11); there is no LLM in the critical path of a **ban** (anti-pattern per arch §17).
- **Acceptance criteria:**
  - [x] verdict matrix on a mock judge: ok/flag/escalate — three branches (tests)
  - [x] judge timeout → fail-closed into HITL (test)
  - [x] a call blocked by layers 1–3 never reaches the judge (spy test)

#### T3.4.2 — Post-call lane and JudgeEscalationRegistry
- **What:** asynchronous analysis of results and temporary gates on a tool class.
- **Where:** `src/swarmy/guardrails/judge.py`.
- **How:** suspicion heuristics (configurable patterns of instruction-like content in results) → an asynchronous judge outside the execution path; `flag` — a note in the journal/context; `escalate_hitl` — an event to the orchestrator + **temporary gates** `JudgeEscalationRegistry` on the tool class until the operator's decision; lifting — only via `OperatorDecision` (arch §6.7).
- **Acceptance criteria:**
  - [x] an escalation turns on temporary gates: subsequent calls of the class become HITL (test)
  - [x] `OperatorDecision` clears the registry (test of the approve/reject branches)
  - [x] post-call analysis does not block execution (async test)

#### T3.4.3 — Judge integration with HITL
- **What:** the end-to-end escalation path against the echo app.
- **Where:** `tests/integration/guardrails/test_judge_hitl.py`.
- **How:** a mock judge returns `escalate_hitl` → the request appears in ApprovalQueue with `origin="judge"` → the operator's decision → lifting the temporary gates; the journal contains the `judge:<verdict>` chain.
- **Acceptance criteria:**
  - [x] the scenario is green; the "escalation → queue → decision → lifting" path is confirmed by integration

---

### P3.5 · Phase "Parallel delegations and the verification scenario" (F3)

**Goal:** confirming async parallelism (D19) and the end-to-end reactive loop "finding → verification" (the F3 criterion).
**Dependencies:** P3.2–P3.4 (runtime, HITL, judge), P1.5 (fixture modules).
**Phase DoD:** the headless F3 criteria are met in the integration suite.
**Tasks:** T3.5.1–T3.5.3.

#### T3.5.1 — Parallel task() with global limits
- **What:** integration confirmation of D19 (arch §9.4).
- **Where:** `tests/integration/runtime/test_parallel_tasks.py`.
- **How:** N parallel `task()` calls in one graph step (fixture modules) against the echo app with small limits; measuring the actual concurrency and total pressure; the limiter is global — it knows nothing about subagents (T2.1.2).
- **Acceptance criteria:**
  - [x] actual concurrency > 1 is confirmed by measurement
  - [x] total rps/semaphore are not exceeded at any moment (test metrics)
  - [x] events of all tasks carry individual correlation_id

#### T3.5.2 — Multi-interrupts (arch §19.2)
- **What:** clarifying the behavior of `snapshot.interrupts` with several parallel `task()` calls.
- **Where:** `tests/integration/hitl/test_multi_interrupts.py`.
- **How:** several tasks of the verify class are interrupted simultaneously; the actual L0 behavior is recorded in a test comment (open question §19.2 of arch); the FIFO ApprovalQueue serves all requests.
- **Acceptance criteria:**
  - [x] the test documents the observed L0 behavior (a comment referencing arch §19.2) and passes
  - [x] all interruptions are served by the queue without losses

#### T3.5.3 — The "finding → verification" scenario (headless)
- **What:** the end-to-end reactive loop — the F3 criterion.
- **Where:** `tests/integration/scenarios/test_finding_verification.py`.
- **How:** a fixture crawler-like module → `EndpointsDiscovered` → the `notify_orchestrator` policy → the orchestrator (a scripted LLM mock) delegates the verification (RD-5: a repeated task of the detector module with safe payloads) → `memory_save_finding`/`update_finding_status` (platform) → `FindingVerified` → the `tree_proposal` policy; the trace by correlation_id.
- **Acceptance criteria:**
  - [x] the scenario is green headless (without TUI); the journal contains the complete chain by correlation_id
  - [x] the finding status is changed by the platform `update_finding_status` (not by the agent directly)
  - [x] the F3 criterion "scenario through events" is met (spec wording)

---

## 8. Milestone 4 — "Operator Console" (F4)

**Composition:** P4.1 TUI skeleton and facade · P4.2 information panels · P4.3 HITL modals (UI) and the F4 acceptance · P4.4 attack trees and masking.

### M4 · Definition of Done

Inherits the F4 criterion (spec §12.3):

- [x] **a complete session is driven from the TUI without CLI input** (T4.3.2)
- [x] all 6 MVP panels work (D10): Chat, Swarm Activity, Findings & Endpoints, HITL Approvals, Attack Trees, Progress & Plans
- [x] the HITL modals are modal for the operator but do not block the swarm; the FIFO queue is visible (T4.3.1)
- [x] the TUI receives data only through `SessionView` and `events.models` (arch §16 invariant 8)

---

### P4.1 · Phase "TUI skeleton and the SessionView facade" (F4)

**Goal:** a Textual application, UI state, the core facade, the production CLI.
**Dependencies:** P3.1–P3.5 (a live session; SessionView builds on Session).
**Phase DoD:** the application starts on a real session; the CLI starts and resumes a session.
**Tasks:** T4.1.1–T4.1.3.

#### T4.1.1 — SessionView and TuiState (`tui/state.py`)
- **What:** the core facade for the UI and the owner of the UI state (arch §10.2).
- **Where:** `src/swarmy/tui/state.py`.
- **How:** `SessionView` — read-only queries (memory, statuses, the approvals queue, the journal tail) over `Session`; `TuiState` — an EventBus subscription with a coalescing queue (arch §5.3), a snapshot cache; the TUI imports **only** the facade and `events.models` — core internals are inaccessible (arch §2.5, §10.2); this keeps the core testable without a UI and the TUI interchangeable (headless — post-MVP).
- **Acceptance criteria:**
  - [x] architecture test: `swarmy.tui` imports are limited to the facade + `events.models` (+ the L0 ban)
  - [x] UI queue coalescing loses no events (test)
  - [x] the M3 integration set passes in an environment without importing `swarmy.tui` (dependency inversion)

#### T4.1.2 — SwarmyTui (`tui/app.py`)
- **What:** the Textual application skeleton: layout, workers, rendering.
- **Where:** `src/swarmy/tui/app.py`.
- **How:** a container of six panels (arch §10.1); the session loop — workers inside the Textual event loop (arch §2.2: the core knows nothing about Textual); rich markup (markdown, tables, trees); key bindings for panel navigation.
- **Acceptance criteria:**
  - [x] the application starts on a real session; the stub panels are in place
  - [x] workers do not block the UI: rendering keeps ticking under an event flow (Textual harness test)

#### T4.1.3 — Production CLI (`cli.py`)
- **What:** the full launch and resume syntax (arch §3.4).
- **Where:** `src/swarmy/cli.py`.
- **How:** `swarmy <session-config.yaml> [--agents-dir PATH]... [--profile paranoid|normal|yolo] [--mode interactive|mission] [--model provider:model] [--session-dir PATH]`; `swarmy --resume <session-dir>`; `swarmy --version`; the CLI only prepares the `SessionConfig` and launches `SwarmyTui` (headless is out of scope for v0.1); config errors — fail-fast before the UI starts.
- **Acceptance criteria:**
  - [x] all flags work; config errors do not open the UI
  - [x] `--resume` continues an existing session (integration test)
  - [x] `swarmy --help` shows the current syntax

---

### P4.2 · Phase "Information panels" (F4)

**Goal:** Chat, Swarm Activity, Findings & Endpoints, Progress & Plans.
**Dependencies:** P4.1 (skeleton, facade).
**Phase DoD:** the four panels display live session data and pass the harness tests.
**Tasks:** T4.2.1–T4.2.4.

#### T4.2.1 — Chat panel (`tui/panels/chat.py`)
- **What:** the operator ↔ orchestrator dialog + subagent inspection.
- **Where:** `src/swarmy/tui/panels/chat.py`.
- **How:** sources: `OperatorMessage`/orchestrator replies from the journal; sending → platform → `OperatorMessage` into the journal → runtime (the interactive loop); switching to a live subagent — a read-only message snapshot from the checkpointer (arch §10.1); the snapshot is sanitized.
- **Acceptance criteria:**
  - [x] messages round-trip: send → orchestrator → the reply is displayed (harness test)
  - [x] subagent inspection shows a sanitized snapshot (masking applied — test)

#### T4.2.2 — Swarm Activity panel (`tui/panels/activity.py`)
- **What:** live event feed, delegation tree, approvals queue statuses.
- **Where:** `src/swarmy/tui/panels/activity.py`.
- **How:** the feed — an EventBus subscription (coalescing); the `task()` tree by `correlation_id` (`TaskRequested`/`TaskCompleted`); approvals queue statuses (arch §10.1).
- **Acceptance criteria:**
  - [x] the feed updates in real time (harness test)
  - [x] the delegation tree matches the journal (cross-checked in a test)

#### T4.2.3 — Findings & Endpoints panel (`tui/panels/findings.py`)
- **What:** tables of endpoints/parameters and the finding card.
- **Where:** `src/swarmy/tui/panels/findings.py`.
- **How:** data — SessionView (read-only queries to MemoryStore); the card: severity, evidence files (opened from `evidence/`), reproduction steps; findings are shown with **raw** values (the arch §6.8 rule: verification by the pentester), feeds/chat — masked.
- **Acceptance criteria:**
  - [x] the card opens evidence files (a test of presence and paths)
  - [x] raw values in the card versus masked ones in the feeds (difference test)

#### T4.2.4 — Progress & Plans panel (`tui/panels/plans.py`)
- **What:** orchestrator todos and session statistics.
- **Where:** `src/swarmy/tui/panels/plans.py`.
- **How:** todos — L0 state; statistics: endpoints by status, findings by class/severity — from memory + journal through the facade (arch §10.1).
- **Acceptance criteria:**
  - [x] the statistics reconcile with MemoryStore (cross-check test)
  - [x] todos reflect the graph state (a test with a fixed state)

---

### P4.3 · Phase "HITL modals and the queue (UI)" (F4)

**Goal:** the Approvals panel + the decision modal; the final F4 acceptance (RD-6).
**Dependencies:** P3.3 (ApprovalQueue), P4.1–P4.2.
**Phase DoD:** the spec F4 criterion is met end-to-end.
**Tasks:** T4.3.1–T4.3.2.

#### T4.3.1 — Approvals panel and modal (`tui/approvals.py`)
- **What:** a visible FIFO queue and the decision modal.
- **Where:** `src/swarmy/tui/approvals.py`.
- **How:** the modal shows: the tool, `args_digest` (sanitized arguments), the active rule/profile, the gate source (profile / module / judge escalation / mode); decisions `approve` / `reject` / `edit` (an argument editing form); the modal is modal for the operator and **does not block the swarm** — the other subagents continue, their requests are queued; the decision → `ApprovalQueue.submit_decision` (arch §10.3).
- **Acceptance criteria:**
  - [x] the queue displays N simultaneous requests; the decision is applied to the addressed request (harness test)
  - [x] the swarm keeps working with the modal open (concurrency test)
  - [x] the `edit` form validates the modified arguments (test)

#### T4.3.2 — F4 acceptance
- **What:** the spec criterion "a complete session is driven from the TUI without CLI input".
- **Where:** `tests/integration/tui/test_full_session.py`.
- **How:** a Textual harness scenario (Textual headless mode in CI): session start → fixture swarm activity → approve destructive through the modal → a chat command → check the journal and panels; closes the RD-6 caveat.
- **Acceptance criteria:**
  - [x] the F4 criterion is met end-to-end without CLI input
  - [x] the scenario is included in CI (headless Textual) and is stable

---

### P4.4 · Phase "Attack trees (panel) and masking" (F4)

**Goal:** interactive rendering of trees; a regression of the raw/masked boundary across the whole UI.
**Dependencies:** P4.2 (the finding card for navigation); acceptance — on fixture tree data (RD-9).
**Phase DoD:** all 6 MVP panels work (D10); masking is confirmed by an end-to-end scan.
**Tasks:** T4.4.1–T4.4.2.

#### T4.4.1 — Attack Trees panel (`tui/panels/trees.py`)
- **What:** interactive rendering of attack trees.
- **Where:** `src/swarmy/tui/panels/trees.py`.
- **How:** data — `AttackNode`/`AttackEdge` from memory through the facade; node expansion; the "node → finding card" navigation (arch §10.1); rich trees.
- **Acceptance criteria:**
  - [x] the tree is rendered from fixture memory data (test; RD-9)
  - [x] the "node → finding" navigation works (harness test)

#### T4.4.2 — Masking in the TUI (regression)
- **What:** the raw/masked boundary across all panels.
- **Where:** `src/swarmy/tui/**`.
- **How:** the arch §6.8 rule: event feeds/chat — masked; finding cards — raw; evidence — raw files; an end-to-end scan of UI texts.
- **Acceptance criteria:**
  - [x] the end-to-end test scan finds no secret values outside finding cards and evidence files

---

## 9. Milestone 5 — "Reference swarm and the v0.1 release" (F5 + F6)

**Composition:** P5.1 crawler module · P5.2 xss-detector module · P5.3 attack trees and the demo scenario · P5.4 report (F6) · P5.5 v0.1 release.

### M5 · Definition of Done

Inherits the F5 and F6 criteria (spec §12.3):

- [x] **demo session**: target → endpoints → XSS candidate → verification → tree node (T5.3.2)
- [x] **`report.md` is generated from the F5 session** (T5.4.3)
- [x] both modules are reference implementations of the spec §4 contract (dogfooding); adding a module requires no engine changes (invariant 9)
- [x] v0.1 acceptance: installation from git, the CI matrix + Py3.15 are green, both coverage gates are active, the §14 checklist is closed

---

### P5.1 · Phase "Crawler module" (F5)

**Goal:** the built-in primary reconnaissance module — a reference implementation of the contract (arch §8.7).
**Dependencies:** P1.5 (loader), P2.2 (http tools), P3.5 (the integration scenario harness).
**Phase DoD:** the crawler finds endpoints/parameters on the echo app and stays within the scope.
**Tasks:** T5.1.1–T5.1.3.

#### T5.1.1 — Crawler module skeleton
- **What:** the `AGENT.md` + `guardrails.yaml` + `tools/` directory.
- **Where:** `agents/crawler/`.
- **How:** frontmatter: `name`, `description`, `events: [EndpointsDiscovered, EndpointUpdated]` (arch §8.7); the passive recon system prompt (robots.txt, sitemap, link traversal, forms/parameters, the endpoint map — spec §4.6); `guardrails.yaml`: crawl depth limiting via `url_matches`; `tools/parsers.py` — robots/sitemap/forms/links with `swarmy_risk_class = passive`.
- **Acceptance criteria:**
  - [x] the module is loaded by the loader; event declarations are reconciled with the registry
  - [x] the crawl depth rule fires (a rule test from guardrails.yaml)

#### T5.1.2 — Traversal logic
- **What:** reconnaissance and writing the endpoint map.
- **Where:** `agents/crawler/tools/`.
- **How:** `http_get` through the platform; parsers → `memory_upsert_endpoint` (dedup, parameters append); events `EndpointsDiscovered`/`EndpointUpdated`; scope guarantees are the platform's (out of scope is blocked by the invariant, `out_of_scope` is marked — T2.1.1).
- **Acceptance criteria:**
  - [x] against the echo app: endpoints and parameters are found and written to memory (test)
  - [x] events carry a correct correlation_id (test)
  - [x] the traversal stays within the scope (integration test: outbound links are blocked)

#### T5.1.3 — Reference quality (dogfooding)
- **What:** the crawler as the canonical example of an author's module.
- **Where:** `agents/crawler/`, the README/docs section.
- **How:** compliance with arch §8.5 (full typing, docstrings, the ban on network imports); a short "how to write a module" tutorial on the real crawler code.
- **Acceptance criteria:**
  - [x] the loader and the linter raise no remarks about the module
  - [x] the tutorial is reproducible on the crawler code (snippet cross-check)

---

### P5.2 · Phase "xss-detector module" (F5)

**Goal:** a reflected XSS detector — the second reference implementation of the contract.
**Dependencies:** P5.1 (endpoints in memory), P2.3 (masking), P3.3 (HITL on network-write).
**Phase DoD:** the detector produces justified candidates with evidence; dangerous payloads are blocked.
**Tasks:** T5.2.1–T5.2.2.

#### T5.2.1 — xss-detector module skeleton
- **What:** the `AGENT.md` + `guardrails.yaml` + `tools/` directory.
- **Where:** `agents/xss-detector/`.
- **How:** events: `[FindingCandidate]` (arch §8.7); `guardrails.yaml`: blocking TRUE constructions and known dangerous payloads (the spec §8.3 example); `tools/marker.py` (marker placement), `tools/reflection.py` (contextual analysis of reflections); POST probes are automatically `network-write` (AD-7 → the profile gates).
- **Acceptance criteria:**
  - [x] the module loads; events are reconciled
  - [x] TRUE payloads and dangerous constructions are blocked by the module guardrail (test)

#### T5.2.2 — Detector logic
- **What:** markers → reflections → safe payloads → a finding candidate.
- **Where:** `agents/xss-detector/tools/`.
- **How:** parameter selection (`memory_search` over the crawler endpoints), `http_get` with markers, contextual analysis of reflections, verification with safe payloads (spec §4.6); `memory_save_finding(candidate)` → `FindingCandidate`; evidence — automatically (`evidence=True`).
- **Acceptance criteria:**
  - [x] against the echo app: reflections → candidates with evidence (test)
  - [x] no reflection — no candidate (negative test)
  - [x] a POST probe under the `normal` profile → an HITL request (integration test at the T3.3.2 seam)

---

### P5.3 · Phase "Attack trees and the demo scenario" (F5)

**Goal:** minimal attack trees and the end-to-end demo session of arch §13.4.
**Dependencies:** P5.1–P5.2 (modules), P4.4 (the trees panel), P3.2 (the tree_proposal policy).
**Phase DoD:** the spec F5 criterion is met; the scenario is documented as a quickstart.
**Tasks:** T5.3.1–T5.3.2.

#### T5.3.1 — Linking tree nodes
- **What:** minimal attack trees from verified findings.
- **Where:** `agents/xss-detector/tools/` (link calls), policies in `core/prompts.py` (tree_proposal).
- **How:** `FindingVerified` → the `tree_proposal` policy → the orchestrator delegates the linking → `memory_link_attack_node` (finding node + preconditions + target, edges `requires`/`enables`/`leads_to`) → `AttackTreeUpdated` (arch §13.4).
- **Acceptance criteria:**
  - [x] demo tree: precondition → finding → target with typed edges (memory data test)
  - [x] `AttackTreeUpdated` reaches the TUI (junction with T4.4.1)

#### T5.3.2 — F5 demo scenario
- **What:** the end-to-end demo session (arch §13.4) — the F5 criterion.
- **Where:** `tests/integration/scenarios/test_demo_f5.py`, README quickstart.
- **How:** the operator's command "check target X for XSS" → todos → `task(crawler)` → endpoints → `task(xss-detector)` → markers/reflections → HITL approve (POST, normal profile) → `FindingCandidate` → the verify_finding policy → verification (RD-5) → `FindingVerified` → tree_proposal → `AttackTreeUpdated`; the operator sees the feed, the finding, the tree node.
- **Acceptance criteria:**
  - [x] spec F5 criterion: target → endpoints → XSS candidate → verification → tree node (met)
  - [x] the journal contains the trace of the whole chain by correlation_id
  - [x] the scenario is written up as a reproducible quickstart in the README

---

### P5.4 · Phase "Report" (F6)

**Goal:** a deterministic markdown report of the session.
**Dependencies:** P5.3 (the demo session as the data source), P3.1 (config).
**Phase DoD:** `report.md` is generated from the F5 session (the F6 criterion).
**Tasks:** T5.4.1–T5.4.3.

#### T5.4.1 — ReportGenerator and the `generate_report` tool
- **What:** a generator without LLM text generation + the orchestrator's platform tool.
- **Where:** `src/swarmy/report/generator.py` (the tool is included in the engine's tools — RD-7).
- **How:** input — queries to MemoryStore (findings by severity, endpoints, trees, journal statistics) + the session config; `report` imports only `memory.store` read-only (arch §2.5); output — `<session-dir>/report.md`.
- **Acceptance criteria:**
  - [x] the tool is registered and available to the orchestrator (engine assembly test)
  - [x] generation performs no LLM/network calls (test)
  - [x] the report is written to the session directory (test)

#### T5.4.2 — Report template (`report/templates/report.md.j2`)
- **What:** a jinja2 template per spec §10.
- **Where:** `src/swarmy/report/templates/report.md.j2`.
- **How:** structure: summary (target, scope, period, statistics) → findings (sorted by severity; description, endpoint, evidence references, reproduction steps) → attack trees (text + mermaid) → appendix (the full list of explored endpoints); the first line — the "draft, requires pentester review" note; mermaid — a subset of the syntax compatible with common renderers (closing arch §19.4).
- **Acceptance criteria:**
  - [x] the report from the F5 demo session contains all sections (golden-file test)
  - [x] the mermaid fragment passes a basic syntax check (the §19.4 decision is recorded in a template comment)
  - [x] the draft note is the first line of the file

#### T5.4.3 — F6 criterion
- **What:** `report.md` is generated from the F5 session.
- **Where:** `tests/integration/report/test_report_generation.py`.
- **How:** after the T5.3.2 demo scenario → `generate_report` → check the structure, the references to evidence files and the sorting of findings.
- **Acceptance criteria:**
  - [x] the spec F6 criterion is met in CI
  - [x] the report's evidence references point to existing evidence files (test)

---

### P5.5 · Phase "v0.1 release"

**Goal:** packaging, documentation, full acceptance (D17: no PyPI, installation from git).
**Dependencies:** P5.4 (all phase criteria are closed).
**Phase DoD:** the §14 checklist is closed; the v0.1 tag.
**Tasks:** T5.5.1–T5.5.2.

#### T5.5.1 — Packaging and user documentation
- **What:** the final build and user documentation.
- **Where:** `pyproject.toml`, `README.md`, `docs/development/*`.
- **How:** building the sdist/wheel from `src/swarmy` (docs are not included in the distribution — arch §3.1); installation from git: `uv tool install git+…` (D17: publishing v0.1 on PyPI is not planned; the future distribution is `swarmy-cli`); README: the disclaimer (D15), a quickstart on the T5.3.2 demo scenario, the "writing modules" section (T5.1.3); cross-references spec/architecture/roadmap.
- **Acceptance criteria:**
  - [x] installation from a git source yields a working CLI (verified on a local path/repository)
  - [x] the sdist/wheel build; runtime dependencies do not pull the dev group (an import test of the installed package)
  - [x] the README quickstart reproduces the demo session following the instructions

#### T5.5.2 — Full v0.1 acceptance
- **What:** a control run of all phase criteria F0–F6.
- **Where:** `.github/workflows/ci.yml`, the §14 checklist of this document.
- **How:** passing the §14 traceability checklist; CI is green on the matrix (4 platforms) + the Py3.15 job; both coverage gates are active; the `v0.1` release tag (no PyPI — D17).
- **Acceptance criteria:**
  - [x] the §14 checklist is fully checked
  - [x] the CI matrix + Py3.15 are green; both gates are active
  - [x] the `v0.1` tag; installation from git works

---

## 10. Dependencies and execution order

### 10.1. Phase graph

```
P1.1 ─▶ P1.2 ─▶ P1.3 ─▶ P1.4 ─▶ P1.5 ──┐
  (F0)  memory   events  guardrails loader│
                                        ▼
                     P2.1 ─▶ P2.2 ─▶ P2.3 ─▶ P2.4 ──┐
                     scope/  http+  projector echo+gate│
                     limits  evidence                 │
                                                      ▼
        P3.1 ─▶ P3.2 ─▶ P3.3 ─▶ P3.4 ─▶ P3.5 ────────┤
        session/ runtime HITL    judge   parallelism │
        engine   policies                           │
                                                      ▼
        P4.1 ─▶ P4.2 ─▶ P4.3 ─▶ P4.4 ────────────────┤
        facade/  panels  modals  trees+              │
        CLI           +F4 acceptance masking         │
                                                      ▼
        P5.1 ─▶ P5.2 ─▶ P5.3 ─▶ P5.4 ─▶ P5.5
        crawler  xss-    demo    report  release
                 detector F5      F6      v0.1
```

### 10.2. Key cross-dependencies

| Phase | Depends on | What it consumes |
|---|---|---|
| P1.3 | P1.2 | domain ids in payload models; the `events` DDL |
| P1.4 | P1.3 | the `GuardrailBlocked` event |
| P1.5 | P1.4, P1.3, P1.2 | GuardrailMiddleware, EventRegistry, the platform `memory_*` |
| P2.1 | P1.4 | the invariant layer (the T1.4.3 slots) |
| P2.2 | P2.1, P1.4 | scope/limits in the client pipeline |
| P2.3 | P2.2 | HTTP response previews; P1.3 — digests (RD-4) |
| P2.4 | P2.1–P2.3 | the full perimeter pipeline |
| P3.1 | P1.5, P2.4 | SubAgent dicts; engine tools; the secrets config (T2.3.3) |
| P3.2 | P3.1 | Engine, prompt templates |
| P3.3 | P3.2 | runtime injections; P2.3 — sanitized digests |
| P3.4 | P3.3, P1.4 | the HITL queue for escalations; the pipeline's judge slot |
| P3.5 | P3.2–P3.4 | the full swarm loop |
| P4.1 | P3.1–P3.5 | a live session, ApprovalQueue |
| P4.3 | P3.3, P4.1–P4.2 | the ApprovalQueue API |
| P4.4 | P4.2 | the finding card; fixture tree data (acceptance, RD-9) |
| P5.1–P5.2 | P1.5, P2.2, P3.5 | loader, http tools, the integration harness |
| P5.3 | P5.1–P5.2, P3.2, P4.4 | modules, the tree_proposal policy, the trees panel |
| P5.4 | P5.3 | demo session data |
| P5.5 | P5.4 | all F0–F6 criteria |

### 10.3. Allowed parallelism

- **Within M1:** T1.2.1 (models) and T1.3.1 (payload models by id — after the models are fixed) start in parallel; P1.4 does not start until T1.3.1.
- **Within M2:** T2.3.1 (projection steps as pure functions) runs in parallel with T2.2.2–T2.2.4; the hookup — T2.3.2.
- **Within M3:** T3.1.4 (prompt) and T3.1.1 (config) are parallel after the T3.1.3 skeleton; T3.4.1–T3.4.2 (the judge on mocks) run in parallel with T3.3.2 after T3.3.1.
- **Within M4:** the T4.2.1–T4.2.4 panels are independent after T4.1.1.
- **Within M5:** T5.1.1 and T5.2.1 (module skeletons) are parallel.

---

## 11. Risks and mitigations

| # | Risk | Phase | Mitigation |
|---|---|---|---|
| R1 | L0 API drift: the middleware hook names (`wrap_tool_call`/post-tool-call) differ from expectations (arch §19.1) | P1.4, P2.3 | cross-check against the 0.7.41 pin sources in T1.4.5/T2.3.2; the typed L0 wrapper is the isolation point; deviations — the §12 defect procedure |
| R2 | The behavior of `snapshot.interrupts` with multiple parallel `task()` calls is unknown (arch §19.2) | P3.5 | the dedicated T3.5.2 test pins the actual behavior; the FIFO queue isolates the UI from L0 details |
| R3 | deepagents/dependencies compatibility with Py3.15 (classifiers up to 3.14) | P1.1 | the T1.1.4 smoke in CI from day one; a divergence is an early signal, before code accumulates |
| R4 | The single-writer runtime (AD-8) narrows the orchestrator's throughput at step boundaries | P3.2 | measured in T3.5.1; notifications — a coalescing queue; if problems arise — a revision (as in D19: "revisit if target pressure becomes a problem") |
| R5 | Serialization of the records of three subsystems in one SQLite (AD-6) under a parallel swarm | P3.5 | `busy_timeout` + WAL are already in place; the concurrency integration tests (T3.5.1) as a minimal load run |
| R6 | The D22 thresholds (unit 85%) slow down early iterations | P1.5 | the threshold activates at the end of M1 (T1.5.6), when the core is already covered; exceptions — only spot ones |
| R7 | HITL modals in Textual: contention between the UI thread and the swarm's workers | P4.3 | all the queue logic is tested headless in P3.3; the UI is a thin layer over ApprovalQueue (T4.3.1) |
| R8 | Mermaid rendering of trees in the report is limited by the renderers (arch §19.4) | P5.4 | choosing a compatible syntax subset in T5.4.2; text rendering — the fallback |
| R9 | Uncertainty about the "verifier" of the demo scenario | P5.3 | resolved by RD-5: repeated delegation of xss-detector + the platform `update_finding_status`; no separate module is introduced |
| R10 | Operator secrets on Windows: chmod 600 is not applicable | P2.3 | a POSIX test + a documented Windows limitation (T2.3.3); masking is the primary guarantee, permissions are an additional one |

---

## 12. Open implementation questions (mapped to phases)

From arch §19 — clarified as the phases progress against the deepagents pin (the D18 procedure); there are no new blocking questions:

| # | Question (arch §19) | Phase | Task |
|---|---|---|---|
| Q1 | The L0 middleware hook names for the Guardrail/Projector middleware | P1.4, P2.3 | T1.4.5, T2.3.2 |
| Q2 | The behavior of `Snapshot.interrupts` with many parallel `task()` calls | P3.5 | T3.5.2 |
| Q3 | Minimum dependency versions (other than the deepagents pin) | P1.1 | T1.1.1, T1.1.4 |
| Q4 | The mermaid rendering format for report trees | P5.4 | T5.4.2 |

Planning ambiguities resolved by this document: RD-1–RD-9 (§4). If the implementation reveals a new divergence from spec/architecture, it is recorded as a design defect and added to this section.

---

## 13. Post-MVP and reserved extension points

Out of scope for v0.1 (spec §1.4, §12.3) — in the order they appear after the release:

- **gRPC tools** — `grpcio`; Python 3.15 wheels are tracked via grpc#41010 (spec §7.5);
- **vector search** — `VecSearchIndex` (sqlite-vec, a version pin because of its pre-v1 status) on top of the `SearchIndex` interface (arch §4.5; the `memory.search_backend` key is already in place);
- **Docker sandbox** for execution — optional isolation (D4);
- **proxy integration** (Burp/mitm);
- **headless mode** without a TUI — `swarmy.core` already knows nothing about Textual (arch §2.2), the `SessionView` facade is ready (T4.1.1);
- **an attack tree correlation engine**;
- **non-HTTP evidence** — `screenshot`/`har`/`grpc_file`: the values are already reserved in `EvidenceKind` without schema migrations (D20).

The extension points reserved in v0.1 keep Post-MVP additive: the `EvidenceKind` enum (D20), the `SearchIndex` interface (arch §4.5), `action: review/allow` in the guardrail DSL (v0.1 — only `block`, arch §6.6), the `metadata.include_tools` of skills (arch §8.6), MCP servers via the session config (arch §12.1).

---

## 14. Traceability and v0.1 acceptance checklist

The mapping of the spec §12.3 phases onto the roadmap phases and the tasks that carry the criteria:

| Spec phase | Spec criterion (§12.3) | Roadmap phases | Criterion carriers |
|---|---|---|---|
| F0 | `pip install -e .` + `swarmy --help` on all platforms | P1.1 | T1.1.1–T1.1.5 |
| F1 | Core unit tests are green; the unit gate ≥ 85% in CI (D22); a stub module loads | P1.2–P1.5 | T1.5.5 (stub), T1.5.6 (gate) |
| F2 | Echo app: out-of-scope is blocked, evidence is written, budgets/masking work; the integration gate ≥ 70% | P2.1–P2.4 | T2.4.2 (scenarios), T2.4.3 (gate) |
| F3 | The "finding → verification" scenario through events; parallel `task()` with global limits; HITL intercepts destructive, the queue works | P3.1–P3.5 | T3.5.3 (scenario), T3.5.1 (parallelism), T3.3.3 (queue, headless; the modal — T4.3.1, RD-6) |
| F4 | A complete session is driven from the TUI without CLI input | P4.1–P4.4 | T4.3.2 |
| F5 | Demo session: target → endpoints → XSS candidate → verification → tree node | P5.1–P5.3 | T5.3.2 |
| F6 | `report.md` is generated from the F5 session | P5.4 | T5.4.3 |

Release acceptance (closed in T5.5.2):

- [x] all F0–F6 phase criteria are checked in the table above (through the corresponding tasks)
- [x] the CI matrix (windows/amd64, macos/arm64, linux/amd64, linux/arm64) is green
- [x] the Python 3.15 job is green
- [x] the unit gate ≥ 85% and the integration gate ≥ 70% are active and green
- [x] the F5 demo scenario is reproduced following the README quickstart
- [x] installation from git yields a working CLI; the package builds (sdist/wheel)
- [x] the `v0.1` tag is set (no PyPI — D17)

---

*Sources: [spec.md](spec.md) v0.3-draft · [architecture.md](architecture.md) v0.1-draft. The document is maintained together with the code: a divergence of the implementation from spec/architecture/roadmap is a defect.*
