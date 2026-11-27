# swarmy — implementation architecture

- **Version:** 0.1-draft
- **Date:** 2026-11-25
- **Basis:** [spec.md](spec.md) v0.3-draft — adopted decisions D1–D22, phases F0–F6
- **Status:** design document; detail sufficient to implement the codebase
- **Languages:** English (documentation, code, identifiers, CLI, UI)

---

## 1. Purpose and reading rules

The specification (`spec.md`) fixes **what** is built and **why** (principles P1–P5,
decisions D1–D22). This document fixes **how** the specification maps onto code: the
set of packages, types, interfaces, pipelines, data schemas and the responsibilities
of each component.

Document rules:

- The document does not contradict the specification. Where the specification leaves
  freedom, a decision is introduced here with the label **AD-n** (architecture decision)
  and a brief rationale. The list of ADs is collected in §18.2.
- The names of types, functions, packages and files below are canonical: the
  implementation follows them so that "document ↔ code" cross-references are exact.
- Tracing "section ↔ spec § ↔ decision D" is in §18.1. A divergence of the code from
  this document is treated as a defect, the same as a divergence from `spec.md`.
- Diagrams are ASCII; types are Pydantic v2 (D9); code appears only for canonical
  signatures.

## 2. Architectural overview

### 2.1. Layers and the L0 dependency rule

```
┌──────────────────────────────────────────────────────────────────────┐
│ L2  Interface: TUI (Textual) + CLI (`swarmy`, argparse)              │
├──────────────────────────────────────────────────────────────────────┤
│ L1  swarmy domain core (src/swarmy/*, our code):                     │
│     core (session/engine/runtime/hitl/config) · events · memory ·    │
│     tools (http, platform, projector) · guardrails · modules ·       │
│     report · agents (built-in modules: data, sources in              │
│     `<repo>/agents`, in the distribution — `swarmy/agents`)          │
├──────────────────────────────────────────────────────────────────────┤
│ L0  Harness: deepagents >=0.7.41,<0.8 (LangChain + LangGraph)        │
└──────────────────────────────────────────────────────────────────────┘
```

L0 is **never forked** (D16). L1 depends on L0 only through documented extension
points:

| L0 extension point | Use in swarmy | Where in code |
|--------------------|---------------|---------------|
| `create_deep_agent(...)` | orchestrator assembly | `core/engine.py` |
| `subagents` parameter (`SubAgent` dict) | declarative subagent modules | `modules/loader.py` |
| `middleware` parameter + `SubAgent["middleware"]` | `GuardrailMiddleware`, `ProjectorMiddleware` | `guardrails/pipeline.py`, `tools/projector.py` |
| `interrupt_on` parameter (`InterruptOnConfig`) | HITL gates per tool risk classes | `core/hitl.py` |
| `checkpointer` parameter | persistence of interrupts and state | `core/engine.py` (SQLite checkpointer) |
| `response_format` parameter / `SubAgent["response_format"]` | typed task result | `modules/loader.py` (schemas from modules) |
| `skills` parameter / `SubAgent` skills | skills per the agentskills.io spec — the orchestrator's repository-root `skills/` container (`/skills/`) and each module's `skills/` (`/module-skills/<name>/`); both are **virtual composite routes**, never disk paths (AD-10) | `core/skills.py`, `core/engine.py` (composite); `modules/loader.py` (module routes) |
| `backend` parameter (`CompositeBackend` over `StateBackend` + read-only `FilesystemBackend` routes) | disk access for the skills containers only (`/skills/` and `/module-skills/<name>/` virtual routes) | `core/skills.py`, `core/engine.py` |
| `model` parameter (`"provider:model"`) | any tool-calling models (D1) | `core/engine.py` |
| deepagents MCP support | platform MCP servers | `core/engine.py`, session config |

Additional layer rules:

- L1 does not use private deepagents/LangGraph APIs (symbols without a documented
  export). Anything not covered by the table above is a design defect.
- L2 (TUI/CLI) depends on L1 and does not import L0 directly.
- L0 is updated only by the D18 procedure (minor-version pin, changelog review, full
  test run, lock bump).

### 2.2. Process model

- **One Python process, one asyncio event loop** (D4: in-process isolation).
- The text interface is a Textual application; the session loop runs as workers/tasks
  inside the Textual loop. The L1 core **does not know about Textual**: `swarmy.core`
  does not import `swarmy.tui` (see §2.5), which makes it possible to run a session in
  tests and future modes (headless) without a TUI.
- All blocking operations (SQLite, network) go through async interfaces: `aiosqlite`,
  `httpx.AsyncClient`. There are no synchronous DB/network calls in the event loop.
- L1 components are owned by the `Session` object (composition root, §3.3,
  `core/session.py`): Session creates EventBus, MemoryStore, ToolRegistry,
  GuardrailPipeline, ModuleLoader, Engine and passes them a shared context. No
  component creates another "on its own".

### 2.3. L1 components

| Component | Package | Responsibility | Owns |
|-----------|---------|----------------|------|
| `Session` | `core/session.py` | composition root; lifecycle: open/resume/close | all components below |
| `SessionConfig` | `core/config.py` | session config schema, loading, profile and limit resolution | config objects (Pydantic) |
| `Database` | `core/database.py` | single aiosqlite connection to `memory.sqlite`, WAL, migrations | connection, write lock |
| `Engine` | `core/engine.py` | `create_deep_agent` assembly (orchestrator + subagents + checkpointer) | compiled graph |
| `OrchestratorSkills` | `core/skills.py` | the repository-root `skills/` container: resolution, fail-fast validation (§8.6); with `build_skills_backend`/`module_skills_routes` it also assembles the composite every skills container is mounted through (orchestrator `/skills/` + module `/module-skills/<name>/` routes) | validated skill names, the composite backend |
| `OrchestratorRuntime` | `core/runtime.py` | three orchestrator loops (§9.2), single-writer for the graph | notification queue, graph tasks |
| `ApprovalQueue` | `core/hitl.py` | queue of HITL interrupts, resume decisions, profiles → `interrupt_on` | pending interrupts |
| `EventBus` | `events/bus.py` | in-memory asyncio pub/sub | subscriptions, subscriber queues |
| `EventRegistry` | `events/models.py` | taxonomy: type name → payload model | event type registry |
| `JournalWriter/Reader` | `events/journal.py` | append-only journal in SQLite `events`, reading for resume/audit | `events` table |
| `MemoryStore` | `memory/store.py` | typed CRUD of domain entities | domain tables |
| `SearchIndex` | `memory/search.py` | full-text search (FTS5), interface for phase 2 (sqlite-vec) | FTS5 tables |
| `ToolRegistry` | `tools/registry.py` | tool names, prefixes, collisions, risk classes | tool registry |
| `ScopeRegistry` | `tools/scope.py` | scope allowlist, call target check | current scope |
| `ResourceLimiter` | `tools/limits.py` | session-global limits (§6.4) | semaphores, budget, rate state |
| `SwarmyHttpClient` | `tools/http/client.py` | the single network path, request pipeline (§6.2) | httpx.AsyncClient |
| `EvidenceRecorder` | `tools/http/evidence.py` | evidence files + `Evidence` records | `evidence/` directory |
| `GuardrailPipeline` | `guardrails/pipeline.py` | pre-tool-call pipeline: 3 layers + judge (§6.5) | rules of all layers |
| `LlmJudge` | `guardrails/judge.py` | asynchronous second look (§6.7) | judge model config |
| `ContextProjector` | `tools/projector.py` | LLM-context sanitization (§6.8, D21) | budgets, secret patterns |
| `ModuleLoader` | `modules/loader.py` | module scanning/validation, SubAgent dict assembly | `agents/` directories |
| `ModuleRegistry` | `modules/registry.py` | module names, `events` check against the registry | module registry |
| `ReportGenerator` | `report/generator.py` | `generate_report`: jinja2 → `report.md` (§11) | template, memory queries |
| `SwarmyTui` | `tui/app.py` | 6 panels, HITL modals, bus subscription | UI state |

### 2.4. Data flow

```
                    ┌────────────────────────── session (Session) ─────────────────────┐
                    │                                                                  │
 subagent (L0)      │  tools                             execution pipeline            │
 ┌───────────┐      │  ┌──────────────┐    args   ┌──────────────────┐   allowed        │
 │  LLM +    │──────┼─▶│ tool wrapper │──────────▶│ GuardrailPipeline │───────┐         │
 │  task()/  │      │  │ (platform/   │           │ invariants →      │       │         │
 │  tools    │◀─────┼──│ module)      │◀ feedback │ engine → modules  │       ▼         │
 └───────────┘      │  └──────────────┘  (block)  │ → judge (async)   │  ┌───────────┐  │
      ▲             │        │  ▲                  └──────────────────┘  │ HTTP/     │  │
      │ result      │        │  │ ProjectorMiddleware                     │ memory/   │  │
      │ (sanitized) │        │  └────────── result    ────────────────┐  │ emit_event│  │
      └─────────────┼────────┼──────────── (truncate/mask) ◀──────────┘  └─────┬─────┘  │
                    │        │                                                 │        │
                    │        ▼                                       GuardrailBlocked   │
                    │  EventBus ── append-only ──▶ SQLite `events` ◀──────────┘        │
                    │     │  (fan-out)                    journal (audit/resume)       │
                    │     ├──────────────▶ TUI (panels, approvals)                      │
                    │     └── policies ▶ notifications ▶ OrchestratorRuntime ▶ graph L0│
                    │                        │                                          │
                    │                        └── task()/chat/operator poll  ◀── TUI ───┤
                    └──────────────────────────────────────────────────────────────────┘
```

Key property: the **single** path to the network, memory and the bus is through platform
tools and the guardrail pipeline. Modules do not access these subsystems directly (§8.5).

### 2.5. Inter-package dependency rules

| Package | Imports | Must not import |
|---------|---------|-----------------|
| `swarmy.memory.models` | pydantic | any swarmy packages — **leaf module** |
| `swarmy.events.models` | `memory.models`, pydantic | `core`, `tui`, L0 |
| `swarmy.events.{bus,journal,emit}` | `events.models`, `core.database` | `tui` |
| `swarmy.memory.{store,schema,search}` | `memory.models`, `core.database` | `events`, `tools`, `tui` |
| `swarmy.tools.*` | `memory.models`, `events.*`, `guardrails.models` | `core`, `modules`, `tui` |
| `swarmy.guardrails.*` | `tools.scope`, `tools.limits`, `events.models` | `memory.store` (models only), `tui` |
| `swarmy.modules.*` | `guardrails.pipeline`, `events.models`, `tools.registry` | `core.engine`, `tui` |
| `swarmy.core.*` | all L1 packages (except `tui`, `report`) | `swarmy.tui` |
| `swarmy.report` | `memory.store` (read-only) | `core`, `tools`, `tui` |
| `swarmy.tui` | `core` (only the `SessionView` facade, §10.2), `events.models` | L0 |
| `swarmy.cli` | `core`, `tui` | — |

Consequences (invariants, §16):

- `memory.models` is the only place for domain Pydantic models; it depends on nothing
  inside swarmy, so any package can import the models without cycles.
- The direction of the "knowledge" arrows is downward and inward toward the core; the
  TUI is the top — nothing imports it.
- `report` reads memory directly (read-only) so that the report can be built without a
  live swarm.

## 3. Codebase structure

### 3.1. Repository tree (src-layout, spec §12.1)

```
swarmy2/
├── pyproject.toml                  # metadata, deps, entry point, tool configs (§3.2)
├── uv.lock                         # dependency pinning (D18: incl. deepagents)
├── README.md                       # responsibility disclaimer (D15/§8.6)
├── LICENSE                         # MIT
├── .github/workflows/ci.yml        # platform CI matrix + coverage gate (§15.4)
├── docs/
│   └── development/
│       ├── spec.md                 # specification (what/why)
│       ├── architecture.md         # this document (how)
│       ├── roadmap.md              # work plan: milestones → phases → tasks
│       └── consistency-check-2026-11-25.md  # document cross-check report
├── src/
│   └── swarmy/
│       ├── __init__.py             # __version__
│       ├── __main__.py             # python -m swarmy → cli.main
│       ├── cli.py                  # argparse: session start/resume (§12)
│       ├── core/
│       │   ├── config.py           # SessionConfig, profiles, limits; YAML loading
│       │   ├── session.py          # Session: composition root, open/resume/close
│       │   ├── database.py         # Database: aiosqlite, WAL, migrations (§4.3)
│       │   ├── engine.py           # Engine: create_deep_agent, checkpointer (§9.1)
│       │   ├── runtime.py          # OrchestratorRuntime: loops, single-writer (§9.2)
│       │   ├── hitl.py             # ApprovalQueue, profiles → interrupt_on (§7)
│       │   ├── prompts.py          # orchestrator system prompt, notification templates
│       │   └── skills.py           # skills containers: resolve/validate the orchestrator's; the read-only composite (orchestrator + module routes, §8.6)
│       ├── events/
│       │   ├── models.py           # EventEnvelope, payload models, EventRegistry (§5)
│       │   ├── emit.py             # emit_event tool factory
│       │   ├── bus.py              # EventBus (asyncio pub/sub)
│       │   └── journal.py          # JournalWriter / JournalReader
│       ├── memory/
│       │   ├── models.py           # domain entities Pydantic v2 — leaf (§4.2)
│       │   ├── schema.py           # DDL + migrations (§4.3)
│       │   ├── store.py            # MemoryStore (§4.4)
│       │   └── search.py           # SearchIndex: interface + FTS5 (§4.5)
│       ├── tools/
│       │   ├── registry.py         # ToolRegistry (§6.1)
│       │   ├── scope.py            # ScopeRegistry (§6.3)
│       │   ├── limits.py           # ResourceLimiter (§6.4)
│       │   ├── platform.py         # session_info, memory_* wrappers (§6.1)
│       │   ├── projector.py        # ContextProjector + ProjectorMiddleware (§6.8)
│       │   └── http/
│       │       ├── client.py       # SwarmyHttpClient (§6.2)
│       │       ├── models.py       # RequestSpec, ResponseRecord
│       │       ├── evidence.py     # EvidenceRecorder
│       │       └── tools.py        # http_get/http_post/http_put/http_delete...
│       ├── guardrails/
│       │   ├── models.py           # GuardrailRule, Verdict, blocked feedback (§6.5)
│       │   ├── dsl.py              # guardrails.yaml parsing/validation (§6.6)
│       │   ├── invariants.py       # layer 1: platform invariants
│       │   ├── engine_rules.py     # layer 2: base rules + default set
│       │   ├── pipeline.py         # GuardrailPipeline + GuardrailMiddleware
│       │   └── judge.py            # LlmJudge, JudgeEscalationRegistry (§6.7)
│       ├── modules/
│       │   ├── manifest.py         # AgentModuleManifest (§8.2)
│       │   ├── loader.py           # ModuleLoader (§8.3)
│       │   └── registry.py         # ModuleRegistry (§8.4)
│       ├── report/
│       │   ├── generator.py        # ReportGenerator (§11)
│       │   └── templates/
│       │       └── report.md.j2    # jinja2 report template
│       └── tui/
│           ├── app.py              # SwarmyTui: layout, workers (§10)
│           ├── state.py            # TuiState + SessionView (facade)
│           ├── approvals.py        # HITL queue panel + modals
│           └── panels/
│               ├── chat.py         # Chat
│               ├── activity.py     # Swarm Activity
│               ├── findings.py     # Findings & Endpoints
│               ├── trees.py        # Attack Trees
│               └── plans.py        # Progress & Plans
├── agents/                         # built-in modules: crawler, xss-detector (§8.7)
│   ├── crawler/
│   │   ├── AGENT.md
│   │   ├── guardrails.yaml
│   │   └── tools/
│   └── xss-detector/
│       ├── AGENT.md
│       ├── guardrails.yaml
│       └── tools/
├── skills/                         # orchestrator skills container: <skill-name>/SKILL.md (§8.6)
│   └── README.md                   # layout + rules; loose files at the root are not skills
└── tests/
    ├── unit/                       # mirror the packages; gate ≥ 85% (§15)
    ├── integration/                # end-to-end scenarios; gate ≥ 70%
    └── fixtures/
        └── echo_app/               # local echo app for integration tests
```

Notes:

- `agents/` at the repository root is the **source of the built-in modules** (`crawler`,
  `xss-detector`). The build maps the directory to `swarmy/agents` inside the wheel
  (`force-include`), and the loader finds it both in the installed package and in an
  editable checkout. User modules are not placed in this directory — a separate
  directory is used for them (`--agents-dir`).
- `skills/` at the repository root is the **orchestrator skills container** (arch §8.6):
  every `<skill-name>/SKILL.md` in it is loaded into the orchestrator context
  automatically. It ships the same way as `agents/` (`force-include` →
  `swarmy/skills`, included in the sdist) and is resolved by
  `core/skills.py:builtin_skills_root()` in both layouts. Module skills stay
  inside their module directory (`agents/<module>/skills/`) and are mounted
  read-only through the same composite under `/module-skills/<name>/` (AD-10);
  the two containers are independent.
- `docs/` is not part of the distribution; the package is built from `src/swarmy` +
  `agents`.

### 3.2. `pyproject.toml`

| Section | Contents |
|---------|----------|
| `[project]` | `name = "swarmy"`, `license = "MIT"`, `requires-python = ">=3.11,<4.0"` |
| `[project.scripts]` | `swarmy = "swarmy.cli:main"` |
| `[project] dependencies` | `deepagents>=0.7.41,<0.8` (D18), `pydantic>=2,<3` (D9), `httpx`, `textual`, `rich`, `jinja2>=3.1`, `aiosqlite`, `langgraph-checkpoint-sqlite` |
| `[dependency-groups] dev` | `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `ty` (type checker; the fallback is `mypy`, chosen in F0), `aiohttp` (fixture echo app) |
| `[tool.hatch.build.targets.wheel]` | `packages = ["src/swarmy"]`, `force-include = {"agents" = "swarmy/agents", "skills" = "swarmy/skills"}` — the built-in modules and the orchestrator skills container from the repository root are shipped inside the package |
| `[tool.hatch.build.targets.sdist]` | `include = ["src/swarmy", "agents", "skills", "README.md", "LICENSE", "pyproject.toml"]` — module sources and the skills container are included in the sdist |
| `[tool.ruff]` | strict rule set in the spirit of upstream deepagents: no `Any` in domain code (`ANN401`), mandatory annotations, `I`, `UP`, `B` |
| `[tool.ty]` / `[tool.mypy]` | strict: `disallow_any_explicit`, `disallow_untyped_defs`, `warn_return_any` |
| `[tool.pytest.ini_options]` | `asyncio_mode = "auto"`, markers `unit` / `integration` |
| `[tool.coverage.*]` | two report sources: `tests/unit` → threshold 85, `tests/integration` → 70 (`--cov-fail-under` in separate CI commands, D22) |

**AD-2.** `aiosqlite` and `langgraph-checkpoint-sqlite` are added to the list of runtime
dependencies in spec §11: the "SQLite checkpointer + one file per session" decision
(§5.6, spec §6.1) requires an async SQLite driver and the official LangGraph
checkpointer. The exact minimum versions of all dependencies are selected in F0 (smoke on
Py3.15) and pinned in `uv.lock`; `pyproject.toml` states the lower working bounds.

### 3.3. Session directory

A session is a portable directory (spec §6.1):

```
<session-dir>/
├── session.yaml        # config resolution snapshot (target, scope, profile, limits) — audit
├── secrets.yaml        # operator secrets (chmod 600, §12.3) — never end up in session.yaml
├── memory.sqlite       # WAL: domain tables + events + FTS5 + checkpoints (§4.3)
├── evidence/           # evidence: evidence/<evidence_id>/request.txt, response.txt, ...
└── report.md           # report draft (§11)
```

`session.yaml` is written at start (and when the scope changes through HITL) and serves
as the source of truth for "what the session actually worked with".
`memory.sqlite-wal/-shm` are temporary WAL files; they end up in the session archive
after a correct close (WAL checkpoint).

**AD-5.** Operator secrets are stored in a separate file `secrets.yaml` (mode 600).
`session.yaml` is intended for audit and sharing; secrets must not
end up in it in any form. In the session config, secrets are addressed by name
(`<masked:secret-name>`, §6.8).

### 3.4. Entry point and CLI

`swarmy` is a thin wrapper (argparse, no third-party CLI frameworks — P4):

```
swarmy <session-config.yaml> [--agents-dir PATH]... [--profile paranoid|normal|yolo]
       [--mode interactive|mission] [--model provider:model] [--session-dir PATH]
       [--goal-file PATH]
swarmy --resume <session-dir>
swarmy --version
```

The CLI only prepares `SessionConfig` and launches the TUI application; all the logic
is in L1. Headless mode is out of scope for v0.1 (spec §1.4): `cli.py` always starts
`SwarmyTui`.

**Opening goal.** A goal file — `--goal-file PATH`, or by convention `goal.md` lying
next to the session config when the flag is absent — is read by the CLI (UTF-8,
non-empty; an unreadable or empty file is a fail-fast problem reported before the
session folder is created) and handed to the console as `SwarmyTui(session,
opening_goal=...)`. On mount the console journals it as the first `OperatorMessage`
through the same `SessionView.send_operator_message` path as a typed chat message,
so the worker's first pass runs the orchestrator step: the mission starts without
typing. Without a goal file the console waits for the chat; `--resume` never
auto-starts (the goal is already in the journal) and rejects `--goal-file`. The demo
launchers (`scripts/run`) pass `<demo>/goal.md` in `--tui` mode too (D41).

## 4. Domain models and shared memory

### 4.1. Location and the leaf rule

All domain entities are Pydantic v2 models in `memory/models.py` (D9). The module is a
leaf: it imports only `pydantic` and the standard library (§2.5). Event payload models
(`events/models.py`) refer to domain entities by `id`/`ref`, without nested objects —
the event journal stays compact and does not duplicate memory.

### 4.2. Domain entities

```python
class Severity(str, Enum):       # mandatory on Finding (D14)
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"

class FindingStatus(str, Enum):
    CANDIDATE = "candidate"; VERIFIED = "verified"; REJECTED = "rejected"

class FindingType(str, Enum):    # v0.1: xss, sqli, auth, ... (open set, extensible)
    XSS = "xss"; SQLI = "sqli"; AUTH = "auth"          # + registration of new ones in the type registry

class EvidenceKind(str, Enum):   # D20: v0.1 — HTTP only; the rest are reserved
    HTTP_REQUEST_RESPONSE = "http_request_response"    # SCREENSHOT/HAR/GRPC_FILE — phase 2

class Target(BaseModel):
    id: int; base_url: HttpUrl; stack_metadata: dict[str, str] = {}   # filled in as research progresses

class ScopeEntry(BaseModel):
    id: int
    kind: Literal["domain", "ip_subnet", "port", "scheme"]
    value: str                       # domain: "example.com"; subnet: "10.0.0.0/24"; port: "443"; scheme: "https"
    origin: Literal["config", "operator"]   # addition — only through OperatorDecision (§7.5)

class Endpoint(BaseModel):
    id: int
    host: str                        # full host:port — needed for out-of-scope checks
    method: str                      # GET/POST/...
    path: str
    auth_requirements: list[str] = []    # names of secrets/authorization schemes
    research_status: Literal["undiscovered", "probed", "analyzed"] = "undiscovered"
    out_of_scope: bool = False       # out-of-scope entry: network tools do not serve it
    notes: str = ""

class Parameter(BaseModel):
    id: int; endpoint_id: int
    name: str
    location: Literal["query", "body", "header"]
    type: str = "string"             # string type name (string/number/enum...)
    examples: list[str] = []

class Finding(BaseModel):
    id: int
    type: FindingType
    status: FindingStatus
    severity: Severity               # mandatory; cvss is optional (D14)
    cvss_vector: str | None = None
    endpoint_ref: int | None = None  # → endpoints.id
    evidence_refs: list[int] = []    # → evidence.id
    title: str; description: str
    reproduction: list[str] = []     # reproduction steps (for the report)
    created_by: str                  # module/orchestrator name
    created_at: datetime

class Evidence(BaseModel):
    id: int
    kind: EvidenceKind
    session_paths: list[str]         # relative paths inside <session-dir>/evidence/
    finding_ref: int | None = None   # link when saving a finding
    metadata: dict[str, str]         # ts, tool, correlation_id
    created_at: datetime

class AttackNode(BaseModel):
    id: int
    kind: Literal["precondition", "finding", "goal"]
    finding_ref: int | None = None   # for kind == "finding"
    title: str; description: str

class AttackEdge(BaseModel):
    id: int
    src: int; dst: int               # → attack_nodes.id
    kind: Literal["requires", "enables", "leads_to"]

class Note(BaseModel):               # free-form observations (humans/agents)
    id: int; text: str; tags: list[str] = []; author: str; created_at: datetime

class Fact(BaseModel):               # machine-readable statements about the target/stack
    id: int; subject: str; predicate: str; obj: str
    tags: list[str] = []; source: str; created_at: datetime
```

Conventions:

- References between entities use `int` identifiers (SQLite PKs); Pydantic models
  contain no nested object graphs.
- `out_of_scope` is the only mechanism for "out-of-scope data in memory": network tools
  refuse to serve a flagged endpoint unless the operator extends the scope (§6.3).
- The reserved `EvidenceKind` values (`screenshot`, `har`, `grpc_file`) are declared in
  the enum but not produced in v0.1 — adding new kinds of evidence does not change the
  schemas (D20).

### 4.3. SQLite schema

One file `memory.sqlite`, WAL, `busy_timeout = 5000`, `foreign_keys = ON`. Tables are
divided by logical subsystem (one file — three stores, D2/D3 + checkpointer):

| Subsystem | Tables | Access rules |
|-----------|--------|--------------|
| Domain | `target`, `scope_entries`, `endpoints`, `parameters`, `findings`, `evidence`, `attack_nodes`, `attack_edges`, `notes`, `facts` | only through `MemoryStore` |
| Events | `events` | append-only through `JournalWriter`; `UPDATE`/`DELETE` are forbidden |
| Search | `fts_endpoints`, `fts_findings`, `fts_facts`, `fts_notes` (FTS5) | only through `SearchIndex`; synchronization — triggers on the domain tables |
| L0 checkpointer | `checkpoints`, `checkpoint_writes`, ... (LangGraph schema) | only through the deepagents SQLite checkpointer |
| Service | `schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT)` | only the migrator |

Migrations are sequential `ALTER`/`CREATE` scripts in `memory/schema.py` (a list of
`(version, ddl)` pairs), applied at `Session.open()` in a transaction; the checkpoint
tables are created by the checkpointer itself. Field formats:

- Multi-valued fields (`tags`, `examples`, `evidence_refs`) are JSON strings.
- `events.payload` is a JSON string of the payload model (§5.1); `events.ts` is UTC
  ISO-8601.
- All domain tables have `id INTEGER PRIMARY KEY AUTOINCREMENT`.

**AD-6.** Domain tables, the event journal and the L0 checkpointer live in a single
SQLite file: one file = a portable session (spec §6.1). WAL allows concurrent reads
with a single writer; concurrent writes from the three subsystems are serialized by
SQLite's built-in locking (`busy_timeout`). `Database` gives each subsystem its own
connection (aiosqlite) — the bottleneck (a single writer) is locally acceptable and
controlled by `ResourceLimiter` limits.

### 4.4. MemoryStore API

`MemoryStore` methods are typed functions over the tables; every public method
corresponds to a platform tool in `tools/platform.py` (`memory_*` prefix; the exception
is the verification tool `update_finding_status`, §6.1): argument validation in the tool
is performed by Pydantic models before the store is called.

| MemoryStore method | Tool | Semantics |
|--------------------|------|-----------|
| `search(query, entity_types?, limit) → list[SearchHit]` | `memory_search` | FTS5 (bm25), filter by entity type |
| `get(entity_type, id) → BaseModel` | `memory_get` | typed return of a single entity |
| `upsert_endpoint(EndpointDraft) → Endpoint` | `memory_upsert_endpoint` | dedup by `(host, method, path)`; parameter updates are appended |
| `save_finding(FindingDraft) → Finding` | `memory_save_finding` | candidate creation; `evidence_refs` are validated for existence |
| `update_finding_status(id, status, severity?) → Finding` | `update_finding_status` (platform) | verifiers: `FindingVerified`/`FindingRejected` |
| `link_attack_node(AttackNodeDraft, AttackEdgeDraft...) → AttackNode` | `memory_link_attack_node` | node + typed edges in a single call |
| `add_fact(FactDraft) → Fact` | `memory_add_fact` | — |
| `add_note(NoteDraft) → Note` | `memory_add_note` | — |
| `list_endpoints(filter) → list[Endpoint]` | — (TUI/report) | read-only |
| `list_findings(status?, severity?) → list[Finding]` | — (TUI/report) | read-only |
| `list_facts(subject) → list[Fact]` | — (core replay mechanics) | read-only: full dump of one subject in row order (D39) |

`SearchHit` = `{entity_type, id, title_snippet, score}`. All mutating methods publish
a platform event (`EndpointsDiscovered`/`EndpointUpdated` in `upsert_endpoint`, the
others as needed) — §5.5: the platform creates the event.

### 4.5. SearchIndex

```python
class SearchIndex(Protocol):
    async def index_up(entity_type: EntityType, doc_id: int, text: str) -> None: ...
    async def search(query: str, entity_types: list[EntityType] | None,
                     limit: int) -> list[SearchHit]: ...
```

The v0.1 implementation is `Fts5SearchIndex`: FTS5 virtual tables with `title, body`
columns; synchronization is `AFTER INSERT/UPDATE` triggers. Ranking: bm25 + a boost for
matches in `title`. Phase 2 is `VecSearchIndex` (sqlite-vec, version pinned because of
its pre-v1 status): the same `SearchIndex`, hybrid scoring on top; the backend is
selected by the `memory.search_backend` config key (§12.1). The interface is the only
abstraction here: there are at least two implementations (P4).

## 5. Events: models, bus, journal

### 5.1. Envelope and payload models

```python
class EventSource(str, Enum):
    PLATFORM = "platform"          # platform payload (L1 components)
    ORCHESTRATOR = "orchestrator"  # the orchestrator itself
    MODULE = "module"              # source_detail = module name

class EventEnvelope(BaseModel):
    id: int                        # journal PK (monotonic order)
    ts: datetime                   # UTC
    type: str                      # registry key, e.g. "FindingCandidate"
    source: EventSource
    source_detail: str             # module name / platform component
    correlation_id: str            # delegation (task) or finding id; "" — outside chains
    payload: BaseModel             # concrete class from EventRegistry

class FindingCandidatePayload(BaseModel):
    finding_id: int
    finding_type: FindingType
    endpoint_ref: int | None
    evidence_refs: list[int]

class GuardrailBlockedPayload(BaseModel):
    tool_name: str
    rule_id: str                   # rule id or "invariant:<name>" / "judge:<verdict>"
    layer: Literal["invariant", "engine", "module", "judge"]
    reason: str                    # human-readable reason (goes to the agent)
    tool_args_digest: str          # sanitized argument digest (§6.8)
```

Every event type has a corresponding payload model. The other v0.1 payloads (type list —
§5.5) are structured the same way: domain entity identifiers + digests.

### 5.2. Type registry and `emit_event`

`EventRegistry` (`events/models.py`) is the only place that maps `"TypeName" → payload
class`. Extending the taxonomy: a new type = payload class +
`EventRegistry.register(TypeName, PayloadModel)` at package import (built-ins in
`events/models.py`, module payloads from the module's `tools/` at load time, §8.4).

The `emit_event` tool is a factory in `events/emit.py`: it creates a tool function bound
to a specific session (bus, journal, delegation correlation context). Mechanics:

1. the arguments `{type: str, payload: dict}` are validated by the registry (unknown type
   or invalid payload → tool error to the agent);
2. the envelope gets `source`/`source_detail` from the calling subagent's name and
   `correlation_id` from the delegation context (§9.4);
3. it is published via `EventBus.publish` (§5.3).

Modules have no direct access to the bus/journal — only `emit_event` and the platform
(spec §5.2). Platform tools (`memory_*`, http tools) publish events themselves — an agent
cannot forge `source` or the type.

### 5.3. EventBus

In-memory pub/sub on `asyncio.Queue` (one per subscriber). Semantics:

- **Order:** events are delivered to a subscriber in increasing `id` order
  (journal-first: first append to the `events` table — obtaining the `id` — then
  fan-out).
- **Durability until delivery:** the append happens before fan-out, so a process crash
  between append and delivery does not lose the event — subscribers catch up on the
  journal on resume (§13.1).
- **v0.1 subscribers:** `OrchestratorRuntime` (policy notifications — unbounded queue),
  `SwarmyTui` (feed — queue with coalescing: UI updates are merged, events are not lost,
  only redundant redraws are), `JournalWriter` (pass-through, no filter).
- **Subscription filtering:** `subscribe(types: set[str] | None)` — `None` = all events.
- Subscriber handler errors are isolated: a handler exception is logged, and the bus
  continues delivery to the others.

### 5.4. Journal

`events` is append-only; the unique `id` is assigned by SQLite. `JournalReader` provides:

- `tail(n)` — the last n events (TUI when opening a session);
- `range(from_id)` — catch-up after resume;
- `by_correlation(cid)` — the trace of a delegation/finding (audit);
- `by_type(type)` — statistics for `session_info` and the report.

The journal is the primary source for audit and recovery (D3): "resume = graph
checkpointer + unread journal tail".

### 5.5. v0.1 taxonomy

| Type | source | Payload model | Default subscribers |
|------|--------|---------------|---------------------|
| `TargetSet` | platform | `{target_id, base_url}` | TUI, runtime |
| `ScopeChanged` | platform | `{added: list[ScopeEntry], operator_comment}` | TUI, runtime |
| `EndpointsDiscovered` | module/platform | `{endpoints: list[int], out_of_scope_count}` | TUI, runtime |
| `EndpointUpdated` | module/platform | `{endpoint_id}` | TUI, runtime |
| `FindingCandidate` | module | `FindingCandidatePayload` | TUI, runtime (verification policy) |
| `FindingVerified` / `FindingRejected` | module/platform | `{finding_id, severity?, reason?}` | TUI, runtime (tree policy) |
| `AttackTreeUpdated` | module | `{tree_id, op: add_node\|add_edge, node/edge id}` | TUI |
| `GuardrailBlocked` | platform | `GuardrailBlockedPayload` | TUI, runtime, judge |
| `OutboundSecretWarn` | platform | `OutboundSecretWarnPayload` (`{tool_name, request_id, secret_names, locations}`) | journal (audit only: append without fan-out) |
| `TaskRequested` / `TaskCompleted` | platform/orchestrator | `{correlation_id, subagent, status, summary_digest}` | TUI, runtime |
| `OperatorMessage` | platform (TUI) | `{text_digest}` | runtime |
| `OperatorDecision` | platform (TUI) | `{request_id, decision: approve\|edit\|reject, edited_args_digest?}` | runtime, hitl |

`*_digest` always goes through `ContextProjector` (secrets/size, §6.8). The contract
applies at the journal boundary: a digest field is projected (masking + budget +
normalization, §6.8) at the moment the event is published —
`OperatorMessage.text_digest` and the `summary_digest` of `Task*` pairs are projected at
emit — both **without** the untrusted wrapper: operator chat is a trusted stream typed by
the operator and the `Task*` digest is journal-bound, while the TUI display layer renders
any §6.8 markers it meets as a red background (never as text). `GuardrailBlocked.reason` —
exactly like `tool_args_digest` (D25). "Raw by design" (D21) protects the session files (evidence,
raw tool responses) and does **not** extend to the journal digest fields. New types
after v0.1 are added as a "payload class + registration" pair without changing the bus
or the journal.

## 6. Tooling and Execution Pipeline

### 6.1. ToolRegistry and Risk Classes

`ToolRegistry` maintains a table of `name → ToolEntry{fn, risk_class, owner, source}`:

- `owner` — `"platform"` or the module name; `source` — `"builtin"` / `"module:<dir>"`.
- **Reserved prefixes** of platform tools: `memory_*`, `event_*`,
  `session_*`. A module **cannot** declare its own tool with these prefixes —
  the loader aborts the session start with a list of collisions (fail-fast, spec §4.3). The
  platform tools themselves are **available** to every subagent: the loader adds them
  to the module's toolset (this reconciles spec §4.3 and §4.6: the crawler uses
  `memory_upsert_endpoint` and `emit_event` but cannot declare a tool with such a name).
- **Risk classes** (the basis of HITL gates, §7.2):

| Class | Purpose | Assignment |
|-------|------------|------------|
| `passive` | reading the target/platform | explicit declaration of the platform read tools (all of them declare one); an undeclared module tool gets the most gated class by default (D34, F-3/ASI02) |
| `network-write` | POST/PUT/PATCH/DELETE to the target | http tools, by HTTP method |
| `verify` | exploitation checks | explicit tool attribute |
| `destructive` | potentially breaking operations | explicit tool attribute |

  **AD-7.** The class is set by the `swarmy_risk_class: RiskClass` attribute of the
  tool function (for module tools; an undeclared attribute defaults to `destructive`,
  the most gated class: a forgotten declaration fails toward operator
  approval rather than silent execution — D34, F-3/ASI02). HTTP tools are classified
  automatically by method; a whole group can be marked at the module level in `guardrails.yaml`
  (`tool_classes:`). The class is not computed from the argument contents — only from
  the declaration; otherwise the HITL gates become non-deterministic.

Platform tools (implementations in `tools/platform.py`, `tools/http/tools.py`,
`report/generator.py`): `memory_search/get/upsert_endpoint/save_finding/link_attack_node/
add_fact/add_note`, `update_finding_status` (finding verification, §4.4), `emit_event`,
`session_info`, `http_get`, `http_post`, `http_put`, `http_delete`, `generate_report`.
`session_info` returns the scope, research statuses, profile, request budget counter —
without raw secrets.

### 6.2. HTTP Client

Types (`tools/http/models.py`):

```python
class RequestSpec(BaseModel):
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
    url: HttpUrl
    headers: dict[str, str] = {}     # secrets are passed by name from secrets.yaml
    query: dict[str, str] = {}
    body: str | None = None          # byte limit is enforced by the limiters
    evidence: bool = True            # whether to record evidence
    evidence_depth: Literal["request", "request_response"] = "request_response"

class ResponseRecord(BaseModel):
    status: int; reason: str
    headers: dict[str, str]
    body_preview: str                # already sanitized projection (§6.8)
    body_bytes: int                  # full size
    elapsed_ms: int
    redirects: list[str]             # chain of URLs
    evidence_id: int | None = None   # evidence id in the session
    request_id: str                  # correlation for memory_save_finding
```

The pipeline of every call (implementation `SwarmyHttpClient.request`; the tools are thin
wrappers `http_get/http_post/...` over it):

```
RequestSpec ─▶ GuardrailPipeline.allow? ──no──▶ GuardrailBlocked + feedback to the agent (stop)
                     │ yes
                     ▼
              ResourceLimiter.acquire(host, method)   # semaphore/rate/budget (§6.4)
                     │
                     ▼
              httpx.AsyncClient (redirects=False) ──▶ redirect: each hop re-runs
                     │                                 scope+limits (depth counter)
                     ▼
              EvidenceRecorder (if evidence=True)   # raw req/resp to files, Evidence record
                     │
                     ▼
              ContextProjector.project(response)      # preview: budgets/masks/markers (§6.8)
                     │
                     ▼
              ResponseRecord → to the agent (preview), raw data → evidence/
```

Details:

- **Redirects** are executed manually (`max_redirect_depth` from the limits): each hop is a new
  scope/limits pass. A cross-domain redirect outside the scope = `GuardrailBlocked` block
  (scope invariant, spec §7.2).
- **DNS rebinding** (F-11): before each hop the name from the URL is resolved by the injected
  `HostResolver` (`GetaddrinfoHostResolver`, `loop.getaddrinfo`); **every** resolved
  address must fall into the scope's `ip_subnets` (when they are set), and the first address
  of that name in the session must remain among the records of every subsequent resolution
  (`_HostPin`). The hop connects to the verified address: the request URL carries the
  pinned IP for the socket, while `Host`, SNI and certificate validation stay on the
  name (a documented httpx ≥ 0.28 extension — `sni_hostname`; `Host`
  is substituted only if the request author did not set their own). A failed connect on one
  verified address iterates over the other verified candidates; a timeout
  does not (the target does not respond). A violation = `GuardrailBlocked(invariant: host-pin)`
  block before the network; a hung resolver also blocks the hop (fail-closed: a timeout cannot
  silently skip the check and let the hop through); IP literals and unresolvable names
  pass without resolution (there is nothing to pin / the connection will not happen anyway).
  A client assembled without a resolver (the test seam with injectable transport)
  does not enable the protection; the production build (`core.session`) always passes a resolver.
- **Outbound hygiene** (spec §7.1): headers/body are checked by the operator
  secret detector before sending; a match → a platform warn event + masking in the preview.
  A warn does not block (the operator deliberately passed credentials to test authorization).
- **Evidence recording**: `EvidenceRecorder` writes `request.txt` / `response.txt` (raw,
  complete) into `evidence/<uuid>/` and creates an `Evidence` record (kind=`http_request_response`,
  metadata: ts, tool, correlation_id). The depth (`request` vs `request_response`) —
  from the tool classes config.
- **Timeouts**: connect/read — from the limits; a violation = `TimeoutError` → the platform
  publishes `GuardrailBlocked(layer="invariant", rule_id="timeout")` and returns
  textual feedback to the agent.

### 6.3. ScopeRegistry

- Source: `scope_entries` of the session config; runtime additions — only an operator
  decision: `Session.extend_scope` — the only production path with `origin="operator"` —
  executes `ScopeRegistry.extend()` and publishes a `ScopeChanged` event journal-first
  (invariant 2; spec §7.2); the operator TUI/chat command is wired in M4 (following
  `set_mode`, §9.5). In v0.1 operator additions are journaled for audit but are not
  written into `scope_entries` — a resumed session starts from the `session.yaml` snapshot
  (D28, spec §13).
- The `check(url) → ScopeVerdict(allowed | denied(reason))` check is called **before** every
  network hop. Matching semantics: host — exact domain name or a subordinate subdomain
  (`*.example.com` for `scope.domains: [example.com]`); IP — `ipaddress` subnets;
  port — explicit list (default 80/443 by scheme); scheme — http/https allowlist.
- A memory record with `out_of_scope=True` is not served by the network tools: an attempt
  to request such an endpoint = `GuardrailBlocked(invariant: out-of-scope-target)`. The data
  loop is closed (review #8↔F-1): `core.session` on every open **and** resume
  loads all marked rows into `ScopeRegistry.mark_out_of_scope`, and the
  `EndpointsDiscovered`/`EndpointUpdated` events replenish the registry on a live session (the handler
  re-reads the memory row and repeats the mark; marks are monotonic). Removing a mark —
  only an operator decision: the `memory_upsert_endpoint` tool rejects
  `out_of_scope=False` on an already marked record, and the registry has no unmark — fail-closed:
  a mark is a restriction, removing it is an expansion of the perimeter (D28, spec §13).
- DNS rebinding protection (F-11): before each hop the client resolves the name from the allowlist
  (`HostResolver` = `loop.getaddrinfo`, cross-platform), **every** address is verified
  against `ip_subnets` (`ScopeRegistry.resolved_ip_denial_reason`), the first address is pinned for
  the session, and the connection targets the verified address (pinned IP in the URL,
  `Host`/SNI/certificate — on the name, the `sni_hostname` extension); a resolution in which
  the pinned address no longer appears, and a hung resolver = `GuardrailBlocked
  (invariant: host-pin)` before connecting (§6.2).
- Denial = a `GuardrailBlocked` event **before** the network call; the agent gets the reason and
  adjusts the plan (spec §8.5).

### 6.4. ResourceLimiter (Session-Global Limits)

All limits are invariants, configurable, **session-global** (§7.3, D19): under parallel
`task()` calls the swarm's total pressure on the target does not exceed a single agent's limit —
the limiter does not know which subagent invoked the tool.

| Limit | Implementation mechanism |
|-------|---------------------|
| `rate_limit` (rps per host) | token bucket per host (asyncio) |
| `max_concurrent_requests` | global `asyncio.Semaphore` |
| `max_body_bytes` | cutoff when reading the response (the body goes into evidence — complete up to the threshold, beyond it — a truncation marker) |
| `max_redirect_depth` | hop counter in the client pipeline |
| `total_request_budget` | atomic session counter; exhaustion → denial of all network calls + `GuardrailBlocked(invariant: budget)` |
| timeouts | connect/read of the httpx client |

`acquire(host, method)` — the single entry point: returns an async context, released
on exit from `with`. Waiting for the semaphore/rate does not block the event loop; agent task
cancellation (HITL reject, session close) — via asyncio task cancellation.

### 6.5. GuardrailPipeline

Pre-tool-call pipeline (deepagents middleware — the L0 extension point; `wrap_tool_call` hook).
AND-composition: **a deny from any rule denies the operation**; an allow requires an allow
from all layers (D11).

```
GuardrailMiddleware.wrap(tool, args)
  1. layer 1: invariants.py   — scope, limits, egress, "platform HTTP only"
                                (non-disableable; rule source — code constants)
  2. layer 2: engine_rules.py — basic engine rules (disableable in the session config)
  3. layer 3: module rules    — the given module's guardrails.yaml (for its tools)
  4. judge: LlmJudge          — only for classes from the judge config (§6.7)
     ── block ──▶ GuardrailBlocked {tool, rule, layer, reason, digest} + feedback to the agent
     ── allow ──▶ tool execution
```

Violation semantics (spec §8.5): the call is not executed; the attempt is recorded in the journal and
`GuardrailBlocked` is published; the agent gets textual feedback (rule id, reason,
layer); a forced allow — only `OperatorDecision` through HITL (in both modes).
The agent has no direct "bypass the rule" tool.

Every `GuardrailMiddleware` instance is assembled with the full set of layers: a subagent gets
invariants + engine + its module's rules; the orchestrator gets invariants + engine. Invariants
live in code (`invariants.py`) and are not configurable.

### 6.6. DSL `guardrails.yaml`

The rule schema is a Pydantic model (`guardrails/models.py`); the file is validated by `dsl.py`
(fail-fast with a list of all problems, spec §4.5):

```python
class RuleCondition(BaseModel):
    any_param_matches: str | None = None    # regex over the request parameter values
    url_matches: str | None = None
    header_matches: str | None = None
    body_size_above: int | None = None
    tool_in: list[str] | None = None

class GuardrailRule(BaseModel):
    id: str                                 # unique within the file
    applies_to: list[str]                   # tool names
    condition: RuleCondition                # predicates — conjunction; inside any_* — disjunction
    action: Literal["block"]                # v0.1: block only (review/allow — phase 2)
    severity: Literal["low", "medium", "high"]
    message: str

class ModuleGuardrails(BaseModel):
    tool_classes: dict[str, RiskClass] = {} # optional: classes for the module's own tools
    rules: list[GuardrailRule] = []
```

Predicate evaluation is deterministic, over the `RequestSpec`/tool arguments before the network;
regexes are Python `re` with a compile timeout at validation. The scan ReDoS discipline
(review F-10): module regex predicates are length-limited at validation (512 characters)
and undergo structural loop-safety analysis on the `re` parse tree (the same parser
that compiles the pattern): loops whose iteration boundary can "slide" are rejected —
alternation inside a loop, an optional iteration tail (`(\w?\s?){5,}`, `(?:xa?)+`),
overlapping or unprovable seams (`(a|aa)+`, `a+a+`, `(a*)(a*)`, `(?:x+(?:y|x))+`,
forms inside look-ahead); safe families remain accepted — literal seams
with a disjunction (the corner-case `(?:/[^/?#]+){6,}`), atomic groups and possessive
quantifiers, symmetric fixed seams (`(?:ab)+`). Any analysis error
rejects the pattern (fail-closed): the pipeline runs these patterns over the untrusted
argument tree on every call; the default engine rules use bounded
quantifiers (`.{0,256}`). There is no LLM in the deny critical
path (spec §8.3). The example from the spec (`no-true-based-sqli`) is part of
the default set in `engine_rules.py`; the same file may be supplied by a module.

### 6.7. LLM Judge

Asymmetry (D11): the judge **adds** restrictions (escalation/flag) and **cannot**
lift a deterministic deny. Two tracks:

1. **Pre-call (selected classes).** Judge config: `judge.tools: list[RiskClass]`,
   `judge.model`, `judge.confidence_threshold`, `judge.timeout_s`. If the deterministic
   layers allowed a call of a class from the list — the pipeline waits for the judge's verdict (LLM, a separate
   model) for no longer than `timeout_s`:
   - `ok` → execution;
   - `flag` → execution + a note in the journal (call annotation);
   - `escalate_hitl` (or timeout — fail-closed) → the call is **not executed**, enqueued into the
     HITL queue as an `escalated` request (§7.3); the operator's decision is the only way
     forward. The judge does not "let through" — it only hands over to a human.
2. **Post-call (results).** For tool results that hit the suspicion
   heuristics (configurable patterns of instruction-like content), the judge looks
   asynchronously, outside the execution path: `flag` — a note to the journal/context; `escalate_hitl`
   — an event to the orchestrator and **temporary gates** `JudgeEscalationRegistry` on the tool
   class until the operator's decision (repeat calls of this class become HITL).

`JudgeEscalationRegistry` (`guardrails/judge.py`) — a registry of "tool class → reason",
cleared only by `OperatorDecision`. This is how the judge strengthens guardrails in both `interactive` and
mission mode (spec §5.5) without breaking the determinism of denials.

### 6.8. ContextProjector (D21)

Principle: memory and session files are raw; everything returned to the model (response preview,
event digest, guardrail feedback, endpoint list) is a sanitized projection.

Application — `ProjectorMiddleware` (deepagents post-tool-call hook) on every agent
(orchestrator and subagents) + explicit calls in TUI/journal digests. Four steps
(D23: masking before the budget; D24: deactivation of markers in content):

1. **Operator secret masking**: patterns from `secrets.yaml` (names + values) and
   built-in detectors (Authorization/Cookie-like headers, bearer tokens) →
   `<masked:secret-name>`. Masking is performed **before** the budget (D23): a secret
   cut by the truncation boundary no longer matches in full — the previous
   "budget → masking" order let an uncovered secret prefix into the model context;
   the budget is applied to the already masked text (as in the client's preview path).
   The re-masking guard is tied to the names the projector itself may
   substitute (ingested secrets + `authorization`/`bearer`/`cookie`): a decoy
   `<masked:decoy>` string in a header reflected by the target no longer disables
   masking of the string (D24).
2. **Byte budget** by tool classes (`context.budgets` of the config; defaults
   are conservative): truncation with a `[truncated N bytes]` marker; the full content — in evidence.
3. **Untrusted marking**: target content is wrapped in untrusted-data markers:
   `[untrusted-target-content begin] ... [untrusted-target-content end]`. Occurrences
   of these markers *inside* the content are deactivated into a visible escaped form
   (`[defused:...]`) with a platform note `[note: N untrusted-marker spoof
   attempts defused]` after the closing marker (D24): target content can neither
   close its own block nor fabricate a "quoted" untrusted block.
4. **Normalization**: removal/escaping of control characters and hidden Unicode (biDi, zero-width)
   before entering the context.

Raw data remains available: evidence in `evidence/`, domain records in SQLite, the report.
The TUI shows raw finding values (for pentester verification) and masked ones — in
event feeds/chat.

## 7. HITL

### 7.1. Mechanism

- Gates are deepagents `interrupt_on` (`InterruptOnConfig`) + the L0 `HumanInTheLoopMiddleware`;
  persistence — the SQLite checkpointer (L0 tables in `memory.sqlite`).
- `Engine` builds `interrupt_on` from the profile (§7.2) at assembly; for subagents the loader
  applies the module's `interrupt_on` (spec §4.2) on top of the profile gates **with the primacy
  of the operator** (D34, review F-4): the manifest may only add gates; an entry of `false`
  for a tool gated by the profile, like an entry for an unknown tool, is
  a load error (fail-fast, §8.3). Profile gates are the operator's control
  (SECURITY.md ASI02/ASI09).
- The interrupt is saved in the checkpointer → it survives a session restart (resume §13.1).
- Resume loop (verified L0 API): `graph.aget_state(config) → snapshot.interrupts` →
  `graph.ainvoke(Command(resume={interrupt_id: decision}))` → repeat until
  `snapshot.interrupts` is empty.

### 7.2. Tool Classes and Strictness Profiles

| Profile | `passive` | `network-write` | `verify` | `destructive` |
|---------|-----------|-----------------|----------|----------------|
| `paranoid` | — | gate | gate | gate |
| `normal` (default) | — | — | gate | gate |
| `yolo` | — | — | — | gate |

`ApprovalQueue.build_interrupt_config(profile, module_overrides) → dict[tool,
InterruptOnConfig]` — a mapping of "class × profile" to gates for every tool in the
registry; `allowed_decisions = ["approve", "edit", "reject"]` (the L0 `respond` decision is not
used — reject/edit form the feedback to the agent). Changing the profile on the fly = rebuilding
the config and recompiling the orchestrator graph (a documented L0 operation).

Autonomy modes on top of the gates (spec §5.5): `interactive` adds gates on "significant
forks" (running class tests, verification) via `interrupt_on` in addition to the
profile; `mission` keeps only the profile gates. Switching — an operator command
in the chat → the platform rebuilds the gates → an event to the journal.

### 7.3. ApprovalQueue

`core/hitl.py`:

- Polls the graph state (`snapshot.interrupts`) and maintains a FIFO queue of
  `ApprovalRequest{request_id, interrupt_id, tool, args_digest, rule/profile, origin}`.
  `args_digest` — a sanitized projection of the arguments (§6.8) — what the operator sees.
- Judge escalations (`escalate_hitl`, §6.7) enter the same queue with the
  `origin="judge"` marker.
- `submit_decision(request_id, decision, edited_args?)` → `Command(resume={interrupt_id:
  decision})` into the graph; with `edit` — substituting the edited arguments; the decision
  is published as `OperatorDecision` and lands in the journal.
- The queue is visible in the TUI (HITL Approvals panel); the decision modal is modal for
  the operator but **does not block** the rest of the swarm: other subagents keep working,
  their own interrupts queue up (spec §9.2).

### 7.4. Decision Flow

```
subagent calls a tool (class verify)
  └▶ HumanInTheLoopMiddleware: interrupt → the graph is stopped at the call point
       └▶ the checkpointer saves the state (SQLite)
            └▶ ApprovalQueue notices the interrupt → FIFO → TUI modal
                 └▶ operator: approve / reject / edit
                      └▶ submit_decision → Command(resume) → the graph continues
                           ├─ approve → the tool is executed (guardrails still apply)
                           ├─ edit    → executed with the modified arguments
                           └─ reject  → the agent gets feedback "rejected by the operator"
```

Invariant: after resume the tool goes through the **same** `GuardrailPipeline` — the operator's
approve does not cancel the invariants; it authorizes this specific call (spec §8.5).

## 8. Subagent modules (the extensibility core)

### 8.1. Directory contract

```
agents/<module-name>/
├── AGENT.md          # required: YAML frontmatter + system prompt (body below the frontmatter)
├── tools/            # optional: python files with tool functions (fully typed)
├── skills/           # optional: skills per the agentskills.io specification
└── guardrails.yaml   # optional: module rules + tool classes
```

### 8.2. Manifest (`AgentModuleManifest`, `modules/manifest.py`)

The `AGENT.md` frontmatter is validated by a Pydantic model and mapped onto the L0
`SubAgent` dict:

| Field | Type | Required | → SubAgent |
|------|-----|-------|------------|
| `name` | str | yes | `name` |
| `description` | str | yes | `description` (normalized: control characters → spaces, embedded §6.8 markers are deactivated; limit of 400 characters after normalization — an excess is a load error, not a silent truncation; F-9) |
| `model` | str \| None | no | `model` (`provider:model`), otherwise the orchestrator's model |
| `mode` | `"isolated"` \| `"fork"` | no | `mode` (default `isolated`) |
| `interrupt_on` | dict[str, bool] | no | `interrupt_on` (only adds gates on top of the profile ones, §7.1/§7.2; D34) |
| `events` | list[str] | no | checked against the `EventRegistry` (§8.4) |
| `guardrails` | str | no | path to `guardrails.yaml` (default `./guardrails.yaml`) |
| `result` | str \| None | no | `response_format` (§8.3, AD-3) |

**AD-3.** The specification requires an optional subagent `response_format` (§4.5 spec),
but §4.2 does not define where the schema is declared. Decision: an optional `result`
field in the frontmatter — a path string `"<module>/tools/result.py:FindingResult"`; the
loader imports the Pydantic class and passes it as `response_format`. The alternative of
a "convention by file name" was rejected: implicit conventions are worse than an
explicit field for fail-fast validation.

`tools/` are not declared in the frontmatter: the loader wires up all the contents of
`tools/` and `skills/` automatically. Each subagent has its own isolated
skills-middleware (L0 behavior; `mode="fork"` inherits the parent's skills and has none
of its own — see §4.4 spec and the L0 limitations); the module's `skills/` reaches
that middleware through the composite route `/module-skills/<name>/` (§8.6, AD-10).

### 8.3. Loading and assembly (`ModuleLoader`, `modules/loader.py`)

```
scan (user dirs + built-in modules: <package>/agents in the wheel, <repo>/agents in editable mode)
  └▶ for each directory:
       parse AGENT.md (frontmatter → AgentModuleManifest, body → system_prompt)
       import tools/*.py → tool functions (type validation: §8.5)
       parse guardrails.yaml → ModuleGuardrails (§6.6)
       register events (payload models tools/event_models.py, if present)
  └▶ fail-fast: a single list of problems across ALL modules → ModuleLoadError (session start aborted)
  └▶ assembly of SubAgent dicts:
       {
         "name", "description", "system_prompt", "model", "mode",
         "tools": [platform_tools + module_tools],
         "middleware": [GuardrailMiddleware(invariants, engine_rules, module_rules)],
         "interrupt_on": merge(profile_gates, manifest.interrupt_on),
         "skills": ["/module-skills/<name>/"],   # virtual composite route (§8.6) — never a disk path (AD-10)
         "response_format": imported_model | None,
       }
  └▶ ModuleRegistry: module names, event declarations → creation of the orchestrator graph
```

Import mechanics: `importlib.util.spec_from_file_location` — module `tools/` are not
installed into the project's `sys.path`; module code runs in the same process (D4), and
its tools get access to the platform **only** through the tool functions that are passed
in (§8.5).

Registry lifecycle per load (F-12/#35, #44): `load()` resets the `EventRegistry` to the
built-in taxonomy at the start (one load = one taxonomy: a failed or repeated load
leaves no "ghost" module types for subsequent sessions), while `ToolRegistry` entries
are deferred and applied **exactly once, only when all modules have loaded without
problems** — an aborted load leaves no registered tools (a repeated start in the same
process does not fail on duplicates).

**AD-4.** A user module name colliding with a built-in is a load error (fail-fast);
overriding built-ins is not supported in v0.1. Reason: ambiguous "whose module won"
behavior is dangerous in a pentest tool; explicit selection (`--agents-dir` without
built-ins) will be added if needed.

### 8.4. Module events and the registry

- An optional module `tools/event_models.py` registers payload classes in the
  `EventRegistry` at load time (§5.2) — this is how a module can introduce its own
  event types.
- The registry is process-global, but its lifecycle is **per load** (F-12/#35):
  `EventRegistry.reset()` at the start of each `load()` restores the built-in taxonomy,
  after which module types are registered anew; a collision between two modules within
  one load remains a load error.
- The frontmatter `events` list is checked against the registry: a declared but
  unregistered type = load error; an event emitted via `emit_event` with an undeclared
  type is a tool error returned to the agent (at runtime the type is checked against the
  event registry; the frontmatter is responsible only for loading).

### 8.5. Constraints of the module tool environment

| Constraint | Mechanism |
|-------------|----------|
| Full typing, no `Any`/`dict[str, Any]` | ruff/ty strict on `src/swarmy/**`; ruff strict on `agents/**`; the loader checks `typing.get_type_hints` of every exported tool — an unannotated parameter = load error |
| Docstring = LLM-facing description | the loader requires a non-empty docstring on every tool function |
| Reserved prefixes | see §6.1 |
| Network — only the platform HTTP client | invariant guardrail: calls of module tools that import `socket`/`urllib`/`http.client` and the HTTP client families `httpx`/`aiohttp`/`requests` (F-2: they are installed in the same venv where the module tools run) are blocked statically from network access — the loader's AST scan of imports **and call forms** (`os.system`/`os.popen`, raw asyncio streams `open_connection`/`start_server`; bare `os` is not forbidden — only the process-spawning uses; `subprocess` is forbidden by import) — the same scan covers `skills/**/*.py`; dynamically — the `tool_in` rule at the invariants level (there is no legal path to sockets — module tools work with `RequestSpec`, the platform performs the network access) |
| Single platform entry point | module tools receive `SessionContext` (an object with http/memory/emit) from the loader factory's closure; there are no direct imports of `swarmy.core` from a module |
Direct sockets in modules are forbidden and blocked by the invariant guardrail (§4.3
spec): a static check at load time (analysis of module imports) + the architectural
property "only `SwarmyHttpClient` performs network access" make a workaround impossible
without modifying the engine.

### 8.6. Skills

Full compliance with the agentskills.io specification: `SKILL.md` (frontmatter `name`
≤64, `description` ≤1024; optionally `license`, `compatibility`, `metadata`), resources
in `scripts/`, `references/`, `assets/`. The built-in L0 skills-middleware is used as
is (progressive disclosure: metadata → instructions → resources). A skill's own tools
— `metadata.include_tools` (an L0 extension). The loader statically scans every
`skills/**/*.py` script of both containers (ASI05) and, for a module carrying
skills, requires the module name to be a valid route segment (below); the
orchestrator container's frontmatter is validated fail-fast (below), a module
skill's frontmatter is validated by L0 itself at subagent start (an invalid skill
is skipped with a warning).

**Two containers, one L0 mechanism.** *Module skills* live in `agents/<module>/skills/`
and are wired by the loader into that module's `SubAgent` dict as the **virtual**
source `skills=["/module-skills/<name>/"]` (§8.3) — `Engine` mounts the directory
read-only under that route in the composite backend (below). *Orchestrator skills*
live in the **repository-root `skills/<skill-name>/`** container (shipped as
`swarmy/skills`, resolved by `core/skills.py:builtin_skills_root()` in both layouts —
the D40 mechanism) and are loaded **automatically into the orchestrator context** at
every session start, with no config key: `Session._compose` calls
`load_orchestrator_skills(root)`, and `Engine.build` hands the result to
`create_deep_agent(skills=["/skills/"], backend=...)`. `mode="fork"` subagents inherit
the orchestrator's skills (L0 rule, §8.2); `isolated` subagents keep only their module
skills. **Why routes, not disk paths (AD-10):** L0 builds every subagent's
`SkillsMiddleware` on the *same* backend the orchestrator was compiled with, and the
default `StateBackend` keeps files in graph state — a disk path handed to it resolves
to nothing, silently. `build_skills_backend(orchestrator, module_skills_routes(modules))`
therefore produces one `CompositeBackend(default=StateBackend(), routes={...})` with a
read-only route per container, and L0 resolves both `/skills/` and
`/module-skills/<name>/` through it. The module namespace is separate from the
orchestrator's so a skill named like a module can never shadow the module route.

What `core/skills.py` adds on top of the L0 middleware:

* **Fail-fast validation** (`load_orchestrator_skills`, invariant 10): every immediate
  subdirectory must be a skill — `SKILL.md` present (not a symlink), frontmatter
  `name` (agentskills.io naming rules, ≤64, equal to the directory name) and
  `description` (≤1024, `compatibility` ≤500); every `skills/**/*.py` script passes the
  shared `modules/loader.py:scan_skill_scripts` static scan (ASI05 — skill scripts run
  with operator privileges). L0 itself only warns and skips a broken skill; here all
  problems of the container are collected into one `SkillsError` and the start aborts.
  A container without skills (or a missing one) is valid: the engine is compiled without
  the `SkillsMiddleware`, exactly as before.
* **Read-only routes**: the default L0 `StateBackend` cannot read disk paths, so every
  skills container is mounted through the one
  `CompositeBackend(default=StateBackend(), routes={"/skills/": ReadOnlySkillsBackend,
  "/module-skills/<name>/": ReadOnlySkillsBackend, ...})` built by
  `build_skills_backend` — `ReadOnlySkillsBackend` is a `FilesystemBackend(virtual_mode=True)`
  subclass whose `write`/`edit`/`delete`/`upload_files` refuse. The orchestrator's own
  file tools stay state-backed; a prompt-injected agent (orchestrator or subagent)
  cannot rewrite the vetted instructions loaded at every start (ASI01 persistence).
  Paths outside the routes are untouched. With neither container present the function
  returns `None`, `Engine` passes `backend=None`, and L0 builds its default
  `StateBackend` — the pre-skills assembly.
* **Module name as a route segment**: a module carrying `skills/` is mounted under
  `/module-skills/<name>/`, so its manifest `name` must match
  `^[A-Za-z0-9][A-Za-z0-9_-]*$` (`modules/loader.py:skills_route_name_problem`) —
  otherwise a collected `ModuleLoadError` problem (fail-fast). Modules without skills
  are not subject to the rule.
* **Reload on the first step** (`OrchestratorRuntime(reload_skills=True)`): the L0
  middleware caches the skill index in the checkpoint, so a resumed thread would never
  see skills added between runs; the runtime merges the documented L0 trigger
  (`skills_metadata: None`) into the first committed step's input (the orchestrator's
  index — a subagent lists its module skills on each of its own runs), and
  `Engine.recompile` (profile/mode switch) keeps the container and every module route.

### 8.7. Built-in modules (reference implementations of the contract)

| Module | Tools | Events | Notes |
|--------|-------------|---------|------------|
| `crawler` | `http_get`, `memory_upsert_endpoint`, `emit_event` + own parsers (`tools/parsers.py`: robots/sitemap/forms/links) | `EndpointsDiscovered`, `EndpointUpdated` | passive recon; `swarmy_risk_class` of the parsers — `passive`; guardrails.yaml: crawl depth limit via `url_matches` |
| `xss-detector` | `http_get`, `http_post`, `memory_search`, `memory_save_finding`, `emit_event` + `tools/marker.py` (markers), `tools/reflection.py` (context analysis) | `FindingCandidate` | POST probes are automatically `network-write` (profile gates); guardrails.yaml: blocks TRUE constructs and known dangerous payloads (example §8.3 spec) |

Both modules are written strictly to the contract of §8 and serve as a reference for
authors (dogfooding, §4.6 spec); their `AGENT.md`, `guardrails.yaml` and `tools/`
structure are the canonical examples.

Module sources are **data, not an importable package**: the build maps the
`<repo>/agents/` directory (D40) to `swarmy/agents` inside the wheel and includes it in
the sdist (§3.2); `ModuleLoader` resolves it via `builtin_agents_root()` in both
layouts (§8.3). With `include_builtins=True`, an empty or missing directory is a
fail-fast `ModuleLoadError` with a message to reinstall the package (a broken
installation, not an empty roster).

## 9. Orchestrator and engine

### 9.1. Engine assembly (`core/engine.py`)

```python
def build_engine(session: Session) -> Engine:
    modules = ModuleLoader(session).load()              # §8.3
    interrupt_cfg = build_interrupt_config(session)     # §7.2 (profile × mode × modules)
    graph = create_deep_agent(
        model=session.config.model,                     # "provider:model" (D1)
        system_prompt=ORCHESTRATOR_PROMPT,              # core/prompts.py (§9.6)
        tools=[session_info, generate_report, ...],     # memory/emit available via the platform
        subagents=modules.subagent_specs,               # §8.3
        middleware=[
            GuardrailMiddleware(invariants, engine_rules),   # §6.5
            ProjectorMiddleware(session.projector),           # §6.8
        ],
        interrupt_on=interrupt_cfg.orchestrator,        # HITL gates of the orchestrator tools
        checkpointer=AsyncSqliteSaver(session.database.raw),  # SQLite (§7.1)
        skills=["/skills/"],                            # orchestrator skills container (§8.6)
        backend=skills_backend,                         # CompositeBackend: StateBackend + read-only /skills/ and /module-skills/<name>/ routes (§8.6, AD-10)
    )
    return Engine(graph=graph, modules=modules, interrupt_cfg=interrupt_cfg)
```

The orchestrator gets **the same** middleware as the subagents: its tools
(`session_info`, `generate_report`, memory wrappers) pass through guardrails and
projection on equal footing with module tools.

The `skills=`/`backend=` pair is the skills wiring (§8.6): the L0 default
`StateBackend` keeps files in the graph state and cannot read disk paths, so
`core/skills.py:build_skills_backend(orchestrator_skills, module_skills_routes(modules))`
builds the composite backend routing the virtual `/skills/` prefix to the validated,
read-only orchestrator container and one `/module-skills/<name>/` prefix per module
carrying `skills/` to its read-only directory; `skills=` names the orchestrator route
as the orchestrator's single skills source. L0 hands this same backend to every
subagent's `SkillsMiddleware`, which is what makes the module sources resolvable
(AD-10). With neither container (no orchestrator skill and no module skills)
`Engine.build` passes neither argument and the compilation is byte-for-byte the
pre-skills one; `Engine.skills_backend` exposes the composite (or `None`) as an
assembly fact. `Engine.recompile` (§9.5) rebuilds the graph with the same composite —
the skills wiring is part of the assembly, not of the profile/mode switch.

### 9.2. OrchestratorRuntime: three loops

`core/runtime.py` owns the execution of the orchestrator graph; the discipline is
**a single writer**:

**AD-8.** At any moment, no more than one `ainvoke/astream` call goes into the
orchestrator graph (asyncio.Lock in the runtime). Parallelism is provided by subagents
(D19) within a single graph step; the orchestrator receives new inputs (event
notifications, operator messages) at graph step boundaries. Reason: graph state is
checkpointed — two parallel inputs into one thread would break checkpoint consistency.

| Loop | Source | Mechanics |
|--------|----------|----------|
| Reactive | EventBus subscription (policies, §9.3) | event → policy → notification synthesis (digest + instruction from the template) → runtime queue → injection into the graph as a message at a step boundary |
| Proactive | operator task (chat) | system prompt + L0 todos: the orchestrator plans and delegates on its own |
| Interactive | TUI chat | `OperatorMessage` → runtime queue → injection as a human message (the text passes through `ContextProjector` before both boundaries — the journal one and the graph one, D25) |

Notifications are injected as a message carrying the untrusted-data marker (any quotes
from target content inside the digest pass through `ContextProjector`). On resume, the
runtime: restores state from the checkpointer, reads the journal to the end (§5.3),
restores the interrupt queue (§7.3), continues.

### 9.3. Event policies

A policy = a declaration in the session config (§12.1):

```yaml
policies:
  - on: FindingCandidate          # event type (or a list)
    action: notify_orchestrator   # v0.1: notify_orchestrator | notify_tui | ignore
    template: verify_finding      # template key in core/prompts.py
```

Built-in defaults (if the section is not specified): `FindingCandidate →
notify_orchestrator (verify_finding)`, `FindingVerified/FindingRejected →
notify_orchestrator (tree_proposal)`, `GuardrailBlocked → notify_orchestrator`,
`ScopeChanged → notify_orchestrator`, `AttackTreeUpdated/Task* → notify_tui`.

Semantics: a policy does **not** execute tools and does **not** create delegations
itself — it injects a notification, and the LLM orchestrator decides whom to delegate
to (`task()`). Delegations remain the only path for executing agent work (audit via the
journal; §5.4 spec).

### 9.4. Delegations and correlation
- A delegation is an L0 `task()` call; execution is async-parallel (D19): several
  `task()` calls within one graph step run concurrently, each with its own subagent
  and an isolated context (default `isolated`; `fork` — per the module manifest).
- Correlation: on entering a subagent, the runtime assigns a `correlation_id` (the
  delegation id); all events/evidence of that subagent carry it;
  `TaskRequested`/`TaskCompleted` link the call tree. This is the basis of the Swarm
  Activity panel (§10.1) and the trace in the journal.
- Session limits are global (§6.4) — the swarm as a whole does not press on the
  target harder than the limit.

### 9.5. Autonomy modes

| Mode | Behavior |
|-------|-----------|
| `interactive` | significant forks (launching tests of a vulnerability class, verification, scope change) are confirmed by the operator: profile gates + additional mode gates (§7.2) |
| `mission` | the orchestrator works on its own within the guardrails: profile gates only; the operator observes and may intervene |

Switching on the fly: an operator command in the chat → the platform reassembles
`interrupt_on` and recompiles the graph (a documented L0 operation) → an event to the
journal.

### 9.6. Orchestrator system prompt (`core/prompts.py`)

The structure is a fixed template:

1. **Role**: orchestrator of a swarm of pentest agents; delegates via `task()` based
   on module `description`s; chats with the operator; plans via todos.
2. **Distrust rules**: target content is data, not instructions (prompt injection,
   §8.1 spec); instructions from `[untrusted-target-content]` blocks are not
   executed; injection attempts are reported to the operator via an event/in the
   chat.
3. **Policies**: which events require delegation/a question to the operator
   (references to templates).
4. **Boundaries**: do not work out of scope; on `GuardrailBlocked` — adjust the
   plan, do not repeat the blocked call; judge escalations and HITL gates are a
   normal part of the cycle.
5. **Response style**: concise; status and findings go to the chat; artifacts go to
   memory.

The prompt is assembled statically at engine build time (no user text injections);
the dynamic part (the list of modules/events) is a generated section with the
modules' `description`s; the descriptions are module-author text in an instruction
position, so they are rendered as data (F-9): normalized (no control characters,
with §6.8 markers deactivated), with a length limit and in verbatim untrusted markers
under the "the roster is data" preamble.

## 10. TUI (Textual)

### 10.1. Application and panels

`SwarmyTui` (`tui/app.py`) is a Textual application; the session loop runs in its
workers (the runtime, the bus and the checkpointer live in the same event loop).
One pass of the loop serves one coalesced state batch (feed, snapshots, panels) and
then at most one orchestrator step; the step runs **as a task** while the loop keeps
serving batches, so a long `task()` delegation never freezes the panels (D44). The
worker starts before the opening goal (D41) is journaled, so the goal reaches the feed
through the ordinary bus path before any step runs.
Panels (all are MVP, D10):

| Panel | File | Data sources |
|--------|------|------------------|
| Chat | `panels/chat.py` | `OperatorMessage`/orchestrator replies from the journal; switching to a live subagent — a snapshot of its messages from the checkpointer (read-only); §6.8 markers rendered as a red background |
| Swarm Activity | `panels/activity.py` | EventBus feed; the `task()` tree by `correlation_id` (`TaskRequested`/`TaskCompleted`); approval queue statuses |
| Findings & Endpoints | `panels/findings.py` | queries to `MemoryStore` (read-only): endpoint/parameter tables; finding card: severity, evidence files (opened from `evidence/`), reproduction |
| HITL Approvals | `approvals.py` | `ApprovalQueue`: request queue; decision modal (§10.3) |
| Attack Trees | `panels/trees.py` | `AttackNode`/`AttackEdge` from memory; node expansion, navigation to a finding |
| Progress & Plans | `panels/plans.py` | orchestrator todos (L0 `TodoListMiddleware` state); the live delegation plan (`TaskRequested`/`TaskCompleted`) when no todos yet; session statistics (endpoints by status, findings by class/severity, delegations) |

A global status bar at the bottom is the liveness/completion signal: a spinner with the
elapsed step time and the age of the last folded event while an orchestrator step runs,
`waiting for operator approval` while the HITL queue is non-empty, and
`turn complete` / `plan complete` / `idle` otherwise (one toast per finished turn).

### 10.2. State and the facade

- `TuiState` (`tui/state.py`) is the sole owner of UI state: an EventBus subscription
  (coalescing queue, §5.3) + a snapshot cache from `SessionView`. The queue is
  drained by `wait_batch` (blocking, between steps) or `drain_pending`
  (non-blocking, while a step runs — D44).
- `SessionView` is a facade over `Session` (read-only queries: memory, statuses, the
  approvals queue). The TUI imports **only** the facade and `events.models` — the
  core internals are unavailable to it (§2.5). This keeps the TUI interchangeable
  (headless — roadmap) and the core testable without a UI.
- Rendering is rich markup (markdown, tables, trees); navigation uses Textual key
  bindings (panels: focus/switching; in the finding card — opening evidence).

### 10.3. HITL modals and the queue

- Decision modal: the tool, `args_digest` (sanitized arguments, §6.8), the active
  rule/profile, the source of the gate (profile / module / judge escalation / mode).
  Decisions: `approve` / `reject` / `edit` (editing the arguments via a form).
- Modals are modal for the operator but do not block the swarm: other subagents
  continue executing; parallel requests wait in the visible FIFO queue of the
  Approvals panel; the decision is applied to a specific `interrupt_id` (§7.3).
- Sending `OperatorMessage`/`OperatorDecision` to the journal is done by the
  platform (`events/emit.py`).

## 11. Report

`ReportGenerator` (`report/generator.py`) is the orchestrator's platform tool
`generate_report`; deterministic, with no LLM text generation:

- Input: queries to `MemoryStore` (findings by severity, endpoints, attack trees,
  journal statistics), the session config.
- Template: `report/templates/report.md.j2` (jinja2): summary (target, scope,
  period, statistics) → findings (sorted by severity; description, endpoint,
  evidence links, reproduction steps) → attack trees (text + mermaid) → appendix
  (the full list of explored endpoints).
- Output: `<session-dir>/report.md`; the first line is a "draft, requires pentester
  review" marker (§10 spec).

## 12. Configuration

### 12.1. Session file (`SessionConfig`, `core/config.py`)

**AD-1.** The format is YAML (consistent with `guardrails.yaml` and the `AGENT.md`
frontmatter; validation is Pydantic, errors are a fail-fast list).

```yaml
target:
  base_url: "https://target.example.com"
  notes: "authorized engagement, contract #42"
scope:
  domains: ["target.example.com", "api.target.example.com"]
  ip_subnets: ["203.0.113.0/24"]
  ports: [80, 443]
  schemes: ["https"]
profile: normal                 # paranoid | normal | yolo (§7.2)
mode: interactive               # interactive | mission
model: "anthropic:claude-..."   # provider:model (D1)
limits:                         # global session invariants (§6.4)
  rate_limit: 5                 # rps per host
  max_concurrent_requests: 8
  max_body_bytes: 5242880
  max_redirect_depth: 5
  total_request_budget: 5000
  connect_timeout_s: 10
  read_timeout_s: 30
memory:
  search_backend: fts5          # fts5 | vec (phase 2)
context:
  budgets: {http_preview_bytes: 20000, memory_result_bytes: 8000}   # §6.8
guardrails:
  engine_rules: true            # layer 2 can be disabled (layer 1 — never)
judge:                          # LLM judge (§6.7)
  tools: []                     # classes for the pre-call band; empty = post-call only
  model: null                   # a separate model; null = judge disabled
  confidence_threshold: 0.7
  timeout_s: 15
policies:                       # §9.3; the section is optional — built-in defaults exist
  - {on: FindingCandidate, action: notify_orchestrator, template: verify_finding}
mcp_servers: []                 # platform MCP servers (standard L0 facilities)
agents_dirs: ["./agents"]       # user module directories
```

### 12.2. Resolution

Order (higher takes priority): CLI flags → session file → profile → conservative
defaults in code. Resolution is performed by `SessionConfig.load()` before components
are created; the result is an immutable Pydantic object + a `session.yaml` snapshot
(§3.3). Runtime changes (scope, profile, mode) happen only via
`OperatorDecision`/chat commands and are recorded in the journal.

### 12.3. Operator secrets

`secrets.yaml` (chmod 600, §3.3): `auth_headers`, `cookies`, `tokens` — named values.
Referenced by name in tools/config; the values never end up in `session.yaml`, the
journal, the chat or the LLM context — only `<masked:secret-name>` (§6.8). Secrets
are written to evidence files as is (raw data for verification — §8.7 spec).

### 12.4. Environment variables

- LLM provider keys are the standard LangChain provider variables (not stored in the
  session; the engine neither reads nor writes them).
- `LANGSMITH_*` — optional tracing, disabled by default (§11 spec): the env is not
  set → no data leaves the machine.

## 13. Key flows

### 13.1. Session start

```
cli.main
  ├─ SessionConfig.load(cli_args)            # resolution, fail-fast validation
  ├─ Session.open(session_dir)
  │    ├─ Database.open(memory.sqlite)       # WAL, migrations (schema_migrations)
  │    ├─ JournalWriter/EventBus/ScopeRegistry/ResourceLimiter/ToolRegistry
  │    ├─ MemoryStore + SearchIndex
  │    ├─ ModuleLoader.load()                # fail-fast across all modules (§8.3)
  │    ├─ Engine.build()                     # create_deep_agent + checkpointer (§9.1)
  │    ├─ TargetSet → bus → journal
  │    └─ SessionView (facade for the TUI)
  └─ SwarmyTui(session).run()                # workers: OrchestratorRuntime, subscriptions
```

Resume (`--resume <dir>`): skip migrations (the version matches), read the journal to
the end, restore `snapshot.interrupts` into `ApprovalQueue`, continue the runtime.

### 13.2. A subagent calling a network tool

```
subagent: http_post(spec)
  ├─ GuardrailPipeline: invariants(scope/limits) → engine_rules → module_rules
  │     └─ block → GuardrailBlocked (journal+bus), feedback to the agent; stop
  ├─ judge pre-call (class in the config) → ok/flag/escalate (§6.7)
  ├─ ResourceLimiter.acquire (global per session)
  ├─ httpx (redirects manually: each hop — scope+limits)
  ├─ EvidenceRecorder → evidence/<id>/ + Evidence (raw)
  └─ ContextProjector → ResponseRecord.preview → to the agent
```

### 13.3. HITL cycle

```
tool (verify/destructive/interactive fork)
  └─ interrupt → checkpointer (SQLite) → ApprovalQueue FIFO
       └─ TUI modal (tool, args_digest, rule/profile)
            └─ OperatorDecision → Command(resume={interrupt_id: decision})
                 ├─ approve/edit → execution → guardrails re-run
                 └─ reject → feedback to the agent, the plan is adjusted
```

### 13.4. F5 demo scenario: finding → verification → tree

```
operator: "check target X for XSS"
  └─ orchestrator: todos; task(crawler)
       └─ crawler: http_get... → memory_upsert_endpoint → EndpointsDiscovered
            └─ notify_orchestrator policy → orchestrator: task(xss-detector)
                 └─ xss-detector: http_get (markers) → reflection → http_post (payload)
                      ├─ profile normal: network-write → HITL modal → approve
                      └─ memory_save_finding(candidate) → FindingCandidate
                           └─ policy → orchestrator: task(verifier)
                                └─ FindingVerified → tree_proposal policy
                                     └─ memory_link_attack_node → AttackTreeUpdated
the operator sees: the Swarm Activity feed, the finding in Findings, the node in Attack Trees,
a draft report.md (generate_report)
```

## 14. Observability and audit

- The primary source is the `events` journal (append-only): trace by `correlation_id`
  (`JournalReader.by_correlation`), event digests are sanitized (§6.8).
- L0 checkpointer tables — graph state (for debugging: snapshots of subagent
  messages).
- LangSmith — optional via env, disabled by default (§11 spec).
- Text logging is secondary: everything significant is already in the journal; stdout
  logs contain no secrets (masking is applied there too).

## 15. Testing and quality

### 15.1. Structure

| Suite | What it covers | Gate (D22) |
|-------|---------------|------------|
| `tests/unit` | guardrail pipeline (3 layers, DSL, judge mocks), module loader (fail-fast, collisions), memory schema + migrations, bus/journal (ordering, read-to-end), scope matching, limiters, projector, config resolution | ≥ 85% |
| `tests/integration` | end-to-end scenarios against the echo app: out-of-scope blocking, evidence, redirects, budgets, HITL cycle (resume), the F5 demo scenario on fixture modules | ≥ 70% |

Gates are counted **per suite separately** (`pytest --cov=swarmy --cov-fail-under=...`
in two CI commands); exceptions are spot `pragma: no cover` entries recorded in
`[tool.coverage.report] exclude_lines`; blanket-omitting whole packages is forbidden
(D22).

### 15.2. Echo app (`tests/fixtures/echo_app`, aiohttp)

A fixture server with controlled behavior: parameter echo (reflections for
xss-detector), redirect chains (in and out of scope), large bodies, "slow" endpoints
(timeouts), forms and sitemap. It is deployed on a localhost port; the scope of test
sessions points at it. The dependency is dev-group (does not reach runtime).

### 15.3. Static analysis and typing

- ruff: the strict rule set, a ban on `Any` in domain code, mandatory annotations.
- ty (strict) on all of `src/`; untyped dependencies (L0 when needed) — only through
  typed wrappers (§11 spec).
- The module loader duplicates tool type checking at runtime (§8.5) — the module
  contract is protected from external authors as well.

### 15.4. CI

GitHub Actions — runs on every push to any branch, as well as on `pull_request` and
`workflow_dispatch`; matrix: `windows/amd64`, `macos/arm64`, `linux/amd64`,
`linux/arm64`; steps: `uv sync` → ruff → ty → unit (gate 85) → integration (gate 70,
echo app) → smoke `swarmy --version` (+ a Py3.15 job as the runtime target). No
POSIX-only APIs in the core (§11 spec) — paths via `pathlib`, no process forking.

## 16. Architecture invariants

1. Every network call to the target goes through `SwarmyHttpClient` and
   `GuardrailPipeline` before a connection is opened.
2. Every event is appended to the journal before fan-out to subscribers; `events` is
   append-only.
3. Any access to domain tables goes through `MemoryStore`; FTS tables — through
   `SearchIndex`; checkpointer tables — only through the L0 checkpointer.
4. Everything that enters the LLM context of any agent passes through
   `ContextProjector` (budget, masking, untrusted markers, normalization); session
   files and memory stay raw.
5. A deny from any guardrail layer denies the operation; the LLM judge adds
   restrictions and never lifts a deterministic deny; a forced override is
   `OperatorDecision` only.
6. Subagent delegation happens only via L0 `task()` using the loader's SubAgent
   specs; modules have no direct access to the bus, journal or memory — only
   platform tools.
7. `ResourceLimiter` limits are global per session: the swarm's total traffic is
   bounded regardless of the number of parallel delegations.
8. `swarmy.core` does not import `swarmy.tui`; `swarmy.memory.models` does not
   import swarmy packages; the TUI gets data only through `SessionView` and
   `events.models`.
9. Adding a subagent module requires no engine changes: new directories in `agents/`
   are picked up by the loader; a new event type is a "payload class + registration"
   pair.
10. Session start is fail-fast: all config, manifest, guardrail, skills-container and
    name-collision problems are detected before the first LLM call.
11. Every skills container is read-only for the agent: the orchestrator's `/skills/`
    and each module's `/module-skills/<name>/` reach the graph only through the
    composite routes whose backend refuses every mutation; the agent's file tools never
    write to the operator-vetted instructions (§8.6).

## 17. Anti-patterns

| Anti-pattern | Why it is forbidden |
|--------------|------------------|
| Network call bypassing the platform client (`urllib`, `socket`, `requests` in modules) | bypasses scope/limits/evidence — a violation of invariant 1; checked statically by the loader (§8.5) |
| Direct module access to `MemoryStore`/`EventBus`/SQLite | bypasses type validation, journaling and correlation; only `memory_*`/`emit_event` |
| `dict[str, Any]` in domain code and tools | boundary validation is lost; defeats the point of Pydantic-everywhere (D9) |
| LLM in the critical path of guardrail denial | nondeterministic protection; the judge is for async bands only (§6.7) |
| Fork/patch of deepagents | expensive merges, lost security fixes (D16/D18); only documented extension points |
| Orchestration logic outside the L0 graph (hidden delegations in policy code) | breaks audit and checkpointing; policies only inject notifications (§9.3) |
| Storing secrets in `session.yaml`/journal/chat | leaks into audit artifacts and to LLM providers; only `secrets.yaml` + masking |
| Blanket `pragma: no cover` on a package | masks coverage degradation; the D22 thresholds lose their meaning |
| A custom HITL implementation outside `interrupt_on`/the checkpointer | interrupt persistence and resume are lost; the approval queue diverges from the graph state |
| Two different stores for memory and events | the session stops being a portable folder (D2/D3) |

## 18. Traceability

### 18.1. Document sections ↔ specification ↔ decisions

| Section | §spec | Decisions |
|--------|-------|---------|
| §2 Overview, layers, dependencies | 3.1–3.3 | P2–P4, D4, D16 |
| §3 Code base, pyproject, session | 11, 12.1, 6.1 | D8, D17, D18, AD-1, AD-2, AD-5 |
| §4 Domain models and memory | 6.1–6.4 | D2, D9, D20, AD-6 |
| §5 Events | 5.2, 5.3 | D3, D9 |
| §6 Tools and guardrails | 4.3, 7.1–7.4, 8.1–8.7 | D6, D11, D12, D20, D21, AD-7 |
| §7 HITL | 5.5, 5.6, 9.2 | D5, D13, D19 |
| §8 Modules | 4.1–4.6 | P2, D9, AD-3, AD-4, D40, D42 |
| §9 Orchestrator | 5.1, 5.4, 5.5 | D1, D13, D19, AD-8, AD-9 |
| §10 TUI | 9.1, 9.2 | D10 |
| §11 Report | 10 | — |
| §12 Configuration | 5.5, 5.6, 7.2, 7.3, 8.7 | D5, D6, D14, D21, AD-1 |
| §13 Flows | 12.3 (F0–F6) | D7 |
| §15 Testing | 11, 12.2 | D22 |
| §16–§17 Invariants/anti-patterns | 1.3 (P1–P5), 8 | — |

### 18.2. List of architecture decisions (AD)

| # | Decision | Rationale (brief) |
|---|---------|----------------------|
| AD-1 | Session config — YAML | consistency with guardrails.yaml/AGENT.md; Pydantic validation |
| AD-2 | Runtime-deps + `aiosqlite`, `langgraph-checkpoint-sqlite` | a consequence of the "SQLite checkpointer" and "one file per session" decisions |
| AD-3 | `result` in the frontmatter → `response_format` | resolving the §4.2/§4.5 spec ambiguity; fail-fast instead of conventions |
| AD-4 | Module name collision = fail-fast, no override | predictability of the swarm composition in a pentest tool |
| AD-5 | Secrets in a separate `secrets.yaml` (600) | session.yaml is an audit and sharing artifact |
| AD-6 | Three subsystems in one SQLite file | session portability; WAL serialization of writers is acceptable locally |
| AD-7 | Risk class — a declarative tool attribute | determinism of HITL gates |
| AD-8 | Single-writer for the orchestrator graph | thread checkpoint consistency; parallelism at the subagent level (D19) |
| AD-9 | Orchestrator skills in the repository-root `skills/` container (shipped as `swarmy/skills`), loaded automatically through the L0 `SkillsMiddleware` over a read-only `/skills/` composite route, validated fail-fast (spec D42) | the default `StateBackend` cannot read disk paths; L0 only warns and skips a broken skill, against invariant 10; a writable route would let a prompt-injected agent persist instructions across sessions (ASI01) |
| AD-10 | Module `skills/` directories are mounted through the **same** composite as the orchestrator container — the loader names the virtual `/module-skills/<name>/` route as the module's L0 source and `Engine` mounts `<module>/skills` read-only under it; a module carrying skills must have a route-segment name (spec D43) | L0 builds every subagent's `SkillsMiddleware` on the backend the orchestrator was compiled with, and the default `StateBackend` cannot read disk paths — the pre-AD-10 disk-path sources were silently unloadable (subagents ran without their skills); a separate namespace from `/skills/` keeps an orchestrator skill from shadowing a module route; read-only for the same ASI01 reason as AD-9; validating the name at load time fails fast instead of an L0 source that resolves to nothing |

### 18.3. Mapping to phases (§12.3 spec)

| Phase | Architecture sections implemented by the phase |
|------|----------------------------------------|
| F0 | §3 (skeleton, pyproject, CI), §12.4 |
| F1 | §4, §5, §6.5–§6.6 (DSL), §8.3 (loader, stub module) |
| F2 | §6.2–§6.4, §6.8, evidence (`EvidenceKind`), §15.2 |
| F3 | §7, §9, policies §9.3, D19 parallelism |
| F4 | §10 |
| F5 | §8.7, attack trees (§4.2), §13.4 |
| F6 | §11 |

## 19. Open implementation questions

There are no questions blocking the start of implementation. Items to be refined
during the phases against the deepagents pin (procedure D18):

1. The exact names of the L0 middleware hooks (`wrap_tool_call` / post-tool-call) for
   `GuardrailMiddleware` and `ProjectorMiddleware` — fixed in F1/F2 (the 0.7.x API
   confirms the hooks exist; the names are verified against the pinned sources).
2. The behavior of `Snapshot.interrupts` with many parallel `task()` calls —
   clarified in F3 by an integration test (multiple interrupts in one checkpoint).
3. The minimum versions of dependencies (other than the deepagents pin) — fixed by
   `uv.lock` in F0 after the smoke test on Py3.15.
4. The mermaid rendering format of attack trees in the report (renderer limits) —
   clarified in F6.
