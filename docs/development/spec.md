# swarmy — development specification

- **Version:** 0.3-draft
- **Status:** primary specification, drawn up following a research session; 0.2 — open questions resolved by the operator, decisions D17–D21 (§13–§14); 0.3 — test coverage thresholds introduced (D22, §11)
- **Date:** 2026-11-25
- **Languages:** English (documentation, code, identifiers, CLI, UI)

---

## 1. Overview

### 1.1. Purpose

swarmy is an extensible agent system for security analysis of deployed web applications
(authorized pentest). A swarm of functional subagents under an agent-orchestrator
explores the target, finds weaknesses and vulnerabilities, links them into attack trees;
a human operator observes the process in a TUI, communicates with the agents and steers
them through HITL mechanisms.

### 1.2. Target audience

Experienced pentesters with little experience building their own agents (mostly on
third-party harnesses). The primary use of the codebase is **writing specialized
subagent modules**: reconnaissance, detectors for specific vulnerability classes,
building deep attack trees from found vulnerabilities, etc.

### 1.3. Design principles

| # | Principle | Consequences |
|---|---------|-----------|
| P1 | A tool for hackers, not an enterprise auto-pentester | Every decision is checked with the question "does this make a pentester's life easier?"; no RBAC, multi-tenancy or "admin panels" |
| P2 | Extensibility without engine changes | A subagent module = a folder with declarative files + python tools; the engine does not change when modules are added |
| P3 | Secure from the start and always | The target is an untrusted content source (prompt injection); agent boundaries are deterministic guardrails; a prompt is not considered a security measure |
| P4 | As simple as possible, but no simpler | Minimal dependencies and abstractions; no `dict[str, Any]`; built-in abstractions only where there are at least two implementations or a lifecycle |
| P5 | Human-in-the-loop adjusts to the target's risk | Strictness profiles; interactive and autonomous orchestrator modes |

### 1.4. Out of scope for v0.1 (post-MVP: §12.3 below; roadmap §13)

gRPC tools; vector (semantic) search in memory; Docker execution sandbox; integration
with external proxies (Burp/mitm); headless mode without TUI; automatic attack-tree
correlation engine; multi-user modes.

---

## 2. Terms and domain model

| Term | Definition |
|--------|-------------|
| **Session** | One run of swarmy against one target: scope config, memory, event journal, chat session |
| **Target** | The web application under study (base URL + metadata) |
| **Scope** | Permitted boundaries of network activity: domains, IP/subnets, ports, schemes |
| **Agent module** | Folder `agents/<name>/` with `AGENT.md`, optional `tools/`, `skills/`, `guardrails.yaml` |
| **Orchestrator** | The main deep-agent: reacts to events, delegates tasks to subagents, holds the chat with the operator |
| **Event** | A typed record (Pydantic model) in the event bus; a trigger for orchestrator reactions |
| **Shared memory** | A single store of facts about the target for all subagents (SQLite, one file per session) |
| **Finding** | A vulnerability candidate or a confirmed vulnerability with a status and severity |
| **Evidence** | Material confirmation of a finding: files in the session + typed metadata; `kind` is a Pydantic enum (`http_request_response` in v0.1; `screenshot`/`har`/`grpc_file` reserved, D20) |
| **Attack tree** | A graph of precondition nodes/finding nodes with typed edges (`requires`, `enables`, `leads_to`) |
| **Guardrail** | A rule that forbids or escalates an operation; three layers: platform invariants, basic engine rules, module rules |
| **LLM judge** | An asynchronous second look by a separate model at calls/results; may escalate to HITL, cannot unblock a deterministic deny |
| **HITL** | Human-in-the-loop: an execution interrupt with a request for an operator decision (approve/reject/edit) |
| **Strictness profile** | `paranoid` / `normal` / `yolo` — the default set of HITL gates |

Domain schema (simplified):

```
Target ─ ScopeEntry (many)
Target ─ Endpoint (many) ─ Parameter (many)
Endpoint/Parameter ─ Finding (candidates/confirmations) ─ Evidence (many)
Finding ─ AttackNode ─ AttackEdge ─ AttackNode   (attack trees)
everything ─ Note / Fact (free facts with tags)
```

---

## 3. Architecture

### 3.1. Layers

```
┌────────────────────────────────────────────────────────────┐
│ L2  Interface: TUI (Textual) + `swarmy` CLI entry point    │
├────────────────────────────────────────────────────────────┤
│ L1  swarmy domain core (our code):                         │
│     orchestrator harness · event bus + journal ·           │
│     memory store · tool registry · guardrail pipeline ·    │
│     module loader · report generator                       │
├────────────────────────────────────────────────────────────┤
│ L0  Harness: deepagents (LangChain + LangGraph)            │
│     subagents · HITL interrupt · skills · MCP · context    │
└────────────────────────────────────────────────────────────┘
```

L0 **is not forked**: it is used as a dependency and extended through documented points
(middleware, the SubAgent dict, skills paths, `interrupt_on`, `response_format`, backends).

### 3.2. Process and components

One Python process (in-process, asyncio). Components:

- **Engine** — the orchestrator deep-agent (`create_deep_agent`), configured by the module loader;
- **EventBus** — in-memory asyncio pub/sub + append-only journal (`events` table in SQLite);
- **MemoryStore** — typed access to shared memory (SQLite, WAL, one file per session);
- **ToolRegistry** — platform tools + module tools, name-collision check;
- **GuardrailPipeline** — pre-tool-call middleware: three layers of rules + the LLM judge hook;
- **ModuleLoader** — scanning `agents/`, manifest validation, assembly of SubAgent dicts;
- **Session** — the session object (composition root): open/resume/close lifecycle, owns all the components above; the session config is a separate schema `SessionConfig` (target, scope, strictness profile, limits; the canonical definition is architecture.md §2.2–§2.3).

### 3.3. Data flow

```
subagent ──tools (http_*, memory_*, emit_event)──▶ GuardrailPipeline ─▶ network/memory
   │                                                        │
   └── response_format (typed task result)                  ▼
                                                        EventBus ─▶ journal (SQLite)
                                                            │
            ┌───────────────────────────────────────────────┘
            ▼
      orchestrator: event policies → task delegations / memory / question to the operator
            │                                          ▲
            └── result (Pydantic) ─▶ memory/TUI ───────┘ (HITL approvals from TUI)
```

---

## 4. Subagent module (the extensibility core)

### 4.1. Folder structure

```
agents/<module-name>/
├── AGENT.md          # required: YAML frontmatter + system prompt
├── tools/            # optional: python modules with tools (fully typed)
├── skills/           # optional: skills container per the agentskills.io spec
└── guardrails.yaml   # optional: module guardrail rules
```

### 4.2. `AGENT.md` frontmatter

The fields map onto the documented deepagents `SubAgent` dict:

| Field | Type | Req. | Purpose |
|------|-----|-------|------------|
| `name` | str | yes | Unique identifier (the name for `task()`) |
| `description` | str | yes | What it does and when to delegate — the orchestrator decides by it |
| `model` | str | no | Model override (`provider:model`), otherwise the orchestrator's model |
| `mode` | `isolated` \| `fork` | no | Delegation context (default `isolated`) |
| `interrupt_on` | map[str, bool] | no | HITL gates on specific module tools |
| `events` | list[str] | no | Declaration of the event types the module emits (checked by the loader) |
| `guardrails` | str | no | Path to `guardrails.yaml` (default `./guardrails.yaml`) |

The system prompt is the body of `AGENT.md` below the frontmatter. `skills` and `tools` are
not declared in the frontmatter: the loader automatically connects `tools/` and `skills/`
from the module folder (each subagent has its own isolated `SkillsMiddleware`, as in deepagents).

### 4.3. Rules for `tools/`

- A tool = a python function with **full typing** of arguments and result (Pydantic models
  or primitives), docstring = the description for the LLM.
- `Any`, `dict[str, Any]`, unannotated parameters are forbidden — checked by the linter and the loader.
- Reserved platform tool prefixes (`memory_*`, `event_*`, `session_*`) cannot be used by a
  module in the names of its own tools; the platform tools with these prefixes themselves
  are available to subagents (§7.4). Name collisions — fail-fast at session start.
- Module network tools must go through the platform-provided HTTP client (§7) — direct
  sockets/urllib in modules are forbidden and blocked by the invariant guardrail.

### 4.4. Skills

Full compliance with the [agentskills.io specification](https://agentskills.io/specification):
`SKILL.md` (frontmatter `name` ≤64, `description` ≤1024; optionally `license`,
`compatibility`, `metadata`), resources in `scripts/`, `references/`, `assets/`.
deepagents progressive disclosure is used as is (metadata → instructions → resources).
A skill's own tools — via `metadata.include_tools` (a deepagents extension).

### 4.5. Loader (ModuleLoader)

1. Scans built-in modules (`<package>/agents` in the wheel or `<repo>/agents`
   in an editable checkout) + user directories (`--agents-dir`/`agents_dirs`).
2. Validates each manifest with the Pydantic model `AgentModuleManifest`
   (configuration errors = fail-fast with a list of problems across all modules at once).
3. Assembles SubAgent dicts: `system_prompt`, `tools` (imported functions),
   `model`, `mode`, `interrupt_on`, `skills=[<path>/skills/]`,
   `middleware=[GuardrailMiddleware(module rules)]`,
   `response_format` — if the module declares a result schema.
4. Checks the module's `events` against the event type registry.
5. Passes the list to the orchestrator (`create_deep_agent(subagents=...)`).

### 4.6. Built-in v0.1 modules (contract reference implementations)

| Module | Purpose | Tools | Output events |
|--------|-----------|-------------|-------------------|
| `crawler` | Primary reconnaissance: robots.txt, sitemap, link crawling, form and parameter extraction, endpoint map | `http_get` (+ its own parsers), `memory_upsert_endpoint`, `emit_event` | `EndpointsDiscovered`, `EndpointUpdated` |
| `xss-detector` | Reflected XSS detector: marker placement, contextual analysis of reflections, verification with safe payloads | `http_get`, `http_post`, `memory_search`, `memory_save_finding`, `emit_event` | `FindingCandidate(type=xss)` |

Both modules are written strictly per the contract in §4 (dogfooding) and serve as the
reference for module authors.

---

## 5. Orchestrator and events

### 5.1. Orchestrator

The main deep-agent with an orchestration system prompt. Tools: the built-in `task`
(delegation to subagents), platform `memory_*`, `emit_event`, `session_info`,
`generate_report`, plus the chat with the operator (TUI). Planning — the built-in deepagents
todos. Delegations are **async-parallel** (D19): several `task()` calls may run concurrently;
shared memory and the session resource limits (§7.3) are global for all subagents.

### 5.2. Event taxonomy v0.1

A single envelope (Pydantic): `id`, `ts`, `type`, `source` (module/orchestrator/platform),
`payload` (typed), `correlation_id` (link to a delegation/finding).

| Type | Source | Meaning |
|-----|----------|-------|
| `TargetSet`, `ScopeChanged` | platform | Session target/scope (scope change — only via HITL) |
| `EndpointsDiscovered`, `EndpointUpdated` | crawler etc. | New/updated endpoints in memory |
| `FindingCandidate` | detectors | A vulnerability candidate (type, endpoint_ref, evidence_ref) |
| `FindingVerified`, `FindingRejected` | verifiers | Result of checking a candidate |
| `AttackTreeUpdated` | tree builders | Attack tree mutation |
| `GuardrailBlocked` | platform | A guardrail fired (tool, rule, context) |
| `OutboundSecretWarn` | platform | Non-blocking outbound hygiene: an operator secret value was noticed in the request headers/body/query (the warning does **not** block — the credential was passed by the operator deliberately; audit line ASI10, written only to the journal) |
| `TaskRequested`, `TaskCompleted` | platform | Service: delegations and results |
| `OperatorMessage`, `OperatorDecision` | TUI | Operator messages and decisions |

Extending the taxonomy: a new type = a Pydantic class + registration in the registry; modules
declare the types they emit in `AGENT.md`, the loader cross-checks. Events are created
**only** by the `emit_event` tool (validated against the type from the registry) or by the
platform — modules have no direct access to the bus.

### 5.3. Bus and journal

- In-memory asyncio pub/sub (subscribers: orchestrator, TUI, journal).
- Every event is synchronously appended to the append-only journal (SQLite `events`);
  the journal is the primary source for session audit and recovery (resume = journal + checkpoint).

### 5.4. Orchestrator loop

1. **Reactive loop:** `event → reaction` policies in the session config
   (example: `FindingCandidate(type=xss)` → verification delegation → `FindingVerified` →
   attack tree node proposal).
2. **Proactive loop:** the orchestrator's own plans (todos) for the operator's task.
3. **Interactive loop:** operator commands and questions from the chat.

### 5.5. Autonomy modes (switching on the fly)

| Mode | Behavior |
|-------|-----------|
| `interactive` (default) | Significant forks (launching tests of a vulnerability class, verification, scope change) are confirmed by the operator |
| `mission` | The orchestrator runs on its own within the guardrails; HITL gates and the strictness profile remain in effect; the operator observes in the TUI and can intervene |

### 5.6. HITL

- The mechanism — deepagents `interrupt_on` + SQLite checkpointer (interrupt state is persistent).
- Strictness profiles define gates by **tool classes**: `passive` (reading the target),
  `network-write` (POST/PUT/DELETE to the target), `verify` (exploitation checks),
  `destructive` (potentially breaking operations).
  - `paranoid`: gates on everything except `passive`;
  - `normal` (default): gates on `verify` and `destructive`;
  - `yolo`: gates only on `destructive`.
- The TUI shows: tool, arguments (sanitized), active rule/profile;
  decisions: approve / reject / edit.
- With parallel delegations (D19), approval requests form a queue (FIFO);
  each decision applies to a specific call — the queue is visible in the TUI (§9.2).

---

## 6. Shared memory

### 6.1. Persistence

One file per session: `<session-dir>/memory.sqlite` (SQLite, WAL). The same `<session-dir>`
holds the evidence files and the session config; a session = a portable folder.

### 6.2. Entities (Pydantic v2; tables mirror the schemas)

- `Target` — base URL, stack metadata (filled in as the exploration proceeds);
- `ScopeEntry` — domain/IP subnet/port/scheme;
- `Endpoint` — method, path, auth requirements, exploration status, notes;
- `Parameter` — name, location (query/body/header), type, examples;
- `Finding` — type (enum: xss, sqli, auth, …), `status: candidate|verified|rejected`,
  `severity: critical|high|medium|low|info` (mandatory), `cvss_vector` (optional),
  `endpoint_ref`, `evidence_refs`, description;
- `Evidence` — `kind: EvidenceKind` (Pydantic enum: `http_request_response` in v0.1;
  `screenshot`, `har`, `grpc_file` reserved — added without schema migrations, D20),
  path to the file(s) in the session, metadata (ts, tool);
- `AttackNode` / `AttackEdge` — nodes (precondition/finding/goal) and typed edges
  (`requires`, `enables`, `leads_to`);
- `Note`, `Fact` — free-form records with tags (stack peculiarities, observations).

### 6.3. Tool API (available to all subagents)

`memory_search` (FTS5, filters by entity type), `memory_get`, `memory_upsert_endpoint`,
`memory_save_finding`, `memory_link_attack_node`, `memory_add_fact`, `memory_add_note`.
A separate platform tool `update_finding_status` (without the `memory_*` prefix) moves a
finding to `verified`/`rejected` and publishes `FindingVerified`/`FindingRejected` — used by
the finding verification loop (§5.2).
Records pointing outside the scope (new hosts in endpoints) are flagged with `out_of_scope` —
the network tools do not serve them without a scope extension via HITL.

### 6.4. Search

- v0.1: **FTS5** — full-text search over the text fields of entities; sorting by relevance and type.
- The `SearchIndex` interface abstracts the backend; phase 2: `sqlite-vec` (pre-v1, breaking
  changes possible — pin the version) for semantic search; the embedding model — from the LLM config.

---

## 7. Tooling

### 7.1. HTTP client (platform)

- `httpx` async client wrapped in `SwarmyHttpClient`; types `RequestSpec` / `ResponseRecord`
  (Pydantic): method, URL, headers, body, status, time, redirects.
- **Mandatory pass through GuardrailPipeline** before the network (§8); evidence recording
  (depth configurable); context hygiene: truncation of large bodies, secret detection in
  outbound headers/bodies (warn).

### 7.2. Scope enforcement

- `ScopeRegistry` from the session config: domains, IP/subnets, ports, schemes.
- Check **before** the network call; an out-of-scope deny = `GuardrailBlocked` (invariant).
- Scope change — only `OperatorDecision` (HITL) → `ScopeChanged` event.

### 7.3. Resource limits (invariants, configurable)

`rate_limit` (rps per host), `max_concurrent_requests`, `max_body_bytes`,
`max_redirect_depth`, `total_request_budget` (per session), timeouts. Defaults are conservative;
the goal is preventing self-DoS of the target (textbook case: database connection pool
exhaustion). Limits are **session-global**: with async-parallel delegations (D19) the requests
of all running subagents are summed; an individual agent has no personal quota.
It is precisely the total count that keeps the swarm from pressuring the target.

### 7.4. Platform tools

`emit_event`, `memory_*` and `update_finding_status` (§6.3), `session_info` (scope, statuses,
profile), `http_get`/`http_post`/`http_put`/`http_delete` (through the platform HTTP client,
§7.1), `generate_report` (§10). The canonical list and registry — architecture.md §6.1.
MCP servers are connected in the standard deepagents way — at the platform/module level.

### 7.5. gRPC

Phase 2 (`grpcio`; wheels for Python 3.15 are tracked in grpc#41010; if absent —
pin a version or build from source).

---

## 8. Security and guardrails

### 8.1. Threat model of the tool itself

| Threat | Mitigation |
|--------|------|
| Prompt injection from target content (pages, headers, API responses) | All target data is untrusted content: quoted as data; system rules forbid executing instructions from target content; before entering the LLM context — a sanitized projection (§8.7): normalization, untrusted markers, truncation |
| Session secret leak (cookies, tokens) | Stored in the session folder; masked in the LLM context and TUI (§8.7); warn on secret detection in outbound traffic |
| Unauthorized egress | Scope invariant (§7.2): network calls only within the scope |
| Self-DoS of the target | Resource limits (§7.3) |
| Supply chain | Dependencies are pinned by a lock file (uv); deepagents updates — per the D18 procedure (pin `>=0.7.41,<0.8`; changelog review → full test run → bump; security fixes — out of band) |

### 8.2. Three guardrail layers; AND-composition

A rule of **any** layer that returns a deny forbids the operation (AND-composition:
deny = disjunction of the layers' denies; permission requires the permission of all layers).

1. **Platform invariants** (non-disableable): scope, resource limits, egress policy,
   the ban on direct network calls bypassing the platform client.
2. **Basic engine rules** (shipped, disableable in config): examples — blocking
   destructive SQL constructs (`OR 1=1`/TRUE patterns) in SQLi check tools
   and known dangerous payloads by default. A separate rule for the `TRACE`/
   `CONNECT` methods is not required: the platform http tool set structurally offers
   only GET/POST/PUT/DELETE, while the former rule could not see the method value and
   falsely fired on probes with parameter values `trace`/`connect` (D30).
3. **Module rules** (the module's `guardrails.yaml`, "subagents' own guardrails").

### 8.3. Rule format (`guardrails.yaml`)

```yaml
rules:
  - id: no-true-based-sqli
    applies_to: ["http_get", "http_post"]        # tool names
    condition:
      any_param_matches: "(?i)('\\s*(or|and)\\s*'.*'=|1\\s*=\\s*1|true\\s*=)"  # regex over parameters
    action: block
    severity: high
    message: "TRUE constructs in SQLi checks are forbidden: risk of corrupting target data"
```

Declarative predicates of v0.1: `any_param_matches` / `url_matches` / `header_matches` /
`body_size_above` / `tool_in`. Execution — a deterministic pre-tool-call pipeline
(deepagents middleware), with no LLM in the deny critical path.

### 8.4. LLM judge

- An asynchronous "second look" by a separate model (config: model + confidence threshold)
  at suspicious calls and results; verdict: `ok` / `escalate_hitl` / `flag`.
- **Asymmetry of powers:** the judge may escalate to HITL and flag, but **cannot**
  permit what has been blocked by deterministic rules.

### 8.5. Violation semantics

A firing (a rule or a judge escalation confirmed by a block):
1. the call **is not executed**;
2. the attempt is recorded in the journal, `GuardrailBlocked` is published;
3. the agent receives textual feedback (rule id, reason) and adjusts its plan;
4. forced permission — only `OperatorDecision` via HITL (in both modes).

### 8.6. Authorization gate

**Absent** (a deliberate decision: a tool for professionals, responsibility lies with the
operator). The disclaimer on responsibility and the legality of testing — in the README and
the first chat message of the session. The decision is revisited if a public distribution appears.

### 8.7. LLM context sanitization (the raw data boundary, D21)

Principle: **memory and session files are raw; the LLM context is a sanitized projection.**

- Evidence, target responses and facts are stored in the session as is — the pentester needs
  raw data for verifying findings and for the report.
- Everything a tool returns into the model context passes through `ContextProjector`:
  1. **Truncation by byte budget** (configurable per tool class):
     truncation with an explicit `[truncated N bytes]` marker; the full content — in the
     session evidence;
  2. **Operator secret masking** (session cookies/auth tokens): replaced with the
     placeholder `<masked:secret-name>` in the context and TUI; in session files — as is;
  3. **Untrusted marking**: target content is wrapped in untrusted data markers
     (data, not instructions);
  4. **Normalization** of control characters and hidden Unicode before entering the context.
- Secrets found on the target are finding data: stored raw in evidence, they enter the
  context truncated/masked so as not to spread them across the chat history and LLM providers.
- Detailed rules (budgets per tool class, secret patterns, marker format)
  are specified in F2.

---

## 9. TUI (Textual)

### 9.1. Panels (all included in the MVP)

| Panel | Content |
|--------|-----------|
| **Chat** | Operator ↔ orchestrator dialog; switching to a live subagent to inspect its context |
| **Swarm Activity** | Live event feed, delegation statuses, the `task()` call tree |
| **Findings & Endpoints** | Endpoint/parameter tables; finding card: severity, evidence, reproduction |
| **HITL Approvals** | Approve/reject/edit modals showing the rule/profile and sanitized arguments |
| **Attack Trees** | Interactive tree rendering (node expansion, navigation to a finding) |
| **Progress & Plans** | Orchestrator todos, session statistics (progress by endpoints/classes) |

### 9.2. Requirements

- Rendering: rich markup (markdown, tables, trees); keyboard shortcuts for panel navigation.
- HITL modals are modal and non-blocking for the rest of the swarm; with async-parallel
  delegations (D19) simultaneous requests enter a visible queue (FIFO) — decisions
  are applied to a specific call, the queue status is reflected in Swarm Activity.
- TUI is the only interface of v0.1; headless — roadmap.
- Mission start: the console can take the opening goal from a goal file (`--goal-file`, or
  `goal.md` next to the session config) — it is journaled as the first `OperatorMessage`
  on mount and the first worker pass runs the orchestrator step (D41); without a goal
  file the operator types the goal in the Chat panel; `--resume` never auto-starts.

---

## 10. Report (draft, MVP)

- Generation: the orchestrator tool `generate_report` → `<session-dir>/report.md`.
- Structure: summary (target, scope, period, statistics) → findings (sorted by severity;
  description, endpoint, evidence links, reproduction steps) → attack trees (text/mermaid)
  → appendix: the full list of explored endpoints.
- Format — markdown; template — jinja2; the draft is marked as requiring pentester review.

---

## 11. NFRs and quality

| Area | Decision |
|---------|---------|
| Python | **3.15+** (runtime target). Base: deepagents `>=0.7.41,<0.8` (D18), `requires-python >=3.11,<4.0` — compatible; smoke test on 3.15 at bootstrap (deepagents classifiers declare up to 3.14) |
| Platforms | Windows/amd64, macOS/arm64, Linux/amd64+arm64; CI matrix; no POSIX-only APIs in the core |
| Typing | **Pydantic v2** — the single standard for domain structures and boundaries (frontmatter, events, tools, `response_format` results); strict checking (ty/mypy); `Any`/`dict[str, Any]` forbidden in domain code; untyped dependencies — only through typed wrappers |
| Dependencies | runtime: deepagents, httpx, textual, pydantic, rich, jinja2, aiosqlite, langgraph-checkpoint-sqlite (the last two are the AD-2 extension in architecture.md: the async SQLite driver and the LangGraph checkpointer); management: **uv** + lock file; deepagents upgrades — per the D18 procedure; no bcrypt-class dependencies — the engine does not store secrets |
| Tests | pytest + pytest-asyncio: unit tests of the guardrail pipeline, the loader, the memory schema; integration tests — against the local echo app (fixtures); Py3.15 smoke. **Coverage: unit ≥ 85%, integration ≥ 70%** (D22) — thresholds per suite separately (what coverage each suite reaches), CI gate via pytest-cov (`--cov-fail-under`); exceptions — spot `pragma: no cover`, recorded in the coverage config; blanket-omitting whole packages is forbidden |
| Observability | the event journal = the primary source; LangSmith — optional via env (off by default, no data leaves) |
| License | **MIT** |
| Name | package and CLI — **swarmy** (repository: swarmy2). PyPI publication of v0.1 — not planned: installation from git (`uv tool install git+…`); with a future publication the distribution is **swarmy-cli** (D17: the name `swarmy` on PyPI is taken by an abandoned 2011 package, `swarmy-cli` is free — verified 2026-11-25) |

---

## 12. Repository and roadmap

### 12.1. Structure (src-layout)

```
swarmy/                  # package
├── core/                # session, engine glue, orchestrator
├── events/              # taxonomy, bus, journal
├── memory/              # store, schemas, search
├── tools/               # http client, platform tools, registry
├── guardrails/          # pipeline, DSL, judge
├── modules/             # loader, manifest, registry
├── tui/                 # Textual application
└── report/              # report generator
agents/                 # built-in modules: crawler, xss-detector (reference); → swarmy/agents in the wheel
docs/development/       # spec.md · architecture.md · roadmap.md · check reports
tests/
pyproject.toml
```

### 12.2. Development tools

uv, ruff (rules in the spirit of upstream deepagents), ty/mypy strict, pytest, pytest-cov (coverage gate, §11).

### 12.3. Phases

| Phase | Content | Readiness criterion |
|------|-----------|---------------------|
| F0 | Package skeleton, uv, ruff/ty, platform CI matrix | `pip install -e .` + `swarmy --help` on all platforms |
| F1 | Core: memory (schema+FTS5), events (bus+journal), guardrails (3 layers, DSL), module loader | Core unit tests green, unit coverage gate ≥ 85% active in CI (D22); a stub module loads |
| F2 | HTTP tooling, scope, limits, evidence (`kind` enum), LLM context sanitization rules (§8.7) | Echo app: out-of-scope requests are blocked, evidence is written, budgets/masking in `ContextProjector` work; integration coverage gate ≥ 70% active |
| F3 | Orchestrator: event policies, async-parallel delegations (D19), HITL (profiles, queue), interactive/mission modes | "Finding → verification" scenario via events; parallel `task()` with global limits; the HITL modal intercepts destructive, the approval queue works |
| F4 | TUI: 6 panels, chat, approvals | A full session is driven from the TUI without CLI input |
| F5 | crawler + xss-detector modules, minimal attack trees | Demo session: target → endpoints → XSS candidate → verification → tree node |
| F6 | markdown report | `report.md` is generated from the F5 session |

Post-MVP: gRPC, vector search (sqlite-vec), Docker sandbox, proxy integrations,
headless mode, attack tree correlation engine, non-HTTP evidence kinds (`screenshot`, `har`,
`grpc_file` — D20).

---

## 13. Decision log (summary)

| # | Decision | Alternatives, reasons for rejection |
|---|---------|-----------------------------------|
| D1 | LLM: any tool-calling models via LangChain (incl. Ollama/vLLM) | Cloud only — cuts off NDA scenarios; an OpenAI gateway — we lose native provider features |
| D2 | Memory: SQLite as a single file (FTS5; vector — phase 2) | LanceDB — two stores instead of one; server DBMSs — against P1/P4 |
| D3 | Events: in-memory bus + append-only journal | Bare in-memory — audit and resume are lost; a broker — redundant locally |
| D4 | Isolation: in-process + guardrails/allowlist/limits/HITL | Docker-only — against P1/P4; an optional sandbox — roadmap |
| D5 | HITL: paranoid/normal/yolo profiles | A single strict policy — not adjustable to the target's risk |
| D6 | Scope: hard allowlist + resource limits | Soft "in-context" scope — gives no guarantees |
| D7 | MVP: core + crawler + xss-detector + minimal trees + report | gRPC and proxy — phase 2 (the grpcio×Py3.15 risk is off the critical path) |
| D8 | Languages: docs RU / code EN | — |
| D9 | Typing: Pydantic v2 everywhere | dataclasses — manual boundary validation; a hybrid — two styles in one codebase |
| D10 | TUI: all 6 panels in the MVP | — |
| D11 | Guardrails: 3 layers, AND-composition; the judge is asymmetric (escalates, does not unblock) | Module-only/global-only — we lose either flexibility or baseline protection |
| D12 | Violation: block + event + feedback to the agent; override — HITL only | Escalation instead of a block — under yolo, dangerous operations pass automatically; warn-only — not for live sessions |
| D13 | Orchestrator: interactive + mission, on-the-fly switching | A single mode — either friction or loss of control |
| D14 | Severity: a qualitative scale is mandatory, CVSS is optional | Mandatory CVSS — speculative at the reconnaissance stage |
| D15 | Authorization gate: absent (operator's responsibility; disclaimer in the README) | A gate — friction for the target audience; to be revisited upon public distribution |
| D16 | Foundation: deepagents 0.7.x (minor version pin), L0 is not forked | A fork — expensive merges; own harness — against P1/P4 |
| D17 | PyPI: v0.1 — not published, installed from git; upon a future publication the distribution is `swarmy-cli` | `swarmy` is taken by an abandoned 2011 package (bsandrow, "A collection of utils"); publishing before a real distribution — against P4; disputing the name — slow and not guaranteed |
| D18 | deepagents: pin `>=0.7.41,<0.8` + uv.lock; upgrades as needed: changelog review → full test run → lock bump; security fixes — out of band | A monthly patch cycle — regular time spent on someone else's changes; a floating lock — the risk of suddenly broken builds |
| D19 | Delegations: async parallelism from v0.1 on; target protection — session-global resource limits (§7.3), a visible HITL queue (§9.2) | Sequential default — slow recon; a hybrid with concurrency classes — superfluous design in the MVP (revisit if target pressure becomes a problem) |
| D20 | Evidence: `kind` — Pydantic enum; v0.1 — `http_request_response` only; `screenshot`/`har`/`grpc_file` are reserved (§6.2) | HAR import in the MVP — scope without a critical need; screenshots (playwright) — a heavy dependency, against P4 |
| D21 | Sanitization: memory/session files — raw; LLM context — a sanitized projection via `ContextProjector` (byte budgets, operator secret masking, untrusted markers, normalization) (§8.7) | A single pipeline everywhere — raw data for finding verification is lost; size truncation only — operator secrets leak to the LLM provider |
| D22 | Tests: coverage thresholds unit ≥ 85%, integration ≥ 70% — separate CI gates, computed per suite (§11) | One shared threshold for the whole run — masks weak integration coverage of the core (guardrails, scope); no thresholds — coverage degradation goes unnoticed as the codebase grows |
| D23 | §6.8: the order of steps 1↔2 is changed — secret masking **before** the byte budget (the budget applies to the masked text) | The previous "budget → masking" order left an uncovered prefix of a secret cut by the truncation boundary (the attacker controls the content length); "document the window" — left the step's guarantee empty precisely on large contents; the order matches the HTTP client's preview path |
| D24 | §6.8: occurrences of untrusted markers inside content are deactivated (`[defused:...]` + a platform note on the number of attempts); the re-masking guard is tied to the secret names actually being substituted | The markers are public repository constants: the literal marker string in a target response closed the block and passed the following text off as the platform's voice; a decoy `<masked:decoy>` in a header line disabled the built-in masking of reflected Cookie/Authorization; the alternative "count lines/block length" — complicates the format against the verbatim contract of §6.8 |
| D29 | Report: all target/LLM-derived text is escaped in the view models (`ReportGenerator._report_safe`: `<`/`>` → HTML entities, `|`, backtick, `[`, leading `#`/`!` are neutralized; evidence paths verbatim), mermaid labels — a safe charset without `<>`; `autoescape=False` is kept (markdown output, §10) | Full HTML autoescape — breaks markdown output; escaping in the view models eliminates the stored-XSS vector in analytics viewers (review #40/#18) and removes the "accepted risk" from SECURITY.md; the draft marker + pentester review remain the final control |
| D30 | The `block-trace-connect-methods` rule is removed from the default set (§8.2): methods are structurally fixed (`Literal` GET/POST/PUT/DELETE in the http tools), the rule never saw the method value in the first place and falsely blocked legitimate probes with leaf values `trace`/`connect` (review #59) | A method-oriented predicate — new evaluation mechanics on the client/tools side, out of v0.1 scope; narrowing to headers — predicates see only values, the class of false positives remains; protection = the structure of the tool surface |
| D25 | §5.5/§16.4: operator text from the chat and correlation digests pass through `ContextProjector` before both boundaries — the journal one (`OperatorMessage.text_digest`, the `summary_digest` of `Task*` pairs are projected at emit; for `Task*` — masking/budget without the untrusted wrapper: the digest is a journal one, the TUI display layer adds the markers itself, a double wrapper would deactivate as spoofing) and the graph one (the already-projected text goes into the queue and into `HumanMessage`); `GuardrailBlocked.reason` is projected exactly like `tool_args_digest` (review #36↔F-22, #55, #39) | The "journal copy of raw data per D21" interpretation (the F-22 reading) is rejected: D21 protects session files (evidence, raw tool responses), the digest field is not a session file, and §5.5 directly requires projecting `*_digest`; treating the operator's chat as trusted without the projector — a pasted credential goes to the LLM provider and into the journal verbatim (the only violation of the absolute §16.4); re-projecting at the step boundary (queue drain) — double untrusted markers on notifications already projected at enqueue time; untrusted markers on operator text — an even consequence of marking at the projector constructor level (§6.8), operator text often quotes target content |
| D26 | §6.7/§5.5: the argument digest in the judge's journal rows (`GuardrailBlocked`, `layer="judge"`) — **implemented** (wave 4, review #49): the `LlmJudge.sink` signature is extended to `(BlockedFeedback, subject, tool_args_digest)`; pre-call rows carry the digest computed by the pipeline, post-call rows — the digest computed by the projector middleware; payload assembly in `core/session.py` writes it into the column without an interim agreement | The interim agreement "empty column until a separate task" is closed in the same wave as the production wiring of the post-call band (#54↔F-19): an empty digest on new judge rows — an audit defect, a separate task is no longer needed |
| D27 | §5.2/§5.5: the v0.1 taxonomy — **14** built-in types: `OutboundSecretWarn` is registered in the registry (`OutboundSecretWarnPayload`: `tool_name`, `request_id`, `secret_names`, `locations`); the HTTP client no longer holds its own payload class — its name became an alias of the registered model (review #29↔F-5); the journal read contract — tolerant decoding: types missing from the reading process's registry are decoded as `UnknownEventPayload` instead of an error (review #7) | Duplicating the shape "one type — two models" (client-side and registry-side) would sooner or later drift — a warn row unreadable by the registry broke resume/report/TUI reading (#29↔F-5: a single warn "bricked" session recovery); the journal is append-only — rows written by a build that knows more types than the reading one must be readable rather than crash the read: an unfamiliar type — is data (an envelope with raw fields), not a failure; the alternative "hard error on an unknown type" contradicts session folder portability (arch §3.3: the folder opens "on another machine" with the same or an older build) |
| D28 | §6.3/§6.2 (arch): the "out of scope" loop and the operator's scope change are closed in code (review #8↔F-1, #9; F-1 MUST FIX): (1) all memory rows with `out_of_scope=True` are loaded into `ScopeRegistry.mark_out_of_scope` on every open **and** resume, live replenishment — via the `EndpointsDiscovered`/`EndpointUpdated` events (the handler re-reads the row; marks are monotonic); (2) clearing the mark — an operator decision only: `memory_upsert_endpoint` rejects `out_of_scope=False` on a marked record, the registry has no unmark; (3) omitted fields of a repeated upsert keep their previous values — None sentinels at the tool boundary (#9); (4) the endpoint method is normalized at the write boundary — RFC 9110 token, an invalid value is rejected before writing (F-15); (5) operator extension — `Session.extend_scope`, the only production path with `origin="operator"`, `ScopeChanged` journal-first, the TUI hook in M4; (6) F-11: the client resolves the name before every hop, the first address is verified against `ip_subnets` and pinned to the session — `invariant: host-pin`; (7) `session_info` is added to every subagent's toolset per arch §6.1 (#2) | A flag in memory without a registry — a documented fail-closed control that is actually fail-open (F-1: the invariant could not deny anyone, CWE-1188); "the agent clears the mark with a repeated upsert" — perimeter expansion without the operator (§6.3: marking — a restriction, clearing — an expansion); no unmark in the registry — marks are monotonic, event races cannot expand the perimeter; operator additions are not carried over on resume (the `scope_entries` table is not written in v0.1) — the `session.yaml` snapshot remains the source of truth for recovery (§13.1), carrying them over — a seam after v0.1; transport-level IP pinning (connection substitution at the socket level) — httpx transport surgery out of v0.1 scope, name pinning + re-verification at intercept catches DNS record rebinding |
| D31 | §8.5 arch: the loader's static-scan deny list is extended to the `httpx`/`aiohttp`/`requests` HTTP client families (runtime dependencies of the same venv where module tools run), the `subprocess` import, the `os.system`/`os.popen` call forms and raw asyncio streams `open_connection`/`start_server` (bare `os` is not forbidden); the same scan applies to `skills/**/*.py` (review F-2, ASI02/ASI05) | The scan — a named SECURITY.md point of deterministic control, but it lagged behind its own contract: a careless author could `import httpx` and hit the network bypassing scope/limits/journal; inversion into an allowlist (`swarmy.*` + vetted stdlib only) is rejected — too heavy for module authors in v0.1 (P4), revisit when the contract expands |
| D32 | §8.4 arch: the lifecycle of the process-global `EventRegistry` — one per load (`EventRegistry.reset()` at the start of every `load()`), while tool registrations in `ToolRegistry` are deferred until all modules are completely problem-free (atomic flush on the success path) (review #35↔F-12, #44) | The rollback variant (deregistration on abort) requires a new API in `ToolRegistry` outside the wave's ownership; the reset at load start covers both retry-after-failure and cross-session collisions of built-in/module types; the "one load = one taxonomy" semantics is compatible with the D27 journal read contract (unfamiliar types — `UnknownEventPayload`, not an error) |
| D33 | §9.6 arch: the manifest `description` — module-author text that is model-facing; normalization (control characters, deactivation of embedded §6.8 markers), a 400-character limit (exceeding it — a load error) and rendering in the orchestrator's roster wrapped in verbatim untrusted markers under the "the roster is data" preamble (review F-9) | Validation "against instruction patterns" — an unreliable heuristic filter, false positives on legitimate descriptions; markers kill precisely the instructional force of the position while keeping its usefulness for `task()` routing; the residual risk (convincing prose inside markers) is documented in SECURITY.md ASI04 — operator vetting remains the control |

### 13.1. Wave 4 log (review fixes for judge/HITL/perimeter)

| D* | Decision | Rationale |
| --- | --- | --- |
| D34 | §7.2/ASI02: (F-3) an undeclared risk class of a **module** tool defaults to the most gated class `destructive` (in `ToolRegistry.register_many` and `_build_subagent`; platform tools all declare theirs, their `passive` fallback is kept for non-gating reads); (F-4) a module manifest may **only add** HITL gates: an `interrupt_on: false` entry for a tool gated by the profile, and an entry for an unknown tool — a load error (fail-fast, arch §8.3); "explicit module entries win" (arch §7.1) is replaced by operator primacy | The `passive` default contradicted SECURITY.md ASI02 (undeclared → most gated): a forgetful module author shipped a side-effecting tool without a single approval pause under any profile (CWE-1188/453); `interrupt_on.update()` let the manifest remove operator gates and advertise "paranoid" without its own destructive calls (CWE-274/250, ASI09); the test pins (`test_registry.py`, `test_loader.py`) are flipped semantically, not weakened |
| D35 | §6.7 (F-18): operator decisions on judge escalations are persistent — a `facts` ledger `judge_class_gate` (the existing `MemoryStore.add_fact`/`search`/`get` API, no new migration): each escalation — an `escalate` row, each decision — a resolution row keyed by the escalation row; replay on open/resume before the first LLM call (§16.9): reject restores the permanent class deny, an unresolved escalation is re-queued for approval; a duplicate escalation of the same class is idempotent (`escalate()` returns the existing id, review #37) — an orphan resolver is impossible | The in-process `JudgeEscalationRegistry` was recreated on every session build: an operator reject "evaporated" on restart (CWE-754/1188, ASI09) even though interrupt decisions survive restart via the checkpointer; a separate `memory/schema.py` migration — outside the wave's ownership (RD-8), while `facts` — an existing machine-readable table with an FTS trigger; the decision key — the fact row id, not a per-process `judge-esc-NNNN` |
| D36 | §6.7/§12.3: (1) the judge's post-call band is wired into production (#54↔F-19): `postcall` in the `JudgeBand` contract, the call — in `GuardrailMiddleware.awrap_tool_call` after tool execution (fire-and-forget, deny is not escaped — there is nothing to escape), `wait_pending()` on session close; (2) secret substitution by name (#11): the reference form `<masked:secret-name>` (the `projector.mask_reference` canon) is resolved at the tool boundary (`bind_secret_substitution` in tools/platform, applied to `http_*` in the session toolset) — the pipeline and journal digests see the reference, the target host and evidence receive the values, the journal — neither (D21); client-side `GuardrailBlocked.reason` is projected at the emit boundary (the reason quotes the already-substituted URL) | The band was dead code despite the documented delivery (T3.4.2 `[x]`); the documented secrets workflow was unreachable — the agent either inserted a literal (→ #10↔F-16) or could not authenticate; the substitution point — after guardrail evaluation, per the write contract; the edit-prefill form (`<masked:…>` in edited arguments) is resolved by the same mechanics |

### 13.2. Wave 5 log (review fixes for the ReDoS analyzer / DNS pinning / replay ledger)

| D* | Decision | Rationale |
| --- | --- | --- |
| D37 | §6.6 (F-10): the string heuristic for nested quantification is replaced by a structural loop-safety analyzer over the `re` parse tree (`re._parser` — the same parser that compiles the pattern; stable across supported 3.11–3.15). Rejected are loops whose iteration boundary can "slide": alternation inside a loop, an optional iteration tail (`(\w?\s?){5,}`, `(?:xa?)+`), overlapping/unprovable seams (`(a|aa)+$`, `a+a+`, `(a*)(a*)`, `(?:x+(?:y|x))+`, forms inside look-ahead), as well as a pair of adjacent variable quantifiers at the top level with an unproven disjunction (`a+a+`, `\d+\w+` — the latter is a documented FP). Safe families remain accepted: a literal seam with a disjunction (the curious `(?:/[^/?#]+){6,}`), atomic groups and possessive quantifiers (`(?>a+)+`, `(?:xa++)+`), symmetric fixed seams (`(?:ab)+`, `(?:a{2})+`), an optional leading part with a mandatory trailing one (`(?:a?x)+`). Analysis failure = rejection (fail-closed) | The string heuristic missed canonical catastrophic forms (CWE-1333): `(a|aa)+$` and `(\w?\s?){5,}` passed validation and empirically spiraled into multiplicative backtracking — the parser itself factors `a\|aa` into a nested branch, while optional tokens blur the iteration boundary; a hand-written parser would yield silent false negatives (the same class of defect), while `re._parser` on an internal API change degrades into a fail-closed rejection, not a pass-through |
| D38 | §6.2/§6.3 (F-11): (1) **every** resolved address is checked against `ip_subnets` (a mixed "legitimate+internal" record does not allow connecting to an unverified member); (2) the hop connects to the verified address — the URL carries the pinned IP, `Host`/SNI/certificate verification stay on the name via the documented httpx ≥ 0.28 `sni_hostname` extension (`Host` is substituted only when the author did not supply one; an IPv6 literal is bracketed by `copy_with`); a failed connect iterates over the remaining verified candidates, a timeout does not; (3) a hung resolver = deny (fail-closed), an unresolvable name — pass (nothing to contact). This cancels the deferred part of D28 ("transport-level IP pinning — out of v0.1 scope") | The address being checked was not the one the connection actually went to (check-then-connect TOCTOU against httpx's independent resolution), and a resolver timeout silently bypassed the protection on the in-flight hop — against the invariant's own contract; the D28 premise ("httpx transport surgery") stopped being true — `sni_hostname` is a documented extension point (0.28 is pinned in the lock), no surgery needed; name pinning + re-verification at intercept are kept as a duplicate layer |
| D39 | §6.7 (F-18)/§4.4: replaying the `judge_class_gate` ledger reads it via the new `MemoryStore.list_facts(subject)` — a full read-only scan of the domain table in row order (rowid is monotonic = ledger order), instead of the ranked FTS `search(..., limit=500)` with N+1 `get` | Beyond ~500 ledger rows (an escalation per gated call — hundreds over a long session is the norm) window truncation dropped the resolution row: replay either crashed (`SessionError` "unknown gate" — the session became unrecoverable) or silently evaporated a permanent deny — exactly the failure F-18 exists to prevent; FTS by subject — semantically wrong access (an exact ledger prefix, not token search); the new method — in the API table §4.4, the "domain tables only via MemoryStore" invariant is untouched |
| D40 | §3.1/§8.3/§8.7: the built-in modules (`crawler`, `xss-detector`) are moved from the `swarmy.agents` package to the root `agents/` directory; the build includes it in the wheel as `swarmy/agents` (`[tool.hatch.build.targets.wheel] force-include`) and in the sdist; `ModuleLoader` resolves the directory in two layouts — `<package>/agents` (installed package) and `<repo>/agents` (editable/src layout) — via `builtin_agents_root()`; an empty or missing directory with `include_builtins=True` — fail-fast `ModuleLoadError` with a clear message (reinstall the package) rather than an empty roster; `include_builtins=False` remains an explicit escape hatch without built-ins | Modules are data, not an importable package: keeping them in `src/swarmy/agents` meant dragging the directory through `importlib.resources`, which is absent in an editable install (`.pth` pointing at `src`), and depending on `__init__.py`; the root `agents/` — a single source of truth for the reference modules, while the mapping to `swarmy/agents` preserves the package namespace and rules out a collision with a top-level `agents` in site-packages; an "empty directory" — a broken install, not a valid configuration: a silent empty roster would violate fail-fast (spec §4.5) and leave the operator without an orchestrator |

### 13.3. Operator feedback log (post-v0.1)

| D* | Decision | Rationale |
| --- | --- | --- |
| D41 | §3.4 (arch)/§9.2: the TUI auto-starts the mission from a goal file — `--goal-file PATH`, or by convention `goal.md` next to the session config; the CLI reads it (UTF-8, non-empty; an unreadable or empty file — a fail-fast problem before the session folder is created) and hands it to the console as `opening_goal`, which journals it as the first `OperatorMessage` on mount through the same path as a typed message (projected by `ContextProjector`, journal-first, drained by the worker's first pass). `--resume` never auto-starts and rejects `--goal-file`; without a goal file the console waits for the chat as before; the demo launchers pass `<demo>/goal.md` in `--tui` mode too | The goal file used to be a headless-only input, so `run.sh --tui` silently ignored `goal.md`: the operator saw idle panels and a mission that never started — the "the scan does not start" report; the alternatives: chat-only — a demo directory's `goal.md` becomes meaningless in TUI mode and every TUI run repeats the typing of the same goal; auto-start on resume — duplicates a mission whose goal is already in the journal (a second identical `OperatorMessage` restarts the work); a silent skip on an empty/unreadable file — the very "ignored input" defect being fixed, against fail-fast (§4.5); a new `--no-auto-start` flag — not needed: removing/renaming the file is the opt-out, and an absent file already means "wait for the chat" |

---

## 14. Open questions (resolved 2026-11-25)

All five version 0.1 questions were put to the operator with answer options and marked
recommendations; the choice is recorded in the decision log:

| # | Question | Decision |
|---|--------|---------|
| 1 | PyPI name | **D17**: v0.1 without publication, installed from git; upon publication — `swarmy-cli` (verified 2026-11-25: `swarmy` is taken by an abandoned 2011 package, `swarmy-cli` is free) |
| 2 | deepagents update policy | **D18**: pin `>=0.7.41,<0.8` + lock; upgrades as needed (changelog → tests → bump), security fixes — out of band |
| 3 | Delegation parallelism | **D19**: async parallelism in the MVP from the start *(the operator's choice differs from the "sequential" recommendation — compensated by global limits and the HITL queue)* |
| 4 | Evidence format for non-HTTP findings | **D20**: the `kind` enum; v0.1 — `http_request_response` only, the other kinds are reserved |
| 5 | LLM context sanitization | **D21**: raw memory + a sanitized projection (§8.7); detailed rules — in F2 |

There are no new open questions as of version 0.3.
