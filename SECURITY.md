# Security Policy

> **This is a security *policy*, not an audit report.** It defines the project's threat model and the secure coding rules every contributor and coding agent must follow. It does **not** record whether the current codebase complies with these rules — compliance verification belongs in code review, audits, or the issue tracker, never in this file.

swarmy is an extensible agent system for **authorized** web-application penetration testing: an orchestrator deep-agent (deepagents / LangGraph) drives a swarm of functional subagents that probe a target web application, while a human operator observes a Textual TUI and steers the swarm through human-in-the-loop (HITL) gates. It is a **single-operator desktop tool** — there is no server, no user accounts, and no multi-tenant deployment. Its two defining security properties are:

1. **The target under test is an adversary.** Every page, header, and API response the swarm fetches is attacker-controlled untrusted content flowing into LLM contexts. Classical appsec treats the network as the hostile boundary; here the hostile boundary is *inside* the model context window.
2. **Extension is code execution.** A subagent module is a folder of Python files that the loader executes in-process on the operator machine. Installing a third-party module is a trust decision equivalent to installing a PyPI package.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | :white_check_mark: |
| < v0.1  | :x:                |

v0.1 is pre-1.0 software installed from git (no PyPI distribution for v0.1 — decision D17). Security fixes land on the default branch only; there are no long-lived maintenance branches. Always run the latest commit of the release tag you depend on.

## Reporting a Vulnerability

**Preferred channel:** GitHub private vulnerability reporting — use the **Security tab → Report a vulnerability** of this repository.

**Do NOT** open public GitHub issues for security vulnerabilities. Do not include target data, session folders, or real secrets in any report.

**Response SLA:**
- Acknowledgment: within 48 hours
- Triage & severity assessment: within 5 business days
- Fix timeline: Critical — 7 days, High — 30 days, Medium — 90 days

**Disclosure policy:** Coordinated disclosure. We request a 90-day embargo before public disclosure. We credit reporters in release notes unless they prefer anonymity.

**Bug bounty:** No.

*Assumption:* the repository will be hosted on GitHub; until it is pushed, this channel is not yet reachable — publish the repository before public distribution.

---

## Threat Model

### Assets

| Asset | Sensitivity | Description |
| --- | --- | --- |
| Operator secrets (`secrets.yaml`) | Critical | Target-auth credentials (session cookies, bearer tokens, API keys) used by the swarm against the target. Exfiltration = target account compromise. |
| LLM provider credentials | Critical | API keys for the model/judge providers used by the harness. |
| Session memory (`memory.sqlite`) | High | Endpoints, findings, facts, notes, event journal, LangGraph checkpoints; may embed target-derived secrets and PII. |
| Evidence files (`evidence/<id>/`) | High | **Raw, byte-exact** request/response traffic, including any credentials and PII the target returned (D21). |
| Findings & attack trees | High | Vulnerability descriptions, payloads, and exploit paths for the target — disclosure degrades the target owner's security position. |
| Agent system prompts | High | Orchestrator prompt, module `AGENT.md` bodies, guardrail rule texts — extraction reveals testing methodology and bypass conditions. |
| Guardrail rule integrity | High | `guardrails.yaml` rules and engine rules; tampering with them re-opens the deny gates. |
| Event journal (append-only) | High | The audit receipt chain — "who/what did this and why" (ASI10). Loss or tampering destroys accountability. |
| Target availability & integrity | High | The target is a third party's production system; swarm pressure can outages or data corruption. Protected contractually by limits, not just politeness. |
| Session config snapshot (`session.yaml`) | Medium | Audit source of truth for what the session ran with; contains masked secret references only (AD-5). |
| Operator workstation availability | Medium | Local TUI/CLI process; resource exhaustion degrades the operator machine. |
| Generated report (`report.md`) | Medium | Draft pentest report embedding target-derived strings; consumers must treat it as untrusted content. |

Sensitivity rationale: everything that can unlock the *target* (credentials, findings, exploit paths) is Critical/High; process-local conveniences (config snapshots, reports) are Medium because exposure embarrasses but does not directly breach.

### Threat Actors

- **The target under test (adversarial content source)** — the defining actor. A compromised, malicious, or simply hostile web application crafts pages, headers, and API responses to hijack the swarm (prompt injection), exhaust it, or exfiltrate operator secrets.
- **Malicious or careless module author** — publishes a third-party subagent module (tools, prompts, guardrails, skills) whose code executes on the operator machine in-process (ASI04/ASI05), or whose prompt steers the swarm badly.
- **Prompt-injection adversary (ASI01/ASI06)** — plants hostile instructions in any content the swarm reads: target responses, stored facts/findings, even a module description.
- **Malicious MCP server / tool provider** — serves forged tool schemas or deceptive descriptions to the orchestrator (ASI04).
- **Local opportunist / other local user** — reads a session folder on a shared or compromised workstation: raw evidence, `memory.sqlite`, `report.md`, LLM provider keys in process environment.
- **Compromised supply chain** — malicious PyPI package (deepagents, LangChain stack: 88 locked packages), hijacked GitHub Action, typosquatted module dependency.
- **LLM provider** — third-party inference service that receives sanitized (but sensitive) session context; trusted with availability and confidentiality only up to its contract.
- **The over-trusting operator (ASI09)** — approves a confident agent's request without reading the raw intent; the human is part of the attack surface.
- **Careless operator error** — points the swarm at an unauthorized target; the tool has no authorization gate by design (D15) and relies on the operator's legal authorization.

### Attack Surface

Everything below is an actual v0.1 entry point, verified against the source tree:

- **CLI arguments and session config** — `swarmy.cli` parses flags plus `session.yaml` (resolution CLI → file → defaults, fail-fast) and `secrets.yaml` (mode 0600, POSIX enforcement).
- **Module loading** — `--agents-dir` directories and built-in `src/swarmy/agents/`: `AGENT.md` frontmatter + system prompt, `tools/*.py` **imported and executed in-process** via `importlib.util.spec_from_file_location`, `guardrails.yaml`, optional `skills/` (SKILL.md + scripts).
- **MCP servers** — `SessionConfig.mcp_servers` integrates external tool servers into the harness (ASI04).
- **Platform HTTP tools** — `http_get` / `http_post` / `http_put` / `http_delete`: the **only** sanctioned egress to the target; each call passes the guardrail pipeline, scope check, and resource limits *before* the first byte is sent.
- **LLM provider APIs** — orchestrator, subagents, and the LLM judge all send model context (sanitized projections) to third-party inference endpoints.
- **Event bus / journal / memory** — in-process `emit_event` fan-out, append-only journal, `memory.sqlite` (domain tables + FTS5 + checkpoints), resume path replays the journal tail.
- **HITL approval queue + TUI** — the Approvals panel renders raw tool intents for approve/reject/edit; TUI panels render target-derived and agent-derived text.
- **Report generator** — deterministic jinja2 render (`autoescape=False`, markdown) of memory contents into `report.md`; no LLM, no network.
- **CI pipeline** — GitHub Actions across a 4-platform matrix; third-party actions (`actions/checkout@v4`, `astral-sh/setup-uv@v6`) and the PyPI dependency graph (88 packages).
- **PyPI / git supply chain** — runtime dependencies incl. `deepagents>=0.7.41,<0.8` and its LangChain/LangGraph transitive tree.

### Trust Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  Operator zone (trusted)                                     │
│  CLI, session.yaml/secrets.yaml, TUI chrome, engine rules,   │
│  built-in module prompts                                     │
└──────────────┬───────────────────────────────────────────────┘
               │ instruction/data separation (projector markers)
┌──────────────▼───────────────────────────────────────────────┐
│  Agent reasoning zone (semi-trusted)                         │
│  Orchestrator + subagent contexts, plans, tool-call intents  │
└───┬──────────────────────┬───────────────────────┬───────────┘
    │ least-agency gates   │ sanitized context     │ task() delegation
    │ (guardrails+HITL)    │ egress (to providers) │ (in-process bus)
┌───▼──────────────┐  ┌────▼─────────────┐  ┌──────▼─────────────┐
│ Target (hostile) │  │ LLM providers    │  │ Subagent modules   │
│ SwarmyHttpClient │  │ model + judge    │  │ (code = trust      │
│ scope+limits     │  │ third parties    │  │  decision, ASI04)  │
└───┬──────────────┘  └──────────────────┘  └──────┬─────────────┘
    │ raw traffic                                  │ MCP servers,
┌───▼──────────────────────────────────────────────▼─────────────┐
│ Session folder (raw persistence, D21)                          │
│ session.yaml · secrets.yaml (0600) · memory.sqlite · evidence/ │
└────────────────────────────────────────────────────────────────┘
```

The boundaries that matter:

1. **Instruction/data (ASI01):** trusted developer/operator instructions (engine prompts, `AGENT.md` bodies, engine guardrail rules) vs. untrusted runtime content (target responses, stored facts, module-provided text). Both reach the model as natural language — the projector's untrusted markers and the prompts' data-handling rules are what keep them apart.
2. **Target network boundary:** every byte to/from the target crosses `SwarmyHttpClient` *after* `GuardrailPipeline` approval and the scope allowlist (arch invariant 1). No other component may open a socket to the target.
3. **Module installation boundary:** `--agents-dir` content is executable code and LLM instructions installed by the operator; the loader validates the *contract*, not the *intent*.
4. **LLM provider boundary:** everything in a model context leaves the machine to a third party. Sanitization (masking, budgets) reduces but does not eliminate exposure.
5. **Raw persistence vs. sanitized context (D21):** session files and memory stay raw for pentester verification; only the model-bound preview is sanitized. Anything entering **any** LLM context goes through `ContextProjector` (arch invariant 4).
6. **Agent intent vs. operator decision (ASI09):** agents propose, the approval queue disposes; a deny from any guardrail layer is overridden only by an `OperatorDecision` (arch invariant 5).
7. **CI/CD boundary:** build-time trust in GitHub Actions and the PyPI graph.

### Known Risks & Accepted Trade-offs

Design-level decisions, each anchored in the decision log — not compliance findings:

| Risk | Severity | Mitigation / Rationale |
| --- | --- | --- |
| No authorization gate: the tool never verifies the operator may test the target (D15, spec §8.6) | High (misuse) | Conscious decision for professional use; README + first session chat message carry the legal disclaimer. Revisit before any public distribution. |
| Module tools execute in-process with operator privileges; no sandbox (D4) | High | Extensibility over isolation. Loader contract validation (typed args, no `Any`, forbidden imports, declared risk classes, name-collision fail-fast) narrows but does not eliminate the risk; operators must vet third-party modules like any PyPI install. |
| Session files are raw and unencrypted (D21): `memory.sqlite`, `evidence/`, `report.md` may contain target secrets and PII at rest | High | Pentesters need raw data for verification. Folder-level OS permissions are the control; `secrets.yaml` is 0600. Operators must treat the session folder as sensitive. |
| `os.chmod` cannot express POSIX 0600 on Windows; ACL hardening is out of scope for v0.1 (roadmap T2.3.3) | Medium | Documented platform limitation; secrets-file mode is enforced as a no-op on Windows. Use OS-level folder protection on Windows. |
| Sanitized session context travels to third-party LLM providers (orchestrator, subagents, judge) | Medium | Inherent to an LLM tool; budgets + masking shrink exposure. Provider/model choice is an operator decision (`model` config). |
| Outbound secret detection in the HTTP client is **warn-not-block**: a call whose headers/body contain an operator secret value proceeds (with a warn event and masked preview) | Medium | Deliberate: the operator passed the credential by name for authenticated testing; hard-blocking would break the tool's purpose. The warn + preview keep the operator informed. |
| Report renders target-derived strings as markdown through jinja2 with `autoescape=False` (markdown has no single escape grammar) | Low | Escaping contract (decision D29, review Issues #40/#18): every target/LLM-derived field (finding title/description/reproduction, endpoint path/host/parameters, tree text) is markdown/HTML-neutralized in the view models (`ReportGenerator._report_safe`); mermaid labels are restricted to a safe charset without `<`/`>`. Residual risk: the escaper neutralizes a denylist of markdown-sensitive sequences, not the full CommonMark grammar — the report stays draft-marked and requires pentester review; consumers must still treat `report.md` as untrusted content, like any raw target artifact. |
| CI third-party actions pinned by version tag (`@v4`, `@v6`), not commit SHA | Low | Standard upstream tags; upgrade to SHA pinning if the repository becomes a higher-value target. |
| In-process event bus and delegation have no transport encryption/authentication (ASI07) | Low | All inter-agent communication is local function/graph calls inside one process; there is no wire to protect in v0.1. External transports are out of scope. |

---

## Security Architecture

These are the security domains this architecture involves and what the policy **requires** of each. Framed as obligations for contributors and coding agents — not an inventory of what exists.

### Scope & Egress Control (platform invariant)

- **Every** network call to the target MUST go through `SwarmyHttpClient`, and only **after** `GuardrailPipeline` approval — checked pre-connect (arch invariant 1).
- The scope allowlist (`ScopeRegistry`) MUST be checked before any connection; out-of-scope attempts raise `GuardrailBlocked`. Scope changes MUST go through an operator decision that emits `ScopeChanged` and is journaled — never by mutating config at runtime.
- Module tools MUST NOT import or use `socket`, `urllib`, `http.client`, `requests`, or `subprocess` for network access — the loader enforces this; new network features MUST wrap the platform client.
- Redirect following, TLS, and connection handling MUST stay inside the platform client so scope and limits apply transitively.

### Resource Limits Protecting the Target

- The target's availability is a security asset. `ResourceLimiter` limits (requests/second per host, concurrent requests, body size, redirect depth, session request budget) MUST remain **session-global** — summed across all parallel delegations (arch invariant 7). Per-agent limits are forbidden: they multiply under delegation.
- Any new outbound capability (new verb, new protocol, WebSocket, file download) MUST integrate with the limiter before its first release.
- Limits MUST be enforced deterministically in the platform layer, not by prompt instructions to the model.

### Guardrail Pipeline (deny-critical path)

- Three rule layers compose by AND: platform invariants (non-disableable), engine base rules (disableable in config), module rules (`guardrails.yaml`). **A deny from any layer denies the operation** (spec §8.2).
- The deny path MUST be deterministic code — **no LLM in the deny critical path** (arch §17). The LLM judge may `escalate_hitl` or `flag` but MUST NEVER unblock a deterministic deny (spec §8.4); forced override is `OperatorDecision` via HITL only (arch invariant 5).
- Module `guardrails.yaml` rules may only **add** denies with the declarative predicates (`any_param_matches`, `url_matches`, `header_matches`, `body_size_above`, `tool_in`) — never whitelists that re-allow a platform deny.
- A guardrail hit MUST: not execute the call, journal the attempt, publish `GuardrailBlocked`, and return the rule id + reason as textual feedback to the agent (spec §8.5).

### Secret Management

- Operator secrets live **only** in `secrets.yaml` (mode 0600, enforced on load and write; POSIX — Windows no-op documented). `SessionConfig` MUST remain structurally incapable of holding secret values: secrets are addressed **by name** (AD-5). Never type a raw credential into a tool argument.
- Secrets MUST appear as `<masked:secret-name>` references in model context, TUI, journal, config snapshots, and reports. Raw values stay in memory only, wired to the projector as masking rules.
- The projector's masking step (literal values, longest-first, plus regex patterns and the built-in `Authorization`/`Cookie`/`Bearer` detectors) MUST run on everything leaving toward a model context. Masking is context hygiene, **not** a cryptographic control — do not rely on it as one.
- The HTTP client's outbound hygiene scan (secret value in outgoing headers/body → warn event + masked preview) MUST be preserved for every new request field.
- Secrets discovered **on the target** are findings: stored raw in evidence, truncated/masked in model context — never spread through chat history to providers.
- Never commit secrets to version control; tests use obviously fake values. Rotate any secret that may have entered a model context unmasked.

### Data Protection (raw vs. sanitized, D21)

- Everything entering **any** LLM context MUST pass through `ContextProjector` (arch invariant 4): byte-budget truncation with explicit `[truncated N bytes]` markers → secret masking → `[untrusted-target-content begin/end]` marking → control-character/hidden-Unicode normalization — in that canonical order.
- Session files and memory stay **raw** (pentesters verify findings against raw data). Consequently: TUI panels, reports, and exports that render raw content MUST keep provenance visible and never silently blend raw target content into trusted UI chrome.
- No encryption-at-rest layer is provided in v0.1; the session folder's OS permissions are the control. Documentation and tooling MUST treat session folders as sensitive artifacts (warn before sharing, `.gitignore` session dirs).

### Logging, Audit & Incident Reconstruction

- The event journal is **append-only**; every event MUST be journaled **before** fan-out to subscribers (arch invariant 2). Guardrail blocks, judge escalations, operator decisions, scope changes, and mode switches MUST all be journaled — this is the receipt chain for post-incident "what happened and why".
- Log and journal enough to reconstruct an incident (tool, args, rule ids, source agent, correlation id) but **never** secret values, tokens, or raw credentials.
- `session.yaml` is the audit snapshot of what the session ran with; it MUST stay structurally secret-free (masked references only, AD-5).

### Input Validation & Config

- Every boundary — CLI flags, `session.yaml`, `secrets.yaml`, `AGENT.md` frontmatter, `guardrails.yaml`, tool arguments, event payloads — MUST be validated by Pydantic v2 models with `extra="forbid"`; unknown keys are rejected, not ignored.
- Session start MUST be fail-fast and aggregate **all** problems (missing file, bad YAML, unknown event type, module contract violation, name collisions) before the first LLM call (arch invariant 9). Problems never open the UI.
- YAML MUST be parsed with `yaml.safe_load` only. No `eval`/`exec`/`pickle` anywhere in domain code.
- Guardrail regexes come from config: compile-time `re.error` MUST be caught and reported fail-fast (aggregated), never crash mid-session.

### Persistence & SQL

- One storage engine: `memory.sqlite` (WAL). Domain tables only via `MemoryStore`, full-text via `SearchIndex`, LangGraph checkpoints only via the L0 checkpointer (arch invariant 3). No second storage engine; no module-level SQLite handles.
- All SQL MUST use parameterized queries (aiosqlite placeholders). Never interpolate model-influenced or config values into SQL strings.
- Migrations live in the single ordered list in `memory/schema.py` (RD-8).
- Evidence files are keyed by server-generated uuid4 request ids — never by model- or target-supplied path components.

### File & Path Handling

- Paths via `pathlib` only (ruff `PTH`); no POSIX-only APIs in core (no `fork`, no `os.path` string juggling) — the CI matrix includes Windows.
- Writes stay inside the session folder; CLI-provided directories are canonicalized before use; model-influenced strings never become path components without validation.

### Dependency & Supply Chain Management

- Exact versions pinned in `uv.lock` (hash-verified entries); lower bounds declared in `pyproject.toml`. `uv lock --check` runs in CI — commit lock updates with `pyproject.toml` changes.
- `deepagents` is pinned `>=0.7.41,<0.8` and upgraded **only** via the D18 procedure: manual changelog review → bump lock → full `make check`; security fixes may land out of band.
- Add runtime dependencies only when necessary (P4); prefer stdlib; review new dependencies for maintenance activity, known vulnerabilities, and transitive weight before adoption.
- Automated vulnerability scanning (e.g., Dependabot on GitHub, or a scheduled `pip-audit`) MUST be enabled before public distribution.

### Cross-Platform Correctness

- The CI matrix (windows/amd64, macos/arm64, linux/amd64, linux/arm64) is a security control: path handling, permission enforcement, and process behavior MUST be portable. A control that silently no-ops on one platform (e.g., secrets-file mode on Windows) MUST be documented in code, not just in this file.

---

## Agentic Application Security

This project is unambiguously agentic: agents plan, call side-effecting tools, persist memory across sessions, and coordinate under an orchestrator. The OWASP Top 10 for Agentic Applications (2026) applies in full. The governing principle is **least agency** — grant an agent only the minimum autonomy required for a safe, bounded task. Least privilege fixes reach; least agency fixes latitude within that reach. Ask **both** about every module and every autonomy mode.

### ASI01 — Agent Goal Hijacking

**Why it applies here:** the target under test is an adversary whose content — pages, headers, API bodies — becomes model context. A hostile `200 OK` can carry instructions indistinguishable from operator intent.

Rules:
- Target-derived content MUST be wrapped in the verbatim untrusted markers (`[untrusted-target-content begin] … end`) by the projector before entering any model context; only streams that are provably not target-derived may disable marking.
- System prompts (orchestrator and every module `AGENT.md`) MUST instruct the model to treat marked content as **data, never as instructions** — including "instructions" that claim to be safety rules, authorization grants, or operator messages.
- Instruction/data separation MUST be structural (markers + prompt rules), not stylistic. Never concatenate raw target content into instruction-position text.
- Recursive propagation is contained by the same rule at every hop: a subagent that quotes target content into its findings output re-enters the orchestrator's context still marked untrusted; findings, facts, and notes keep their source provenance.
- Prompt-extraction resistance is a prompt-content concern: module prompts MUST NOT enumerate guardrail bypass conditions or secret locations.

### ASI02 — Tool Misuse and Exploitation

**Why it applies here:** the swarm's whole job is calling side-effecting tools (`http_*` against a live target, `memory_*` writes, `emit_event`); volume and chaining are the attack mode.

Rules:
- Subagents get the **platform tool allowlist only** (`memory_*`, `emit_event`, `http_*`, `session_info`, `update_finding_status`) — never the bus, journal, or store directly (arch invariant 6). Reserved name prefixes (`memory_`, `event_`, `session_`) are forbidden in custom tool names; collisions fail the session start.
- Every tool's parameters MUST be fully typed (Pydantic-grade annotations; `Any` and `dict[str, Any]` forbidden — the loader rejects them) and carry a non-empty LLM-facing docstring that honestly describes behavior; no deceptive descriptions.
- Every tool MUST declare its risk class (AD-7 declaration, e.g. `swarmy_risk_class`); undeclared tools default to the most gated class, not the least.
- HITL strictness profiles gate risk classes: `paranoid` gates everything except passive; `normal` (default) gates verify + destructive; `yolo` gates only destructive. Shipping a new side-effecting tool requires deciding its class explicitly.
- Dangerous operations are restricted **regardless of agent request** by engine rules (e.g., TRUE-based SQLi payloads, `TRACE`/`CONNECT` methods, executing XSS payloads — inert markers only) — the model cannot argue them away.
- Runaway volume is bounded by the session-global `ResourceLimiter` (rps, concurrency, body size, redirect depth, session request budget) — a loop of allowed calls still exhausts at the budget, deterministically.

### ASI03 — Agent Identity and Privilege Abuse

**Why it applies here:** many subagents act under one session identity; a hijacked crawler must not inherit more than a crawler needs.

Rules:
- There is exactly one principal — the operator's session. Subagents hold **no credentials**: they receive masked references (`<masked:name>`), never values (AD-5). The platform client injects credentials at request time.
- Delegation happens only via the L0 `task()` tool; the delegation tree (who tasked whom, with what) is visible in the TUI and reconstructable from the journal — the original caller is preserved on every hop.
- Events carry `source` and `correlation_id`; modules may emit only the event types declared in their frontmatter (validated at load) — a module cannot impersonate another component's events.
- Confused-deputy containment is structural: even a fully hijacked subagent's network calls pass the deterministic scope + guardrail + limit layers; the orchestrator cannot delegate a privilege a module did not declare.

### ASI04 — Agentic Supply Chain Compromise

**Why it applies here:** extension is the product. Modules, MCP servers, skills, and 88 PyPI packages all feed trusted material into the swarm.

Rules:
- Installing a third-party module is an operator trust decision and MUST be treated like installing a PyPI package: review its `tools/` code, `AGENT.md` prompt, and `guardrails.yaml` before pointing `--agents-dir` at it. Built-in modules (`crawler`, `xss-detector`) are the reviewed reference implementations.
- The loader's contract validations (typed signatures, no `Any`, docstring presence, forbidden-import scan, reserved-name collisions, declared event types, risk classes) MUST stay fail-fast; a module that fails validation never reaches the model.
- Tool and skill descriptions MUST be reviewed for manipulative or deceptive language when vetting a module — a tool docstring is model-facing instructions (ASI04's description-deception vector). The module manifest `description` additionally gets deterministic hardening before it reaches the orchestrator system prompt (F-9 fix): it is normalized (control characters flattened, embedded §6.8 untrusted markers defused), capped (400 characters; over-length is a load problem, not a silent truncation), and rendered in the roster wrapped in the verbatim untrusted markers under a preamble that positions the roster as data. Residual risk, kept honest: a vetted module author can still write persuasive prose *inside* the markers — the markers remove the instruction authority of the roster, they do not make hostile prose harmless; operator vetting remains the control.
- MCP servers MUST be configured explicitly (`mcp_servers`); no runtime/dynamic tool discovery beyond the explicitly configured dirs and servers in v0.1. Adding dynamic discovery would be a design decision requiring spec/architecture updates.
- Python dependencies: exact pins in `uv.lock` (hash-verified), deepagents upgraded only via D18 with changelog review; new dependencies reviewed before adoption; automated vulnerability scanning enabled before public distribution.

### ASI05 — Unexpected Code Execution

**Why it applies here:** module `tools/*.py` run in-process on the operator machine by design (D4); `skills/` scripts exist in the module contract.

Rules:
- No new code-execution surface (no `eval`, `exec`, `compile`, dynamic `import` of module-supplied paths, `subprocess`, `os.system`) in domain code or module tools. The loader's forbidden-import scan is the enforcement point — keep it current when new dangerous modules matter. The scan (F-2 fix) covers the stack's own raw-network escapes — `socket`, `urllib`, `http.client` **and the HTTP-client families `httpx`/`aiohttp`/`requests`** installed in the same venv — plus `subprocess` imports, the `os.system`/`os.popen` attribute-call shapes, and asyncio's raw stream APIs (`open_connection`/`start_server`); bare `os` stays legal, only the process-spawning uses are rejected. The same static scan runs over `tools/*.py` **and `skills/**/*.py`** (skill scripts execute with operator privileges); non-Python skill scripts are outside the AST scan's reach and stay covered by the ASI04 vetting rule.
- Any future feature that would run model-influenced or module-supplied code outside the plain-import path MUST be a deliberate design decision: spec + architecture update, sandbox or approval gate defined, decision journaled — not a convenience PR.
- Module import runs before the first LLM call (fail-fast): a module that throws at import blocks the session rather than partially loading.
- Skills' `scripts/` execute under operator privileges with no sandbox in v0.1 — the vetting rule of ASI04 applies to them identically.

### ASI06 — Memory and Context Poisoning

**Why it applies here:** `memory.sqlite` persists endpoints, findings, facts, and notes, and sessions are resumable — poison written today shapes tomorrow's run.

Rules:
- Memory writes MUST go through the typed `MemoryStore` APIs only (Pydantic-validated models); no raw SQL from tools or modules. Validation is the first filter against poisoned payloads.
- Facts, findings, and notes MUST retain their provenance (source agent, correlation id) so a review can distinguish target-derived claims from operator intent.
- Session isolation is per-folder: one session = one `memory.sqlite`. No cross-session shared store exists in v0.1; do not add one without an isolation design.
- Purging poisoned memory = deleting the session folder (and its checkpoints). Resume replays the journal tail through the policy pipeline — corrupted-journal detection is fail-fast, not silent.
- Target-derived facts are claims, not instructions: prompts MUST instruct the model to re-verify target-derived assertions before acting on them with gated tools.

### ASI07 — Insecure Inter-Agent Communication

**Why it applies here:** an event bus fans out to TUI, policies, and the orchestrator; `task()` delegates between agents — all in-process.

Rules:
- Events are typed Pydantic envelopes (`id`, `ts`, `type`, `source`, `payload`, `correlation_id`) created **only** via `emit_event` or the platform; a new event type = payload class + registry entry, declared in the module's `AGENT.md` and validated at load.
- Delegation depth follows the L0 `task()` tree; the tree is observable in the Swarm Activity panel — do not introduce hidden side-channels (direct object references between agents) outside the graph.
- A compromised module cannot forge another component's identity: event `source` is platform-assigned, and modules cannot emit undeclared types. Preserve this assignment server-side; never accept `source` from tool arguments.
- v0.1 has no network transport between agents; if one is ever added, it MUST bring authentication, integrity protection, and transport security as a design decision — this section's rules extend to it.

### ASI08 — Cascading Agent Failures

**Why it applies here:** orchestrator → subagents → tools chains multiply; one blocked tool invites creative workarounds.

Rules:
- Fail-closed everywhere: an unreachable or errored guardrail pipeline MUST deny, never allow-by-exception. Resource-limit enforcement errors deny the call.
- Blocked operations return rule id + reason as agent feedback so the swarm **replans within the rules** — improvised bypasses (new egress path, direct storage) are structurally unavailable because non-platform channels don't exist.
- Cascade containment is budgeted: the session-global request budget and rate limits bound the total damage of any runaway chain; per-hop timeouts (e.g., the judge's `timeout_s`) stop single-dependency hangs from stalling the swarm.
- Deny-rate and failure visibility: `GuardrailBlocked` and limit events surface in the TUI activity feed so the operator sees a cascade forming rather than inferring it from output quality.

### ASI09 — Human-Agent Trust Exploitation

**Why it applies here:** HITL is the product's core steering mechanism; approval fatigue and fluent agent prose are the attack.

Rules:
- The Approvals panel MUST display the **raw intent** — tool name and typed arguments — never an agent-generated natural-language summary of what it wants to do.
- Approval requests MUST carry provenance markers: target-derived content shown in the queue keeps its untrusted markers; agents are visibly labeled as agents (the operator always knows who is asking).
- Block justifications come from the deterministic policy layer (rule id + message), not from the agent being blocked — the thing being judged never writes the rationale for its own approval.
- Forced override of a deny is an `OperatorDecision` — an explicit, journaled, attributed act; it must never be collapsible into a routine approve click.
- Parallel delegations produce a visible FIFO approval queue (no hidden or out-of-band approvals); strictness profiles exist so operators can match gate breadth to risk instead of clicking through noise. When touching this surface, optimize for the operator actually reading the intent.

### ASI10 — Rogue Agents

**Why it applies here:** `mission` mode grants the orchestrator extended autonomy; drift or runaway behavior must be bounded, visible, and stoppable.

Rules:
- Autonomy is bounded by hard budgets, not prompts: session request budget, rate limits, concurrency caps, and the L0 graph's own structure. A new autonomy feature MUST declare its bounds numerically.
- The receipt chain is complete: every event — including every tool call, guardrail block, decision, and mode switch — is journaled before fan-out, so any session can be reconstructed after the fact. Never add an agent action that skips the journal.
- Mode switches (`interactive` ↔ `mission`) and scope changes are journaled operator decisions; agents cannot self-promote autonomy.
- The kill-switch is the operator's interrupt, made persistent by the SQLite checkpointer: a stopped session resumes to the same state, decisions intact. Hidden orchestration logic outside the L0 graph is forbidden (arch §17) precisely so behavior stays inspectable.
- Drift monitoring tools (activity panel, journal statistics in the report) exist so operators can *see* volume, deny rate, and delegation depth — keep them fed by the journal, not by agent self-reporting.

---

## Secure Coding Guidelines

These guidelines apply to ALL contributors: human developers, code reviewers, and AI coding agents. Automated agents MUST treat these rules as hard constraints. Stack: Python `>=3.11,<4.0`, Pydantic v2, httpx, Textual, aiosqlite, deepagents/LangGraph — rules are tailored to that stack.

### Input Validation

- Validate every external input at its boundary with a Pydantic v2 model (`extra="forbid"`): CLI args, config files, manifest frontmatter, guardrail rules, tool arguments, event payloads. No `dict[str, Any]` schemas at boundaries.
- Reject unknown fields; never silently drop them. Aggregate all validation problems and fail fast (session-start style), rather than first-error abort.
- Parse YAML with `yaml.safe_load` only — `yaml.load`/`unsafe_load`/`Loader=` variants are forbidden.
- Prefer allowlists (scope allowlist, event-type registry, tool allowlist, declared risk classes) over denylists in every new mechanism.
- Canonicalize paths with `pathlib` (`resolve()`) before validation; validate then use, never validate then re-derive.

### Output Encoding & Injection Prevention

- All SQL via parameterized queries (aiosqlite `?` placeholders). Building SQL by f-string/concatenation — even from "trusted" config — is forbidden.
- No shell execution anywhere in domain code; if a build/test script needs it, keep it in the `Makefile`/CI layer, never in `src/`.
- Templating: jinja2 for report/markdown rendering is allowed with `autoescape=False` **only** because the output is markdown and target-derived label text is sanitized to a safe charset before rendering; any new template rendering HTML or another interpreted format MUST enable context-appropriate autoescaping and sanitize target-derived content for that format first.
- Never interpolate target-derived strings into code, regex bodies for guardrails (they are config, not runtime content), file paths, or shell-like commands.

### Authentication & Session Security

- No user accounts, no sessions of the classical kind — this is a single-operator tool. There are no password/token generation requirements in v0.1.
- Identifier generation (evidence request ids, correlation ids) uses `uuid4` — CSPRNG-backed. Never substitute a homegrown "random" (e.g., `random.random()`-derived ids) where uniqueness matters.
- Target-auth credentials belong to `secrets.yaml` handling only; never persist them anywhere else (see Secrets & Configuration).

### Cryptography

- Do not implement cryptographic primitives; none are needed in v0.1. If a future feature needs hashing/encryption/MAC, use the standard library (`hashlib`, `hmac`, `secrets`) or a reviewed dependency, and record the design decision.
- Masking (`<masked:name>`) is **context hygiene, not cryptography** — never present it as a protection against a determined local attacker with filesystem access.
- File permission enforcement (0600) is the at-rest control for `secrets.yaml`; document any platform where it degrades (Windows, in v0.1).

### Error Handling & Logging

- Fail securely: unexpected errors in the guardrail/limit/scope layers deny the operation; a crashed control never defaults to allow.
- Never include secret values, tokens, or raw credentials in exceptions, logs, journal events, or TUI output. Config validation errors may name fields and files, not values.
- Use the structured event system (`EventEnvelope` + severity) for anything the operator or journal needs; ad-hoc `print` in domain code is forbidden.
- Fail-fast at startup with aggregated problems; degrade loudly at runtime (event + deny), never silently.

### File & Resource Handling

- `pathlib` everywhere (ruff `PTH`); portable across the CI matrix; no `fork`/`signal`-dependent control flow in core.
- Evidence and report writes are keyed by server-generated identifiers inside the session folder; never derive write paths from model or target content.
- Enforce and preserve size limits (body size, evidence truncation thresholds, context budgets) in the platform layer; new content types MUST get budgets.
- All long-running operations carry timeouts (the judge's `timeout_s` pattern); unbounded awaits on external I/O are forbidden.

### Dependency & Supply Chain Rules

- Declare lower bounds in `pyproject.toml`; pin exact versions via `uv.lock` (hash-verified). `uv lock --check` in CI fails on drift — commit lock and manifest together.
- Upgrade `deepagents` only via `make upgrade-deepagents` (D18): changelog review → lock bump → full `make check`. Security fixes may go out of band.
- Adopt new runtime dependencies only with a stated necessity (P4), a maintenance/vulnerability check, and reviewer sign-off; prefer stdlib and already-pinned deps.
- Keep automated dependency scanning enabled once the repository is public (Dependabot or scheduled `pip-audit`); triage critical/high findings before the next release.

### Secrets & Configuration

- Operator secrets exist **only** in `secrets.yaml` (mode 0600) and are referenced everywhere else as `<masked:name>` (AD-5). `SessionConfig` must never gain a field that can hold a raw secret value.
- Secrets never appear in: source code, tests (use obviously fake placeholders), commit messages, the journal, `session.yaml`, reports, or chat transcripts.
- Session folders (`memory.sqlite`, `evidence/`, `secrets.yaml`) are gitignored; never commit, copy into `dist/`, or attach them to bug reports.
- Rotate any credential that was exposed unmasked to a model context or committed by accident, and treat the exposure as a security incident.

---

## Rules for AI Coding Agents

These directives are non-negotiable for any AI agent (Copilot, Cursor, Qoder, etc.) working on this repository. swarmy's own architecture document (arch §16 invariants, §17 anti-patterns) doubles as this project's security-control list — most rules below are its security reading.

### Hard Constraints

1. **No secret exposure** — never write, echo, log, or commit secrets, tokens, or API keys in source, tests, comments, commit messages, or CI configuration. Tests use obviously fake values.
2. **No weakened invariants** — do not bypass or weaken the arch §16 invariants: egress only via `SwarmyHttpClient` post-pipeline; journal-before-fan-out; `MemoryStore`/`SearchIndex`/checkpointer as the only storage paths; `ContextProjector` before any LLM context; deterministic deny supremacy; platform-tools-only modules; session-global limits; fail-fast startup. Even "temporary" test shortcuts that bypass them are forbidden — use the existing test doubles instead.
3. **No unsafe deserialization or dynamic execution** — `yaml.safe_load` only; no `eval`/`exec`/`compile`/`pickle`; no `subprocess`/`os.system` in `src/`; no dynamic import of module-supplied paths beyond the loader's audited pattern.
4. **No untyped boundaries** — Pydantic v2 models at every boundary; no `Any`/`dict[str, Any]` in domain code or tool signatures (ruff ANN401; the single sanctioned exception is the L0 wrapper `core/engine.py`). Untyped third-party values enter only through typed wrappers.
5. **No new network paths** — any new outbound capability wraps `SwarmyHttpClient` and integrates scope checking, the guardrail pipeline, and `ResourceLimiter` before its first release. Raw `socket`/`urllib`/`requests` in module tools are rejected by the loader — keep it that way.
6. **No LLM in the deny path** — the judge may escalate or flag, never unblock; never move a security decision into model discretion, and never add an agent-facing tool that can override a deterministic deny without an `OperatorDecision`.
7. **No suppression without justification** — `# pragma: no cover` only as recorded point exceptions in coverage config; `# noqa` only with a written reason; no blanket-omitting packages from coverage or lint.
8. **Preserve instruction/data separation** — when editing prompts (`core/prompts.py`, `AGENT.md` files) or the projector, keep the verbatim untrusted markers and the data-not-instructions prompt rules intact; never teach the model to trust target content, and never move target content into instruction position.
9. **Preserve the tool contract** — loader validations (typing, docstrings, forbidden imports, reserved prefixes, declared event types, risk classes) must not be loosened; new tools declare a risk class and honest docstrings. Deceptive tool descriptions are a supply-chain vulnerability, not a UX choice.
10. **No unbounded autonomy** — new autonomy, delegation, or retry behavior must ship with numeric bounds (budgets, caps, timeouts) wired to the session-global limiters and journaled events.
11. **Design-doc sync** — changing security-relevant behavior requires updating `docs/development/spec.md`/`architecture.md` and recording the decision (D*/RD* journals) **in the same change**; divergence between code and design docs is a defect.
12. **Ask before boundary changes** — if a change touches scope enforcement, guardrails, HITL, secret handling, the projector, or module loading, flag it for human review rather than merging quietly.

### Behavioral Guidelines for Agents

- **Preserve existing security patterns** — when modifying code, identify the invariant it implements and keep it green; add or update the tests that pin the security property (the guardrail pipeline, scope matching, limiters, projector, and loader contract all have dedicated suites).
- **Default to secure** — when options exist, choose the fail-closed, budgeted, journaled one even if it costs more code.
- **Flag uncertainty** — if unsure whether a change weakens a control, say so explicitly in the PR description.
- **Respect `.gitignore` and session hygiene** — never suggest committing session folders or removing ignore entries that protect secrets.
- **Run the full gate** — `make check` (lint, strict typing, both coverage gates, smoke) must pass before any task is considered done.

---

## Security-Related Configuration Files

| File | Purpose |
| --- | --- |
| `pyproject.toml` | Ruff strict rules, ty strict rules, coverage gates (85% unit / 70% integration), dependency lower bounds |
| `uv.lock` | Exact pinned, hash-verified dependency set; `uv lock --check` enforced in CI |
| `.github/workflows/ci.yml` | 4-platform CI matrix; lock check, lint, type check, coverage gates, smoke tests |
| `Makefile` | Developer gate entry point (`make check`), D18 deepagents upgrade procedure |
| `.gitignore` | Excludes session folders, `.venv`, coverage artifacts |
| `src/swarmy/agents/*/guardrails.yaml` | Built-in modules' deterministic deny rules (reference examples of the module rule DSL) |
| `docs/development/spec.md` §8, `architecture.md` §6–§7 | Canonical security design: threat model, guardrail layers, sanitization boundary, pipelines |
| *(session-time, never committed)* `session.yaml` / `secrets.yaml` / `memory.sqlite` / `evidence/` | The portable session folder — raw persistence boundary |

---

## Revision History

| Date       | Author    | Change           |
| ---------- | --------- | ---------------- |
| 2026-11-26 | maintainers | Initial version |
