# swarmy

Extensible agent system for **authorized** web-application penetration testing.
A swarm of functional subagents under an orchestrator deep-agent explores the
target, finds weaknesses and links them into attack trees; a human operator
observes the session in a Textual TUI and steers it through human-in-the-loop
gates.

Built on the [deepagents](https://github.com/langchain-ai/deepagents) harness
(LangChain + LangGraph). The primary use of this codebase is **writing
specialized subagent modules** (recon, vulnerability detectors, attack-tree
builders) — see `docs/development/architecture.md` §8 for the module contract.

## ⚠️ Legal disclaimer

swarmy is a tool for **professional penetration testers**. You are responsible
for ensuring you have **explicit authorization** to test every target you point
it at. Scanning or attacking systems without permission is illegal. The authors
accept no liability for misuse; there is no authorization gate by design (spec
D15) — responsibility for authorized testing lies with the operator.

## Status

Design-phase implementation tracking `docs/development/roadmap.md`
(milestones M1–M5 → release v0.1). The design documents are canonical:

| Document | Role |
|---|---|
| [`docs/development/spec.md`](docs/development/spec.md) | WHAT and WHY — principles, decision log, phases F0–F6 |
| [`docs/development/architecture.md`](docs/development/architecture.md) | HOW — packages, pipelines, invariants |
| [`docs/development/roadmap.md`](docs/development/roadmap.md) | WORK PLAN — milestones → phases → atomic tasks |

## Install from sources

Requirements: Python `>=3.11,<4.0` (runtime target 3.15), [uv](https://docs.astral.sh/uv/).

```sh
git clone <this repository> swarmy2 && cd swarmy2
uv sync            # creates .venv, installs swarmy (editable) + dev tools
uv run swarmy --version
uv run pytest tests/unit       # fast suite
make check                     # full CI-parity gate (lint, typing, coverage, smoke)
```

A released checkout also builds distributable artifacts (sdist/wheel, into
`dist/`):

```sh
make build
```

Installing from git (D17 — no PyPI for v0.1; a future distribution would use
the name `swarmy-cli`):

```sh
uv tool install git+<this repository URL>
```

The developer workflow lives in the `Makefile` (`make help`).

## Quickstart: the F5 demo session

One session = one portable folder (config snapshot, `memory.sqlite`,
`evidence/`, `report.md`). The built-in reference swarm — the `crawler` and
`xss-detector` modules — reproduces the roadmap's F5 demo: goal → endpoints →
XSS candidate → operator-approved verification → attack tree.

1. **Write a session config** (`demo.yaml`) pointing at your *authorized*
   target (example runs swarmy against itself on loopback — replace with a
   target you are allowed to test):

   ```yaml
   target:
     base_url: "http://127.0.0.1:8080/"
   scope:
     ip_subnets: ["127.0.0.1/32"]
     ports: [8080]
     schemes: ["http"]
   limits:
     rate_limit: 5          # requests/second, session-global (arch §6.4)
     max_concurrent_requests: 8
   policies:                 # arch §9.3 defaults, spelled out for clarity
     - {on: EndpointsDiscovered, action: notify_orchestrator, template: generic}
     - {on: FindingCandidate, action: notify_orchestrator, template: verify_finding}
     - {on: FindingVerified, action: notify_orchestrator, template: tree_proposal}
   ```

2. **Start the console** (the built-in modules load automatically; add your
   own folders with `--agents-dir`):

   ```sh
   swarmy demo.yaml --session-dir demo-session
   ```

3. **Tell the orchestrator what you want** in the chat panel:

   ```text
   check the target for reflected XSS
   ```

   The swarm then runs the §13.4 chain: `crawler` maps `robots.txt`,
   `sitemap.xml` and pages into the endpoint memory (`EndpointsDiscovered`);
   the `tree_proposal` policy steers the orchestrator; `xss-detector` probes
   parameters with inert markers, classifies reflections and verifies with
   safe (non-executing) payloads. The detector's POST probes are gated by
   the HITL queue — approve them in the Approvals panel.

4. **Watch and steer**: Swarm Activity shows the live event feed and the
   `task()` tree; Findings & Endpoints shows the endpoint map and finding
   cards with evidence links; Attack Trees grows
   `precondition --enables--> finding --leads_to--> goal`.

5. **Generate the report**: ask the orchestrator to run `generate_report` —
   a deterministic draft lands in `demo-session/report.md` (first line marks
   it as requiring pentester review; findings sorted by severity; evidence
   file links; attack trees as text + mermaid).

The same scenario is exercised headless by the integration suite:
`tests/integration/scenarios/test_demo_f5.py`.

## Writing a module (tutorial)

A module is a folder — no engine changes are needed to add one (invariant 9).
Drop it into a user module directory (for example `my-agents/`, passed via
`--agents-dir` or the config `agents_dirs`) with this layout:

```
my-agents/my-detector/
├── AGENT.md          # required: YAML frontmatter + system prompt
├── guardrails.yaml   # optional: declarative block rules (arch §6.6)
└── tools/            # optional: typed Python tool functions
```

**`AGENT.md` frontmatter** maps onto the L0 `SubAgent` dict (arch §8.2). The
`events` list is checked against the event registry at load — declaring an
unknown type fails the session start:

```yaml
---
name: my-detector
description: One sentence the orchestrator uses to pick you for a task().
events:
  - FindingCandidate
---
```

Everything below the frontmatter is the subagent's system prompt — write the
method, the boundaries and which platform tools to use.

**Tools** are plain Python functions in `tools/*.py`. The loader enforces the
contract at load time (arch §8.5): full type annotations (no `Any`), a
non-empty docstring per tool (it is the LLM-facing description), no
`socket`/`urllib`/`http.client` imports — network runs only through the
platform's `http_get`/`http_post`/`http_put`/`http_delete`. The risk class is
a declarative attribute (AD-7) — inert parsers stay ungated:

```python
from swarmy.guardrails.models import RiskClass


def score_response(body: str, marker: str) -> str:
    """Classify a marker reflection; returns a JSON report for the model.

    Args:
        body: the response body the platform http tools fetched.
        marker: your session-unique marker token.

    Returns:
        JSON object with the reflection context and a verdict.
    """
    return '{"context": "html_text"}'  # real logic here


score_response.swarmy_risk_class = RiskClass.PASSIVE  # AD-7 declaration
```

**Guardrails** (`guardrails.yaml`) are deterministic pre-call denies — the
LLM is never in the deny path (spec §8.3). Conditions are conjunctions of
`any_param_matches` / `url_matches` / `header_matches` / `body_size_above` /
`tool_in`:

```yaml
rules:
  - id: no-executing-payloads
    applies_to: ["http_get", "http_post"]
    condition:
      any_param_matches: "(?i)(<\\s*script|javascript:|\\bon[a-z]+\\s*=|alert\\s*\\()"
    action: block
    severity: high
    message: Executing payloads are forbidden — verify with inert markers only.
```

**State** flows through the platform tools every subagent receives:
`memory_search`/`memory_get`/`memory_upsert_endpoint`/`memory_save_finding`/
`memory_link_attack_node`/`memory_add_fact`/`memory_add_note`,
`update_finding_status` and `emit_event` (restricted to your declared event
types). Modules never touch the bus, journal or SQLite directly.

**Reference implementations**: read the built-ins for the full idiom —
`agents/crawler/` (parsers, depth guardrail, passive recon
prompt) and `agents/xss-detector/` (marker/reflection tools,
TRUE-payload block rules, the `http_post` manifest gate, finding + attack-tree
protocol). Their `AGENT.md`, `guardrails.yaml` and `tools/` are the canonical
examples this tutorial summarized; the loader contract is pinned by
`tests/unit/agents/`.

## License

MIT — see [LICENSE](LICENSE).
