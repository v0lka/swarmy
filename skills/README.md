# Orchestrator skills

This directory is the **orchestrator-level** skills container of swarmy
(architecture §8.6). Every skill found here is loaded automatically into the
orchestrator context at session start — no config key, no manifest entry.
Subagent modules keep their own skills next to `AGENT.md`
(`agents/<module>/skills/`); this container is for skills the orchestrator
itself uses (planning and delegation conventions, reporting rules, engagement
methodology, operator-specific workflows).

## Layout (agentskills.io)

```
skills/
├── README.md              # this file — loose files at the root are not skills
└── <skill-name>/          # one directory per skill; the directory name IS the skill name
    ├── SKILL.md           # required: YAML frontmatter (name, description) + instructions
    ├── scripts/           # optional: helper scripts
    ├── references/        # optional: reference material
    └── assets/            # optional: templates and other assets
```

`SKILL.md` frontmatter:

```yaml
---
name: engagement-reporting        # <=64 chars, lowercase alphanumerics and single hyphens,
                                  # must equal the directory name
description: >                    # <=1024 chars: what the skill does and when to use it
  Conventions for consolidating confirmed findings into the final report.
license: MIT                      # optional
compatibility: swarmy >=0.1       # optional, <=500 chars
metadata:                         # optional
  include_tools: ""               # L0 extension: tools disclosed together with the skill
---
```

## How the skills reach the model

* The container ships inside the wheel as `swarmy/skills` (the same mapping as
  `agents/`) and is resolved in both layouts by `builtin_skills_root()`
  (`src/swarmy/core/skills.py`).
* The session validates every skill **fail-fast** before the first LLM call:
  a directory without `SKILL.md`, a `name` that does not match its directory,
  a missing or over-long `name`/`description`, invalid YAML, a symlinked
  skill — any of these aborts the start with the full problem list
  (`SkillsError`). Every `*.py` under the container gets the same
  forbidden-import / raw-egress static scan as module skills.
* Inside the graph the skills are served by the L0 `SkillsMiddleware`
  (progressive disclosure: the orchestrator first sees only `name` and
  `description`, then reads a `SKILL.md` on demand through the `skill` tool).
  The container is mounted **read-only** under the virtual `/skills/` path —
  the agent cannot modify it.
* `mode: fork` subagents inherit these skills (L0 rule); `isolated`
  subagents do not.
* A resumed session re-reads the container on its first step, so skills added
  between runs are picked up.

## Vetting

Skills are operator-vetted instructions that enter the orchestrator's context
with instruction authority (the module roster, in contrast, is rendered as
data). Treat a skill from an untrusted source like untrusted prompt text
(SECURITY.md ASI04); scripts under `scripts/` run with operator privileges and
without a sandbox.
