# User module directory

This directory is the **example user-module location** (`cwd/agents`, arch §3.1).
Built-in modules live inside the installed package (`src/swarmy/agents/`) and are
loaded via `importlib.resources`.

Drop a module folder here (`<name>/AGENT.md` + optional `tools/`, `skills/`,
`guardrails.yaml`) and point `--agents-dir` (or the session config `agents_dirs`)
at it — see docs/development/architecture.md §8.
