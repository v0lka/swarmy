# Built-in modules

This directory is the **source of truth for the built-in subagent modules**
(`crawler`, `xss-detector`) — the reference implementations of the module
contract (arch §8.7).

## Packaging

The repository keeps the modules here; the build maps this directory into the
wheel as `swarmy/agents`:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/swarmy"]
force-include = {"agents" = "swarmy/agents"}
```

`ModuleLoader` resolves the directory in either layout:

- installed package: `<site-packages>/swarmy/agents/`;
- editable / src-layout checkout: `<repo>/agents/`.

An empty or missing directory is a fail-fast session start error (`ModuleLoadError`),
so a broken installation never reaches the first LLM call.

## User modules

Do **not** place user modules here: this directory is package data, and a user
module name colliding with a built-in is a load error without override (AD-4).
Point `--agents-dir` (or the config `agents_dirs`) at a separate directory
instead, e.g. `my-agents/`.

See `docs/development/architecture.md` §8 for the module contract.
