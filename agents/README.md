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

## Adding a module

New modules live here by default: `agents/<module-name>/`, written to the
contract of `docs/development/architecture.md` §8 (the `create-swarmy-agent`
skill scaffolds one from a plain-language description). Every directory here
ships inside the wheel as `swarmy/agents/<module-name>`, so module names must
be unique: a module loaded from elsewhere (`--agents-dir` or the config
`agents_dirs`) whose name collides with one here is a load error without
override (AD-4). A directory kept outside this one is loaded the same way,
only through `--agents-dir` / `agents_dirs`.

See `docs/development/architecture.md` §8 for the module contract.
