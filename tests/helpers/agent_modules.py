"""On-the-fly fixture agent modules for the headless M3 integration tests.

Every builder writes a complete module folder (``AGENT.md`` frontmatter +
typed tool file) into a directory handed to ``SessionConfig.agents_dirs`` —
the documented module contract (arch §8.1), following the ``dummy`` template.
"""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 - runtime: module folders are written here
from typing import Literal

RiskLevel = Literal["passive", "network-write", "verify", "destructive"]


def _module(name: str, description: str, prompt: str, tool_py: str) -> tuple[str, str]:
    """The AGENT.md and tools/body.py texts of one fixture module."""
    agent_md = f"""---
name: {name}
description: {description}
---

{prompt}
"""
    return agent_md, tool_py


def make_module(
    root: Path,
    name: str,
    *,
    description: str,
    prompt: str,
    risk: RiskLevel = "passive",
    tool_name: str | None = None,
) -> Path:
    """Write one fixture module with a single typed tool of ``risk`` class.

    The tool is a no-op formatter (no network, no side effects) — the risk
    class declaration alone drives the HITL gates under test. Modules that
    need real network use the injected platform ``http_*`` tools instead and
    may declare no tools at all.
    """
    tool_name = tool_name if tool_name is not None else f"{name}_probe"
    agent_md, tool_py = _module(
        name,
        description,
        prompt,
        f'"""Fixture tool of the ``{name}`` module."""\n\n'
        "from __future__ import annotations\n\n"
        "from swarmy.guardrails.models import RiskClass\n\n\n"
        f"def {tool_name}(message: str = \"go\") -> str:\n"
        "    \"\"\"Echo ``message`` back tagged with the module name (no I/O).\n\n"
        "    Args:\n"
        "        message: any short text to echo.\n\n"
        "    Returns:\n"
        f"        The string ``{name}: <message>``.\n"
        "    \"\"\"\n"
        f"    return \"{name}: \" + message\n\n\n"
        f"{tool_name}.swarmy_risk_class = RiskClass.{risk.upper().replace('-', '_')}"
        "  # AD-7 declaration\n",
    )
    module_dir = root / name
    (module_dir / "tools").mkdir(parents=True, exist_ok=True)
    (module_dir / "AGENT.md").write_text(agent_md, encoding="utf-8")
    (module_dir / "tools" / "body.py").write_text(tool_py, encoding="utf-8")
    return module_dir


def crawler_prompt(name: str) -> str:
    """System prompt for a crawl module; ``name`` doubles as the script marker."""
    return (
        f"You are {name}: you crawl the authorized target using the platform "
        "`http_get` tool and record what you find with `memory_add_note`. "
        "Never leave the scope the operator set."
    )


def verifier_prompt(name: str) -> str:
    """System prompt for a verifier module; ``name`` doubles as the script marker."""
    return (
        f"You are {name}: you verify stored findings with safe `http_get` "
        "probes, then record the outcome with `memory_save_finding` and "
        "`update_finding_status`. Never invent results."
    )
