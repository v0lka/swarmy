"""``ModuleLoader`` tests (roadmap T1.5.3, arch §8.3, spec §4.5).

Acceptance criteria under test: a module with valid AGENT.md/tools/guardrails.yaml
loads and its ``SubAgent`` dict carries exactly the arch §8.3 keys; each of the
five violation kinds (missing docstring, ``Any`` annotation, reserved prefix,
network import, declared-but-unregistered event type) produces its exact line
in the aggregated ``ModuleLoadError``; a problem in one module does not stop
collecting the problems of the others.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from swarmy.events.models import EVENT_TYPES
from swarmy.guardrails.pipeline import GuardrailMiddleware
from swarmy.modules import loader as loader_module
from swarmy.modules.loader import ModuleLoader, PlatformToolsetFactory
from swarmy.modules.registry import ModuleLoadError
from swarmy.tools.projector import ProjectorMiddleware

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

EXPECTED_SUBAGENT_KEYS = {
    "name",
    "description",
    "system_prompt",
    "model",
    "mode",
    "tools",
    "middleware",
    "interrupt_on",
    "skills",
    "response_format",
}

GOOD_TOOL = '''
def good_probe(target: str, depth: int = 1) -> str:
    """Probe the target text and return a short annotation.

    Args:
        target: text to annotate.
        depth: recursion limit for the probe.

    Returns:
        The annotated string ``probe:<target>:<depth>``.
    """
    return f"probe:{target}:{depth}"


good_probe.swarmy_risk_class = "verify"
'''

GOOD_GUARDRAILS = """
tool_classes:
  good_probe: verify
rules:
  - id: good-no-doom
    applies_to: [good_probe]
    condition:
      tool_in: [good_probe]
    action: block
    severity: low
    message: "The probe must not be used on production assets."
"""


def _make_module(
    root: Path,
    name: str,
    *,
    manifest_name: str | None = None,
    frontmatter: str = "",
    tool_files: Mapping[str, str] | None = None,
    guardrails: str | None = None,
    skills: bool = False,
    result_py: str | None = None,
    event_models_py: str | None = None,
) -> Path:
    """Write one module directory (AGENT.md + optional attachments)."""
    module_dir = root / name
    module_dir.mkdir(parents=True)
    fm = f"name: {manifest_name if manifest_name is not None else name}\ndescription: Test module {name}."
    if frontmatter:
        fm = f"{fm}\n{frontmatter}"
    body = f"You are the {name} module."
    (module_dir / "AGENT.md").write_text(f"---\n{fm}\n---\n{body}\n", encoding="utf-8")
    tools_dir = module_dir / "tools"
    if tool_files or result_py or event_models_py:
        tools_dir.mkdir()
    for filename, code in (tool_files or {}).items():
        (tools_dir / filename).write_text(code, encoding="utf-8")
    if result_py is not None:
        (tools_dir / "result.py").write_text(result_py, encoding="utf-8")
    if event_models_py is not None:
        (tools_dir / "event_models.py").write_text(event_models_py, encoding="utf-8")
    if guardrails is not None:
        (module_dir / "guardrails.yaml").write_text(guardrails, encoding="utf-8")
    if skills:
        (module_dir / "skills").mkdir()
        (module_dir / "skills" / "SKILL.md").write_text(
            "---\nname: dummy-skill\ndescription: Probe skill folder.\n---\n",
            encoding="utf-8",
        )
    return module_dir


def _recording_factory() -> tuple[PlatformToolsetFactory, list[frozenset[str]]]:
    """Build a platform toolset factory recording the declarations it receives."""
    calls: list[frozenset[str]] = []

    def factory(module_name: str, declared_event_types: frozenset[str]) -> dict[str, Callable[..., str]]:
        calls.append(declared_event_types)

        async def memory_probe() -> str:
            """Platform probe standing in for the memory_*/emit_event set."""
            return f"platform for {module_name}"

        return {"memory_probe": memory_probe}

    return factory, calls


def _load_error_message(loader: ModuleLoader) -> str:
    """Run ``load()`` expecting the aggregated error; return its full text."""
    with pytest.raises(ModuleLoadError) as excinfo:
        loader.load()
    return str(excinfo.value)


def test_valid_module_loads_with_exact_subagent_keys(tmp_path: Path) -> None:
    """AC (T1.5.3): valid AGENT.md + tools/ + guardrails.yaml → arch §8.3 dict."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "good",
        tool_files={"probe.py": GOOD_TOOL},
        guardrails=GOOD_GUARDRAILS,
    )
    factory, _calls = _recording_factory()
    registry = ModuleLoader(user_dirs=[root], platform_toolset_factory=factory, include_builtins=False).load()
    assert "good" in registry
    module = registry.get("good")
    # ``model`` is NotRequired (T3.1.3 wiring): the key is present only when
    # the manifest declares one — an absent key inherits the orchestrator's
    # model in the L0 SubAgent dict.
    assert set(module.subagent) == EXPECTED_SUBAGENT_KEYS - {"model"}
    assert module.subagent["name"] == "good"
    assert module.subagent["description"] == "Test module good."
    assert module.subagent["system_prompt"] == "You are the good module."
    assert module.subagent["mode"] == "isolated"
    tool_names = {getattr(fn, "__name__", "?") for fn in module.subagent["tools"]}  # type: ignore[union-attr]
    assert tool_names == {"memory_probe", "good_probe"}  # platform + module tools (arch §6.1)
    middleware = module.subagent["middleware"]
    assert isinstance(middleware, list)
    assert len(middleware) == 2
    assert isinstance(middleware[0], GuardrailMiddleware)  # pre-tool-call gate (arch §6.5)
    assert isinstance(middleware[1], ProjectorMiddleware)  # post-tool-call §6.8 (T2.3.2)
    assert module.subagent["interrupt_on"] == {"memory_probe": False, "good_probe": True}
    assert module.subagent["skills"] == []
    assert module.subagent["response_format"] is None
    assert module.source == f"module:{root / 'good'}"


def test_five_violation_kinds_produce_exact_lines(tmp_path: Path) -> None:
    """AC (T1.5.3): each violation kind yields its exact aggregated-error line."""
    root = tmp_path / "agents"
    _make_module(root, "no_doc", tool_files={"naked.py": "def naked(x: int) -> int:\n    return x\n"})
    _make_module(
        root,
        "any_ann",
        tool_files={
            "loose.py": (
                "from typing import Any\n\n\ndef loose(x: Any) -> int:\n"
                '    """Loose tool."""\n    return 1\n'
            )
        },
    )
    _make_module(
        root,
        "prefix",
        tool_files={
            "evil.py": (
                "def memory_evil(x: int) -> int:\n"
                '    """Evil tool with a reserved prefix."""\n    return x\n'
            )
        },
    )
    _make_module(
        root,
        "netimport",
        tool_files={
            "dialer.py": "import socket\n\n\ndef dialer(host: str) -> str:\n"
            '    """Dialer tool that must not exist."""\n    return host\n'
        },
    )
    _make_module(root, "ghostevent", frontmatter="events:\n  - NeverRegistered")
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    # 1: missing docstring (arch §8.5)
    assert "tool 'naked' has no docstring" in message
    assert "the docstring is the LLM-facing description" in message
    # 2: Any annotation (spec §4.3)
    assert "tool 'loose': parameter 'x' uses Any" in message
    # 3: reserved prefix (arch §6.1)
    assert "uses the reserved platform prefix 'memory_' (arch §6.1, spec §4.3)" in message
    # 4: network import (arch §8.5)
    assert "imports 'socket': module tools must use the platform HTTP client" in message
    assert "socket/urllib/http.client are forbidden (arch §8.5)" in message
    # 5: declared but unregistered event type (arch §8.4)
    assert (
        "declared event type 'NeverRegistered' is not registered in the EventRegistry"
        in message
    )
    for name in ("no_doc", "any_ann", "prefix", "netimport", "ghostevent"):
        assert f"{root / name}:" in message  # every problem names its module directory


def test_one_bad_module_does_not_stop_collection(tmp_path: Path) -> None:
    """AC (T1.5.3): problems of ALL modules are collected into one report."""
    root = tmp_path / "agents"
    _make_module(root, "bad_a", tool_files={"naked.py": "def naked(x: int) -> int:\n    return x\n"})
    _make_module(
        root,
        "bad_b",
        tool_files={
            "loose.py": (
                "from typing import Any\n\n\ndef loose(x: Any) -> str:\n"
                '    """Loose tool."""\n    return "x"\n'
            )
        },
    )
    _make_module(
        root,
        "bad_c",
        tool_files={
            "sneaky.py": (
                "def event_sneaky(x: int) -> int:\n"
                '    """Sneaky tool with a reserved prefix."""\n    return x\n'
            )
        },
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert f"{root / 'bad_a'}: tool 'naked' has no docstring" in message
    assert f"{root / 'bad_b'}: tool 'loose': parameter 'x' uses Any" in message
    assert f"{root / 'bad_c'}: tool name 'event_sneaky' uses the reserved platform prefix" in message
    assert "module loading failed, 3 problem(s)" in message


def test_duplicate_user_module_names_are_a_problem(tmp_path: Path) -> None:
    """Two user modules claiming one name collide (fail-fast, no override)."""
    root = tmp_path / "agents"
    _make_module(root, "alpha")
    _make_module(root, "beta", manifest_name="alpha")
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert f"duplicate module name 'alpha' (already provided by {root / 'alpha'})" in message


def test_user_module_colliding_with_builtin_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AD-4: a user module overriding a built-in name is a load error."""
    builtin_root = tmp_path / "builtin"
    _make_module(builtin_root, "dup", frontmatter="")
    user_root = tmp_path / "user"
    _make_module(user_root, "dup", frontmatter="")
    monkeypatch.setattr(loader_module, "_builtin_module_dirs", lambda stack: [builtin_root / "dup"])
    message = _load_error_message(ModuleLoader(user_dirs=[user_root]))
    assert "collides with the built-in module at" in message
    assert "built-in modules cannot be overridden (AD-4)" in message


def test_guardrails_crosschecked_against_tool_registry(tmp_path: Path) -> None:
    """Rule ``applies_to``/``tool_classes`` names are checked against the toolset."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "crossed",
        tool_files={"probe.py": GOOD_TOOL},
        guardrails=(
            "tool_classes:\n"
            "  memory_probe: destructive\n"  # platform tool: not a tool of THIS module
            "rules:\n"
            "  - id: crossed-unknown\n"
            "    applies_to: [no_such_tool]\n"
            "    condition:\n"
            "      tool_in: [no_such_tool]\n"
            "    action: block\n"
            "    severity: low\n"
            '    message: "Unknown tool rule."\n'
        ),
    )
    factory, _calls = _recording_factory()
    message = _load_error_message(
        ModuleLoader(user_dirs=[root], platform_toolset_factory=factory, include_builtins=False)
    )
    assert "rule 'crossed-unknown': applies_to names unknown tool 'no_such_tool'" in message
    assert "ToolRegistry cross-check, T1.4.2" in message
    assert "tool_classes declares 'memory_probe' which is not a tool of this module (AD-7)" in message


def test_invalid_guardrails_yaml_is_collected(tmp_path: Path) -> None:
    """A DSL-invalid guardrails.yaml contributes its problems to the report."""
    root = tmp_path / "agents"
    _make_module(root, "badyaml", guardrails="tool_classes:\n  probe: no_such_class\n")
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "unknown risk class 'no_such_class'" in message


def test_tool_classes_override_gates_by_profile(tmp_path: Path) -> None:
    """``tool_classes`` (AD-7) feeds the profile gates; paranoid spares passive."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "gated",
        frontmatter="interrupt_on:\n  memory_probe: true\n",
        tool_files={
            "heavy.py": (
                "def heavy_probe(x: int) -> int:\n"
                '    """Heavy tool marked destructive by the module config."""\n    return x\n'
            )
        },
        guardrails=(
            "tool_classes:\n  heavy_probe: destructive\n"
            "rules: []\n"
        ),
    )
    factory, _calls = _recording_factory()
    registry = ModuleLoader(
        include_builtins=False,
        user_dirs=[root],
        strictness="paranoid",
        platform_toolset_factory=factory,
    ).load()
    assert registry.get("gated").subagent["interrupt_on"] == {
        "memory_probe": True,  # manifest overlay merges on top of the profile (arch §7.2)
        "heavy_probe": True,  # destructive is gated by every profile
    }
    registry_yolo = ModuleLoader(
        include_builtins=False,
        user_dirs=[root],
        strictness="yolo",
        platform_toolset_factory=factory,
    ).load()
    assert registry_yolo.get("gated").subagent["interrupt_on"] == {
        "memory_probe": True,  # overlay again
        "heavy_probe": True,
    }


def test_response_format_imported_from_result_py(tmp_path: Path) -> None:
    """AD-3: the ``result`` class is imported and set as ``response_format``."""
    root = tmp_path / "agents"
    result_py = (
        "from pydantic import BaseModel\n\n\n"
        "class ProbeResult(BaseModel):\n"
        '    """Structured result of the probe tool."""\n\n'
        "    score: int\n    label: str\n"
    )
    _make_module(
        root,
        "shaped",
        frontmatter="result: shaped/tools/result.py:ProbeResult\n",
        tool_files={"probe.py": GOOD_TOOL},
        result_py=result_py,
    )
    factory, _calls = _recording_factory()
    registry = ModuleLoader(user_dirs=[root], platform_toolset_factory=factory, include_builtins=False).load()
    fmt = registry.get("shaped").subagent["response_format"]
    assert getattr(fmt, "__name__", None) == "ProbeResult"
    assert getattr(fmt, "model_fields", {}).keys() == {"score", "label"}  # type: ignore[union-attr]


def test_result_reference_failures_are_collected(tmp_path: Path) -> None:
    """A missing or non-pydantic result class is a load problem (AD-3)."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "missing_cls",
        frontmatter="result: missing_cls/tools/result.py:Nope\n",
        result_py="X = 1\n",
    )
    _make_module(
        root,
        "not_model",
        frontmatter="result: not_model/tools/result.py:NotModel\n",
        result_py="class NotModel:\n    pass\n",
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "result class 'Nope' is not found" in message
    assert "is not a pydantic BaseModel subclass (AD-3)" in message


def test_event_models_register_and_factory_receives_declarations(tmp_path: Path) -> None:
    """``tools/event_models.py`` feeds the EventRegistry; the factory sees the manifest."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "emitter",
        frontmatter="events:\n  - LoaderProbeEvent\n",
        event_models_py=(
            "from pydantic import BaseModel\n\n\n"
            "class LoaderProbeEvent(BaseModel):\n"
            '    """Payload of the loader probe event."""\n\n'
            "    detail: str\n"
        ),
    )
    factory, calls = _recording_factory()
    registry = ModuleLoader(user_dirs=[root], platform_toolset_factory=factory, include_builtins=False).load()
    assert "emitter" in registry
    assert calls == [frozenset({"LoaderProbeEvent"})]  # arch §8.4 → allowed_types wiring
    assert "LoaderProbeEvent" in EVENT_TYPES
    assert EVENT_TYPES["LoaderProbeEvent"].model_fields.keys() == {"detail"}


def test_event_model_collision_across_modules(tmp_path: Path) -> None:
    """Two modules claiming one event type collide loudly (arch §8.4)."""
    root = tmp_path / "agents"
    model_py = (
        "from pydantic import BaseModel\n\n\n"
        "class LoaderCollideEvent(BaseModel):\n"
        '    """Payload claimed by two modules."""\n\n'
        "    detail: str\n"
    )
    _make_module(root, "first", event_models_py=model_py)
    _make_module(root, "second", event_models_py=model_py)
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "event model 'LoaderCollideEvent'" in message
    assert "already registered" in message


def test_network_import_variants_are_all_rejected(tmp_path: Path) -> None:
    """socket, urllib (any submodule) and http.client are all forbidden (arch §8.5)."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "nets",
        tool_files={
            "a_socket.py": (
                "import socket\n\n\ndef via_socket(host: str) -> str:\n"
                '    """Direct socket tool."""\n    return host\n'
            ),
            "b_urllib.py": (
                "from urllib.request import urlopen\n\n\ndef via_urllib(url: str) -> str:\n"
                '    """urllib tool."""\n    return url\n'
            ),
            "c_httpclient.py": (
                "from http.client import HTTPConnection\n\n\ndef via_http(url: str) -> str:\n"
                '    """http.client tool."""\n    return url\n'
            ),
            "d_relative.py": (
                "from .helpers import thing\n\n\ndef via_relative(x: int) -> int:\n"
                '    """Relative import (not network, but standalone files cannot)."""\n'
                "    return x\n"
            ),
        },
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "imports 'socket'" in message
    assert "imports 'urllib.request'" in message
    assert "imports 'http.client'" in message


def test_broken_tool_file_is_reported(tmp_path: Path) -> None:
    """A tool file raising at import time contributes a problem, not a crash."""
    root = tmp_path / "agents"
    _make_module(root, "broken", tool_files={"boom.py": "raise RuntimeError('boom')\n"})
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "boom.py: file failed to import: RuntimeError: boom" in message


def test_annotation_gaps_and_nested_any(tmp_path: Path) -> None:
    """Unannotated params/returns, ``dict[str, Any]`` and nested ``Any`` are problems."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "typos",
        tool_files={
            "half.py": "def half(x):\n    return x\n",
            "no_return.py": "def no_return(x: int):\n    return x\n",
            "dictany.py": (
                "from typing import Any\n\n\ndef dictany(x: dict[str, Any]) -> int:\n"
                '    """Tool with a dict[str, Any] parameter."""\n    return 1\n'
            ),
            "listany.py": (
                "from typing import Any\n\n\ndef listany(x: list[Any]) -> int:\n"
                '    """Tool with a nested Any parameter."""\n    return 1\n'
            ),
        },
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "tool 'half': parameter 'x' is not annotated (full typing required, spec §4.3)" in message
    assert "tool 'half': return type is not annotated (spec §4.3)" in message
    assert "tool 'no_return': return type is not annotated" in message
    assert "tool 'dictany': parameter 'x' uses dict[str, Any]" in message
    assert "tool 'listany': parameter 'x' uses Any" in message


def test_skills_dir_is_attached_when_present(tmp_path: Path) -> None:
    """``skills=[<dir>/skills/]`` when the folder exists (arch §8.3)."""
    root = tmp_path / "agents"
    module_dir = _make_module(root, "skilled", skills=True)
    factory, _calls = _recording_factory()
    registry = ModuleLoader(user_dirs=[root], platform_toolset_factory=factory, include_builtins=False).load()
    assert registry.get("skilled").subagent["skills"] == [str(module_dir / "skills")]


def test_bare_module_without_tools_loads_with_platform_toolset(tmp_path: Path) -> None:
    """``tools/`` is optional (arch §8.1); the platform toolset is still included."""
    root = tmp_path / "agents"
    _make_module(root, "bare")
    loader = ModuleLoader(user_dirs=[root], include_builtins=False)  # default factory: empty platform toolset
    registry = loader.load()
    module = registry.get("bare")
    assert module.subagent["tools"] == []
    assert "bare" in registry


def test_missing_agents_root_and_empty_loader(tmp_path: Path) -> None:
    """A missing user root is a load problem; an empty loader loads nothing."""
    message = _load_error_message(ModuleLoader(user_dirs=[tmp_path / "nope"], include_builtins=False))
    assert f"agents root directory does not exist: {tmp_path / 'nope'}" in message
    registry = ModuleLoader(include_builtins=False).load()
    assert len(registry) == 0
    assert registry.names() == ()
    assert registry.subagent_dicts() == []


def test_builtin_scan_edge_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Built-in scanning tolerates a missing package and a non-directory root."""
    from contextlib import ExitStack
    from types import SimpleNamespace

    def _raise(name: str) -> object:
        raise ModuleNotFoundError("no swarmy.agents")

    monkeypatch.setattr(loader_module.importlib.resources, "files", _raise)
    assert loader_module._builtin_module_dirs(ExitStack()) == []
    monkeypatch.setattr(
        loader_module.importlib.resources,
        "files",
        lambda name: SimpleNamespace(is_dir=lambda: False),
    )
    assert loader_module._builtin_module_dirs(ExitStack()) == []
