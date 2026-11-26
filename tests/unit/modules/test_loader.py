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

from swarmy.events.models import EVENT_TYPES, EventRegistry
from swarmy.guardrails.pipeline import GuardrailMiddleware
from swarmy.modules import loader as loader_module
from swarmy.modules.loader import ModuleLoader, PlatformToolsetFactory
from swarmy.modules.registry import ModuleLoadError
from swarmy.tools.projector import ProjectorMiddleware

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping
    from pathlib import Path


@pytest.fixture(autouse=True)
def _clean_event_taxonomy() -> Iterator[None]:
    """Restore the built-in-only taxonomy after each loader test (F-12).

    Loader tests register module event types in the process-global registry;
    the reset keeps every other suite's exact-taxonomy assertions honest no
    matter the collection order.
    """
    yield
    EventRegistry.reset()

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
    # 4: network import (arch §8.5, F-2 families)
    assert "imports 'socket': module tools must use the platform HTTP client" in message
    assert (
        "socket/urllib/http.client and the httpx/aiohttp/requests families "
        "are forbidden (arch §8.5)" in message
    )
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


def test_undeclared_module_tool_defaults_to_destructive(tmp_path: Path) -> None:
    """F-3 (SECURITY.md ASI02): an undeclared module tool defaults to the most gated class."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "forgetful",
        tool_files={
            "oops.py": (
                "def oops_probe(x: int) -> int:\n"
                '    """Forgot its swarmy_risk_class declaration."""\n    return x\n'
            )
        },
    )
    factory, _calls = _recording_factory()
    for profile in ("paranoid", "normal", "yolo"):
        registry = ModuleLoader(
            include_builtins=False,
            user_dirs=[root],
            strictness=profile,  # type: ignore[arg-type]
            platform_toolset_factory=factory,
        ).load()
        assert registry.get("forgetful").subagent["interrupt_on"] == {
            "memory_probe": False,  # the platform tool declares passive explicitly
            "oops_probe": True,  # undeclared → destructive → gated by every profile
        }, profile


def test_manifest_cannot_remove_operator_gate(tmp_path: Path) -> None:
    """F-4 (ASI02/ASI09): a manifest ``False`` for a profile-gated tool fails the load."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "selfungating",
        frontmatter="interrupt_on:\n  self_probe: false\n",
        guardrails="tool_classes:\n  self_probe: destructive\nrules: []\n",
        tool_files={
            "self.py": (
                "def self_probe(x: int) -> int:\n"
                '    """Destructive tool its manifest tries to un-gate."""\n    return x\n'
            )
        },
    )
    factory, _calls = _recording_factory()
    message = _load_error_message(
        ModuleLoader(
            include_builtins=False,
            user_dirs=[root],
            strictness="paranoid",
            platform_toolset_factory=factory,
        )
    )
    assert "removes the operator gate for 'self_probe'" in message


def test_manifest_cannot_ungate_destructive_under_yolo(tmp_path: Path) -> None:
    """F-4: destructive is gated even under yolo — the manifest False still fails."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "selfungating",
        frontmatter="interrupt_on:\n  self_probe: false\n",
        guardrails="tool_classes:\n  self_probe: destructive\nrules: []\n",
        tool_files={
            "self.py": (
                "def self_probe(x: int) -> int:\n"
                '    """Destructive tool its manifest tries to un-gate."""\n    return x\n'
            )
        },
    )
    factory, _calls = _recording_factory()
    message = _load_error_message(
        ModuleLoader(
            include_builtins=False,
            user_dirs=[root],
            strictness="yolo",
            platform_toolset_factory=factory,
        )
    )
    assert "removes the operator gate for 'self_probe'" in message


def test_manifest_gate_for_unknown_tool_fails(tmp_path: Path) -> None:
    """F-4: an interrupt_on entry naming a tool outside the toolset fails the load."""
    root = tmp_path / "agents"
    _make_module(root, "ghost", frontmatter="interrupt_on:\n  ghost_probe: true\n")
    factory, _calls = _recording_factory()
    message = _load_error_message(
        ModuleLoader(
            include_builtins=False,
            user_dirs=[root],
            platform_toolset_factory=factory,
        )
    )
    assert "not a tool of this module's toolset" in message


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


# ---------------------------------------------------------------------------
# F-2: extended forbidden-import / call-shape scan.
# ---------------------------------------------------------------------------


def test_http_client_family_imports_are_rejected(tmp_path: Path) -> None:
    """F-2: httpx/aiohttp/requests are raw-network escapes and are forbidden."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "httpfam",
        tool_files={
            "a_httpx.py": (
                "import httpx\n\n\ndef via_httpx(url: str) -> str:\n"
                '    """httpx tool that must not load."""\n    return url\n'
            ),
            "b_aiohttp.py": (
                "import aiohttp\n\n\ndef via_aiohttp(url: str) -> str:\n"
                '    """aiohttp tool."""\n    return url\n'
            ),
            "c_requests.py": (
                "import requests\n\n\ndef via_requests(url: str) -> str:\n"
                '    """requests tool."""\n    return url\n'
            ),
        },
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "imports 'httpx'" in message
    assert "imports 'aiohttp'" in message
    assert "imports 'requests'" in message


def test_subprocess_import_and_os_spawn_usage_are_rejected(tmp_path: Path) -> None:
    """F-2/ASI05: subprocess import, os.system/os.popen uses are problems; bare os is legal."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "spawn",
        tool_files={
            "a_sub.py": (
                "import subprocess\n\n\ndef via_sub(cmd: str) -> str:\n"
                '    """subprocess tool."""\n    return cmd\n'
            ),
            "b_from_os.py": (
                "from os import system\n\n\ndef via_from_os(cmd: str) -> str:\n"
                '    """from-os tool."""\n    return cmd\n'
            ),
            "c_os_system.py": (
                "import os\n\n\ndef via_os_system(cmd: str) -> str:\n"
                '    """os.system tool."""\n    return os.system(cmd)  # noqa: S605 - test fixture\n'
            ),
            "d_os_popen.py": (
                "import os\n\n\ndef via_os_popen(cmd: str) -> str:\n"
                '    """os.popen tool."""\n    return os.popen(cmd).read()  # noqa: S607 - test fixture\n'
            ),
        },
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "imports 'subprocess'" in message
    assert "SECURITY.md ASI05" in message
    assert "imports os.system from os" in message
    assert "calls os.system()" in message
    assert "calls os.popen()" in message


def test_bare_os_without_spawn_is_legal(tmp_path: Path) -> None:
    """F-2: bare ``os`` import with non-spawn use loads clean (no bare-os ban)."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "osok",
        tool_files={
            "osuser.py": (
                "import os\n\n\ndef osuser(name: str) -> str:\n"
                '    """Join a path under the current working directory."""\n'
                "    return os.path.join(os.getcwd(), name)\n"
            )
        },
    )
    registry = ModuleLoader(user_dirs=[root], include_builtins=False).load()
    assert "osok" in registry


def test_asyncio_raw_streams_are_rejected(tmp_path: Path) -> None:
    """F-2: asyncio.open_connection/start_server bypass the platform client."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "rawsock",
        tool_files={
            "a_open_conn.py": (
                "import asyncio\n\n\nasync def via_open_conn(host: str) -> str:\n"
                '    """Raw stream tool."""\n'
                "    reader, writer = await asyncio.open_connection(host, 80)\n"
                "    writer.close()\n"
                "    return host\n"
            ),
            "b_from_asyncio.py": (
                "from asyncio import start_server\n\n\n"
                "async def via_start_server(host: str) -> str:\n"
                '    """Raw server tool."""\n'
                "    return host\n"
            ),
        },
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "calls asyncio.open_connection()" in message
    assert "imports asyncio.start_server" in message


def test_skill_scripts_get_the_same_static_scan(tmp_path: Path) -> None:
    """F-2 (option b): skills/**/*.py scripts are scanned like tools."""
    root = tmp_path / "agents"
    module_dir = _make_module(root, "skilled_bad")
    scripts_dir = module_dir / "skills" / "helper" / "scripts"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "helper.py").write_text(
        "import httpx\n\n\ndef grab(url: str) -> str:\n"
        '    """Skill helper that must be rejected."""\n    return url\n',
        encoding="utf-8",
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "helper.py imports 'httpx'" in message


def test_skill_scripts_syntax_and_non_python_are_handled(tmp_path: Path) -> None:
    """Broken skill scripts are problems; non-Python scripts stay outside the AST scan."""
    root = tmp_path / "agents"
    module_dir = _make_module(root, "skilled_edge")
    scripts_dir = module_dir / "skills" / "s" / "scripts"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (scripts_dir / "run.sh").write_text("import httpx\n", encoding="utf-8")
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "broken.py: invalid syntax" in message
    assert "run.sh" not in message  # non-Python scripts are a vetting matter, not AST


# ---------------------------------------------------------------------------
# #57: non-UTF-8 module files aggregate instead of crashing.
# ---------------------------------------------------------------------------


def test_non_utf8_module_files_aggregate_into_the_report(tmp_path: Path) -> None:
    """#57: bad AGENT.md + bad guardrails.yaml + a later module all report."""
    root = tmp_path / "agents"
    bad_agent = root / "bad_agent"
    bad_agent.mkdir(parents=True)
    (bad_agent / "AGENT.md").write_bytes(
        b"---\nname: badagent\ndescription: \xf2\xe5\xf1\xf2\n---\nBody.\n"
    )
    bad_guardrails = _make_module(root, "bad_guardrails", guardrails="rules: []\n")
    (bad_guardrails / "guardrails.yaml").write_bytes(b"rules: []\n\xf2\xee\xec\n")
    later = _make_module(
        root,
        "later",
        tool_files={"naked.py": "def naked(x: int) -> int:\n    return x\n"},
    )
    with pytest.raises(ModuleLoadError) as excinfo:
        ModuleLoader(user_dirs=[root], include_builtins=False).load()
    message = str(excinfo.value)
    assert "not valid UTF-8" in message
    assert str(bad_agent / "AGENT.md") in message
    assert str(bad_guardrails / "guardrails.yaml") in message
    # the module AFTER the broken ones still had its problems collected (§4.5)
    assert f"{later}: tool 'naked' has no docstring" in message


def test_non_utf8_tool_file_is_a_collected_problem(tmp_path: Path) -> None:
    """#57: a non-UTF-8 tools/*.py file joins the report, no raw ValueError."""
    root = tmp_path / "agents"
    _make_module(root, "badtool")
    (root / "badtool" / "tools").mkdir()
    (root / "badtool" / "tools" / "cp1251.py").write_bytes(b"\xf2\xee\xec\n")
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    # The import (which reads the file first) fails before the AST read can:
    # the aggregate report still names the file — no raw UnicodeDecodeError
    # escapes (the #57 contract; the tolerant AST read is belt-and-braces).
    assert "cp1251.py" in message
    assert "file failed to import" in message


# ---------------------------------------------------------------------------
# #44: an aborted load writes nothing into the ToolRegistry.
# ---------------------------------------------------------------------------


def test_failed_load_leaves_the_tool_registry_untouched(tmp_path: Path) -> None:
    """#44 (option a): registry writes flush only after ALL modules load clean."""
    root = tmp_path / "agents"
    _make_module(root, "good", tool_files={"probe.py": GOOD_TOOL})
    _make_module(root, "bad", tool_files={"naked.py": "def naked(x: int) -> int:\n    return x\n"})
    factory, _calls = _recording_factory()
    tool_registry = loader_module.ToolRegistry()
    with pytest.raises(ModuleLoadError):
        ModuleLoader(
            user_dirs=[root],
            platform_toolset_factory=factory,
            tool_registry=tool_registry,
            include_builtins=False,
        ).load()
    assert len(tool_registry) == 0  # nothing registered on the abort path
    # Fix the broken module (distinct tool name; the retry registers atomically).
    (root / "bad" / "tools" / "naked.py").write_text(
        GOOD_TOOL.replace("good_probe", "fixed_probe"), encoding="utf-8"
    )
    ModuleLoader(
        user_dirs=[root],
        platform_toolset_factory=factory,
        tool_registry=tool_registry,
        include_builtins=False,
    ).load()
    assert {"memory_probe", "good_probe", "fixed_probe"} <= set(tool_registry.names())


def test_flush_time_collisions_are_aggregated_with_sources(tmp_path: Path) -> None:
    """Two modules claiming one tool name collide at flush with both sources."""
    root = tmp_path / "agents"
    _make_module(root, "first", tool_files={"probe.py": GOOD_TOOL})
    _make_module(
        root,
        "second",
        tool_files={"clash.py": GOOD_TOOL},  # same tool name as module "first"
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "duplicate tool name 'good_probe'" in message
    assert f"{root / 'second'}:" in message


# ---------------------------------------------------------------------------
# #35 ↔ F-12: reset-per-load lifecycle of the EventRegistry.
# ---------------------------------------------------------------------------


_PROBE_EVENT_PY = (
    "from pydantic import BaseModel\n\n\n"
    "class ProbeStarted(BaseModel):\n"
    '    """Payload of the probe started event."""\n\n'
    "    detail: str\n"
)

_PROBE_EVENT_PY_V2 = (
    "from pydantic import BaseModel\n\n\n"
    "class ProbeStarted(BaseModel):\n"
    '    """Payload of the probe started event, schema v2."""\n\n'
    "    detail: str\n    score: int\n"
)


def test_two_consecutive_loads_with_colliding_event_types(tmp_path: Path) -> None:
    """#35↔F-12: the second load re-registers a fresh schema instead of colliding."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "prober",
        frontmatter="events:\n  - ProbeStarted\n",
        event_models_py=_PROBE_EVENT_PY,
    )
    factory, _calls = _recording_factory()
    ModuleLoader(
        user_dirs=[root], platform_toolset_factory=factory, include_builtins=False
    ).load()
    first_cls = EVENT_TYPES["ProbeStarted"]
    assert first_cls.model_fields.keys() == {"detail"}  # type: ignore[union-attr]
    # The module ships a new schema of the same event type between sessions.
    (root / "prober" / "tools" / "event_models.py").write_text(
        _PROBE_EVENT_PY_V2, encoding="utf-8"
    )
    second = ModuleLoader(
        user_dirs=[root], platform_toolset_factory=factory, include_builtins=False
    ).load()
    assert "prober" in second  # no "event type 'ProbeStarted' is already registered"
    assert EVENT_TYPES["ProbeStarted"] is not first_cls
    assert EVENT_TYPES["ProbeStarted"].model_fields.keys() == {"detail", "score"}  # type: ignore[union-attr]


def test_failed_load_then_retry_with_the_same_event_type(tmp_path: Path) -> None:
    """#35: types registered before a module's later failure do not poison the retry."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "halfbroken",
        frontmatter="events:\n  - ProbeStarted\n",
        event_models_py=_PROBE_EVENT_PY,
        tool_files={"naked.py": "def naked(x: int) -> int:\n    return x\n"},
    )
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "tool 'naked' has no docstring" in message
    # Retry after the fix: the ghost registration of the failed load is gone.
    (root / "halfbroken" / "tools" / "naked.py").write_text(GOOD_TOOL, encoding="utf-8")
    registry = ModuleLoader(user_dirs=[root], include_builtins=False).load()
    assert "halfbroken" in registry
    assert "ProbeStarted" in EVENT_TYPES


def test_loader_reset_keeps_builtin_taxonomy_intact(tmp_path: Path) -> None:
    """The reset at load start never drops the built-in types (arch §5.2)."""
    root = tmp_path / "agents"
    _make_module(
        root,
        "prober",
        frontmatter="events:\n  - ProbeStarted\n",
        event_models_py=_PROBE_EVENT_PY,
    )
    ModuleLoader(user_dirs=[root], include_builtins=False).load()
    assert "FindingCandidate" in EVENT_TYPES  # built-ins survive the reset+reload
    assert "ScopeChanged" in EVENT_TYPES


def test_flush_platform_failure_is_attributed_to_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flush-time platform batch collision fails the load, attributed to 'platform'."""
    root = tmp_path / "agents"
    _make_module(root, "plain", tool_files={"probe.py": GOOD_TOOL})
    factory, _calls = _recording_factory()
    tool_registry = loader_module.ToolRegistry()

    async def squatter() -> str:
        """Platform name squatter pre-registered by a broken earlier state."""
        return "x"

    tool_registry.register_many(
        [
            loader_module.ToolSpec(
                name="memory_probe",
                fn=squatter,
                owner=loader_module.PLATFORM_OWNER,  # stale platform registration
                source=loader_module.BUILTIN_SOURCE,
            )
        ]
    )
    message = _load_error_message(
        ModuleLoader(
            user_dirs=[root],
            platform_toolset_factory=factory,
            tool_registry=tool_registry,
            include_builtins=False,
        )
    )
    assert "platform: duplicate tool name 'memory_probe'" in message
    # The squatted entry was not silently replaced.
    assert tool_registry.entry("memory_probe").owner == loader_module.PLATFORM_OWNER


def test_non_utf8_skill_script_is_a_collected_problem(tmp_path: Path) -> None:
    """A non-UTF-8 skills/**/*.py script joins the report (#57 treatment)."""
    root = tmp_path / "agents"
    module_dir = _make_module(root, "skilled_cp1251")
    scripts_dir = module_dir / "skills" / "s" / "scripts"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "cp1251.py").write_bytes(b"x = '\xf2\xe5\xf1\xf2'\n")
    message = _load_error_message(ModuleLoader(user_dirs=[root], include_builtins=False))
    assert "cp1251.py" in message
    assert "not valid UTF-8" in message
