"""Manifest tests (roadmap T1.5.2): strict AGENT.md frontmatter parsing (arch §8.2).

Covers the T1.5.2 acceptance criteria: minimal manifest validity, full
frontmatter round-trip (model/mode/interrupt_on/events/guardrails/result),
precise errors for unknown fields and wrong types, missing-file and
missing-required-field error strings, AD-3 ``result`` shape recognition
without importing the class, and the body → system_prompt mapping.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from swarmy.modules.manifest import (
    AgentModuleManifest,
    ManifestError,
    ParsedAgentModule,
    parse_agent_module,
    parse_result_spec,
)

if TYPE_CHECKING:
    from pathlib import Path


def _write_agent_md(directory: Path, content: str) -> Path:
    """Write ``AGENT.md`` into ``directory`` and return its path."""
    path = directory / "AGENT.md"
    path.write_text(content, encoding="utf-8")
    return path


def _parse_failing(tmp_path: Path, content: str, *fragments: str) -> str:
    """Parse ``content`` expecting ``ManifestError``; return the message text."""
    path = _write_agent_md(tmp_path, content)
    with pytest.raises(ManifestError) as excinfo:
        parse_agent_module(path)
    message = str(excinfo.value)
    for fragment in fragments:
        assert fragment in message, f"expected {fragment!r} in error: {message!r}"
    return message


def test_minimal_manifest_is_valid(tmp_path: Path) -> None:
    """AC (T1.5.2): name+description frontmatter is valid; defaults per arch §8.2."""
    path = _write_agent_md(
        tmp_path,
        "---\n"
        "name: crawler\n"
        "description: Explores the target within scope.\n"
        "---\n"
        "You are the crawler agent.\n",
    )
    parsed = parse_agent_module(path)
    assert isinstance(parsed, ParsedAgentModule)
    assert parsed.source == path
    manifest = parsed.manifest
    assert manifest.name == "crawler"
    assert manifest.description == "Explores the target within scope."
    assert manifest.model is None
    assert manifest.mode == "isolated"
    assert manifest.interrupt_on == {}
    assert manifest.events == []
    assert manifest.guardrails == "./guardrails.yaml"
    assert manifest.result is None
    assert parsed.system_prompt == "You are the crawler agent."


def test_full_frontmatter_parses(tmp_path: Path) -> None:
    """AC (T1.5.2): every optional arch §8.2 field round-trips, incl. mode: fork."""
    path = _write_agent_md(
        tmp_path,
        "---\n"
        "name: xss-detector\n"
        "description: Detects reflected XSS in discovered endpoints.\n"
        "model: anthropic:claude-sonnet-4\n"
        "mode: fork\n"
        "interrupt_on:\n"
        "  http_fetch: true\n"
        "  browser_click: false\n"
        "events:\n"
        "  - FindingCreated\n"
        "  - EndpointDiscovered\n"
        "guardrails: security/guardrails.yaml\n"
        "result: xss-detector/tools/result.py:FindingResult\n"
        "---\n"
        "Detect XSS.\n",
    )
    parsed = parse_agent_module(path)
    manifest = parsed.manifest
    assert manifest.name == "xss-detector"
    assert manifest.description == "Detects reflected XSS in discovered endpoints."
    assert manifest.model == "anthropic:claude-sonnet-4"
    assert manifest.mode == "fork"
    assert manifest.interrupt_on == {"http_fetch": True, "browser_click": False}
    assert manifest.events == ["FindingCreated", "EndpointDiscovered"]
    assert manifest.guardrails == "security/guardrails.yaml"
    assert manifest.result == "xss-detector/tools/result.py:FindingResult"
    assert parsed.system_prompt == "Detect XSS."


def test_unknown_frontmatter_field_rejected(tmp_path: Path) -> None:
    """AC (T1.5.2): unknown fields are validation errors naming the field."""
    message = _parse_failing(
        tmp_path,
        "---\n"
        "name: crawler\n"
        "description: Explores the target.\n"
        "tools: []\n"  # tools/skills are never declared in frontmatter (spec §4.2)
        "---\n"
        "Prompt.\n",
        "\ntools\n",
        "Extra inputs are not permitted",
    )
    assert "invalid AGENT.md frontmatter" in message


@pytest.mark.parametrize(
    ("field_line", "field", "expected"),
    [
        ("name: 42", "name", "Input should be a valid string"),
        ("description: 42", "description", "Input should be a valid string"),
        ("model: 7", "model", "Input should be a valid string"),
        ("mode: chatty", "mode", "Input should be 'isolated' or 'fork'"),
        ("interrupt_on: [http_fetch]", "interrupt_on", "Input should be a valid dictionary"),
        ("events: recon", "events", "Input should be a valid list"),
        ("guardrails: 3", "guardrails", "Input should be a valid string"),
        ("result: tools/result.py:C", "result", "must have the form"),
    ],
)
def test_wrong_type_rejected_with_precise_message(
    tmp_path: Path, field_line: str, field: str, expected: str
) -> None:
    """AC (T1.5.2): type mismatches produce validation errors naming the field."""
    frontmatter = f"---\nname: crawler\ndescription: Explores.\n{field_line}\n---\nPrompt.\n"
    message = _parse_failing(tmp_path, frontmatter, f"\n{field}\n", expected)
    assert "invalid AGENT.md frontmatter" in message


def test_empty_description_rejected(tmp_path: Path) -> None:
    """Empty/whitespace-only required fields fail with a field-naming message."""
    message = _parse_failing(
        tmp_path,
        "---\nname: crawler\ndescription: '   '\n---\nPrompt.\n",
        "\ndescription\n",
        "field 'description' must be a non-empty string",
    )
    assert "invalid AGENT.md frontmatter" in message


def test_result_spec_parses_without_import() -> None:
    """AC (T1.5.2, AD-3): the result shape is recognized without importing the class."""
    spec = parse_result_spec("xss-detector/tools/result.py:FindingResult")
    assert spec.module_name == "xss-detector"
    assert spec.class_name == "FindingResult"
    manifest = AgentModuleManifest.model_validate(
        {
            "name": "xss-detector",
            "description": "Detects XSS.",
            "result": "xss-detector/tools/result.py:FindingResult",
        }
    )
    assert manifest.result == "xss-detector/tools/result.py:FindingResult"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "tools/result.py:FindingResult",
        "crawler/result.py:FindingResult",
        "crawler/tools/result.py",
        "crawler/tools/result.py:",
        "crawler/tools/result.py:FindingResult:extra",
        "crawler/tools/result.py:1Bad",
        "crawler/tools/other.py:FindingResult",
        "  crawler/tools/result.py:FindingResult",
    ],
)
def test_result_spec_rejects_malformed_shapes(value: str) -> None:
    """AD-3: anything but '<module>/tools/result.py:ClassName' is rejected."""
    with pytest.raises(ValueError, match="must have the form"):
        parse_result_spec(value)


def test_manifest_rejects_bad_result_field(tmp_path: Path) -> None:
    """A malformed result reference fails at manifest validation (fail-fast)."""
    message = _parse_failing(
        tmp_path,
        "---\n"
        "name: crawler\n"
        "description: Explores.\n"
        "result: crawler/result.py:FindingResult\n"
        "---\n"
        "Prompt.\n",
        "\nresult\n",
        "must have the form '<module>/tools/result.py:ClassName'",
    )
    assert "invalid AGENT.md frontmatter" in message


def test_body_becomes_system_prompt(tmp_path: Path) -> None:
    """AC (T1.5.2): everything below the frontmatter is the system prompt."""
    path = _write_agent_md(
        tmp_path,
        "---\n"
        "name: crawler\n"
        "description: Explores.\n"
        "---\n"
        "\n"
        "# Role\n"
        "\n"
        "You are the crawler.\n"
        "---\n"  # a fence inside the body must NOT terminate the frontmatter
        "More instructions.\n",
    )
    parsed = parse_agent_module(path)
    assert parsed.system_prompt == (
        "# Role\n\nYou are the crawler.\n---\nMore instructions."
    )


def test_empty_body_yields_empty_system_prompt(tmp_path: Path) -> None:
    """A module file with frontmatter only parses to an empty system prompt."""
    path = _write_agent_md(tmp_path, "---\nname: crawler\ndescription: Explores.\n---\n")
    parsed = parse_agent_module(path)
    assert parsed.system_prompt == ""


def test_missing_agent_md_file(tmp_path: Path) -> None:
    """AC (T1.5.2): a missing AGENT.md produces the exact not-found error string."""
    path = tmp_path / "AGENT.md"
    with pytest.raises(ManifestError) as excinfo:
        parse_agent_module(path)
    assert str(excinfo.value) == f"AGENT.md not found: {path}"


@pytest.mark.parametrize("missing_field", ["name", "description"])
def test_missing_required_field_names_the_field(
    tmp_path: Path, missing_field: str
) -> None:
    """AC (T1.5.2): missing name/description yields an error naming the field."""
    fields = {"name": "crawler", "description": "Explores."}
    del fields[missing_field]
    lines = "---\n" + "".join(f"{key}: {value}\n" for key, value in fields.items())
    message = _parse_failing(
        tmp_path, f"{lines}---\nPrompt.\n", f"\n{missing_field}\n", "Field required"
    )
    assert "invalid AGENT.md frontmatter" in message


def test_missing_frontmatter_fence(tmp_path: Path) -> None:
    """A file without a leading fence is a manifest error naming the file."""
    path = tmp_path / "AGENT.md"
    message = _parse_failing(tmp_path, "# Just a prompt, no frontmatter.\n", "'---'")
    assert str(path) in message


def test_unterminated_frontmatter(tmp_path: Path) -> None:
    """An opening fence without a closing one is a manifest error."""
    _parse_failing(
        tmp_path,
        "---\nname: crawler\ndescription: Explores.\n",
        "missing closing '---'",
    )


def test_malformed_yaml_frontmatter(tmp_path: Path) -> None:
    """Invalid YAML inside the fence is reported with the file name."""
    _parse_failing(
        tmp_path,
        '---\nname: "unterminated\ndescription: Explores.\n---\nPrompt.\n',
        "invalid YAML frontmatter",
    )


def test_non_mapping_frontmatter(tmp_path: Path) -> None:
    """Frontmatter that parses to a non-mapping is a precise manifest error."""
    _parse_failing(
        tmp_path,
        "---\n- just\n- a list\n---\nPrompt.\n",
        "frontmatter must be a YAML mapping, got list",
    )


def test_empty_frontmatter_reports_missing_fields(tmp_path: Path) -> None:
    """An empty frontmatter block behaves like missing name+description."""
    _parse_failing(
        tmp_path,
        "---\n---\nPrompt.\n",
        "\nname\n",
        "\ndescription\n",
        "Field required",
    )


def test_empty_file_reports_frontmatter_error(tmp_path: Path) -> None:
    """An empty AGENT.md reports the missing frontmatter fence."""
    _parse_failing(tmp_path, "", "'---' frontmatter fence")
