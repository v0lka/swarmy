"""Tests of the guardrails.yaml DSL (arch §6.6, spec §8.3, T1.4.2).

Fail-fast discipline (arch §4.5): the report carries ALL problems of a file,
not the first one. The canonical spec §8.3 example (``no-true-based-sqli``,
Russian message included) must parse untouched.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from swarmy.guardrails.dsl import (
    GuardrailsDslError,
    load_module_guardrails,
    parse_module_guardrails,
)
from swarmy.guardrails.models import RiskClass

if TYPE_CHECKING:
    from pathlib import Path

#: The spec §8.3 example, byte-for-byte (comments stripped, whitespace kept).
SPEC_SQLI_EXAMPLE = """\
rules:
  - id: no-true-based-sqli
    applies_to: ["http_get", "http_post"]        # имена инструментов
    condition:
      any_param_matches: "(?i)('\\\\s*(or|and)\\\\s*'.*'=|1\\\\s*=\\\\s*1|true\\\\s*=)"  # regex по параметрам
    action: block
    severity: high
    message: "TRUE-конструкции в SQLi-проверках запрещены: риск порчи данных цели"
"""

#: Expected parsed value of the spec's regex (YAML ``\\\\`` unescapes to ``\\``).
SPEC_SQLI_PATTERN = r"(?i)('\s*(or|and)\s*'.*'=|1\s*=\s*1|true\s*=)"

#: A file with four distinct problems (three required by the AC + duplicate id).
THREE_ERRORS_YAML = """\
tool_classes:
  probe_tool: risky
rules:
  - id: dup
    applies_to: ["http_get"]
    condition:
      any_param_matches: "(unclosed"
    action: block
    severity: high
    message: m
  - id: dup
    applies_to: ["http*get"]
    condition:
      tool_in: ["http_get"]
    action: block
    severity: high
    message: m
"""


def test_spec_8_3_example_parses_without_errors() -> None:
    """The canonical no-true-based-sqli example parses and compiles (AC)."""
    guardrails = parse_module_guardrails(SPEC_SQLI_EXAMPLE)
    assert guardrails.tool_classes == {}
    assert len(guardrails.rules) == 1
    rule = guardrails.rules[0]
    assert rule.id == "no-true-based-sqli"
    assert rule.applies_to == ["http_get", "http_post"]
    assert rule.action == "block"
    assert rule.severity == "high"
    assert rule.message == (
        "TRUE-конструкции в SQLi-проверках запрещены: риск порчи данных цели"
    )
    assert rule.condition.any_param_matches == SPEC_SQLI_PATTERN
    # The pattern is a working Python regex (arch §6.6: compiled at validation).
    compiled = re.compile(rule.condition.any_param_matches or "")
    assert compiled.search("1 OR 1=1 --")
    assert not compiled.search("regular query")


def test_full_file_with_tool_classes_round_trips(tmp_path: Path) -> None:
    """tool_classes + rules load through the file-level API."""
    (tmp_path / "guardrails.yaml").write_text(
        "tool_classes:\n"
        "  probe_tool: verify\n"
        "rules:\n"
        "  - id: guard-admin\n"
        "    applies_to: [\"http_get\"]\n"
        "    condition:\n"
        "      url_matches: \"/admin\"\n"
        "      header_matches: \"^internal$\"\n"
        "      body_size_above: 1024\n"
        "      tool_in: [\"http_get\", \"http_post\"]\n"
        "    action: block\n"
        "    severity: medium\n"
        "    message: admin probing needs care\n",
        encoding="utf-8",
    )
    guardrails = load_module_guardrails(tmp_path / "guardrails.yaml")
    assert guardrails.tool_classes == {"probe_tool": RiskClass.VERIFY}
    condition = guardrails.rules[0].condition
    assert condition.url_matches == "/admin"
    assert condition.header_matches == "^internal$"
    assert condition.body_size_above == 1024
    assert condition.tool_in == ["http_get", "http_post"]


def test_three_distinct_errors_yield_three_report_entries() -> None:
    """The fail-fast report collects every problem, not just the first (AC)."""
    with pytest.raises(GuardrailsDslError) as excinfo:
        parse_module_guardrails(THREE_ERRORS_YAML)
    report = str(excinfo.value)
    # The three AC problems are each present…
    assert "unknown risk class 'risky'" in report
    assert "does not compile as a regex" in report
    assert "is not a valid tool name" in report
    # …plus the duplicate-id problem, and every problem names the source.
    assert len(excinfo.value.problems) >= 3
    assert all(problem.source.startswith("<guardrails.yaml") for problem in excinfo.value.problems)


def test_invalid_regex_rejected_at_validation() -> None:
    """A non-compiling regex predicate is a validation-time error (AC)."""
    with pytest.raises(GuardrailsDslError) as excinfo:
        parse_module_guardrails(
            "rules:\n"
            "  - id: bad-regex\n"
            "    applies_to: [\"http_get\"]\n"
            "    condition:\n"
            "      url_matches: \"([a-\"\n"
            "    action: block\n"
            "    severity: low\n"
            "    message: m\n"
        )
    messages = [problem.message for problem in excinfo.value.problems]
    assert any("url_matches does not compile" in message for message in messages)


def test_duplicate_rule_ids_rejected() -> None:
    """Rule ids are unique within the file (arch §6.6)."""
    with pytest.raises(GuardrailsDslError) as excinfo:
        parse_module_guardrails(
            "rules:\n"
            "  - &rule\n"
            "    id: same\n"
            "    applies_to: [\"http_get\"]\n"
            "    condition: {tool_in: [\"http_get\"]}\n"
            "    action: block\n"
            "    severity: low\n"
            "    message: m\n"
            "  - *rule\n"
        )
    assert any("duplicate rule id 'same'" in p.message for p in excinfo.value.problems)


def test_condition_without_predicates_rejected() -> None:
    """An empty condition would fire on every call — rejected (arch §4.5)."""
    with pytest.raises(GuardrailsDslError) as excinfo:
        parse_module_guardrails(
            "rules:\n"
            "  - id: empty-condition\n"
            "    applies_to: [\"http_get\"]\n"
            "    condition: {}\n"
            "    action: block\n"
            "    severity: low\n"
            "    message: m\n"
        )
    assert any("at least one predicate" in p.message for p in excinfo.value.problems)


@pytest.mark.parametrize(
    ("yaml_text", "expected_fragment"),
    [
        (
            "tools: []\n",
            "unknown top-level key 'tools'",
        ),
        (
            "- just\n- a\n- list\n",
            "root must be a mapping, got list",
        ),
        (
            "rules: not-a-list\n",
            "rules must be a list",
        ),
        (
            "rules: [42]\n",
            "rules[0] must be a mapping",
        ),
        (
            "rules:\n  - id: broken\n    applies_to: ['http_get']\n    action: [oops\n",
            "invalid YAML",
        ),
        (
            "rules:\n"
            "  - id: bad-name\n"
            "    applies_to: [\"HTTP-GET\"]\n"
            "    condition: {tool_in: [\"http_get\"]}\n"
            "    action: block\n"
            "    severity: low\n"
            "    message: m\n",
            "applies_to entry 'HTTP-GET' is not a valid tool name",
        ),
        (
            "rules:\n"
            "  - id: bad-class-key\n"
            "    applies_to: [\"http_get\"]\n"
            "    condition: {tool_in: [\"http_get\"]}\n"
            "    action: block\n"
            "    severity: low\n"
            "    message: m\ntool_classes:\n  'Probe-Tool': verify\n",
            "tool_classes key 'Probe-Tool' is not a valid tool name",
        ),
    ],
    ids=[
        "unknown-top-key",
        "non-mapping-root",
        "rules-not-a-list",
        "rule-not-a-mapping",
        "yaml-syntax-error",
        "bad-applies-to-name",
        "bad-tool-classes-key",
    ],
)
def test_structural_negatives(yaml_text: str, expected_fragment: str) -> None:
    """Every structural defect surfaces as a named problem in the report."""
    with pytest.raises(GuardrailsDslError) as excinfo:
        parse_module_guardrails(yaml_text)
    assert any(expected_fragment in p.message for p in excinfo.value.problems)


def test_missing_file_raises_oserror(tmp_path: Path) -> None:
    """A missing file is an I/O error, not a DSL problem."""
    with pytest.raises(OSError, match="absent"):
        load_module_guardrails(tmp_path / "absent.yaml")


def test_tool_classes_only_file_is_valid() -> None:
    """A module may declare classes without rules (arch §6.6 defaults)."""
    guardrails = parse_module_guardrails("tool_classes:\n  probe_tool: destructive\n")
    assert guardrails.tool_classes == {"probe_tool": RiskClass.DESTRUCTIVE}
    assert guardrails.rules == []
