"""DSL ``guardrails.yaml``: parse + validate module rules (arch §6.6, T1.4.2).

A module's ``guardrails.yaml`` is YAML conforming to
:class:`~swarmy.guardrails.models.ModuleGuardrails`. Loading is *fail-fast
with a complete report* (arch §4.5): every problem of the file is collected
into one :class:`GuardrailsDslError` — a truncated report would force the
module author through one fix per run, which is the failure mode §4.5
forbids.

Collected problems:

* YAML syntax errors and a non-mapping root;
* unknown top-level keys (only ``tool_classes``/``rules`` exist);
* per-rule validation errors (each rule validated independently so one bad
  rule cannot hide the problems of the others);
* regex predicates that do not compile (arch §6.6: every regex is compiled
  at validation time);
* rule ids that are not unique within the file;
* conditions without any predicate (a rule that would fire on every call);
* structural validation of tool names in ``applies_to``/``tool_classes``
  (lowercase snake_case identifiers). The cross-check against the
  ``ToolRegistry`` arrives with the module loader in P1.5.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Final

import yaml
from pydantic import ValidationError

from swarmy.guardrails.models import GuardrailRule, ModuleGuardrails, RiskClass

if TYPE_CHECKING:
    from pathlib import Path

#: Structural shape of a tool name in v0.1 (lowercase snake_case identifier).
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

#: The only top-level keys of a guardrails.yaml (arch §6.6).
_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset({"tool_classes", "rules"})

#: The regex-bearing predicates of :class:`RuleCondition`, with their names.
_REGEX_PREDICATES: Final[tuple[tuple[str, str], ...]] = (
    ("any_param_matches", "any_param_matches"),
    ("url_matches", "url_matches"),
    ("header_matches", "header_matches"),
)


class DslProblem:
    """One problem found while validating a guardrails.yaml file."""

    __slots__ = ("message", "source")

    def __init__(self, source: str, message: str) -> None:
        """Bind the file the problem belongs to and its description."""
        self.source = source
        self.message = message

    def __str__(self) -> str:
        """Render ``source: message`` (the fail-fast report line format)."""
        return f"{self.source}: {self.message}"


class GuardrailsDslError(Exception):
    """Raised when a guardrails.yaml has at least one problem (arch §4.5).

    Carries *all* problems of the file — the fail-fast report is rendered by
    ``str(exception)``.
    """

    def __init__(self, problems: Sequence[DslProblem]) -> None:
        """Build the error from the collected problems (never empty)."""
        lines = "\n".join(f"  - {problem}" for problem in problems)
        super().__init__(f"guardrails.yaml rejected, {len(problems)} problem(s):\n{lines}")
        self.problems: tuple[DslProblem, ...] = tuple(problems)


def load_module_guardrails(path: Path) -> ModuleGuardrails:
    """Load, parse and validate one ``guardrails.yaml`` file.

    Args:
        path: file to read (module directory's ``guardrails.yaml``).

    Returns:
        The validated module guardrails.

    Raises:
        GuardrailsDslError: with *all* problems of the file (arch §4.5).
        OSError: propagates if the file cannot be read.
    """
    return parse_module_guardrails(path.read_text(encoding="utf-8"), source=str(path))


def parse_module_guardrails(text: str, *, source: str = "<guardrails.yaml>") -> ModuleGuardrails:
    """Parse and validate YAML text into :class:`ModuleGuardrails`.

    Args:
        text: raw YAML text of a guardrails.yaml.
        source: file name used in problem messages (defaults to a marker).

    Returns:
        The validated module guardrails.

    Raises:
        GuardrailsDslError: with every problem found (never just the first).
    """
    problems: list[DslProblem] = []

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GuardrailsDslError([DslProblem(source, f"invalid YAML: {exc}")]) from exc

    if not isinstance(document, Mapping):
        raise GuardrailsDslError(
            [DslProblem(source, f"root must be a mapping, got {type(document).__name__}")]
        )

    for key in sorted(document):
        if key not in _TOP_LEVEL_KEYS:
            problems.append(
                DslProblem(source, f"unknown top-level key {key!r}; allowed: {sorted(_TOP_LEVEL_KEYS)}")
            )

    tool_classes = _parse_tool_classes(document.get("tool_classes"), source, problems)
    rules = _parse_rules(document.get("rules"), source, problems)
    _check_unique_ids(rules, source, problems)

    if problems:
        raise GuardrailsDslError(problems)
    return ModuleGuardrails(tool_classes=tool_classes, rules=rules)


def _parse_tool_classes(
    raw: object, source: str, problems: list[DslProblem]
) -> dict[str, RiskClass]:
    """Validate the ``tool_classes`` mapping; collect problems, never raise."""
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        problems.append(
            DslProblem(source, f"tool_classes must be a mapping, got {type(raw).__name__}")
        )
        return {}
    classes: dict[str, RiskClass] = {}
    for tool_name, raw_class in raw.items():
        tool_key = str(tool_name)
        if not _TOOL_NAME_RE.match(tool_key):
            problems.append(
                DslProblem(
                    source,
                    f"tool_classes key {tool_key!r} is not a valid tool name "
                    "(lowercase snake_case identifier)",
                )
            )
            continue
        try:
            classes[tool_key] = RiskClass(str(raw_class))
        except ValueError:
            allowed = [item.value for item in RiskClass]
            problems.append(
                DslProblem(
                    source,
                    f"tool_classes[{tool_key!r}]: unknown risk class {raw_class!r}; "
                    f"allowed: {allowed}",
                )
            )
    return classes


def _parse_rules(raw: object, source: str, problems: list[DslProblem]) -> list[GuardrailRule]:
    """Validate every rule independently; collect ALL problems (arch §4.5)."""
    if raw is None:
        return []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        problems.append(
            DslProblem(source, f"rules must be a list, got {type(raw).__name__}")
        )
        return []
    rules: list[GuardrailRule] = []
    for index, raw_rule in enumerate(raw):
        rule = _parse_one_rule(raw_rule, index, source, problems)
        if rule is not None:
            _compile_rule_regexes(rule, source, problems)
            _check_condition_not_empty(rule, source, problems)
            _check_applies_to_names(rule, source, problems)
            rules.append(rule)
    return rules


def _parse_one_rule(
    raw_rule: object, index: int, source: str, problems: list[DslProblem]
) -> GuardrailRule | None:
    """Validate one rule mapping; on failure collect every pydantic error."""
    where = f"rules[{index}]"
    if not isinstance(raw_rule, Mapping):
        problems.append(DslProblem(source, f"{where} must be a mapping"))
        return None
    rule_id = raw_rule.get("id", f"<missing id at {where}>")
    try:
        return GuardrailRule.model_validate(raw_rule)
    except ValidationError as exc:
        for error in exc.errors():
            loc = ".".join(str(part) for part in error["loc"]) or "<rule>"
            problems.append(
                DslProblem(source, f"{where} ({rule_id!r}) field {loc}: {error['msg']}")
            )
        return None


def _compile_rule_regexes(rule: GuardrailRule, source: str, problems: list[DslProblem]) -> None:
    """Compile every regex predicate now (arch §6.6: fail at validation)."""
    condition = rule.condition
    for field, label in _REGEX_PREDICATES:
        pattern = getattr(condition, field)
        if pattern is None:
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            problems.append(
                DslProblem(
                    source,
                    f"rule {rule.id!r}: {label} does not compile as a regex: {exc}",
                )
            )


def _check_condition_not_empty(rule: GuardrailRule, source: str, problems: list[DslProblem]) -> None:
    """Reject rules whose condition has no predicate at all."""
    condition = rule.condition
    predicates = (
        condition.any_param_matches,
        condition.url_matches,
        condition.header_matches,
        condition.body_size_above,
        condition.tool_in,
    )
    if all(value is None for value in predicates):
        problems.append(
            DslProblem(
                source,
                f"rule {rule.id!r}: condition must set at least one predicate "
                "(an empty condition would block every call)",
            )
        )


def _check_applies_to_names(rule: GuardrailRule, source: str, problems: list[DslProblem]) -> None:
    """Structural tool-name validation (ToolRegistry cross-check: P1.5)."""
    for name in rule.applies_to:
        if not _TOOL_NAME_RE.match(name):
            problems.append(
                DslProblem(
                    source,
                    f"rule {rule.id!r}: applies_to entry {name!r} is not a valid "
                    "tool name (lowercase snake_case identifier)",
                )
            )


def _check_unique_ids(rules: Sequence[GuardrailRule], source: str, problems: list[DslProblem]) -> None:
    """Rule ids must be unique within the file (arch §6.6)."""
    seen: dict[str, int] = {}
    for index, rule in enumerate(rules):
        first = seen.setdefault(rule.id, index)
        if first != index:
            problems.append(
                DslProblem(
                    source,
                    f"duplicate rule id {rule.id!r} (rules[{first}] and rules[{index}])",
                )
            )


__all__ = [
    "DslProblem",
    "GuardrailsDslError",
    "load_module_guardrails",
    "parse_module_guardrails",
]
