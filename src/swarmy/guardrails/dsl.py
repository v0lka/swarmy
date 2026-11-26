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
* regex predicates beyond the scan-size discipline (review F-10): over the
  pattern-length cap, or with a repeated-shape the loop-safety analyzer
  cannot prove free of catastrophic backtracking (CWE-1333) — analyzed
  structurally on the ``re`` parse tree, with any analysis failure
  rejecting the pattern (fail closed);
* rule ids that are not unique within the file;
* conditions without any predicate (a rule that would fire on every call);
* structural validation of tool names in ``applies_to``/``tool_classes``
  (lowercase snake_case identifiers). The cross-check against the
  ``ToolRegistry`` arrives with the module loader in P1.5.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Final, TypeAlias, cast

import yaml
from pydantic import ValidationError

from swarmy.guardrails.models import GuardrailRule, ModuleGuardrails, RiskClass

if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

# The parse-tree opcodes live in CPython-internal ``re._constants`` and the
# parser in ``re._parser`` — resolved through ``importlib`` so the absence of
# type stubs cannot fail the type check. A renamed opcode surfaces at import
# time (AttributeError), long before any session starts.
_RE_PARSER: Final[ModuleType] = importlib.import_module("re._parser")
_RE_CONSTANTS: Final[ModuleType] = importlib.import_module("re._constants")


def _opcode(name: str) -> int:
    """One parse-tree opcode by name (an int constant in ``re._constants``)."""
    return cast("int", getattr(_RE_CONSTANTS, name))


ANY: Final[int] = _opcode("ANY")
ANY_ALL: Final[int] = _opcode("ANY_ALL")
ASSERT: Final[int] = _opcode("ASSERT")
ASSERT_NOT: Final[int] = _opcode("ASSERT_NOT")
AT: Final[int] = _opcode("AT")
ATOMIC_GROUP: Final[int] = _opcode("ATOMIC_GROUP")
BRANCH: Final[int] = _opcode("BRANCH")
CATEGORY: Final[int] = _opcode("CATEGORY")
IN: Final[int] = _opcode("IN")
LITERAL: Final[int] = _opcode("LITERAL")
LITERAL_IGNORE: Final[int] = _opcode("LITERAL_IGNORE")
LITERAL_LOC_IGNORE: Final[int] = _opcode("LITERAL_LOC_IGNORE")
LITERAL_UNI_IGNORE: Final[int] = _opcode("LITERAL_UNI_IGNORE")
MAXREPEAT: Final[int] = cast("int", _RE_CONSTANTS.MAXREPEAT)
MAX_REPEAT: Final[int] = _opcode("MAX_REPEAT")
MIN_REPEAT: Final[int] = _opcode("MIN_REPEAT")
NEGATE: Final[int] = _opcode("NEGATE")
NOT_LITERAL: Final[int] = _opcode("NOT_LITERAL")
NOT_LITERAL_IGNORE: Final[int] = _opcode("NOT_LITERAL_IGNORE")
NOT_LITERAL_LOC_IGNORE: Final[int] = _opcode("NOT_LITERAL_LOC_IGNORE")
NOT_LITERAL_UNI_IGNORE: Final[int] = _opcode("NOT_LITERAL_UNI_IGNORE")
POSSESSIVE_REPEAT: Final[int] = _opcode("POSSESSIVE_REPEAT")
RANGE: Final[int] = _opcode("RANGE")
SUBPATTERN: Final[int] = _opcode("SUBPATTERN")

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

#: Maximum length of one module-rule regex predicate (review F-10
#: scan-size discipline: oversized patterns are a validation problem).
_MAX_PATTERN_LENGTH: Final[int] = 512

# ---- Loop-safety analysis (review F-10, CWE-1333) --------------------------
#
# Catastrophic backtracking is a *structural* property of a pattern: it
# needs a repetition whose iterations can proceed in more than one way.
# String-shape heuristics miss the canonical forms — ``(a|aa)+$`` (the
# parser factors the common prefix into a nested branch) or
# ``(\w?\s?){5,}`` (variable-width tokens inside a loop) — so the check
# walks the same parse tree the ``re`` module itself builds. The opcodes
# come from ``re._constants`` (CPython-internal but stable across the
# supported 3.11-3.15 range); any construct the walk cannot classify
# rejects the pattern, and so does any parse-tree failure: the patterns
# run over untrusted argument trees on every tool call, so the safe
# verdict on doubt is rejection, never acceptance.
#
# Two rules, checked at every level of the tree:
#
# * *a loop's cross-iteration boundary must be forced*: the body must end
#   with a mandatory seam whose characters are provably disjoint from the
#   body's leading seam (the crawler's ``(?:/[^/?#]+){6,}`` — ``/`` then
#   a run that cannot contain ``/`` — is forced; ``(?:xa?)+`` and
#   ``(\w?\s?){5,}`` end their iteration optionally and are rejected).
#   Symmetrical fixed-width edges (``(?:ab)+``) are forced too; overlapping
#   or unprovable seams across variable edges (``(?:x+(?:y|x))+``) reject;
# * *at the top level* two adjacent variable-width repetitions are safe
#   only when their character sets are provably disjoint (``a+b+`` — the
#   boundary is forced by the disjoint runs); overlapping or unprovable
#   pairs (``a+a+``, ``\d+\w+``) are rejected, a fixed-width neighbour
#   keeps the continuation work linear and is always allowed.
#
# Alternations inside loops multiply the per-iteration choices and are
# rejected outright; atomic groups and possessive quantifiers are opaque
# (the engine never backtracks into them); assertions are zero-width but
# their subpatterns are walked (a catastrophic shape inside a lookahead is
# re-evaluated at every matched position).

#: Type of one ``re`` parse-tree node: an opcode and its (heterogeneous)
#: argument. Opcodes are named int constants; arguments are tuples or
#: lists whose shape depends on the opcode (guaranteed by ``re.compile``,
#: which has already succeeded when the analyzer runs).
_Node: TypeAlias = tuple[int, object]

#: View of one single-width atom: the exact admitted character set when
#: finite (``None`` otherwise), a membership predicate, and the category
#: kind for ``\d``/``\w``/``\s``-style atoms (``None`` when the atom is
#: not a plain category class).
_AtomView: TypeAlias = tuple[
    frozenset[str] | None,
    Callable[[str], bool | None],
    tuple[str, bool] | None,
]

#: Opcodes matching exactly one character (single-width atoms).
_SINGLE_CHAR_OPS: Final[frozenset[int]] = frozenset(
    {
        ANY,
        ANY_ALL,
        IN,
        LITERAL,
        LITERAL_IGNORE,
        LITERAL_LOC_IGNORE,
        LITERAL_UNI_IGNORE,
        NOT_LITERAL,
        NOT_LITERAL_IGNORE,
        NOT_LITERAL_LOC_IGNORE,
        NOT_LITERAL_UNI_IGNORE,
    }
)

#: Opcode of zero-width anchors (``^``, ``$``, ``\b``): never consumes,
#: transparent when locating the neighbours of a repetition.
_ANCHOR_OPS: Final[frozenset[int]] = frozenset({AT})

#: Zero-width assertions: consume nothing themselves, but their
#: subpatterns are still walked.
_ASSERT_OPS: Final[frozenset[int]] = frozenset({ASSERT, ASSERT_NOT})

#: Atomic constructs (atomic groups, possessive quantifiers): the engine
#: commits to their match and never backtracks into them, so their inner
#: quantifiers cannot multiply iteration split points — opaque to the
#: walk, though their seam atoms remain usable for pin proofs.
_ATOMIC_OPS: Final[frozenset[int]] = frozenset({ATOMIC_GROUP, POSSESSIVE_REPEAT})

#: Loop opcodes: one node shape, three greediness flavours.
_REPEAT_OPS: Final[frozenset[int]] = frozenset(
    {MAX_REPEAT, MIN_REPEAT, POSSESSIVE_REPEAT}
)

#: ASCII character sets of the ``\d``/``\w``/``\s`` categories. Membership
#: of a concrete ASCII character is decidable from these; non-ASCII
#: characters are decidable only for the unicode variants (via the
#: documented ``str`` predicate equivalents). Locale variants stay
#: unknown.
_ASCII_DIGITS: Final[frozenset[str]] = frozenset("0123456789")
_ASCII_WORD: Final[frozenset[str]] = frozenset(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
)
_ASCII_SPACE: Final[frozenset[str]] = frozenset(" \t\n\r\f\v")

#: Provable overlap of two category kinds (Python ``re`` unicode
#: semantics: ``\d`` = decimal digits, ``\w`` = word characters, ``\s`` =
#: whitespace, ``any`` = ``.``). ``\d`` is a subset of ``\w``; whitespace
#: intersects neither; ``.`` admits everything but the newline, hence
#: overlaps every category. Key: ``(kind, negated, kind, negated)``.
_CATEGORY_OVERLAP: Final[dict[tuple[str, bool, str, bool], bool]] = {
    ("any", False, "any", False): True,
    ("any", False, "d", False): True,
    ("any", False, "d", True): True,
    ("any", False, "w", False): True,
    ("any", False, "w", True): True,
    ("any", False, "s", False): True,
    ("any", False, "s", True): True,
    ("d", False, "any", False): True,
    ("d", True, "any", False): True,
    ("w", False, "any", False): True,
    ("w", True, "any", False): True,
    ("s", False, "any", False): True,
    ("s", True, "any", False): True,
    ("d", False, "d", False): True,
    ("w", False, "w", False): True,
    ("s", False, "s", False): True,
    ("d", True, "d", True): True,
    ("w", True, "w", True): True,
    ("s", True, "s", True): True,
    ("d", False, "w", False): True,
    ("w", False, "d", False): True,
    ("d", False, "w", True): False,
    ("w", False, "d", True): True,
    ("d", True, "w", False): True,
    ("d", True, "w", True): True,
    ("s", False, "d", False): False,
    ("d", False, "s", False): False,
    ("s", False, "d", True): True,
    ("d", False, "s", True): True,
    ("s", True, "d", False): True,
    ("d", True, "s", False): True,
    ("s", True, "d", True): True,
    ("s", False, "w", False): False,
    ("w", False, "s", False): False,
    ("s", False, "w", True): True,
    ("w", False, "s", True): True,
    ("s", True, "w", False): True,
    ("w", True, "s", False): True,
    ("s", True, "w", True): True,
}


def _catastrophe_reason(pattern: str) -> str | None:
    """Structural loop-safety verdict for one compiled-clean regex.

    Args:
        pattern: the regex source (already accepted by ``re.compile``).

    Returns:
        ``None`` when the pattern cannot backtrack catastrophically:
        every loop proceeds in at most one way per iteration. Otherwise
        the reason, including on any analysis failure — an unanalyzable
        pattern fails closed (review F-10).
    """
    try:
        parsed = _RE_PARSER.parse(pattern)
    except Exception:
        # The pattern already passed ``re.compile`` above, so a parse-tree
        # failure means the interpreter's internal tree API changed: the
        # safe verdict is rejection, never acceptance.
        return "the pattern could not be statically analyzed"
    return _sequence_problem(list(parsed), in_loop=False)


def _sequence_problem(sequence: list[_Node], *, in_loop: bool) -> str | None:
    """First loop-unsafety reason inside one parse-tree sequence, or ``None``.

    Args:
        sequence: the parse-tree nodes of one sequence (pattern top level,
            a group body, a branch alternative, a loop body, an assertion
            body).
        in_loop: the sequence is the body of a repetition — variable-width
            elements then need a provable seam pin, and unsupported
            constructs reject instead of being skipped.

    Returns:
        The reason the shape risks catastrophic backtracking, or ``None``.
    """
    for index, (op, av) in enumerate(sequence):
        if (
            not in_loop
            and _is_variable_width((op, av))
            and _overlapping_pair_after(sequence, index)
        ):
            return (
                "two adjacent variable-length quantifiers sharing "
                "characters: their split points multiply exponentially"
            )
        if op is BRANCH:
            if in_loop:
                return (
                    "an alternation inside a repeated group: each iteration "
                    "can take more than one branch, multiplying the split "
                    "points"
                )
            for alternative in _branch_alternatives(av):
                reason = _sequence_problem(alternative, in_loop=False)
                if reason is not None:
                    return reason
            continue
        if op in _REPEAT_OPS:
            if op == POSSESSIVE_REPEAT:
                continue  # atomic: the engine never backtracks into it
            _low, high, body = _repeat_args(av)
            is_loop = high == MAXREPEAT or high >= 2
            reason = _sequence_problem(body, in_loop=in_loop or is_loop)
            if reason is not None:
                return reason
            if is_loop:
                cross = _loop_cross_reason(body)
                if cross is not None:
                    return cross
            continue
        if op is SUBPATTERN:
            reason = _sequence_problem(_subpattern_body(av), in_loop=in_loop)
            if reason is not None:
                return reason
            continue
        if op in _ATOMIC_OPS:
            continue  # opaque: handled as a whole, never backtracked into
        if op in _ASSERT_OPS:
            reason = _sequence_problem(_assert_body(av), in_loop=in_loop)
            if reason is not None:
                return reason
            continue
        if op in _SINGLE_CHAR_OPS or op in _ANCHOR_OPS:
            continue
        if in_loop:
            return (
                "a construct inside a repeated group the analyzer cannot "
                f"prove safe ({_op_name(op)})"
            )
        # Top-level exotic constructs (conditionals, backreferences) carry
        # no loop amplification; the length cap bounds their scan.
    return None


def _loop_cross_reason(body: list[_Node]) -> str | None:
    r"""Whether one loop's cross-iteration boundary provably cannot slide.

    The iteration boundary is forced when the body ends with a *mandatory*
    seam (the iteration always consumes up to those characters) whose
    characters are provably disjoint from — or symmetrical fixed-width
    neighbours of — the body's leading seam. An optional tail (``(?:xa?)+``,
    ``(\w?\s?){5,}``) lets the boundary slide between iterations and
    multiplies the split points; so do overlapping or unprovable seams
    across variable-width edges (``(?:x+(?:y|x))+``).

    Args:
        body: the parse-tree nodes of one loop body.

    Returns:
        The rejection reason, or ``None`` when the boundary is forced.
    """
    if not body:
        return "a repeated group with an empty body"
    trailing = _edge_atoms(body, leading=False)
    leading = _edge_atoms(body, leading=True)
    if trailing is None or leading is None:
        return (
            "the characters at the edge of a repeated group cannot be "
            "statically proven"
        )
    trailing_atoms, trailing_mandatory, trailing_forced = trailing
    leading_atoms, _leading_mandatory, leading_forced = leading
    if trailing_forced or leading_forced:
        # An atomic edge is engine-committed: the match length at a given
        # position is deterministic, the boundary cannot slide.
        return None
    if not trailing_mandatory:
        return (
            "a repeated group whose iteration can end without consuming "
            "input: the boundary between iterations can slide"
        )
    disjoint = _atoms_disjoint(leading_atoms, trailing_atoms)
    if disjoint is True:
        return None
    if (
        disjoint is False
        and _fixed_width(body[-1]) is not None
        and _fixed_width(body[0]) is not None
    ):
        # Both edges are fixed-width: each iteration consumes exactly the
        # same shape, so the boundary sits after every body match.
        return None
    return (
        "the leading and trailing characters of a repeated group's "
        "iteration overlap (or are unprovable): the boundary between "
        "iterations can slide"
    )


def _edge_atoms(
    sequence: list[_Node], *, leading: bool
) -> tuple[list[_Node], bool, bool] | None:
    """The seam atoms at one edge of a sequence, with mandatory-ness.

    Zero-width elements (anchors, assertions) are transparent: the scan
    steps over them. Returns ``None`` when no consuming edge exists (an
    all-zero-width sequence) or the edge cannot be proven. The third
    element flags an *engine-committed* edge (atomic construct): the
    engine never backtracks into it, so the boundary next to it cannot
    slide regardless of the atom's width.
    """
    order: Sequence[_Node] = sequence if leading else list(reversed(sequence))
    for element in order:
        op = element[0]
        if op in _ANCHOR_OPS or op in _ASSERT_OPS:
            continue
        return _node_edge(element, leading=leading)
    return None


def _node_edge(
    node: _Node, *, leading: bool
) -> tuple[list[_Node], bool, bool] | None:
    r"""The seam atoms of one element, with mandatory-ness and commitment.

    A seam is mandatory when the element always consumes at least one
    character at that edge; an optional seam (``\s?``, ``a*``) lets an
    iteration boundary slide past it. Atomic constructs (``(?>…)``,
    ``a*+``) are flagged as committed: their match at a given position is
    deterministic because the engine never backtracks into them.
    """
    op, av = node
    if op in _SINGLE_CHAR_OPS:
        return [(op, av)], True, False
    if op == ATOMIC_GROUP:
        body = list(cast("list[_Node]", av))
        edge = _edge_atoms(body, leading=leading)
        if edge is None:
            return None
        return edge[0], edge[1], True
    if op == POSSESSIVE_REPEAT:
        low, _high, body = _repeat_args(av)
        edge = _edge_atoms(body, leading=leading)
        if edge is None:
            return None
        return edge[0], edge[1] and low >= 1, True
    if op in _REPEAT_OPS:
        low, _high, body = _repeat_args(av)
        edge = _edge_atoms(body, leading=leading)
        if edge is None:
            return None
        return edge[0], edge[1] and low >= 1, False
    if op is SUBPATTERN:
        return _edge_atoms(_subpattern_body(av), leading=leading)
    if op is BRANCH:
        atoms: list[_Node] = []
        mandatory = True
        forced = True
        for alternative in _branch_alternatives(av):
            edge = _edge_atoms(alternative, leading=leading)
            if edge is None:
                return None
            atoms.extend(edge[0])
            mandatory = mandatory and edge[1]
            forced = forced and edge[2]
        return atoms, mandatory, forced
    return None  # anchors, assertions and unknown opcodes: unprovable


def _fixed_width(node: _Node) -> int | None:
    """The exact match width of one element, ``None`` when it varies.

    Repetitions must be bounded with an equal count over fixed-width
    content; alternations must offer the same fixed width on every branch.
    """
    op, av = node
    if op in _SINGLE_CHAR_OPS:
        return 1
    if op == ATOMIC_GROUP:
        widths = [
            _fixed_width(element) for element in cast("list[_Node]", av)
        ]
        if any(width is None for width in widths):
            return None
        return sum(cast("list[int]", widths))
    if op in _REPEAT_OPS:
        low, high, body = _repeat_args(av)
        if low != high:
            return None
        inner = _fixed_width_of_sequence(body)
        if inner is None:
            return None
        return low * inner
    if op is SUBPATTERN:
        return _fixed_width_of_sequence(_subpattern_body(av))
    if op is BRANCH:
        widths = {_fixed_width_of_sequence(alternative) for alternative in _branch_alternatives(av)}
        if len(widths) != 1:
            return None
        return widths.pop()
    return None  # anchors and assertions are zero-width but never edges


def _fixed_width_of_sequence(sequence: list[_Node]) -> int | None:
    """The exact total width of one sequence, ``None`` when it varies."""
    total = 0
    for element in sequence:
        width = _fixed_width(element)
        if width is None:
            return None
        total += width
    return total


def _overlapping_pair_after(sequence: list[_Node], index: int) -> bool:
    """Whether the repeat at ``index`` forms an exponential pair to its right.

    Args:
        sequence: the enclosing top-level sequence.
        index: position of the variable-width repeat.

    Returns:
        ``True`` when the right neighbour is itself variable-width and the
        two provably overlap (or the overlap is unprovable — fail closed).
        A fixed neighbour keeps the continuation work linear: never a
        pair.
    """
    right = _right_neighbour(sequence, index)
    if right is None or not _is_variable_width(right):
        return False
    mine = _node_edge(sequence[index], leading=False)
    theirs = _node_edge(right, leading=True)
    if mine is None or theirs is None:
        return True  # unprovable: fail closed
    if mine[2] or theirs[2]:
        return False  # engine-committed edge: deterministic match length
    return _atoms_disjoint(mine[0], theirs[0]) is not True


def _right_neighbour(sequence: list[_Node], index: int) -> _Node | None:
    """The nearest non-anchor, non-assertion element right of ``index``."""
    for position in range(index + 1, len(sequence)):
        op = sequence[position][0]
        if op in _ANCHOR_OPS or op in _ASSERT_OPS:
            continue
        return sequence[position]
    return None


def _is_variable_width(node: _Node) -> bool:
    """Whether one element can match different lengths.

    Recursively resolved: a bounded loop over variable content (or a group
    or branch containing a variable repetition anywhere) is still
    variable-width; possessive quantifiers and atomic groups are committed
    (one match per position); assertions are zero-width.
    """
    op, av = node
    if op in _ATOMIC_OPS or op in _ASSERT_OPS or op in _ANCHOR_OPS:
        return False
    if op in _REPEAT_OPS:
        low, high, body = _repeat_args(av)
        return low != high or any(_is_variable_width(element) for element in body)
    if op is SUBPATTERN:
        return any(_is_variable_width(element) for element in _subpattern_body(av))
    if op is BRANCH:
        return any(
            _is_variable_width(element)
            for alternative in _branch_alternatives(av)
            for element in alternative
        )
    return False


def _atoms_disjoint(left: list[_Node], right: list[_Node]) -> bool | None:
    """Whether two seam-atom sets provably share no character.

    Args:
        left: seam atoms of one side.
        right: seam atoms of the other side.

    Returns:
        ``True`` (provably disjoint), ``False`` (a common character is
        proven) or ``None`` (unknown — callers fail closed).
    """
    any_unknown = False
    for left_node in left:
        for right_node in right:
            overlap = _atom_overlap(left_node, right_node)
            if overlap is True:
                return False  # a common character is proven
            if overlap is None:
                any_unknown = True
    return None if any_unknown else True


def _atom_overlap(left: _Node, right: _Node) -> bool | None:
    """Whether two single-width atoms can match a common character.

    Returns ``False`` only when disjointness is *proven*; ``True`` on a
    proven common character and ``None`` on doubt (fail closed).
    """
    left_view = _atom_view(left[0], left[1])
    right_view = _atom_view(right[0], right[1])
    if left == right:
        return True  # an atom always overlaps itself (it admits ≥ 1 char)
    if left_view is None or right_view is None:
        return None
    left_set, left_admits, left_kind = left_view
    right_set, right_admits, right_kind = right_view
    if left_set is not None and right_set is not None:
        return not left_set.isdisjoint(right_set)
    if left_set is not None:
        return _set_overlaps_predicate(left_set, right_admits)
    if right_set is not None:
        return _set_overlaps_predicate(right_set, left_admits)
    return _category_kinds_overlap(left_kind, right_kind)


def _set_overlaps_predicate(
    chars: frozenset[str], admits: Callable[[str], bool | None]
) -> bool | None:
    """Whether a concrete character set shares a character a predicate admits."""
    for char in chars:
        verdict = admits(char)
        if verdict is None:
            return None
        if verdict:
            return True
    return False


def _category_kinds_overlap(
    left: tuple[str, bool] | None, right: tuple[str, bool] | None
) -> bool | None:
    r"""Provable overlap of two opaque atoms via their category kinds.

    Both atoms must carry a kind (``\d``/``\w``/``\s`` class or ``.``);
    anything else (mixed class contents, exotic constructs) stays unknown.
    """
    if left is None or right is None:
        return None
    return _CATEGORY_OVERLAP.get((*left, *right))


def _atom_view(op: int, av: object) -> _AtomView | None:
    """The concrete set, predicate and category kind of one atom.

    Args:
        op: the parse-tree opcode.
        av: the opcode argument.

    Returns:
        ``(concrete_set_or_None, admits(char), category_kind_or_None)``,
        or ``None`` for atoms whose membership is not decidable at all
        (locale-dependent constructs, unknown opcodes).
    """
    if op == ANY:
        return None, _admits_any, ("any", False)
    if op == ANY_ALL:
        return None, _admits_everything, ("any", False)
    if op == IN:
        return _class_view(av)
    if op == LITERAL:
        char = chr(cast("int", av))
        return frozenset({char}), _admits_char(char), None
    if op in (LITERAL_IGNORE, LITERAL_UNI_IGNORE):
        char = chr(cast("int", av))
        cases = frozenset({char, char.swapcase()})
        return cases, cases.__contains__, None
    if op in (NOT_LITERAL, NOT_LITERAL_IGNORE, NOT_LITERAL_UNI_IGNORE):
        char = chr(cast("int", av))
        excluded = frozenset({char, char.swapcase()})
        return None, _admits_not_in(excluded), None
    return None  # locale-dependent literals and unknown opcodes


def _admits_any(candidate: str) -> bool | None:
    """``.`` membership: everything but the newline."""
    return candidate != "\n"


def _admits_everything(_candidate: str) -> bool | None:
    """DOTALL ``.`` membership: everything."""
    return True


def _admits_char(char: str) -> Callable[[str], bool | None]:
    """Membership predicate of a single literal character."""
    return lambda candidate: candidate == char


def _admits_not_in(excluded: frozenset[str]) -> Callable[[str], bool | None]:
    """Membership predicate of a negated literal (its two ignore-cases)."""

    def admits(candidate: str) -> bool | None:
        return candidate not in excluded

    return admits


def _class_view(av: object) -> _AtomView:
    """Concrete set, predicate and category kind of one ``IN`` class atom."""
    items = list(cast("list[_Node]", av))
    negated = bool(items) and items[0][0] == NEGATE
    if negated:
        items = items[1:]

    def admits(candidate: str) -> bool | None:
        verdict = _class_admits(items, candidate)
        if verdict is None:
            return None
        return not verdict if negated else verdict

    kind = _class_category_kind(items, negated)
    concrete = None if negated else _concrete_class_set(items)
    return concrete, admits, kind


_CATEGORY_KINDS: Final[dict[str, str]] = {"DIGIT": "d", "WORD": "w", "SPACE": "s"}


def _class_category_kind(items: list[_Node], negated: bool) -> tuple[str, bool] | None:
    r"""The category kind of a class that is exactly one category item.

    ``\d`` → ``("d", False)``, ``\W`` → ``("w", True)``; mixed classes
    (``[\w-]``) and plain classes carry no kind — their overlap proofs
    fall back to the membership predicate.
    """
    if len(items) != 1 or items[0][0] not in _CATEGORY_ITEM_OPS:
        return None
    name = getattr(items[0][1], "name", "")
    if "LOC" in name:
        return None
    base = name.removeprefix("CATEGORY_UNI_").removeprefix("CATEGORY_")
    not_item = base.startswith("NOT_")
    kind = _CATEGORY_KINDS.get(base.removeprefix("NOT_"))
    if kind is None:
        return None
    # The item-level NOT (``[\W]``) and the class-level NEGATE (``[^\w]``)
    # both flip the admitted complement.
    return kind, negated != not_item


_CATEGORY_ITEM_OPS: Final[frozenset[int]] = frozenset({CATEGORY})


def _class_admits(items: list[_Node], candidate: str) -> bool | None:
    """Whether one class (positive items only) admits ``candidate``."""
    verdict = False
    for item_op, item_av in items:
        if item_op == LITERAL:
            verdict = verdict or candidate == chr(cast("int", item_av))
        elif item_op == RANGE:
            low, high = cast("tuple[int, int]", item_av)
            verdict = verdict or low <= ord(candidate) <= high
        else:
            category = _category_admits(item_av, candidate)
            if category is None:
                return None
            verdict = verdict or category
    return verdict


def _concrete_class_set(items: list[_Node]) -> frozenset[str] | None:
    """The exact admitted set of a positive class with only plain items."""
    chars: set[str] = set()
    for item_op, item_av in items:
        if item_op == LITERAL:
            chars.add(chr(cast("int", item_av)))
        elif item_op == RANGE:
            low, high = cast("tuple[int, int]", item_av)
            if high - low > 0x10000:
                return None  # enormous range: not a concrete set
            chars.update(chr(code) for code in range(low, high + 1))
        else:
            return None  # categories: not a concrete set
    return frozenset(chars)


def _category_admits(item_av: object, candidate: str) -> bool | None:
    """Whether one ``CATEGORY`` class item admits ``candidate``."""
    name = getattr(item_av, "name", "")
    if "LOC" in name:
        return None  # locale-dependent: unknown
    base = name.removeprefix("CATEGORY_UNI_").removeprefix("CATEGORY_")
    kind = base.removeprefix("NOT_")
    negated = base != kind
    if ord(candidate) < 128:
        if kind == "DIGIT":
            admitted = candidate in _ASCII_DIGITS
        elif kind == "WORD":
            admitted = candidate in _ASCII_WORD
        else:
            admitted = candidate in _ASCII_SPACE
        return not admitted if negated else admitted
    # Non-ASCII characters: decidable only for the unicode variants, via
    # the documented ``str`` predicate equivalents of ``\d``/``\w``/``\s``.
    if not name.startswith("CATEGORY_UNI_"):
        return None
    if kind == "DIGIT":
        admitted = candidate.isdecimal()
    elif kind == "WORD":
        admitted = candidate.isalnum() or candidate == "_"
    else:
        admitted = candidate.isspace()
    return not admitted if negated else admitted


def _repeat_args(av: object) -> tuple[int, int, list[_Node]]:
    """Decode one repetition node: ``(low, high, body sequence)``."""
    low, high, body = cast("tuple[int, int, list[_Node]]", av)
    return low, high, list(body)


def _subpattern_body(av: object) -> list[_Node]:
    """The body sequence of one ``SUBPATTERN`` node (transparent group)."""
    return list(cast("tuple[object, object, object, list[_Node]]", av)[-1])


def _assert_body(av: object) -> list[_Node]:
    """The body sequence of one lookahead/lookbehind node."""
    return list(cast("tuple[object, list[_Node]]", av)[-1])


def _branch_alternatives(av: object) -> list[list[_Node]]:
    """The alternative sequences of one ``BRANCH`` node."""
    alternatives = cast("tuple[object, list[list[_Node]]]", av)[-1]
    return [list(alternative) for alternative in alternatives]


def _op_name(op: int) -> str:
    """Human-readable opcode name for analyzer rejection messages."""
    return getattr(op, "name", str(op))


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
    """Compile every regex predicate now (arch §6.6: fail at validation).

    Also enforces the ReDoS scan-size discipline (review F-10): a length
    cap per pattern plus the structural loop-safety analysis of
    :func:`_catastrophe_reason` — the pipeline runs these patterns over
    untrusted argument trees on every tool call. Typical deny rules
    (literal alternations, ``[^…]*`` classes, delimiter-pinned runs) are
    unaffected.
    """
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
            continue
        if len(pattern) > _MAX_PATTERN_LENGTH:
            problems.append(
                DslProblem(
                    source,
                    f"rule {rule.id!r}: {label} exceeds the "
                    f"{_MAX_PATTERN_LENGTH}-character pattern limit "
                    "(review F-10 scan-size discipline)",
                )
            )
        reason = _catastrophe_reason(pattern)
        if reason is not None:
            problems.append(
                DslProblem(
                    source,
                    f"rule {rule.id!r}: {label} risks catastrophic backtracking "
                    f"(CWE-1333): {reason}. Restructure the pattern — pull "
                    "alternations out of repeated groups, pin variable-width "
                    "runs with disjoint literals, or use atomic groups "
                    "(review F-10 scan-size discipline)",
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
