"""Layer 2 — shipped engine rules: the disableable default set (arch §6.6, T1.4.4).

The engine ships a small set of defensive rules that are active by default
and can be disabled as a whole (constructor flag of the pipeline; the config
key ``guardrails.engine_rules`` is read only from T3.1.1 — until then the
flag is a build-time argument). The set follows arch §6.6 / spec §8.2:

* ``no-true-based-sqli`` — the canonical spec §8.3 example: TRUE-construction
  payloads (``OR 1=1``, ``'=''``-style) in HTTP tool parameters are blocked
  because they corrupt target data during SQLi probing;
* ``block-destructive-payloads`` — known destructive payload patterns
  (``DROP TABLE``-style statements, ``rm -rf``-style shell fragments).

HTTP methods need no engine rule: the platform HTTP tool surface offers
exactly GET/POST/PUT/DELETE (fixed ``Literal`` per tool), so TRACE/CONNECT
are structurally unsendable — the former ``block-trace-connect-methods``
rule could never observe a method value and only misfired on probe
parameters whose value happened to be ``trace``/``connect`` (removed per
review Issue #59; decision D30).

Engine rules are ordinary :class:`~swarmy.guardrails.models.GuardrailRule`
models evaluated by the same code path as layer-3 module rules; their ids
are unprefixed (the ``layer`` field of the feedback/event says ``engine`` —
only invariants carry the ``invariant:`` prefix). Compilation of the regexes
happens once, at pipeline construction (fail-fast, arch §4.5). Pattern note
(review F-10): patterns must not contain unbounded ``.*``/``.+`` scans —
quantifiers are bounded (``.{0,N}``) so a hostile multi-hundred-KB argument
cannot drive quadratic regex backtracking on every tool call.
"""

from __future__ import annotations

from swarmy.guardrails.models import GuardrailRule, RuleCondition

#: Spec §8.3 example — TRUE-constructions in SQLi probe parameters.
#: The gap quantifier is bounded (review F-10): the engine caps the regex
#: steps per argument leaf, keeping deny semantics for realistic payloads.
_TRUE_BASED_SQLI_REGEX = r"(?i)('\s*(or|and)\s*'.{0,256}'=|1\s*=\s*1|true\s*=)"

#: Known destructive payload fragments (spec §8.2 default set). These target
#: data destruction on the host, not the probing payloads the xss/sql
#: detectors legitimately send.
_DESTRUCTIVE_PAYLOAD_REGEX = (
    r"(?i)(\bdrop\s+table\b|\btruncate\s+table\b|\bdelete\s+from\b"
    r"|\brm\s+-rf\b|\bmkfs\b|\bshutdown\s+(-h|-P|now)\b)"
)

#: The HTTP tools the engine rules guard — the definitive platform HTTP set
#: of arch §6.1/§6.2 (shipped with the HTTP client, T2.2.3); the invariants
#: ``PLATFORM_HTTP_TOOLS`` and this tuple move together.
_HTTP_TOOL_NAMES: tuple[str, ...] = ("http_get", "http_post", "http_put", "http_delete")


def no_true_based_sqli_rule() -> GuardrailRule:
    """Build the spec §8.3 example rule (TRUE-constructions are denied).

    Returns:
        The ``no-true-based-sqli`` guardrail rule for the HTTP tools.
    """
    return GuardrailRule(
        id="no-true-based-sqli",
        applies_to=list(_HTTP_TOOL_NAMES),
        condition=RuleCondition(any_param_matches=_TRUE_BASED_SQLI_REGEX),
        action="block",
        severity="high",
        message=(
            "TRUE-constructions in SQLi probing are forbidden: risk of "
            "corrupting target data (spec §8.3)"
        ),
    )


def block_destructive_payloads_rule() -> GuardrailRule:
    """Build the rule blocking known destructive payload patterns.

    Returns:
        The ``block-destructive-payloads`` guardrail rule.
    """
    return GuardrailRule(
        id="block-destructive-payloads",
        applies_to=list(_HTTP_TOOL_NAMES),
        condition=RuleCondition(any_param_matches=_DESTRUCTIVE_PAYLOAD_REGEX),
        action="block",
        severity="high",
        message="destructive payload pattern blocked by the engine policy",
    )


def default_engine_rules() -> tuple[GuardrailRule, ...]:
    """Assemble the shipped default rule set (arch §6.6, disableable).

    Returns:
        The engine rules in evaluation order.
    """
    return (
        no_true_based_sqli_rule(),
        block_destructive_payloads_rule(),
    )


__all__ = [
    "block_destructive_payloads_rule",
    "default_engine_rules",
    "no_true_based_sqli_rule",
]
