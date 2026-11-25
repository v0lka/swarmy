"""Reflection analysis tools of the built-in ``xss-detector`` module.

Locates a session marker inside a response body and classifies the markup
context of every occurrence (arch §8.7 ``tools/reflection.py``): the context
drives which safe verification payload (:func:`marker.plan_payloads`)
proves the missing escaping. Pure local text analysis —
``swarmy_risk_class = "passive"`` (AD-7), no network, no storage (arch §8.5).
"""

from __future__ import annotations

import json
from typing import Final

from pydantic import BaseModel, ConfigDict

from swarmy.guardrails.models import RiskClass

_EXCERPT_RADIUS: Final[int] = 60


class ReflectionOccurrence(BaseModel):
    """One marker occurrence with its classified context (tool result)."""

    model_config = ConfigDict(extra="forbid")

    offset: int  # character offset of the marker in the body
    context: str  # html_text | inside_tag | attribute_value | script_code | comment
    excerpt: str  # surrounding body text (control chars flattened)


class ReflectionReport(BaseModel):
    """Full marker-reflection analysis of one response body (tool result)."""

    model_config = ConfigDict(extra="forbid")

    marker: str
    reflected: bool
    occurrences: list[ReflectionOccurrence]
    contexts: list[str]  # distinct contexts, first-seen order
    verdict: str  # one-line guidance for the next detector step


def _excerpt(body: str, start: int, end: int) -> str:
    """Flattened body window around ``start:end`` (newlines/tabs → spaces)."""
    left = max(0, start - _EXCERPT_RADIUS)
    right = min(len(body), end + _EXCERPT_RADIUS)
    raw = body[left:right]
    return " ".join(raw.split())


def _script_span(body: str, position: int) -> bool:
    """Whether ``position`` lies between ``<script`` and its closing tag."""
    opened = body.rfind("<script", 0, position)
    if opened == -1:
        return False
    closed = body.find("</script", opened)
    return closed == -1 or closed > position


def _comment_span(body: str, position: int) -> bool:
    """Whether ``position`` lies inside an HTML comment."""
    opened = body.rfind("<!--", 0, position)
    if opened == -1:
        return False
    closed = body.find("-->", opened)
    return closed == -1 or closed > position


def _tag_start(body: str, position: int) -> int | None:
    """Offset of the unclosed ``<`` governing ``position`` (``None``: none)."""
    opened = body.rfind("<", 0, position)
    if opened == -1:
        return None
    closed = body.find(">", opened)
    if closed != -1 and closed < position:
        return None  # the last tag already ended before the marker
    return opened


def _classify(body: str, position: int) -> str:
    """Context label of one marker occurrence at ``position``."""
    if _script_span(body, position):
        return "script_code"
    if _comment_span(body, position):
        return "comment"
    tag_start = _tag_start(body, position)
    if tag_start is None:
        return "html_text"
    tag_head = body[tag_start:position]
    gt = body.find(">", position)
    after = body[position : gt + 1] if gt != -1 else ""
    if ("=" in tag_head or "=" in after) and (
        '"' in tag_head or "'" in tag_head or '"' in after or "'" in after
    ):
        return "attribute_value"
    return "inside_tag"


def analyze_reflection(body: str, marker: str, param: str = "q") -> str:
    """Locate a marker in a response body and classify its markup contexts.

    Feed the ``body_preview`` (or the raw body you fetched with the platform
    http tools) of the probe response here, together with the exact marker
    from `make_marker`. The result tells you whether the marker was
    reflected at all, how often, in which markup contexts, and what to do
    next: no reflection → next parameter; a context → request the matching
    safe payloads with `plan_payloads` and verify.

    Args:
        body: the response body text to search.
        marker: the session-unique marker token you injected.
        param: the parameter name you injected the marker into (only used
            for the verdict text).

    Returns:
        JSON object ``{marker, reflected, occurrences, contexts, verdict}``;
        each occurrence carries ``offset``, ``context`` and an ``excerpt``.
    """
    occurrences: list[ReflectionOccurrence] = []
    contexts: list[str] = []
    if marker:
        position = body.find(marker)
        while position != -1:
            context = _classify(body, position)
            occurrences.append(
                ReflectionOccurrence(
                    offset=position,
                    context=context,
                    excerpt=_excerpt(body, position, position + len(marker)),
                )
            )
            if context not in contexts:
                contexts.append(context)
            position = body.find(marker, position + len(marker))
    if not occurrences:
        report = ReflectionReport(
            marker=marker,
            reflected=False,
            occurrences=[],
            contexts=[],
            verdict=(
                f"marker not reflected via '{param}' — no candidate; try the next "
                "parameter or endpoint"
            ),
        )
        return report.model_dump_json()
    primary = contexts[0]
    report = ReflectionReport(
        marker=marker,
        reflected=True,
        occurrences=occurrences,
        contexts=contexts,
        verdict=(
            f"marker reflected {len(occurrences)} time(s) in context(s) "
            f"{contexts} — request safe payloads with plan_payloads for "
            f"'{primary}' and verify unescaped reflection"
        ),
    )
    return report.model_dump_json()


def safe_payload_report(body: str, payload: str) -> str:
    """Check whether a safe verification payload survived verbatim.

    Feed the response body of a payload probe here together with the exact
    payload string. ``survived_verbatim`` is the verification signal: the
    payload came back character-for-character (no escaping, no stripping)
    — together with the earlier reflection this justifies a finding
    candidate via `memory_save_finding`. Escaped or mangled echoes mean the
    context is defended: record nothing and move on.

    Args:
        body: the response body text of the payload probe.
        payload: the exact safe payload string that was sent.

    Returns:
        JSON object ``{payload, survived_verbatim, occurrences}`` —
        ``survived_verbatim`` is true when the payload came back
        character-for-character at least once (``occurrences`` counts hits).
    """
    found = body.count(payload) if payload else 0
    report = {
        "payload": payload,
        "survived_verbatim": found > 0,
        "occurrences": found,
    }
    return json.dumps(report)


# AD-7: inert local computation — passive, never HITL-gated.
analyze_reflection.swarmy_risk_class = RiskClass.PASSIVE
safe_payload_report.swarmy_risk_class = RiskClass.PASSIVE

__all__ = [
    "analyze_reflection",
    "safe_payload_report",
]
