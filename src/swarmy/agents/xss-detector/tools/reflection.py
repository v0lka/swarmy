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

#: Maximum occurrences kept in one reflection report (review entry K): a
#: degenerate short marker in a saturated body would otherwise return an
#: unbounded list into the model context. The count itself is still
#: reported in full (:attr:`ReflectionReport.total_occurrences`).
_MAX_OCCURRENCES: Final[int] = 500


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
    occurrences: list[ReflectionOccurrence]  # first _MAX_OCCURRENCES hits, in body order
    truncated: bool = False  # true when the body carried more hits than kept
    total_occurrences: int = 0  # the complete hit count (occurrences may be capped)
    contexts: list[str] = []  # distinct contexts, first-seen order (kept hits only)
    verdict: str  # one-line guidance for the next detector step


def _excerpt(body: str, start: int, end: int) -> str:
    """Flattened body window around ``start:end`` (newlines/tabs → spaces)."""
    left = max(0, start - _EXCERPT_RADIUS)
    right = min(len(body), end + _EXCERPT_RADIUS)
    raw = body[left:right]
    return " ".join(raw.split())


class _SpanTracker:
    """Bounding-span tracker for one markup token pair (linear total).

    Answers "does ``position`` lie inside a ``<token>``…``</closer>`` span"
    for a sequence of non-decreasing query positions with the from-0
    semantics of the previous implementation — but every ``rfind`` window
    starts at the frontier already proven token-free, so each body
    character is scanned a bounded number of times across the whole
    analysis instead of once per marker occurrence (Issue #61).
    """

    __slots__ = ("_body", "_close", "_closed", "_floor", "_open", "_opened")

    def __init__(self, body: str, open_token: str, close_token: str) -> None:
        self._body = body
        self._open = open_token
        self._close = close_token
        self._floor = 0  # body[:floor] holds no governing open token
        self._opened = -1  # last open token found (-1: none)
        self._closed = -1  # its close offset (-1: not resolved yet)

    def inside(self, position: int) -> bool:
        """Whether ``position`` lies in a span (queries are non-decreasing)."""
        body = self._body
        while True:
            if self._opened == -1:
                opened = body.rfind(self._open, self._floor, position)
                if opened == -1:
                    self._floor = position  # nothing governs before position
                    return False
                self._opened = opened
                self._closed = -1
            if self._closed == -1:
                closed = body.find(self._close, self._opened)
                self._closed = closed if closed != -1 else len(body)
            if self._closed > position:
                return True
            # The span closed before the query: only a later token governs.
            self._floor = self._closed + 1
            self._opened = -1


class _TagTracker:
    """Unclosed-``<`` tracker for ordered queries (linear total).

    Mirrors the from-0 semantics (``rfind('<', 0, position)``, the tag must
    not close before ``position``; equality/quote flags over the whole tag
    head) while re-scanning only the gap between consecutive queries. The
    governing ``<`` is cached together with its closing ``>`` and the
    equality/quote flags of the head — every tag's head is scanned once,
    however many marker occurrences it contains (Issue #61).
    """

    __slots__ = (
        "_body",
        "_floor",
        "_gt",
        "_has_eq",
        "_has_quote",
        "_lt",
        "_scanned",
    )

    def __init__(self, body: str) -> None:
        self._body = body
        self._floor = 0  # body[:floor] cannot govern any query position
        self._scanned = 0  # body[:scanned] holds no '<' beyond ``_lt``
        self._lt = -1  # cached governing '<' (-1: none)
        self._gt = -2  # closing '>' of ``_lt`` (-2: unresolved; -1: unclosed)
        self._has_eq = False  # '=' inside the cached tag head
        self._has_quote = False  # '"'/"'" inside the cached tag head

    def head(self, position: int) -> tuple[bool, bool] | None:
        """``('=', quote)`` flags of the tag governing ``position``.

        ``None`` when the position lies in plain text between tags. Query
        positions must be non-decreasing.
        """
        body = self._body
        while True:
            if self._lt == -1:
                lt = body.rfind("<", self._floor, position)
                if lt == -1:
                    self._floor = position
                    self._scanned = position
                    return None
                self._lt = lt
                self._scanned = position
                self._gt = -2
            if self._gt == -2:
                self._resolve()
            if self._gt >= 0 and self._gt < position:
                # The cached '<' is closed before the query: a later one governs.
                self._floor = self._gt + 1
                self._lt = -1
                continue
            if self._scanned < position:
                # A raw '<' after the cached one would take over per the
                # from-0 semantics — inspect the gap once.
                later = body.rfind("<", self._scanned, position)
                self._scanned = position
                if later != -1:
                    later_close = body.find(">", later)
                    if later_close != -1 and later_close < position:
                        self._floor = later_close + 1
                        self._lt = -1
                        return None
                    self._lt = later
                    self._gt = -2
                    self._resolve()
                    return self._has_eq, self._has_quote
            return self._has_eq, self._has_quote

    def _resolve(self) -> None:
        """Resolve the cached tag's closing ``>`` and head flags (once)."""
        self._gt = self._body.find(">", self._lt)
        head_end = len(self._body) if self._gt == -1 else self._gt + 1
        self._has_eq = self._body.find("=", self._lt, head_end) != -1
        self._has_quote = (
            self._body.find('"', self._lt, head_end) != -1
            or self._body.find("'", self._lt, head_end) != -1
        )


class _ContextScanner:
    """Incremental markup-context classifier (linear over ordered queries).

    Replaces the per-occurrence ``rfind``/``find`` scans from position 0
    (quadratic on a marker-saturated body — Issue #61): classification
    state advances monotonically with the occurrence positions, so the
    total work is linear in the body size.
    """

    __slots__ = ("_comment", "_script", "_tag")

    def __init__(self, body: str) -> None:
        self._script = _SpanTracker(body, "<script", "</script")
        self._comment = _SpanTracker(body, "<!--", "-->")
        self._tag = _TagTracker(body)

    def classify(self, position: int) -> str:
        """Context label of one marker occurrence (positions ascend)."""
        if self._script.inside(position):
            return "script_code"
        if self._comment.inside(position):
            return "comment"
        head = self._tag.head(position)
        if head is None:
            return "html_text"
        has_eq, has_quote = head
        return "attribute_value" if (has_eq and has_quote) else "inside_tag"


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
        At most 500 occurrences are kept (``truncated`` marks a saturated
        body; ``total_occurrences`` always carries the complete count).
    """
    occurrences: list[ReflectionOccurrence] = []
    contexts: list[str] = []
    total = 0
    if marker:
        scanner = _ContextScanner(body)
        position = body.find(marker)
        while position != -1:
            total += 1
            if len(occurrences) < _MAX_OCCURRENCES:
                context = scanner.classify(position)
                occurrences.append(
                    ReflectionOccurrence(
                        offset=position,
                        context=context,
                        excerpt=_excerpt(body, position, position + len(marker)),
                    )
                )
                if context not in contexts:
                    contexts.append(context)
            # Beyond the cap only the count advances: the classifier queries
            # are non-decreasing, so skipping the calls stays consistent.
            position = body.find(marker, position + len(marker))
    truncated = total > len(occurrences)
    if not occurrences:
        report = ReflectionReport(
            marker=marker,
            reflected=False,
            occurrences=[],
            contexts=[],
            total_occurrences=0,
            verdict=(
                f"marker not reflected via '{param}' — no candidate; try the next "
                "parameter or endpoint"
            ),
        )
        return report.model_dump_json()
    primary = contexts[0]
    kept_note = f" (first {len(occurrences)} kept)" if truncated else ""
    report = ReflectionReport(
        marker=marker,
        reflected=True,
        occurrences=occurrences,
        truncated=truncated,
        total_occurrences=total,
        contexts=contexts,
        verdict=(
            f"marker reflected {total} time(s){kept_note} in context(s) "
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
