"""Marker tools of the built-in ``xss-detector`` module (arch §8.7, T5.2.1).

Session-unique reflection markers and the *safe* (non-executing) payload
sets the detector verifies reflections with. Everything here is inert local
computation (``swarmy_risk_class = "passive"``, AD-7): no network, no
storage — the probe requests themselves run through the platform ``http_*``
tools behind the guardrail pipeline.

Safety contract (spec §4.6): the payloads of :func:`plan_payloads` never
contain script tags, ``javascript:`` URIs, inline event handlers or
``alert``/``eval`` calls — they only break out of the surrounding markup
context so that a *verbatim* reflection proves missing output escaping.
The module's ``guardrails.yaml`` rules deny the forbidden constructs
deterministically even if a model tries them anyway.
"""

from __future__ import annotations

import re
import secrets
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict

from swarmy.guardrails.models import RiskClass

if TYPE_CHECKING:
    from collections.abc import Callable

_MARKER_BODY_BYTES: Final[int] = 8  # 16 hex chars — collision-free per session
_DEFAULT_MARKER_PREFIX: Final[str] = "swx"

_CONTEXTS: Final[tuple[str, ...]] = (
    "html_text",
    "inside_tag",
    "attribute_value",
    "script_code",
    "comment",
    "unknown",
)

_QUERY_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


class PayloadPlan(BaseModel):
    """Safe payloads for one reflection context (tool result)."""

    model_config = ConfigDict(extra="forbid")

    context: str
    payloads: list[str]
    rationale: str


def make_marker(prefix: str = _DEFAULT_MARKER_PREFIX) -> str:
    """Generate a session-unique reflection marker token.

    Call once per probe campaign. The token is ``<prefix>`` plus 16 random
    hex characters — safe to place in URLs, unique enough to search for in
    a response body without false positives. Use it with `build_probe_url`,
    then locate it in the response with `analyze_reflection`.

    Args:
        prefix: short alphanumeric token prefix (default ``swx``); the
            module guardrails deny known payload patterns, so keep it a
            plain identifier.

    Returns:
        The marker string, e.g. ``swx3f9a1c027b54e8d1``.
    """
    safe_prefix = re.sub(r"[^A-Za-z0-9_-]", "", prefix) or _DEFAULT_MARKER_PREFIX
    return f"{safe_prefix}{secrets.token_hex(_MARKER_BODY_BYTES)}"


def build_probe_url(url: str, param: str, value: str) -> str:
    """Inject a value into one query parameter of a URL (replace or append).

    Builds the probe URL for a marker or payload: if ``param`` already
    exists in ``url``'s query string its value is replaced, otherwise the
    pair is appended. Fragment and existing other parameters are preserved.
    Non-query injection points (body fields) are probed with the platform
    ``http_post`` tool instead — pass the payload as its ``body``.

    Args:
        url: absolute target URL, e.g. ``http://host:port/query``.
        param: parameter name to inject into (e.g. ``q``).
        value: the value to place (a marker from `make_marker` or a safe
            payload from `plan_payloads`).

    Returns:
        The absolute probe URL; the original URL unchanged when it is not
        a valid absolute http(s) URL or ``param`` is empty.
    """
    if not param or not _QUERY_RE.match(url):
        return url
    fragment = ""
    base_and_query = url
    if "#" in url:
        base_and_query, _, fragment = url.partition("#")
    if "?" in base_and_query:
        base, _, query = base_and_query.partition("?")
    else:
        base, query = base_and_query, ""
    pairs = [pair for pair in query.split("&") if pair]
    replaced = False
    rebuilt: list[str] = []
    for pair in pairs:
        name = pair.split("=", 1)[0]
        if name == param:
            rebuilt.append(f"{param}={value}")
            replaced = True
        else:
            rebuilt.append(pair)
    if not replaced:
        rebuilt.append(f"{param}={value}")
    probe = f"{base}?{'&'.join(rebuilt)}"
    return f"{probe}#{fragment}" if fragment else probe


def plan_payloads(marker: str, context: str) -> str:
    """Return the safe (non-executing) verification payloads for a context.

    Call after `analyze_reflection` named a reflection context. Every
    payload breaks out of exactly that markup context while staying inert —
    no script execution even when reflected unescaped — so a verbatim echo
    proves the missing escaping without touching the target's users.
    Fetch them with `http_get`/`http_post` and run `analyze_reflection`
    again: a payload reflected verbatim (not escaped, not stripped) in the
    same context justifies a finding candidate.

    Args:
        marker: your session-unique marker from `make_marker`.
        context: the context reported by `analyze_reflection` — one of
            ``html_text``, ``inside_tag``, ``attribute_value``,
            ``script_code``, ``comment``, ``unknown``.

    Returns:
        JSON object ``{context, payloads, rationale}``; ``payloads`` is
        empty for an unknown context value (the error is in ``rationale``).
    """
    if context not in _CONTEXTS:
        plan = PayloadPlan(
            context=context,
            payloads=[],
            rationale=(
                f"unknown context {context!r}; expected one of {list(_CONTEXTS)} "
                "— re-run analyze_reflection"
            ),
        )
        return plan.model_dump_json()
    payloads = _PAYLOAD_BUILDERS[context](marker)
    plan = PayloadPlan(
        context=context, payloads=payloads, rationale=_RATIONALES[context]
    )
    return plan.model_dump_json()


def _html_text_payloads(marker: str) -> list[str]:
    """Payloads breaking into element content from text context."""
    return [f"<swxtag{marker}>", f"</swx><swx{marker}>"]


def _inside_tag_payloads(marker: str) -> list[str]:
    """Payloads proving injection between tag name and attributes."""
    return [f"/>{marker}<swx", f">{marker}<swx/"]


def _attribute_value_payloads(marker: str) -> list[str]:
    """Payloads breaking out of a quoted attribute value (inert, no handlers)."""
    return [f'"{marker}" x="', f"'{marker}' x='"]


def _script_code_payloads(marker: str) -> list[str]:
    """Payloads breaking out of a script string context (inert, no calls)."""
    return [f"'{marker}'//", f'";{marker}//']


def _comment_payloads(marker: str) -> list[str]:
    """Payloads closing an HTML comment and opening a benign element."""
    return [f"--><swx{marker}><!--", f"-->{marker}<!--"]


def _unknown_payloads(marker: str) -> list[str]:
    """Generic probes when the context classifier was inconclusive."""
    return [f"<swxtag{marker}>", f"'{marker}'", f'"{marker}"']


_PAYLOAD_BUILDERS: Final[dict[str, Callable[[str], list[str]]]] = {
    "html_text": _html_text_payloads,
    "inside_tag": _inside_tag_payloads,
    "attribute_value": _attribute_value_payloads,
    "script_code": _script_code_payloads,
    "comment": _comment_payloads,
    "unknown": _unknown_payloads,
}

_RATIONALES: Final[dict[str, str]] = {
    "html_text": "verbatim <swxtag…> in element content proves unescaped HTML output",
    "inside_tag": "verbatim />… <swx proves markup injection inside the tag",
    "attribute_value": "a quote-break reflected verbatim proves unescaped attribute output (no event handlers used)",
    "script_code": "a string terminator reflected verbatim proves script-context injection (no calls made)",
    "comment": "a comment close reflected verbatim proves attacker markup can leave the comment",
    "unknown": "generic inert probes: quote-breaks and a benign tag, safe in every context",
}


# AD-7: inert local computation — passive, never HITL-gated.
make_marker.swarmy_risk_class = RiskClass.PASSIVE
build_probe_url.swarmy_risk_class = RiskClass.PASSIVE
plan_payloads.swarmy_risk_class = RiskClass.PASSIVE

__all__ = [
    "build_probe_url",
    "make_marker",
    "plan_payloads",
]
