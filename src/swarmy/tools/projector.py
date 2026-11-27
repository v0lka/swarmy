"""``ContextProjector`` — sanitization of everything returned to the model (arch §6.8, D21).

Principle (arch §6.8, decisions D23/D24): session memory and session files stay
**raw**; everything that reaches a model (HTTP preview, event digest, guardrail
feedback, endpoint listing) passes through this projection first. Four steps,
in the canonical order of arch §6.8:

1. **Operator-secret masking**: literal secret values and/or regex patterns
   injected explicitly through the constructor (the ``secrets.yaml`` loader
   wires them in) plus built-in detectors (``Authorization``/``Cookie``-style
   headers, bearer tokens) → ``<masked:secret-name>``. Masking runs *before*
   the budget (D23) so a secret straddling the truncation boundary can never
   keep an unmasked prefix in the model context.
2. **Byte budgets** per tool class (session ``context.budgets``, conservative
   defaults): truncation with the ``[truncated N bytes]`` marker; the full
   content remains available in the evidence files (raw, D21).
3. **Untrusted marking**: target content is wrapped in the verbatim
   ``[untrusted-target-content begin] ... [untrusted-target-content end]``
   markers of arch §6.8 (prompt-injection containment). Occurrences of the
   markers *inside* the content are defused into a visibly escaped form and a
   platform note counts them (D24) — target text can neither close its own
   untrusted block nor fabricate a quoted one.
4. **Normalization**: control characters and hidden Unicode (biDi overrides,
   zero-width) are escaped before the text enters any model context.

Boundary (arch §2.5): the projector imports nothing from ``swarmy`` — the
``ContextProjector`` itself is a pure, synchronous ``str → str`` component;
callers keep owning the raw copies (evidence files, memory rows, report).
The module also hosts ``ProjectorMiddleware`` (T2.3.2) — the L0 post-tool-call
hook applying this projection to *every* tool result before it reaches any
model context (arch §6.8 application point; engine wiring lands in M3).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Final, TypeAlias

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from langgraph.prebuilt.tool_node import ToolCallRequest

# ---- canonical marker formats (arch §6.8 — kept verbatim, tests assert them) ----

#: Verbatim begin marker wrapping untrusted target content (arch §6.8).
UNTRUSTED_BEGIN: Final[str] = "[untrusted-target-content begin]"

#: Verbatim end marker wrapping untrusted target content (arch §6.8).
UNTRUSTED_END: Final[str] = "[untrusted-target-content end]"

#: Module logger — projection failures of the middleware are recorded here
#: before the fail-closed feedback replaces the tool result (arch §6.8).
LOG = logging.getLogger(__name__)


def _defused_marker(marker: str) -> str:
    """Visibly escaped form of one containment marker (D24).

    ``[untrusted-target-content end]`` → ``[defused:untrusted-target-content
    end]``: the platform's own markers stay verbatim, while the same literal
    typed by the *target* can no longer be interpreted as the real block
    boundary (the replacement never contains the original marker string).
    """
    return f"[defused:{marker[1:-1]}]"


def _defuse_containment_markers(text: str) -> tuple[str, int]:
    """Defuse every in-content occurrence of the §6.8 markers (D24, F-14).

    Returns:
        ``(text, spoof_count)`` — the defused copy and how many marker
        occurrences (begin + end) were rewritten. ``spoof_count == 0`` means
        the text is returned unchanged.
    """
    count = text.count(UNTRUSTED_BEGIN) + text.count(UNTRUSTED_END)
    if count == 0:
        return text, 0
    defused = text.replace(UNTRUSTED_BEGIN, _defused_marker(UNTRUSTED_BEGIN))
    defused = defused.replace(UNTRUSTED_END, _defused_marker(UNTRUSTED_END))
    return defused, count


def _spoof_note(count: int) -> str:
    """Platform note counting the defused in-content markers (D24).

    Appended *after* the platform's own end marker, so the model reads it as
    projector-authored context, never as target content.
    """
    if count == 0:
        return ""
    return f"\n[note: {count} untrusted-marker spoof attempts defused]"

#: Conservative byte budgets for the tool classes named in arch §12.1
#: (``context.budgets``). Tool classes without an entry fall back to
#: :attr:`ProjectorConfig.default_budget_bytes`.
DEFAULT_BUDGETS: Final[dict[str, int]] = {
    "http_preview_bytes": 20_000,
    "memory_result_bytes": 8_000,
}

#: Budget applied to a tool class with no explicit entry (arch §6.8:
#: "дефолты консервативные").
DEFAULT_BUDGET_BYTES: Final[int] = 4_000


def truncation_marker(dropped: int) -> str:
    """Render the verbatim truncation marker of arch §6.8 (step 1)."""
    return f"[truncated {dropped} bytes]"


def mask_reference(name: str) -> str:
    """Render the canonical masked reference ``<masked:secret-name>`` (arch §6.8, §12.3).

    The format is owned here because §12.3 (secrets) refers to §6.8 for it;
    ``swarmy.core.config`` imports this function instead of redefining it.
    """
    return f"<masked:{name}>"


class ProjectorConfig(BaseModel):
    """Static configuration of the projector (arch §6.8; session ``context`` section).

    ``budgets`` maps a tool class (``http_preview``, ``memory_result``, ...)
    to its per-call byte budget; the session config sample of arch §12.1
    shows the two canonical keys. Unknown tool classes use
    ``default_budget_bytes`` — a budget is always applied (fail-safe:
    oversized tool output can never flood the model context).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    budgets: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_BUDGETS))
    default_budget_bytes: int = Field(default=DEFAULT_BUDGET_BYTES, ge=1)

    @field_validator("budgets")
    @classmethod
    def _budgets_positive(cls, value: dict[str, int]) -> dict[str, int]:
        """Reject non-positive budgets — a zero budget would truncate everything."""
        non_positive = sorted(name for name, budget in value.items() if budget < 1)
        if non_positive:
            raise ValueError(f"budgets must be >= 1 byte, offending keys: {non_positive}")
        return value

    def budget_for(self, tool_class: str | None) -> int:
        """Resolve the byte budget for one tool class (``None`` → default)."""
        if tool_class is None:
            return self.default_budget_bytes
        return self.budgets.get(f"{tool_class}_bytes", self.default_budget_bytes)


# ---- step 1: built-in detectors (arch §6.8) ----

#: Canonical masked-reference names the built-in detectors produce. The
#: header-line guard (D24) exempts a line only when it carries a reference
#: whose name is one of the injected secrets or one of these — a decoy
#: ``<masked:...>`` with any other name never disables masking.
_BUILTIN_MASK_NAMES: Final[tuple[str, ...]] = ("authorization", "bearer", "cookie")

#: Header-line regex templates for the authz/cookie families (arch §6.8).
#: The ``{guard}`` slot receives the *name-tied* negative lookahead built by
#: :func:`_masked_reference_guard`: a line is exempt from re-masking only when
#: it already carries a masked reference **this projector could have
#: produced** (a known secret name or a built-in detector name). A decoy
#: ``<masked:`` with an unknown name no longer disables masking (D24) — the
#: whole value is masked instead.
_AUTHORIZATION_HEADER_TEMPLATE: Final[str] = (
    r"(?i)\b((?:proxy-)?authorization)\s*:\s*{guard}[^\r\n]+"
)
_COOKIE_HEADER_TEMPLATE: Final[str] = r"(?i)\b(set-cookie|cookie)\s*:\s*{guard}[^\r\n]+"


def _masked_reference_guard(known_names: Iterable[str]) -> str:
    """Negative lookahead exempting only *known* masked references (D24).

    ``(?![^\r\n]*<masked:(?:name1|name2|...)>)`` — the lookahead scans the
    rest of the line for a reference whose name the projector itself could
    have substituted (injected secrets + built-in detector names). An
    attacker-chosen decoy name never matches, so the line stays masked.
    """
    alternation = "|".join(sorted(re.escape(name) for name in known_names))
    return rf"(?![^\r\n]*<masked:(?:{alternation})>)"


def _compiled_header_rules(
    known_names: Iterable[str],
) -> tuple[tuple[re.Pattern[str], str], ...]:
    """Compile the authz/cookie header detectors for one projector instance."""
    guard = _masked_reference_guard(known_names)
    return (
        (re.compile(_AUTHORIZATION_HEADER_TEMPLATE.format(guard=guard)), "authorization"),
        (re.compile(_COOKIE_HEADER_TEMPLATE.format(guard=guard)), "cookie"),
    )


#: Bearer tokens (``Authorization: Bearer <token>`` and bare occurrences).
#: The token charset excludes ``<``/``>``/``:`` so already-masked references
#: (``<masked:...>``) are never re-masked; 8+ chars avoid false positives on
#: the ordinary word following ``Bearer``.
_BEARER_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(bearer)[ \t]+([A-Za-z0-9\-._~+/=]{8,})")


def _header_masker(secret_name: str) -> Callable[[re.Match[str]], str]:
    """Build a ``re.sub`` replacement keeping the header name, masking the value."""

    def _mask(match: re.Match[str]) -> str:
        return f"{match.group(1)}: {mask_reference(secret_name)}"

    return _mask


def _mask_bearer(match: re.Match[str]) -> str:
    """Replace ``Bearer <token>`` with the scheme kept and the token masked."""
    return f"Bearer {mask_reference('bearer')}"


# ---- step 4: normalization tables (arch §6.8) ----

#: CR/LF normalization: CRLF and lone CR become LF.
_NEWLINE_RE: Final[re.Pattern[str]] = re.compile(r"\r\n?")

#: Hidden Unicode: zero-width (ZWSP/ZWNJ/ZWJ/word joiner), BOM, biDi
#: embedding/override/isolate controls. Escaped (not deleted) so the model
#: sees that something was there without the layout attack surviving.
_HIDDEN_UNICODE_RE: Final[re.Pattern[str]] = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]"
)

#: C0 controls except ``\\t`` and ``\\n`` (kept) plus the C1 range and DEL.
_CONTROL_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _escape_char(match: re.Match[str]) -> str:
    """Render one hidden/control character as a visible ``\\uXXXX`` escape."""
    return f"\\u{ord(match.group(0)):04x}"


class ContextProjector:
    """Pure ``str → str`` sanitizer applied to every model-bound text (arch §6.8).

    The four §6.8 steps run in canonical order on :meth:`project` (D23:
    masking before budget): secret masking → byte-budget truncation →
    untrusted marking (with in-content marker defusing, D24) → control-char
    normalization. The instance is immutable after construction; secret rules
    are injected explicitly (constructor), which keeps this module free of any
    ``swarmy`` import (arch §2.5: ``tools.*`` never imports ``core``).
    """

    __slots__ = ("_config", "_header_rules", "_mark_untrusted", "_secret_rules")

    def __init__(
        self,
        config: ProjectorConfig | None = None,
        *,
        budgets: Mapping[str, int] | None = None,
        secrets: Mapping[str, str] | None = None,
        secret_patterns: Mapping[str, str] | None = None,
        mark_untrusted: bool = True,
    ) -> None:
        """Build a projector.

        Args:
            config: full :class:`ProjectorConfig`; mutually exclusive with
                ``budgets``.
            budgets: shorthand for ``ProjectorConfig(budgets=...)`` — mapping
                of tool-class budget keys (``<tool_class>_bytes``) to byte
                limits.
            secrets: operator secrets as ``name → literal value``. Values are
                matched literally (regex-escaped internally) and replaced with
                ``<masked:name>``.
            secret_patterns: operator secrets as ``name → regex source`` for
                value shapes no literal can cover (e.g. rotating session
                cookies). Invalid regexes raise ``ValueError`` here — at
                construction, never mid-session (fail-fast, arch §4.5).
            mark_untrusted: wrap output in the verbatim §6.8 untrusted
                markers (step 3). Only streams that are *not* target-derived
                content may disable this.

        Raises:
            ValueError: on an empty secret value/pattern or an invalid
                ``secret_patterns`` regex (aggregated over all offenders).
        """
        if config is not None and budgets is not None:
            msg = "pass either config or budgets, not both"
            raise ValueError(msg)
        if config is not None:
            self._config = config
        elif budgets is not None:
            self._config = ProjectorConfig(budgets=dict(budgets))
        else:
            self._config = ProjectorConfig()
        self._mark_untrusted = mark_untrusted
        self._secret_rules: tuple[tuple[str, re.Pattern[str]], ...] = self._compile_rules(
            secrets, secret_patterns
        )
        # D24: the authz/cookie detectors' re-masking guard is tied to the
        # names this projector can actually produce (injected secrets + the
        # built-in detector names), so a decoy ``<masked:...>`` can never
        # disable masking of a reflected credential line.
        self._header_rules: tuple[tuple[re.Pattern[str], str], ...] = _compiled_header_rules(
            (*{name for name, _pattern in self._secret_rules}, *_BUILTIN_MASK_NAMES)
        )

    @staticmethod
    def _compile_rules(
        secrets: Mapping[str, str] | None,
        secret_patterns: Mapping[str, str] | None,
    ) -> tuple[tuple[str, re.Pattern[str]], ...]:
        """Compile injected secret rules; literal values first, longest-first.

        Longest-first ordering for literals prevents the shorter of two
        overlapping values (``abc`` vs ``abcd``) from leaving a residual
        fragment unmasked. Pattern rules keep caller order after them.
        """
        problems: list[str] = []
        literal_rules: list[tuple[str, re.Pattern[str]]] = []
        for name, value in (secrets or {}).items():
            if not value:
                problems.append(f"secret {name!r} has an empty value")
                continue
            literal_rules.append((name, re.compile(re.escape(value))))
        literal_rules.sort(key=lambda rule: len(rule[1].pattern), reverse=True)
        pattern_rules: list[tuple[str, re.Pattern[str]]] = []
        for name, pattern in (secret_patterns or {}).items():
            if not pattern:
                problems.append(f"secret pattern {name!r} is empty")
                continue
            try:
                pattern_rules.append((name, re.compile(pattern)))
            except re.error as exc:
                problems.append(f"secret pattern {name!r} is not a valid regex: {exc}")
        if problems:
            raise ValueError("; ".join(problems))
        return (*literal_rules, *pattern_rules)

    @property
    def untrusted_begin(self) -> str:
        """The verbatim §6.8 begin marker (read by the display layer)."""
        return UNTRUSTED_BEGIN

    @property
    def untrusted_end(self) -> str:
        """The verbatim §6.8 end marker (read by the display layer)."""
        return UNTRUSTED_END

    def project(
        self,
        text: str,
        *,
        tool_class: str | None = None,
        mark_untrusted: bool | None = None,
        defuse_markers: bool = True,
    ) -> str:
        """Project one model-bound text through the four §6.8 steps in order.

        Canonical order (D23): masking → budget → marking → normalization.
        Masking before truncation guarantees no secret can keep an unmasked
        prefix when the budget cuts mid-value; the budget applies to the
        masked text (the truncation marker counts masked-text bytes).

        Args:
            text: raw content destined for a model context (tool result,
                digest, guardrail feedback, ...).
            tool_class: class of the producing tool (``http_preview``,
                ``memory_result``, ...) selecting the byte budget; ``None``
                uses the conservative default budget.
            mark_untrusted: override the instance's untrusted-marking default
                for this call. ``None`` keeps the constructor value;
                ``False`` projects without the §6.8 wrapper (operator chat,
                display-bound digests). Masking, budgeting and normalization
                still run.
            defuse_markers: deactivate in-content occurrences of the §6.8
                markers (D24). The display layer passes ``False`` so genuine
                markers survive for red-background rendering; every
                model-bound stream keeps the default ``True``.

        Returns:
            The sanitized projection; the raw ``text`` is left untouched for
            evidence/memory (D21).
        """
        projected = self._mask_secrets(text)  # §6.8 step 1 (D23: before the budget)
        projected = self._apply_budget(projected, tool_class)  # §6.8 step 2
        mark = self._mark_untrusted if mark_untrusted is None else mark_untrusted
        projected = self._mark_untrusted_target(
            projected, mark=mark, defuse_markers=defuse_markers
        )  # §6.8 step 3
        return self._normalize(projected)  # §6.8 step 4

    def _apply_budget(self, text: str, tool_class: str | None) -> str:
        """§6.8 step 2: truncate to the tool class budget with a marker."""
        budget = self._config.budget_for(tool_class)
        encoded = text.encode("utf-8")
        if len(encoded) <= budget:
            return text
        kept = encoded[:budget].decode("utf-8", errors="ignore")  # never split a code point
        dropped = len(encoded) - len(kept.encode("utf-8"))
        return f"{kept}\n{truncation_marker(dropped)}"

    def _mask_secrets(self, text: str) -> str:
        """§6.8 step 1: replace injected secrets, then run the built-in detectors."""
        projected = text
        for name, pattern in self._secret_rules:
            masked = mask_reference(name)
            projected = pattern.sub(lambda _match, masked=masked: masked, projected)
        for pattern, secret_name in self._header_rules:
            projected = pattern.sub(_header_masker(secret_name), projected)
        return _BEARER_TOKEN_RE.sub(_mask_bearer, projected)

    def _mark_untrusted_target(
        self, text: str, *, mark: bool, defuse_markers: bool = True
    ) -> str:
        """§6.8 step 3: wrap the content in the verbatim untrusted markers.

        In-content occurrences of the markers are defused first (D24): the
        wrapped text can neither close its own block nor fabricate one, and
        the platform note after the end marker reports the defusals. The
        display layer disables defusing so genuine markers survive for
        red-background rendering.
        """
        if not defuse_markers:
            return f"{UNTRUSTED_BEGIN} {text} {UNTRUSTED_END}" if mark else text
        defused, spoof_count = _defuse_containment_markers(text)
        note = _spoof_note(spoof_count)
        if not mark:
            return f"{defused}{note}"
        return f"{UNTRUSTED_BEGIN} {defused} {UNTRUSTED_END}{note}"

    @staticmethod
    def _normalize(text: str) -> str:
        """§6.8 step 4: normalize newlines, control chars and hidden Unicode."""
        projected = _NEWLINE_RE.sub("\n", text)
        projected = _HIDDEN_UNICODE_RE.sub(_escape_char, projected)
        return _CONTROL_RE.sub(_escape_char, projected)


# ---- L0 application point (arch §6.8, T2.3.2) ----

#: Platform read-model tools mapped to the ``memory_result`` budget class
#: (arch §12.1). Tools without an entry use the projector's conservative
#: default budget — a budget is always applied, fail-safe (§6.8 step 2).
DEFAULT_TOOL_CLASSES: Final[dict[str, str]] = {
    "memory_search": "memory_result",
    "memory_get": "memory_result",
}

#: Fail-closed feedback that replaces a tool result the projector could not
#: sanitize: the raw output is never shown to the model (arch §6.8, D21).
#: The raw copy stays with the caller/evidence exactly as before.
_PROJECTION_FAILURE_FEEDBACK: Final[str] = (
    "[projection failed] The tool result could not be sanitized for the model "
    "context and was withheld. The raw output remains available in the "
    "session evidence; re-request a smaller or simpler result."
)

#: A tool result as the L0 post-tool-call hook receives it: either a
#: ``ToolMessage`` or a state ``Command`` carrying one in ``update["messages"]``.
ToolResult: TypeAlias = ToolMessage | Command[object]


class ProjectorMiddleware(AgentMiddleware):
    """L0 post-tool-call projection of every tool result (arch §6.8, T2.3.2).

    Built on the documented middleware extension point (pinned sources,
    arch §19.1): ``AgentMiddleware.awrap_tool_call`` / ``wrap_tool_call``
    (langchain 1.5.2) receive the executed result and may replace it — the
    projection rewrites the result's ``content`` through the
    :class:`ContextProjector` before it can enter any model context. The
    same fail-closed spirit as ``GuardrailMiddleware`` applies: if the
    projection itself fails, a short safe feedback message is returned
    instead of the raw result.

    The projector is synchronous and pure, so the synchronous hook performs
    the same projection (unlike the async-only ``GuardrailMiddleware``).
    State updates other than ``ToolMessage`` content (artifacts, evidence
    ids) are left untouched — raw copies remain raw (D21).
    """

    __slots__ = ("_projector", "_tool_classes")

    def __init__(
        self,
        projector: ContextProjector,
        *,
        tool_classes: Mapping[str, str] | None = None,
    ) -> None:
        """Bind the projector and the tool-name → budget-class mapping.

        Args:
            projector: the :class:`ContextProjector` carrying the session's
                budgets and secret rules.
            tool_classes: mapping of tool name to budget class (the keys of
                ``ProjectorConfig.budgets`` without the ``_bytes`` suffix);
                entries extend :data:`DEFAULT_TOOL_CLASSES`, unknown tools
                use the projector's default budget.
        """
        self._projector = projector
        self._tool_classes: dict[str, str] = {**DEFAULT_TOOL_CLASSES, **(tool_classes or {})}

    def _tool_class(self, tool_name: str) -> str | None:
        """Resolve the budget class of one tool (``None`` → default budget)."""
        return self._tool_classes.get(tool_name)

    def _project_block(
        self, block: str | dict[str, object], tool_class: str | None
    ) -> str | dict[str, object]:
        """Project one content block (§6.8); non-text blocks pass untouched."""
        if isinstance(block, str):
            return self._projector.project(block, tool_class=tool_class)
        text = block.get("text")
        if isinstance(text, str):
            return {**block, "text": self._projector.project(text, tool_class=tool_class)}
        return block

    def _project_tool_message(self, tool_name: str, message: ToolMessage) -> ToolMessage:
        """Return a copy of one ``ToolMessage`` with projected content."""
        tool_class = self._tool_class(tool_name)
        content = message.content
        if isinstance(content, str):
            projected: str | list[str | dict[str, object]] = self._projector.project(
                content, tool_class=tool_class
            )
        else:
            projected = [self._project_block(block, tool_class) for block in content]
        return message.model_copy(update={"content": projected})

    def _project_command(self, command: Command[object], tool_name: str) -> Command[object]:
        """Project the ``ToolMessage`` objects carried in a state ``Command``."""
        update = command.update
        if not isinstance(update, Mapping):
            return command
        messages = update.get("messages")
        if not isinstance(messages, list):
            return command
        projected: list[object] = []
        changed = False
        for message in messages:
            if isinstance(message, ToolMessage):
                projected.append(self._project_tool_message(tool_name, message))
                changed = True
            else:
                projected.append(message)
        if not changed:
            return command
        return Command[object](update={**update, "messages": projected})

    def _project_result(
        self, request: ToolCallRequest, tool_name: str, result: ToolResult
    ) -> ToolMessage | Command[object]:
        """Project one executed result; on failure return safe feedback.

        Fail-closed (arch §6.8): a projection error must never expose the
        raw tool output to the model, so the whole result is replaced by a
        short feedback message addressed to the tool call.
        """
        try:
            if isinstance(result, ToolMessage):
                return self._project_tool_message(tool_name, result)
            return self._project_command(result, tool_name)
        except Exception:
            # Fail-closed with a diagnostic (Issue #24): the safe feedback
            # alone would hide a broken projector from the operator — the
            # log line carries the tool name and the exception.
            LOG.exception("projection failed for tool %r; returning safe feedback", tool_name)
            return ToolMessage(
                content=_PROJECTION_FAILURE_FEEDBACK,
                tool_call_id=str(request.tool_call.get("id", "")),
            )

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolResult]],
    ) -> ToolMessage | Command[object]:
        """Project the executed result of one tool call (async L0 hook).

        Args:
            request: the L0 tool-call request (``tool_call``: name/args/id).
            handler: the L0 continuation that executes the tool.

        Returns:
            The tool result with sanitized content, or the safe failure
            feedback when the projection itself failed.
        """
        tool_name = str(request.tool_call.get("name", ""))
        result = await handler(request)
        return self._project_result(request, tool_name, result)

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolResult],
    ) -> ToolMessage | Command[object]:
        """Project the executed result of one tool call (sync L0 hook).

        The projector is synchronous and pure, so the synchronous path
        performs exactly the same projection as the async hook.

        Args:
            request: the L0 tool-call request.
            handler: the L0 continuation that executes the tool.

        Returns:
            The tool result with sanitized content, or the safe failure
            feedback when the projection itself failed.
        """
        tool_name = str(request.tool_call.get("name", ""))
        result = handler(request)
        return self._project_result(request, tool_name, result)


def make_projector_middleware(
    projector: ContextProjector | None = None,
    *,
    tool_classes: Mapping[str, str] | None = None,
) -> ProjectorMiddleware:
    """Build the post-tool-call projection middleware for one agent (arch §6.8).

    Wiring helper consistent with the other ``make_*`` factories
    (``make_emit_tool``, ``make_memory_tools``); the engine attaches the
    result to the orchestrator and every subagent in M3.

    Args:
        projector: the session projector; ``None`` builds one with the
            conservative default budgets (secret rules arrive with the
            session wiring, T3.1.1).
        tool_classes: mapping of tool name to budget class; entries extend
            :data:`DEFAULT_TOOL_CLASSES`.

    Returns:
        The middleware instance for this agent.
    """
    return ProjectorMiddleware(
        projector if projector is not None else ContextProjector(),
        tool_classes=tool_classes,
    )


__all__ = [
    "DEFAULT_BUDGETS",
    "DEFAULT_BUDGET_BYTES",
    "DEFAULT_TOOL_CLASSES",
    "UNTRUSTED_BEGIN",
    "UNTRUSTED_END",
    "ContextProjector",
    "ProjectorConfig",
    "ProjectorMiddleware",
    "make_projector_middleware",
    "mask_reference",
    "truncation_marker",
]
