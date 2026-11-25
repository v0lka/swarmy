"""``ContextProjector`` tests (roadmap T2.3.1, arch §6.8, D21).

Acceptance criteria under test:

* every §6.8 step is covered by a focused unit test;
* the marker formats match arch §6.8 **verbatim** (``[truncated N bytes]``,
  ``[untrusted-target-content begin] ... [untrusted-target-content end]``,
  ``<masked:secret-name>``);
* the four steps compose in the §6.8 order 1→4 (order-chain tests);
* built-in detection masks bearer tokens and ``Authorization``/``Cookie``
  headers while ordinary values pass through untouched.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from swarmy.tools.projector import (
    DEFAULT_BUDGETS,
    UNTRUSTED_BEGIN,
    UNTRUSTED_END,
    ContextProjector,
    ProjectorConfig,
    mask_reference,
    truncation_marker,
)

# ---- verbatim marker formats (arch §6.8) ----


def test_marker_formats_are_verbatim() -> None:
    """The four canonical formats equal the arch §6.8 strings byte for byte."""
    assert UNTRUSTED_BEGIN == "[untrusted-target-content begin]"
    assert UNTRUSTED_END == "[untrusted-target-content end]"
    assert truncation_marker(7) == "[truncated 7 bytes]"
    assert mask_reference("api_key") == "<masked:api_key>"


# ---- step 1: byte budgets ----


def test_step1_within_budget_untouched() -> None:
    """Text within the tool-class budget passes through byte-identical."""
    projector = ContextProjector(budgets={"http_preview_bytes": 100}, mark_untrusted=False)
    text = "a" * 100
    assert projector.project(text, tool_class="http_preview") == text


def test_step1_truncation_marker_verbatim() -> None:
    """Oversized text is truncated to the budget plus the §6.8 marker."""
    projector = ContextProjector(budgets={"http_preview_bytes": 10}, mark_untrusted=False)
    assert projector.project("b" * 15, tool_class="http_preview") == (
        "b" * 10 + "\n[truncated 5 bytes]"
    )


def test_step1_truncation_never_splits_code_points() -> None:
    """A budget cut inside a multi-byte character drops the partial bytes cleanly."""
    projector = ContextProjector(budgets={"http_preview_bytes": 51}, mark_untrusted=False)
    # 100 'é' = 200 utf-8 bytes; 51 bytes keep 25 whole characters (50 bytes).
    assert projector.project("é" * 100, tool_class="http_preview") == (
        "é" * 25 + "\n[truncated 150 bytes]"
    )


def test_step1_unknown_tool_class_uses_conservative_default() -> None:
    """A tool class without an explicit budget entry still gets a budget."""
    projector = ContextProjector(mark_untrusted=False)
    assert projector.project("c" * 4001) == "c" * 4000 + "\n[truncated 1 bytes]"


def test_default_budgets_match_arch_12_1() -> None:
    """The conservative defaults equal the arch §12.1 config sample values."""
    assert DEFAULT_BUDGETS == {"http_preview_bytes": 20_000, "memory_result_bytes": 8_000}


def test_step1_non_positive_budget_rejected() -> None:
    """Budgets of zero or less are a configuration error (fail-fast)."""
    with pytest.raises(ValidationError, match="offending keys"):
        ContextProjector(budgets={"http_preview_bytes": 0})


def test_config_and_budgets_are_mutually_exclusive() -> None:
    """Passing both a full config and a budgets shorthand is ambiguous."""
    with pytest.raises(ValueError, match="either config or budgets"):
        ContextProjector(ProjectorConfig(), budgets={"http_preview_bytes": 1})


def test_budget_for_resolves_keys_and_default() -> None:
    """Budget keys are ``<tool_class>_bytes``; unknown classes get the default."""
    config = ProjectorConfig(budgets={"http_preview_bytes": 100})
    assert config.budget_for("http_preview") == 100
    assert config.budget_for("memory_result") == config.default_budget_bytes
    assert config.budget_for(None) == config.default_budget_bytes


# ---- step 2: secret masking ----


def test_step2_literal_secret_masked() -> None:
    """An injected literal value becomes ``<masked:name>``; the raw value is gone."""
    projector = ContextProjector(secrets={"api_key": "s3cr3t-value"}, mark_untrusted=False)
    out = projector.project("request used s3cr3t-value against /api")
    assert out == "request used <masked:api_key> against /api"


def test_step2_pattern_secret_masked() -> None:
    """An injected regex covers value shapes no literal can match."""
    projector = ContextProjector(
        secret_patterns={"session_cookie": r"SESS=[0-9a-f]{8}"}, mark_untrusted=False
    )
    assert projector.project("cookie: SESS=0123abcd; ok") == "cookie: <masked:session_cookie>; ok"


def test_step2_overlapping_values_masked_longest_first() -> None:
    """Longer literals win, so the shorter value never leaves a residual fragment."""
    projector = ContextProjector(secrets={"short": "abc", "long": "abcd"}, mark_untrusted=False)
    assert projector.project("abcd") == "<masked:long>"
    assert projector.project("abcd abc") == "<masked:long> <masked:short>"


def test_step2_authorization_headers_masked() -> None:
    """Authorization-style header values are masked, the header name survives."""
    projector = ContextProjector(mark_untrusted=False)
    assert projector.project("Authorization: Basic dXNlcjpwYXNz") == (
        "Authorization: <masked:authorization>"
    )
    assert projector.project("Proxy-Authorization: NTLM TlRMTVNTUAABAAA") == (
        "Proxy-Authorization: <masked:authorization>"
    )


def test_step2_cookie_headers_masked() -> None:
    """Cookie-style header values are masked, the header name survives."""
    projector = ContextProjector(mark_untrusted=False)
    assert projector.project("Cookie: session=abc123; theme=dark") == "Cookie: <masked:cookie>"
    assert projector.project("Set-Cookie: SESS=xyz789; HttpOnly") == "Set-Cookie: <masked:cookie>"


def test_step2_bearer_token_masked() -> None:
    """Bearer tokens are masked, the scheme word survives."""
    projector = ContextProjector(mark_untrusted=False)
    assert projector.project("Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig") == "Bearer <masked:bearer>"


def test_step2_ordinary_values_untouched() -> None:
    """Values that match no detector and no injected secret pass through."""
    projector = ContextProjector(mark_untrusted=False)
    text = "X-Custom: hunter2\nnote: Bearer-like\nauth Bearer short\ncount: 42"
    assert projector.project(text) == text


def test_step2_masked_references_not_remasked() -> None:
    """A line already carrying ``<masked:name>`` keeps the concrete secret name."""
    projector = ContextProjector(secrets={"api_key": "s3cr3t-value"}, mark_untrusted=False)
    assert projector.project("Authorization: Bearer s3cr3t-value") == (
        "Authorization: Bearer <masked:api_key>"
    )


def test_step2_invalid_secret_rules_fail_fast() -> None:
    """Broken secret rules raise at construction, never mid-session (arch §4.5)."""
    with pytest.raises(ValueError, match="not a valid regex"):
        ContextProjector(secret_patterns={"bad": "("})
    with pytest.raises(ValueError, match="empty value"):
        ContextProjector(secrets={"blank": ""})


# ---- step 3: untrusted marking ----


def test_step3_untrusted_markers_wrap_verbatim() -> None:
    """Target content is wrapped in the exact §6.8 begin/end markers."""
    projector = ContextProjector()
    out = projector.project("GET /admin HTTP/1.1\r\nHost: target")
    # The wrapped content is normalized in step 4 (CRLF → LF) — inside the markers.
    assert out == f"{UNTRUSTED_BEGIN} GET /admin HTTP/1.1\nHost: target {UNTRUSTED_END}"


def test_step3_marking_can_be_disabled() -> None:
    """Streams that are not target-derived content may opt out of the markers."""
    projector = ContextProjector(mark_untrusted=False)
    assert UNTRUSTED_BEGIN not in projector.project("plain text")


# ---- step 4: normalization ----


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\u202eb", "a\\u202eb"),  # biDi override
        ("a\u2066b\u2069c", "a\\u2066b\\u2069c"),  # biDi isolates
        ("a\u200bb\u200cc\u200dd", "a\\u200bb\\u200cc\\u200dd"),  # zero-width
        ("a\u2060b", "a\\u2060b"),  # word joiner
        ("a\ufeffb", "a\\ufeffb"),  # BOM
        ("a\r\nb\rc", "a\nb\nc"),  # CR-LF and lone CR become LF
        ("a\x00b\x1fc", "a\\u0000b\\u001fc"),  # C0 controls
        ("a\x7fb\x85c", "a\\u007fb\\u0085c"),  # DEL and C1 controls
        ("a\tb\nc", "a\tb\nc"),  # tab and LF are kept
    ],
)
def test_step4_control_chars_and_hidden_unicode_escaped(raw: str, expected: str) -> None:
    """Hidden Unicode and control characters are escaped before entering context."""
    projector = ContextProjector(mark_untrusted=False)
    assert projector.project(raw) == expected


# ---- order chain (§6.8: steps 1→4 in canonical order) ----


def test_order_budget_runs_before_masking() -> None:
    """§6.8 1→2: truncation sees the raw text, masking sees the truncated text.

    The masked reference survives intact — proof that the full secret was
    masked *after* truncation. Had masking run first, the truncated output
    would carry a cut-up ``<masked:api_`` fragment instead.
    """
    projector = ContextProjector(
        budgets={"http_preview_bytes": 12}, secrets={"api_key": "s3cr3t-value"}, mark_untrusted=False
    )
    assert projector.project("s3cr3t-value!", tool_class="http_preview") == (
        "<masked:api_key>\n[truncated 1 bytes]"
    )


def test_order_masking_runs_before_normalization() -> None:
    """§6.8 2→4: masking matches pre-normalization text.

    The literal secret contains a zero-width character; normalization would
    escape it into visible ``\\u200b`` text and the literal would no longer
    match — the fact the whole value is masked proves masking ran first.
    """
    projector = ContextProjector(secrets={"k": "ab\u200bcd"}, mark_untrusted=False)
    assert projector.project("ab\u200bcd") == "<masked:k>"


def test_order_full_chain_composes_in_canonical_order() -> None:
    """§6.8 1→2→3→4 composed: masked ref and truncation marker inside verbatim
    untrusted markers, hidden Unicode escaped.

    Step 3 vs step 4 relative order is output-equivalent (the markers are pure
    ASCII and normalization is idempotent on them); steps 1→2 and 2→4 are
    pinned exactly by the two tests above, and this composite pins the outer
    shape of the final text.
    """
    projector = ContextProjector(
        budgets={"memory_result_bytes": 4000}, secrets={"k": "s3cr3t"}
    )
    out = projector.project("s3cr3t\u202e!", tool_class="memory_result")
    assert out == f"{UNTRUSTED_BEGIN} <masked:k>\\u202e! {UNTRUSTED_END}"


def test_order_chain_with_truncation_inside_markers() -> None:
    """The §6.8 truncation marker lands inside the untrusted wrap."""
    projector = ContextProjector(
        budgets={"http_preview_bytes": 12}, secrets={"api_key": "s3cr3t-value"}
    )
    out = projector.project("s3cr3t-value!", tool_class="http_preview")
    assert out == f"{UNTRUSTED_BEGIN} <masked:api_key>\n[truncated 1 bytes] {UNTRUSTED_END}"
