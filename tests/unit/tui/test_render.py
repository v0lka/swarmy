"""``tui/render.py`` — §6.8 markers become styling, never printed text."""

from __future__ import annotations

import pytest

from swarmy.tools.projector import UNTRUSTED_BEGIN, UNTRUSTED_END
from swarmy.tui.render import UNTRUSTED_STYLE, render_untrusted

pytestmark = pytest.mark.unit


def test_genuine_markers_are_stripped_and_paint_the_span_red() -> None:
    """The tag text disappears; the enclosed content gets a red background."""
    rendered = render_untrusted(
        f"a {UNTRUSTED_BEGIN} target said hello {UNTRUSTED_END} b",
        UNTRUSTED_BEGIN,
        UNTRUSTED_END,
    )
    assert str(rendered) == "a  target said hello  b"
    assert "untrusted-target-content" not in str(rendered)
    assert any(UNTRUSTED_STYLE in str(span.style) for span in rendered.spans)


def test_defused_markers_are_dropped_without_toggling() -> None:
    """D24 defused markers are target-typed noise: removed, no state change."""
    defused_begin = f"[defused:{UNTRUSTED_BEGIN[1:-1]}]"
    defused_end = f"[defused:{UNTRUSTED_END[1:-1]}]"
    rendered = render_untrusted(
        f"{UNTRUSTED_BEGIN} keep {defused_end} inside {defused_begin} {UNTRUSTED_END}",
        UNTRUSTED_BEGIN,
        UNTRUSTED_END,
    )
    assert str(rendered) == " keep  inside  "
    assert "defused" not in str(rendered)
    # the whole genuine block is still one red span
    assert all(UNTRUSTED_STYLE in str(span.style) for span in rendered.spans)


def test_unbalanced_begin_highlights_to_the_end() -> None:
    """A missing end marker must not crash or leak the tag text."""
    rendered = render_untrusted(f"{UNTRUSTED_BEGIN} rest of line", UNTRUSTED_BEGIN, UNTRUSTED_END)
    assert str(rendered) == " rest of line"
    assert any(UNTRUSTED_STYLE in str(span.style) for span in rendered.spans)


def test_plain_text_has_no_spans() -> None:
    """Text without markers renders unchanged and unstyled."""
    rendered = render_untrusted("plain text", UNTRUSTED_BEGIN, UNTRUSTED_END)
    assert str(rendered) == "plain text"
    assert not rendered.spans
