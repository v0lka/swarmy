"""Display rendering of §6.8 untrusted markers (TUI, arch §6.8/§10).

The verbatim markers are machine boundaries, not operator content: the
console never prints them. Text between a genuine begin/end pair is painted
with a red background; defused marker occurrences (D24) are removed too. The
TUI may not import ``swarmy.tools.projector`` (arch §2.5), so the marker
strings arrive from ``SessionView`` (which reads them off the projector).
"""

from __future__ import annotations

import re
from typing import Final

from rich.text import Text

#: Background painted on untrusted (target-derived) spans.
UNTRUSTED_STYLE: Final[str] = "on dark_red"


def _defused(marker: str) -> str:
    """The D24 display form of one containment marker."""
    return f"[defused:{marker[1:-1]}]"


def render_untrusted(text: str, begin: str, end: str) -> Text:
    """Render one sanitized text with §6.8 markers turned into styling.

    Genuine begin/end markers toggle the red background and disappear;
    defused markers disappear without toggling (they are target-typed noise
    inside an already-marked block). An unbalanced begin highlights to the
    end of the text; an unbalanced end is simply dropped.
    """
    pattern = re.compile(
        "|".join(re.escape(marker) for marker in (begin, end, _defused(begin), _defused(end)))
    )
    rendered = Text()
    cursor = 0
    in_untrusted = False
    for match in pattern.finditer(text):
        rendered.append(
            text[cursor : match.start()], style=UNTRUSTED_STYLE if in_untrusted else ""
        )
        token = match.group(0)
        if token == begin:
            in_untrusted = True
        elif token == end:
            in_untrusted = False
        cursor = match.end()
    rendered.append(text[cursor:], style=UNTRUSTED_STYLE if in_untrusted else "")
    return rendered


__all__ = ["UNTRUSTED_STYLE", "render_untrusted"]
