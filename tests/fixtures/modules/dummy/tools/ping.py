# Tool file of the ``dummy`` fixture module (tests/fixtures/modules/dummy/).
#
# TEMPLATE NOTE (roadmap T1.5.5): this folder is the documented template for
# user modules (arch §8.1 contract) — copy ``tests/fixtures/modules/dummy/``,
# rename the module in AGENT.md, and keep every exported tool function here:
#   * fully annotated parameters and return (no ``Any``/``dict[str, Any]``);
#   * a non-empty LLM-facing docstring;
#   * an explicit ``swarmy_risk_class`` attribute (AD-7; ``passive`` default).
"""Template tool of the ``dummy`` fixture module."""

from __future__ import annotations

from swarmy.guardrails.models import RiskClass


def dummy_ping(message: str = "ping") -> str:
    """Echo ``message`` back prefixed with the module name (template tool).

    Use it to verify that the dummy module loaded and its toolset is wired:
    the tool performs no I/O and only formats its input.

    Args:
        message: any short text to echo back.

    Returns:
        The string ``dummy: <message>``.
    """
    return f"dummy: {message}"


dummy_ping.swarmy_risk_class = RiskClass.PASSIVE  # AD-7 declaration (passive is the default)
