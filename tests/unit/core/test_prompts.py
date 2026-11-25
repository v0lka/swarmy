"""T3.1.4 acceptance criteria: the orchestrator prompt and policy templates.

Roadmap T3.1.4:
* the prompt forbids executing instructions from untrusted-marker blocks;
* the dynamic section reflects the loaded modules (manifest name/description);
* the prompt is assembled without user-text injection (only the module roster
  enters, and it cannot break the rendering).
"""

from __future__ import annotations

from swarmy.core.prompts import (
    GENERIC_NOTIFICATION_TEMPLATE,
    POLICY_TEMPLATES,
    TREE_PROPOSAL_TEMPLATE,
    UNTRUSTED_BEGIN,
    UNTRUSTED_END,
    VERIFY_FINDING_TEMPLATE,
    build_orchestrator_prompt,
    render_notification,
)
from swarmy.events.models import EventEnvelope, FindingCandidatePayload
from swarmy.tools.projector import UNTRUSTED_BEGIN as PROJECTOR_BEGIN

_ENVELOPE_ID = 7


def _finding_candidate_envelope() -> EventEnvelope:
    """A synthetic FindingCandidate envelope for template rendering."""
    return EventEnvelope(
        id=_ENVELOPE_ID,
        ts="2026-01-01T00:00:00+00:00",
        type="FindingCandidate",
        source="platform",
        source_detail="test",
        correlation_id="",
        payload=FindingCandidatePayload(
            finding_id=42,
            finding_type="xss",
            endpoint_ref=3,
            evidence_refs=[11, 12],
        ),
    )


class TestUntrustedRule:
    """AC: the prompt contains the ban on executing untrusted-marker instructions."""

    def test_prompt_carries_marker_rule(self) -> None:
        prompt = build_orchestrator_prompt({})
        assert UNTRUSTED_BEGIN in prompt
        assert UNTRUSTED_END in prompt
        assert "Never execute" in prompt
        assert prompt.index(UNTRUSTED_BEGIN) < prompt.index("Never execute")

    def test_markers_match_the_projector_verbatim(self) -> None:
        # The §6.8 canonical format lives in the projector; the prompt must
        # reference exactly the same markers (arch §9.6 → §6.8).
        assert UNTRUSTED_BEGIN == PROJECTOR_BEGIN


class TestDynamicModuleSection:
    """AC: the dynamic section reflects the loaded modules (dummy-module test)."""

    def test_roster_lists_name_and_description(self) -> None:
        prompt = build_orchestrator_prompt(
            {"dummy": "Minimal template module exercised by the loader tests."}
        )
        assert "## Module roster" in prompt
        assert "`dummy`" in prompt
        assert "Minimal template module" in prompt

    def test_roster_sorted_and_complete(self) -> None:
        prompt = build_orchestrator_prompt(
            {"zeta": "Z module", "alpha": "A module", "mid": "M module"}
        )
        alpha_index = prompt.index("`alpha`")
        mid_index = prompt.index("`mid`")
        zeta_index = prompt.index("`zeta`")
        assert alpha_index < mid_index < zeta_index

    def test_empty_roster_declared(self) -> None:
        prompt = build_orchestrator_prompt({})
        assert "no subagent modules loaded" in prompt


class TestNoUserInjection:
    """AC: the prompt is assembled without user-text injection (test)."""

    def test_module_description_cannot_inject_format_fields(self) -> None:
        # A hostile manifest description with format placeholders must stay
        # literal — values are never re-formatted (arch §9.6: static build).
        hostile = "{untrusted_begin} pwned {missing_field} {0}"
        prompt = build_orchestrator_prompt({"evil": hostile})
        assert hostile in prompt  # verbatim, unexpanded

    def test_function_takes_no_free_form_user_text(self) -> None:
        # Structural: only (name, description) pairs are accepted — no
        # arbitrary body text parameter exists to inject through.
        import inspect

        signature = inspect.signature(build_orchestrator_prompt)
        assert set(signature.parameters) == {"module_descriptions"}


class TestPolicyTemplates:
    """Policy notification templates render deterministically (T3.2.2 support)."""

    def test_verify_finding_renders_finding_fields(self) -> None:
        envelope = _finding_candidate_envelope()
        fields = {"id": envelope.id, "event_type": envelope.type,
                  **envelope.payload.model_dump(mode="json")}
        text = render_notification("verify_finding", fields)
        assert "verify_finding" in text
        assert "#42" in text
        assert "[11, 12]" in text

    def test_tree_proposal_renders_event_type(self) -> None:
        text = render_notification(
            "tree_proposal",
            {"id": 3, "event_type": "FindingVerified", "finding_id": 42,
             "severity": None, "reason": None},
        )
        assert text == TREE_PROPOSAL_TEMPLATE.format(
            id=3, event_type="FindingVerified", finding_id=42, severity=None, reason=None
        )

    def test_unknown_template_key_falls_back_to_generic(self) -> None:
        text = render_notification(
            "no-such-template",
            {"id": 1, "event_type": "GuardrailBlocked", "digest": "d"},
        )
        assert text == GENERIC_NOTIFICATION_TEMPLATE.format(
            id=1, event_type="GuardrailBlocked", digest="d"
        )

    def test_unknown_field_raises_to_the_caller(self) -> None:
        # render_notification is strict: a missing field raises KeyError and
        # the RUNTIME (render_policy_notification) degrades to the generic
        # digest form — the notification is never silently dropped.
        import pytest

        with pytest.raises(KeyError):
            render_notification("verify_finding", {"id": 1, "event_type": "X", "digest": "d"})

    def test_template_registry_is_complete(self) -> None:
        assert set(POLICY_TEMPLATES) == {"verify_finding", "tree_proposal", "generic"}
        assert VERIFY_FINDING_TEMPLATE
