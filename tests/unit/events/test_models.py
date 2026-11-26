"""Event taxonomy tests: registry coverage, validation, envelope (T1.3.1).

Acceptance criteria under test: the registry holds all 14 built-in types of
arch §5.5 plus the platform ``OutboundSecretWarn`` dock, duplicate/non-model
registration fails loudly, ``create`` rejects invalid payloads, and the
envelope defaults ``correlation_id`` to ``""``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from swarmy.events.models import (
    EVENT_TYPES,
    AttackTreeUpdatedPayload,
    EndpointsDiscoveredPayload,
    EndpointUpdatedPayload,
    EventEnvelope,
    EventRegistry,
    EventSource,
    FindingCandidatePayload,
    FindingRejectedPayload,
    FindingVerifiedPayload,
    GuardrailBlockedPayload,
    OperatorDecisionPayload,
    OperatorMessagePayload,
    OutboundSecretWarnPayload,
    ScopeChangedPayload,
    TargetSetPayload,
    TaskCompletedPayload,
    TaskRequestedPayload,
    UnknownEventPayload,
)
from swarmy.memory.models import FindingType, ScopeEntry, Severity

_BUILTIN_TYPES: frozenset[str] = frozenset(
    {
        "TargetSet",
        "ScopeChanged",
        "EndpointsDiscovered",
        "EndpointUpdated",
        "FindingCandidate",
        "FindingVerified",
        "FindingRejected",
        "AttackTreeUpdated",
        "GuardrailBlocked",
        "TaskRequested",
        "TaskCompleted",
        "OperatorMessage",
        "OperatorDecision",
        "OutboundSecretWarn",
    }
)


def test_registry_contains_all_builtin_types() -> None:
    """Every built-in type is registered and maps to a payload model class."""
    assert set(EVENT_TYPES) == _BUILTIN_TYPES
    for name in _BUILTIN_TYPES:
        payload_cls = EventRegistry.get(name)
        assert issubclass(payload_cls, BaseModel), name


def test_register_duplicate_name_raises() -> None:
    """Re-registering a known name is the module-collision error (§8.4)."""
    with pytest.raises(ValueError, match="already registered"):
        EventRegistry.register("TargetSet", TargetSetPayload)


def test_register_non_base_model_raises() -> None:
    """A payload 'class' that is not a pydantic model is rejected."""

    class NotAModel:
        """Stand-in for a wrong registration (deliberately not a model)."""

        pass

    with pytest.raises(ValueError, match="BaseModel"):
        EventRegistry.register("WrongPayload", NotAModel)  # type: ignore[arg-type]


def test_get_unknown_type_raises_helpful_key_error() -> None:
    """The error names the unknown type and lists the registered ones."""
    with pytest.raises(KeyError, match=r"DefinitelyNotAType.*TargetSet"):
        EventRegistry.get("DefinitelyNotAType")


def test_create_builds_typed_payload() -> None:
    """``create`` validates raw data into the concrete payload class."""
    payload = EventRegistry.create(
        "FindingCandidate",
        {
            "finding_id": 7,
            "finding_type": "xss",
            "endpoint_ref": None,
            "evidence_refs": [1, 2],
        },
    )
    assert isinstance(payload, FindingCandidatePayload)
    assert payload.finding_type is FindingType.XSS
    assert payload.evidence_refs == [1, 2]


def test_create_rejects_invalid_payload() -> None:
    """Missing required fields and unknown keys both fail validation."""
    with pytest.raises(ValidationError, match="finding_id"):
        EventRegistry.create(
            "FindingCandidate", {"finding_type": "xss", "endpoint_ref": None}
        )
    with pytest.raises(ValidationError, match="extra"):
        EventRegistry.create(
            "FindingCandidate",
            {
                "finding_id": 1,
                "finding_type": "xss",
                "endpoint_ref": None,
                "evidence_refs": [],
                "unexpected_field": True,
            },
        )


def test_create_unknown_type_raises_key_error() -> None:
    """An unregistered type cannot be instantiated."""
    with pytest.raises(KeyError, match="NoSuchEvent"):
        EventRegistry.create("NoSuchEvent", {})


def _envelope(ts: datetime, payload: BaseModel) -> EventEnvelope:
    """Envelope factory with the boilerplate fixed."""
    return EventEnvelope(
        id=1, ts=ts, type="TargetSet", source=EventSource.PLATFORM,
        source_detail="test", payload=payload,
    )


def test_envelope_correlation_id_defaults_to_empty() -> None:
    """Outside chains the correlation id is the empty string (arch §5.1)."""
    envelope = _envelope(
        datetime.now(UTC),
        TargetSetPayload(target_id=1, base_url="https://example.com"),
    )
    assert envelope.correlation_id == ""


def test_envelope_rejects_naive_ts() -> None:
    """Naive timestamps are forbidden (arch §5.1: ts is UTC)."""
    with pytest.raises(ValidationError, match="timezone-aware"):
        _envelope(datetime(2026, 1, 1), TargetSetPayload(target_id=1, base_url="https://x.io"))


def test_envelope_normalizes_offset_to_utc() -> None:
    """An aware non-UTC stamp is normalized to +00:00."""
    ts = datetime(2026, 1, 1, 3, 0, 0, tzinfo=timezone(timedelta(hours=3)))
    envelope = _envelope(
        ts, TargetSetPayload(target_id=1, base_url="https://example.com")
    )
    assert envelope.ts.utcoffset() == timedelta(0)


def test_scope_changed_embeds_scope_entries() -> None:
    """The one sanctioned nested domain object works (arch §5.5)."""
    payload = ScopeChangedPayload(
        added=[ScopeEntry(id=3, kind="domain", value="example.com", origin="operator")],
        operator_comment="operator approved",
    )
    assert payload.added[0].value == "example.com"


def test_all_payload_models_construct_from_spec_shapes() -> None:
    """Every §5.5 payload accepts its documented field set (round-trip smoke)."""
    scope = ScopeEntry(id=1, kind="domain", value="example.com", origin="config")
    models: list[BaseModel] = [
        TargetSetPayload(target_id=1, base_url="https://example.com"),
        ScopeChangedPayload(added=[scope], operator_comment="ok"),
        EndpointsDiscoveredPayload(endpoints=[1], out_of_scope_count=0),
        EndpointUpdatedPayload(endpoint_id=1),
        FindingCandidatePayload(
            finding_id=1, finding_type=FindingType.XSS, endpoint_ref=None, evidence_refs=[]
        ),
        FindingVerifiedPayload(finding_id=1, severity=Severity.HIGH, reason="confirmed"),
        FindingRejectedPayload(finding_id=1, severity=None, reason="duplicate"),
        AttackTreeUpdatedPayload(tree_id=1, op="add_node", node_id=1),
        AttackTreeUpdatedPayload(tree_id=1, op="add_edge", edge_id=2),
        GuardrailBlockedPayload(
            tool_name="http_post",
            rule_id="invariant:scope",
            layer="invariant",
            reason="out of scope",
            tool_args_digest="<digest>",
        ),
        TaskRequestedPayload(
            correlation_id="c1", subagent="crawler", status="running",
            summary_digest="<digest>",
        ),
        TaskCompletedPayload(
            correlation_id="c1", subagent="crawler", status="done",
            summary_digest="<digest>",
        ),
        OperatorMessagePayload(text_digest="<digest>"),
        OperatorDecisionPayload(
            request_id="req-1", decision="edit", edited_args_digest="<digest>"
        ),
        OutboundSecretWarnPayload(
            tool_name="http_get",
            request_id="0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            secret_names=["api_token"],
            locations=["header:authorization"],
        ),
    ]
    for model in models:
        dumped: dict[str, Any] = model.model_dump(mode="json")
        assert dumped  # each model carries its fields, enums serialized as values


def test_outbound_secret_warn_payload_is_strict() -> None:
    """The warn payload rejects unknown keys (arch §5.5 payload discipline)."""
    with pytest.raises(ValidationError, match="extra"):
        OutboundSecretWarnPayload.model_validate(
            {
                "tool_name": "http_get",
                "request_id": "abc",
                "secret_names": [],
                "locations": [],
                "surprise": 1,
            }
        )


def test_outbound_secret_warn_matches_client_payload_shape() -> None:
    """The registered dock accepts the http client's exact warn field set.

    The client's ``OutboundSecretWarn`` (tools/http) dumps these four fields;
    the registry-side payload must decode rows written from it (#29 ↔ F-5).
    """
    payload = OutboundSecretWarnPayload(
        tool_name="http_post",
        request_id="req-1",
        secret_names=["session_cookie", "bearer"],
        locations=["header:cookie", "body"],
    )
    assert payload.secret_names == ["session_cookie", "bearer"]
    assert EventRegistry.get("OutboundSecretWarn") is OutboundSecretWarnPayload


def test_unknown_event_payload_is_not_registered() -> None:
    """The decode fallback is a reader marker, never an emittable type."""
    assert "UnknownEventPayload" not in EVENT_TYPES
    marker = UnknownEventPayload(
        original_type="ModuleCustomEvent", raw_payload='{"x": 1}'
    )
    assert marker.original_type == "ModuleCustomEvent"
    with pytest.raises(ValidationError, match="extra"):
        UnknownEventPayload.model_validate(
            {"original_type": "t", "raw_payload": "{}", "surprise": 1}
        )


def test_guardrail_blocked_rule_id_spellings_round_trip() -> None:
    """Both stored rule-id spellings survive the payload boundary unchanged.

    Consolidated review #21: layer-1 invariant slots store the canonical
    ``invariant:<name>`` form, the http client's own hop checks historically
    stored the spaced prose form ``invariant: <name>`` — the machine field
    preserves whichever spelling the blocking component wrote; consumers
    must treat the two as the same rule family, and prose stays in
    ``reason``.
    """
    canonical = GuardrailBlockedPayload(
        tool_name="http_get",
        rule_id="invariant:scope",
        layer="invariant",
        reason="target is outside the session allowlist",
        tool_args_digest="<digest>",
    )
    legacy_spaced = GuardrailBlockedPayload(
        tool_name="http_get",
        rule_id="invariant: scope",
        layer="invariant",
        reason="redirect hop left the session allowlist",
        tool_args_digest="<digest>",
    )
    judge = GuardrailBlockedPayload(
        tool_name="http_post",
        rule_id="judge:deny",
        layer="judge",
        reason="judge flagged the payload",
        tool_args_digest="<digest>",
    )
    assert canonical.rule_id == "invariant:scope"
    assert legacy_spaced.rule_id == "invariant: scope"
    assert judge.rule_id == "judge:deny"


# ---------------------------------------------------------------------------
# #35 ↔ F-12: the reset/scoping API of the process-global registry.
# ---------------------------------------------------------------------------


def test_reset_restores_the_builtin_taxonomy() -> None:
    """F-12: reset drops module-added types, keeps exactly the built-ins."""
    class ProbeModulePayload(BaseModel):
        """A module-added type standing in for a loader registration."""

        detail: str

    EventRegistry.register("ProbeModuleEvent", ProbeModulePayload)
    assert "ProbeModuleEvent" in EVENT_TYPES
    EventRegistry.reset()
    assert "ProbeModuleEvent" not in EVENT_TYPES
    assert set(EVENT_TYPES) == _BUILTIN_TYPES
    assert EVENT_TYPES["FindingCandidate"] is FindingCandidatePayload


def test_reset_allows_re_registration_of_a_dropped_name() -> None:
    """After a reset the same type name can register a fresh payload class."""

    class ProbeV1Payload(BaseModel):
        """Schema v1 of the probe event."""

        detail: str

    class ProbeV2Payload(BaseModel):
        """Schema v2 of the probe event (same type name, new fields)."""

        detail: str
        score: int

    EventRegistry.register("ProbeReloadEvent", ProbeV1Payload)
    EventRegistry.reset()
    EventRegistry.register("ProbeReloadEvent", ProbeV2Payload)
    assert EVENT_TYPES["ProbeReloadEvent"] is ProbeV2Payload
    EventRegistry.reset()  # leave the built-in taxonomy for the other tests
    assert set(EVENT_TYPES) == _BUILTIN_TYPES
