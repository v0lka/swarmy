"""Event taxonomy tests: registry coverage, validation, envelope (T1.3.1).

Acceptance criteria under test: the registry holds all 13 built-in types of
arch §5.5, duplicate/non-model registration fails loudly, ``create`` rejects
invalid payloads, and the envelope defaults ``correlation_id`` to ``""``.
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
    ScopeChangedPayload,
    TargetSetPayload,
    TaskCompletedPayload,
    TaskRequestedPayload,
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
    }
)


def test_registry_contains_all_13_builtin_types() -> None:
    """Every §5.5 type is registered and maps to a payload model class."""
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
    ]
    for model in models:
        dumped: dict[str, Any] = model.model_dump(mode="json")
        assert dumped  # each model carries its fields, enums serialized as values
