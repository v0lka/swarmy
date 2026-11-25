"""Event taxonomy v0.1: envelope, payload models, type registry (arch §5.1-§5.2, T1.3.1).

Every event of the session is one ``EventEnvelope`` carrying a typed payload
model; the ``EventRegistry`` is the *single* place mapping the ``"TypeName"``
string to that payload class (arch §5.2). The 13 built-in types of the v0.1
taxonomy (arch §5.5) are registered at import time; module-defined payload
classes register themselves the same way when their module loads (§8.4).

Payload discipline (arch §5.1, §5.5): payloads carry domain ids plus
sanitized digests only — no nested domain objects, with the single documented
exception of ``ScopeChangedPayload`` (which embeds ``ScopeEntry`` records so
the TUI can render the operator's scope change without a memory read).

Boundary (arch §2.5): this module may import only ``swarmy.memory.models``
plus pydantic/stdlib. The memory-model imports stay runtime-visible on
purpose: pydantic resolves payload field annotations at class creation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence  # runtime: used in the alias value below
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, HttpUrl, field_validator

from swarmy.memory.models import FindingType, ScopeEntry, Severity


class EventSource(StrEnum):
    """Who created the event (arch §5.1); tools never accept it as an argument."""

    PLATFORM = "platform"  # L1 platform components (tools, guardrails, TUI bridges)
    ORCHESTRATOR = "orchestrator"  # the orchestrator itself
    MODULE = "module"  # a subagent module; source_detail = module name


#: Recursive JSON value (G3): the shape of untyped tool-argument dicts of
#: ``emit_event``. Deliberately no ``Any`` — every leaf is a JSON scalar.
#: Containers use the covariant ABCs (``Sequence``/``Mapping``) so that
#: ``dict[str, int]`` / ``list[int]`` arguments stay assignable to payloads.
JsonValue: TypeAlias = (
    str | int | float | bool | Sequence["JsonValue"] | Mapping[str, "JsonValue"] | None
)


class EventEnvelope(BaseModel):
    """One journal record + fan-out unit (arch §5.1).

    ``id`` is the SQLite-assigned journal PK — its monotonic order is the
    delivery order of the bus (§5.3). ``ts`` is UTC (naive datetimes are
    rejected). ``payload`` is a concrete registry payload instance.
    """

    model_config = ConfigDict(extra="forbid")

    id: int  # journal PK (assigned by JournalWriter.append, arch §5.4)
    ts: datetime  # UTC, timezone-aware
    type: str  # registry key, e.g. "FindingCandidate"
    source: EventSource
    source_detail: str  # module name / platform component name
    correlation_id: str = ""  # delegation or finding chain id; "" outside chains
    payload: BaseModel

    @field_validator("ts")
    @classmethod
    def _ts_must_be_utc(cls, value: datetime) -> datetime:
        """Require a timezone-aware stamp normalized to UTC (arch §5.1)."""
        if value.tzinfo is None:
            msg = "EventEnvelope.ts must be timezone-aware (UTC); naive datetime given"
            raise ValueError(msg)
        return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# The 13 payload models of the v0.1 taxonomy (arch §5.5).
# ---------------------------------------------------------------------------

_STRICT = ConfigDict(extra="forbid")  # unknown keys are rejected (arch §5.5)


class TargetSetPayload(BaseModel):
    """Session target recorded (§5.5)."""

    model_config = _STRICT

    target_id: int
    base_url: HttpUrl


class ScopeChangedPayload(BaseModel):
    """Operator changed the scope allowlist (§5.5, §6.3).

    The only payload allowed to embed a domain model: ``ScopeEntry`` records
    are small, operator-authored and needed verbatim by TUI/runtime (§5.5).
    """

    model_config = _STRICT

    added: list[ScopeEntry]
    operator_comment: str


class EndpointsDiscoveredPayload(BaseModel):
    """New endpoint row(s) appeared (§5.5); ``out_of_scope_count`` is 0..len."""

    model_config = _STRICT

    endpoints: list[int]
    out_of_scope_count: int


class EndpointUpdatedPayload(BaseModel):
    """An existing endpoint row was updated (§5.5)."""

    model_config = _STRICT

    endpoint_id: int


class FindingCandidatePayload(BaseModel):
    """A finding candidate was saved (exact shape of arch §5.1)."""

    model_config = _STRICT

    finding_id: int
    finding_type: FindingType
    endpoint_ref: int | None
    evidence_refs: list[int]


class FindingVerifiedPayload(BaseModel):
    """A candidate passed verification (§5.5)."""

    model_config = _STRICT

    finding_id: int
    severity: Severity | None = None
    reason: str | None = None


class FindingRejectedPayload(BaseModel):
    """A candidate was rejected (§5.5)."""

    model_config = _STRICT

    finding_id: int
    severity: Severity | None = None
    reason: str | None = None


class AttackTreeUpdatedPayload(BaseModel):
    """An attack tree grew by one node or one edge (§5.5)."""

    model_config = _STRICT

    tree_id: int
    op: Literal["add_node", "add_edge"]
    node_id: int | None = None
    edge_id: int | None = None


class GuardrailBlockedPayload(BaseModel):
    """A guardrail denied an operation (exact shape of arch §5.1)."""

    model_config = _STRICT

    tool_name: str
    rule_id: str  # rule id or "invariant:<name>" / "judge:<verdict>"
    layer: Literal["invariant", "engine", "module", "judge"]
    reason: str  # human-readable reason (returned to the agent)
    tool_args_digest: str  # sanitized arguments digest (§6.8)


class TaskRequestedPayload(BaseModel):
    """A delegation was requested (§5.5)."""

    model_config = _STRICT

    correlation_id: str
    subagent: str
    status: str
    summary_digest: str


class TaskCompletedPayload(BaseModel):
    """A delegation finished (§5.5)."""

    model_config = _STRICT

    correlation_id: str
    subagent: str
    status: str
    summary_digest: str


class OperatorMessagePayload(BaseModel):
    """A message from the operator chat entered the system (§5.5)."""

    model_config = _STRICT

    text_digest: str


class OperatorDecisionPayload(BaseModel):
    """The operator answered a HITL approval request (§5.5, §7)."""

    model_config = _STRICT

    request_id: str
    decision: Literal["approve", "edit", "reject"]
    edited_args_digest: str | None = None


# ---------------------------------------------------------------------------
# Registry: the single "TypeName" -> payload class mapping (arch §5.2).
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type[BaseModel]] = {}

#: Live read-only view of the registry (name -> payload class).
EVENT_TYPES: Mapping[str, type[BaseModel]] = MappingProxyType(_REGISTRY)


class EventRegistry:
    """Classmethod namespace for the event type registry (arch §5.2).

    Do not instantiate: the registry is process-global by design — one
    session, one taxonomy; module payloads add themselves at load time.
    """

    @classmethod
    def register(cls, name: str, payload_cls: type[BaseModel]) -> None:
        """Add ``name -> payload_cls``; duplicates and non-models are errors.

        Duplicate registration is the module-collision guard (arch §8.4):
        two modules declaring the same event type must fail loudly.
        """
        if not isinstance(payload_cls, type) or not issubclass(payload_cls, BaseModel):
            msg = f"payload class for event {name!r} must be a pydantic BaseModel subclass"
            raise ValueError(msg)
        if name in _REGISTRY:
            msg = (
                f"event type {name!r} is already registered "
                f"(payload {_REGISTRY[name].__name__}); module type collisions are "
                f"forbidden (arch §8.4)"
            )
            raise ValueError(msg)
        _REGISTRY[name] = payload_cls

    @classmethod
    def get(cls, name: str) -> type[BaseModel]:
        """Return the payload class for ``name``.

        Raises ``KeyError`` naming the unknown type and listing what exists.
        """
        try:
            return _REGISTRY[name]
        except KeyError:
            known = ", ".join(sorted(_REGISTRY))
            msg = f"unknown event type {name!r}; registered types: {known}"
            raise KeyError(msg) from None

    @classmethod
    def create(cls, name: str, payload_data: Mapping[str, object]) -> BaseModel:
        """Validate ``payload_data`` against the payload class of ``name``.

        Raises ``KeyError`` for an unknown type and pydantic
        ``ValidationError`` (a ``ValueError``) for an invalid payload.
        """
        payload_cls = cls.get(name)
        return payload_cls.model_validate(payload_data)


#: The 13 built-in types of the v0.1 taxonomy (arch §5.5), registered at
#: import time — importing this module is the bootstrap of the taxonomy.
_BUILTINS: tuple[tuple[str, type[BaseModel]], ...] = (
    ("TargetSet", TargetSetPayload),
    ("ScopeChanged", ScopeChangedPayload),
    ("EndpointsDiscovered", EndpointsDiscoveredPayload),
    ("EndpointUpdated", EndpointUpdatedPayload),
    ("FindingCandidate", FindingCandidatePayload),
    ("FindingVerified", FindingVerifiedPayload),
    ("FindingRejected", FindingRejectedPayload),
    ("AttackTreeUpdated", AttackTreeUpdatedPayload),
    ("GuardrailBlocked", GuardrailBlockedPayload),
    ("TaskRequested", TaskRequestedPayload),
    ("TaskCompleted", TaskCompletedPayload),
    ("OperatorMessage", OperatorMessagePayload),
    ("OperatorDecision", OperatorDecisionPayload),
)

for _name, _payload_cls in _BUILTINS:
    EventRegistry.register(_name, _payload_cls)


__all__ = [
    "EVENT_TYPES",
    "AttackTreeUpdatedPayload",
    "EndpointUpdatedPayload",
    "EndpointsDiscoveredPayload",
    "EventEnvelope",
    "EventRegistry",
    "EventSource",
    "FindingCandidatePayload",
    "FindingRejectedPayload",
    "FindingVerifiedPayload",
    "GuardrailBlockedPayload",
    "JsonValue",
    "OperatorDecisionPayload",
    "OperatorMessagePayload",
    "ScopeChangedPayload",
    "TargetSetPayload",
    "TaskCompletedPayload",
    "TaskRequestedPayload",
]
