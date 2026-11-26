"""Event taxonomy v0.1: envelope, payload models, type registry (arch §5.1-§5.2, T1.3.1).

Every event of the session is one ``EventEnvelope`` carrying a typed payload
model; the ``EventRegistry`` is the *single* place mapping the ``"TypeName"``
string to that payload class (arch §5.2). The 14 built-in types of the v0.1
taxonomy (arch §5.5 + the platform ``OutboundSecretWarn`` dock) are
registered at import time; module-defined payload classes register
themselves the same way when their module loads (§8.4).

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
# The 14 payload models of the v0.1 taxonomy (arch §5.5 + OutboundSecretWarn).
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
    # Canonical machine spelling is "invariant:<name>" (guardrails.invariants
    # slots) or "judge:<verdict>". Historical note (consolidated review #21):
    # the http client's *own* hop checks stored the spaced prose form
    # "invariant: <name>" (its rule-id constants) — v0.1 journal rows may
    # therefore carry both spellings of the invariant ids, one per blocking
    # component; prose wording belongs in `reason`, never in this field.
    rule_id: str
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


class OutboundSecretWarnPayload(BaseModel):
    """Non-blocking outbound-secret hygiene warn (arch §6.2, SECURITY.md).

    Appended to the journal when an operator secret value is detected in an
    outgoing request's headers, body or query parameters. The warn never
    blocks the request (the operator passed the credential deliberately);
    it exists so the audit receipt chain (ASI10) records the leak attempt.
    Registered as the 14th built-in type so every journal row is decodable
    (consolidated review #29 ↔ F-5: an unregistered platform type used to
    brick resume/report/TUI decoding of the whole session).
    """

    model_config = _STRICT

    tool_name: str  # platform tool that carried the secret, e.g. "http_get"
    request_id: str  # client request id (CSPRNG uuid4 hex)
    secret_names: list[str]  # operator secret *names* whose values were seen
    locations: list[str]  # e.g. "header:authorization", "body", "query:token"


# ---------------------------------------------------------------------------
# Registry: the single "TypeName" -> payload class mapping (arch §5.2).
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type[BaseModel]] = {}

#: Live read-only view of the registry (name -> payload class).
EVENT_TYPES: Mapping[str, type[BaseModel]] = MappingProxyType(_REGISTRY)


class EventRegistry:
    """Classmethod namespace for the event type registry (arch §5.2).

    Do not instantiate: the registry is process-global by design — one
    session, one taxonomy; module payloads add themselves at load time. The
    lifecycle is per-load: :meth:`reset` restores the built-in taxonomy, and
    the module loader calls it at the start of every ``load()`` so a failed
    or repeated load cannot leak its module types into later loads (F-12,
    review #35).
    """

    @classmethod
    def reset(cls) -> None:
        """Drop every module-added type, restoring the built-in taxonomy (F-12).

        Clears the process-global registry and re-registers the v0.1
        built-in types (the import-time bootstrap set). Called by the module
        loader at the start of each ``load()`` — one load owns one taxonomy:
        stale registrations from an earlier load (a retried failed load, a
        previous session in an embedded process) can no longer collide with
        or shadow the current module set. ``EVENT_TYPES`` stays a live view
        of the same mapping.
        """
        _REGISTRY.clear()
        for name, payload_cls in _BUILTINS:
            EventRegistry.register(name, payload_cls)

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


#: The 14 built-in types of the v0.1 taxonomy (arch §5.5 plus the platform
#: ``OutboundSecretWarn`` dock), registered at import time — importing this
#: module is the bootstrap of the taxonomy.
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
    ("OutboundSecretWarn", OutboundSecretWarnPayload),
)

for _name, _payload_cls in _BUILTINS:
    EventRegistry.register(_name, _payload_cls)


class UnknownEventPayload(BaseModel):
    """Decode fallback for journal rows of a type absent from this registry.

    ``JournalReader`` substitutes this payload when the stored ``type`` has
    no registered payload class in the current process (a module was
    removed/renamed, or the journal was written by a newer build) — one
    unknown row must never brick resume/report/TUI reads (consolidated
    review #7). The envelope keeps the original ``type`` string; consumers
    that must ignore unknown events check for this payload class, while
    statistics surfaces can still count them by type.

    Deliberately NOT registered in ``EventRegistry``: it is a reader-side
    marker, not an emittable taxonomy type.
    """

    model_config = _STRICT

    original_type: str  # the stored (unregistered) event type name
    raw_payload: str  # the stored payload JSON TEXT, kept raw (D21)


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
    "OutboundSecretWarnPayload",
    "ScopeChangedPayload",
    "TargetSetPayload",
    "TaskCompletedPayload",
    "TaskRequestedPayload",
    "UnknownEventPayload",
]
