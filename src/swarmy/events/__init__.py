"""Events subsystem: typed taxonomy, append-only journal, in-memory bus (arch §5).

Boundary-safe re-exports (arch §2.5): consumers of ``swarmy.events`` need no
deeper imports; the package adds no dependencies beyond pydantic/stdlib.
"""

from swarmy.events.bus import EventBus, Handler, Subscription
from swarmy.events.emit import EmitEventTool, make_emit_tool
from swarmy.events.journal import JournalReader, JournalWriter
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
    JsonValue,
    OperatorDecisionPayload,
    OperatorMessagePayload,
    OutboundSecretWarnPayload,
    ScopeChangedPayload,
    TargetSetPayload,
    TaskCompletedPayload,
    TaskRequestedPayload,
    UnknownEventPayload,
)

__all__ = [
    "EVENT_TYPES",
    "AttackTreeUpdatedPayload",
    "EmitEventTool",
    "EndpointUpdatedPayload",
    "EndpointsDiscoveredPayload",
    "EventBus",
    "EventEnvelope",
    "EventRegistry",
    "EventSource",
    "FindingCandidatePayload",
    "FindingRejectedPayload",
    "FindingVerifiedPayload",
    "GuardrailBlockedPayload",
    "Handler",
    "JournalReader",
    "JournalWriter",
    "JsonValue",
    "OperatorDecisionPayload",
    "OperatorMessagePayload",
    "OutboundSecretWarnPayload",
    "ScopeChangedPayload",
    "Subscription",
    "TargetSetPayload",
    "TaskCompletedPayload",
    "TaskRequestedPayload",
    "UnknownEventPayload",
    "make_emit_tool",
]
