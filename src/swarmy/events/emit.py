"""Session-bound ``emit_event`` tool factory (arch §5.2, T1.3.4).

``make_emit_tool`` closes over one session's journal, bus and the caller's
identity, producing the ``emit_event`` tool handed to agents. The agent can
choose only ``type`` and ``payload``: ``source``/``source_detail`` are bound
by the factory and ``correlation_id`` comes from the delegation context — an
agent can never forge an origin (arch §5.2).

Mechanics (arch §5.2): arguments are validated against ``EventRegistry``
(unknown type / invalid payload → ``ValueError`` addressed to the agent);
the envelope is appended to the journal FIRST, then published on the bus —
the journal-first order of arch §5.3.
"""

from __future__ import annotations

from collections.abc import (  # Mapping: used in the alias value
    Awaitable,
    Callable,
    Collection,
    Mapping,
)
from typing import TYPE_CHECKING, TypeAlias

from pydantic import ValidationError

from swarmy.events.models import EventRegistry, EventSource, JsonValue

if TYPE_CHECKING:
    from swarmy.events.bus import EventBus
    from swarmy.events.journal import JournalWriter

#: The ``emit_event`` tool handed to LLM agents (arch §5.2):
#: arguments are exactly ``{type, payload}``.
EmitEventTool: TypeAlias = Callable[[str, Mapping[str, JsonValue]], Awaitable[str]]


def _empty_correlation() -> str:
    """Default provider: outside delegation chains there is no correlation."""
    return ""


def make_emit_tool(
    *,
    journal: JournalWriter,
    bus: EventBus,
    source: EventSource,
    source_detail: str,
    correlation_provider: Callable[[], str] | None = None,
    allowed_types: Collection[str] | None = None,
) -> EmitEventTool:
    """Build one ``emit_event`` tool bound to a session and an identity.

    ``source``/``source_detail`` identify the caller (module name, platform
    component) and are never accepted from the agent (arch §5.2). Until the
    runtime installs the delegation context (T3.2.3), ``correlation_provider``
    defaults to returning ``""``.

    ``allowed_types`` (arch §8.4, T1.5.4) restricts the caller to the event
    types declared in its manifest ``events``: when given, a call with any
    other type fails with a ``ValueError`` addressed to the agent *before*
    the registry is consulted — the session wiring passes ``manifest.events``
    of the module. ``None`` (the default) keeps the platform-wide behaviour:
    any type registered in ``EventRegistry`` is emittable.
    """
    provider = correlation_provider if correlation_provider is not None else _empty_correlation
    allowed: frozenset[str] | None = (
        frozenset(allowed_types) if allowed_types is not None else None
    )

    # ``object`` (not ``JsonValue``) on purpose: L0 builds the tool-call
    # schema from this annotation and rebuilds it later in a namespace where
    # the ``JsonValue`` alias is not importable — a builtin-anchored shape
    # keeps the rebuild resolvable (the alias type-checks the factory API).
    async def emit_event(type: str, payload: Mapping[str, object]) -> str:
        """Emit one session event: validate, append to the journal, fan out.

        Args:
            type: registered event type name, e.g. ``"FindingCandidate"``
                (see the taxonomy in the session documentation). Restricted
                to this agent's declared types when the tool was built with
                ``allowed_types`` (arch §8.4).
            payload: JSON object matching the payload schema of ``type``;
                unknown keys and unknown types are rejected.

        Returns:
            A short confirmation with the journal id of the new event.
        """
        if allowed is not None and type not in allowed:
            declared = ", ".join(sorted(allowed)) or "<none>"
            msg = (
                f"emit_event rejected: event type {type!r} is not declared in this "
                f"agent's manifest (declared: {declared}); an agent may only emit "
                "types listed in its AGENT.md 'events' (arch §8.4)"
            )
            raise ValueError(msg)
        try:
            payload_model = EventRegistry.create(type, payload)
        except KeyError as exc:
            msg = f"emit_event rejected: {exc.args[0]}"
            raise ValueError(msg) from exc
        except ValidationError as exc:
            msg = f"emit_event rejected: invalid payload for type {type!r}: {exc}"
            raise ValueError(msg) from exc
        envelope = await journal.append(
            type=type,
            source=source,
            source_detail=source_detail,
            correlation_id=provider(),
            payload=payload_model,
        )
        await bus.publish(envelope)
        return f"event {type} appended to the journal (id={envelope.id})"

    return emit_event
