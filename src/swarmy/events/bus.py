"""In-memory pub/sub with one queue per subscriber (arch §5.3, T1.3.3).

Delivery discipline: publish puts the envelope into every matching
subscriber queue; each subscriber is drained by its own dispatcher task, so
a single publisher yields per-subscriber FIFO delivery. Because the journal
append (which assigns the ``id``) happens before fan-out, every subscriber
observes events in ascending ``id`` order — the journal-first property of
arch §5.3.

Failure discipline: a handler exception is isolated — logged (with full
traceback) under the ``swarmy.events`` logger and the dispatcher moves on to
the next event; other subscribers are unaffected.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Set

from swarmy.events.models import EventEnvelope

#: Library logger (handler exceptions land here, arch §5.3).
_LOG = logging.getLogger("swarmy.events")

#: Async subscriber callback signature.
Handler = Callable[[EventEnvelope], Awaitable[None]]


class Subscription:
    """One subscriber: its queue, its dispatcher task, its unsubscribe."""

    __slots__ = ("_bus", "handler", "queue", "task", "types")

    def __init__(self, handler: Handler, types: Set[str] | None, bus: EventBus) -> None:
        """Bind the handler and start its dispatcher task (running loop needed)."""
        self.handler = handler
        self.types = types  # None = all events (arch §5.3)
        self.queue: asyncio.Queue[EventEnvelope] = asyncio.Queue()
        self.task: asyncio.Task[None] = asyncio.create_task(
            self._dispatch(), name="swarmy-events-dispatcher"
        )
        self._bus = bus

    async def _dispatch(self) -> None:
        """Drain the queue forever; handler errors never stop delivery."""
        while True:
            envelope = await self.queue.get()
            try:
                await self.handler(envelope)
            except Exception:
                _LOG.exception(
                    "subscriber handler failed for event id=%s type=%s",
                    envelope.id,
                    envelope.type,
                )
            finally:
                self.queue.task_done()

    def unsubscribe(self) -> None:
        """Cancel this dispatcher; no further events are delivered."""
        self._bus._remove(self)
        self.task.cancel()


class EventBus:
    """Asynchronous fan-out point between the journal and subscribers (§5.3).

    v0.1 subscribers: ``OrchestratorRuntime``, the TUI feed, audit glue.
    This class knows nothing about them — wiring stays in the engine.
    """

    def __init__(self) -> None:
        """Start with no subscriptions."""
        self._subs: list[Subscription] = []

    def subscribe(self, handler: Handler, types: Set[str] | None = None) -> Subscription:
        """Register ``handler``; ``types=None`` subscribes to every event.

        Each call creates an independent queue + dispatcher task (arch §5.3).
        """
        subscription = Subscription(handler, types, self)
        self._subs.append(subscription)
        return subscription

    def _remove(self, subscription: Subscription) -> None:
        """Detach one subscription (idempotent, used by unsubscribe/close)."""
        if subscription in self._subs:
            self._subs.remove(subscription)

    async def publish(self, envelope: EventEnvelope) -> None:
        """Fan one journal-committed envelope out to every matching queue.

        Matching is by subscription type filter (``None`` = all). Delivery is
        per-subscriber FIFO, so ids arrive in ascending order per subscriber.
        """
        for subscription in list(self._subs):
            if subscription.types is None or envelope.type in subscription.types:
                subscription.queue.put_nowait(envelope)

    async def close(self) -> None:
        """Cancel every dispatcher and wait for all tasks to finish."""
        subs, self._subs = self._subs, []
        for subscription in subs:
            subscription.task.cancel()
        if subs:
            await asyncio.gather(*(sub.task for sub in subs), return_exceptions=True)
