from __future__ import annotations

import asyncio
import logging
from typing import Callable, Awaitable

from airlock.schemas.events import AnyVerificationEvent

logger = logging.getLogger(__name__)

# Type alias for async event handlers
EventHandler = Callable[[AnyVerificationEvent], Awaitable[None]]


class EventBus:
    """Typed async event bus backed by a bounded asyncio.Queue.

    Producers publish events; a single consumer loop dispatches them to
    registered handlers.  The bounded buffer provides back-pressure: if the
    queue is full, publish() raises asyncio.QueueFull so callers can NACK
    immediately rather than silently blocking.
    """

    def __init__(self, maxsize: int = 1000) -> None:
        self._queue: asyncio.Queue[AnyVerificationEvent] = asyncio.Queue(
            maxsize=maxsize
        )
        self._handlers: list[EventHandler] = []
        self._running = False
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, handler: EventHandler) -> None:
        """Register an async handler that will be called for every event."""
        self._handlers.append(handler)

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    def publish(self, event: AnyVerificationEvent) -> None:
        """Enqueue an event without blocking.

        Raises asyncio.QueueFull if the buffer is at capacity.
        """
        self._queue.put_nowait(event)
        logger.debug(
            "EventBus published %s for session %s",
            event.event_type,
            event.session_id,
        )

    async def publish_async(self, event: AnyVerificationEvent) -> None:
        """Enqueue an event, waiting if the buffer is full."""
        await self._queue.put(event)
        logger.debug(
            "EventBus published (async) %s for session %s",
            event.event_type,
            event.session_id,
        )

    # ------------------------------------------------------------------
    # Consumer loop
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background consumer loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consume())
        logger.info("EventBus consumer loop started")

    async def stop(self) -> None:
        """Gracefully drain the queue and stop the consumer loop."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("EventBus consumer loop stopped")

    async def _consume(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            for handler in self._handlers:
                try:
                    await handler(event)
                except Exception:
                    logger.exception(
                        "EventBus handler %s raised for event %s session %s",
                        handler.__name__,
                        event.event_type,
                        event.session_id,
                    )
                finally:
                    pass

            self._queue.task_done()

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def qsize(self) -> int:
        """Current number of events waiting in the queue."""
        return self._queue.qsize()

    @property
    def is_running(self) -> bool:
        return self._running
