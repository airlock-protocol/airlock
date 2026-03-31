from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from airlock.schemas.events import AnyVerificationEvent

logger = logging.getLogger(__name__)

# Type alias for async event handlers
EventHandler = Callable[[AnyVerificationEvent], Awaitable[None]]


class EventBus:
    """Typed async event bus backed by a bounded asyncio.Queue.

    Producers publish events; a single consumer loop dispatches them to
    registered handlers.  The bounded buffer provides back-pressure: if the
    buffer is full, ``try_publish`` returns False and increments a dead-letter
    counter instead of raising.
    """

    def __init__(self, maxsize: int = 1000) -> None:
        self._queue: asyncio.Queue[AnyVerificationEvent] = asyncio.Queue(
            maxsize=maxsize
        )
        self._handlers: list[EventHandler] = []
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._dead_letter_count = 0

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

    def try_publish(self, event: AnyVerificationEvent) -> bool:
        """Enqueue an event; return False if the queue is full (no exception)."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._dead_letter_count += 1
            logger.warning(
                "EventBus queue full; dead-lettered %s for session %s (total_dl=%d)",
                event.event_type,
                event.session_id,
                self._dead_letter_count,
            )
            return False
        logger.debug(
            "EventBus published %s for session %s",
            event.event_type,
            event.session_id,
        )
        return True

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

    async def drain(self, timeout: float = 5.0) -> None:
        """Wait until all currently enqueued events are processed."""
        if self._queue.empty():
            return
        try:
            await asyncio.wait_for(self._queue.join(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "EventBus drain timed out after %.1fs (remaining_qsize=%d)",
                timeout,
                self._queue.qsize(),
            )

    async def stop(self) -> None:
        """Stop the consumer loop after in-flight work finishes."""
        self._running = False
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        # Drain any items left after the cooperative shutdown loop exits.
        dropped = 0
        while True:
            try:
                _event = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            dropped += 1
            self._queue.task_done()
        if dropped:
            self._dead_letter_count += dropped
            logger.error(
                "EventBus shutdown dropped %d unprocessed events (total_dl=%d)",
                dropped,
                self._dead_letter_count,
            )
        logger.info("EventBus consumer loop stopped")

    async def _consume(self) -> None:
        while True:
            try:
                if self._running:
                    event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                else:
                    try:
                        event = self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
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

            self._queue.task_done()

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def qsize(self) -> int:
        """Current number of events waiting in the queue."""
        return self._queue.qsize()

    @property
    def dead_letter_count(self) -> int:
        return self._dead_letter_count

    @property
    def is_running(self) -> bool:
        return self._running
