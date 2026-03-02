from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from airlock.crypto.keys import KeyPair
from airlock.schemas.envelope import TransportNack
from airlock.schemas.handshake import HandshakeRequest
from airlock.sdk.client import AirlockClient

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Coroutine[Any, Any, Any]])


class AirlockMiddleware:
    """Drop-in protection decorator for agent handlers."""

    def __init__(self, airlock_url: str, agent_private_key: KeyPair, timeout: float = 10.0) -> None:
        self._client = AirlockClient(
            base_url=airlock_url,
            agent_keypair=agent_private_key,
            timeout=timeout,
        )
        self._heartbeat_task: asyncio.Task[None] | None = None

    def protect(self, func: F) -> F:
        """Decorator that gates an async handler behind Airlock verification."""

        @functools.wraps(func)
        async def wrapper(request: HandshakeRequest, *args: Any, **kwargs: Any) -> Any:
            result = await self._client.handshake(request)
            if isinstance(result, TransportNack):
                raise PermissionError(
                    f"Airlock rejected handshake: [{result.error_code}] {result.reason}"
                )
            return await func(request, *args, **kwargs)

        return wrapper  # type: ignore[return-value]

    def start_heartbeat(
        self,
        agent_did: str,
        endpoint_url: str,
        interval: int = 10,
    ) -> None:
        """Start a background asyncio task that pings /heartbeat every `interval` seconds."""

        async def _beat() -> None:
            while True:
                try:
                    await self._client.heartbeat(agent_did, endpoint_url)
                except Exception as exc:
                    logger.warning("Heartbeat failed: %s", exc)
                await asyncio.sleep(interval)

        self._heartbeat_task = asyncio.ensure_future(_beat())

    def stop_heartbeat(self) -> None:
        """Cancel the background heartbeat task."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
