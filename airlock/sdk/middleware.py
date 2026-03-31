from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from starlette.requests import Request as StarletteRequest

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_model
from airlock.schemas import create_envelope
from airlock.schemas.envelope import TransportNack
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.requests import HeartbeatRequest
from airlock.sdk.client import AirlockClient

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Coroutine[Any, Any, Any]])


class AirlockMiddleware:
    """Drop-in protection decorator for agent handlers."""

    def __init__(self, airlock_url: str, agent_private_key: KeyPair, timeout: float = 10.0) -> None:
        self._agent_kp = agent_private_key
        self._client = AirlockClient(
            base_url=airlock_url,
            agent_keypair=agent_private_key,
            timeout=timeout,
        )
        self._heartbeat_task: asyncio.Task[None] | None = None

    def protect(self, func: F) -> F:
        """Decorator that gates an async handler behind Airlock verification."""

        @functools.wraps(func)
        async def wrapper(
            request: HandshakeRequest | StarletteRequest, *args: Any, **kwargs: Any
        ) -> Any:
            if isinstance(request, StarletteRequest):
                raw = await request.json()
                hs = HandshakeRequest.model_validate(raw)
            else:
                hs = request
            result = await self._client.handshake(hs)
            if isinstance(result, TransportNack):
                raise PermissionError(
                    f"Airlock rejected handshake: [{result.error_code}] {result.reason}"
                )
            return await func(hs, *args, **kwargs)

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
                    env = create_envelope(sender_did=agent_did)
                    hb = HeartbeatRequest(
                        agent_did=agent_did,
                        endpoint_url=endpoint_url,  # type: ignore[arg-type]
                        envelope=env,
                        signature=None,
                    )
                    hb.signature = sign_model(hb, self._agent_kp.signing_key)
                    await self._client.heartbeat(hb)
                except Exception as exc:
                    logger.warning("Heartbeat failed: %s", exc)
                await asyncio.sleep(interval)

        self._heartbeat_task = asyncio.ensure_future(_beat())

    def stop_heartbeat(self) -> None:
        """Cancel the background heartbeat task."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
