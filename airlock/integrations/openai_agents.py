"""OpenAI Agents SDK integration — decorator and guard for agent tool functions."""

from __future__ import annotations

import functools
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from airlock.crypto.keys import KeyPair
from airlock.schemas.envelope import TransportAck
from airlock.sdk.client import AirlockClient
from airlock.sdk.simple import build_signed_handshake

F = TypeVar("F", bound=Callable[..., Coroutine[Any, Any, Any]])


def airlock_guard(
    gateway_url: str,
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str | None = None,
) -> Callable[[F], F]:
    """Decorator that performs an Airlock handshake before each async tool call."""
    _target = target_did or agent_kp.did

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            req = build_signed_handshake(
                agent_kp,
                issuer_kp,
                _target,
                action="tool_call",
                description=f"OpenAI tool: {func.__name__}",
            )
            async with AirlockClient(gateway_url, agent_kp) as client:
                result = await client.handshake(req)
            if not isinstance(result, TransportAck):
                raise PermissionError(f"Airlock rejected tool '{func.__name__}': {result}")
            return await func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


class AirlockAgentGuard:
    """Standalone guard for verifying agent identity before tool execution."""

    def __init__(
        self,
        gateway_url: str,
        agent_kp: KeyPair,
        issuer_kp: KeyPair,
        target_did: str | None = None,
    ) -> None:
        self.gateway_url = gateway_url
        self.agent_kp = agent_kp
        self.issuer_kp = issuer_kp
        self.target_did = target_did or agent_kp.did

    async def check(self, agent_name: str) -> bool:
        """Return True if handshake accepted, raise PermissionError otherwise."""
        req = build_signed_handshake(
            self.agent_kp,
            self.issuer_kp,
            self.target_did,
            action="agent_check",
            description=f"OpenAI agent: {agent_name}",
        )
        async with AirlockClient(self.gateway_url, self.agent_kp) as client:
            result = await client.handshake(req)
        if not isinstance(result, TransportAck):
            raise PermissionError(f"Airlock rejected agent '{agent_name}': {result}")
        return True
