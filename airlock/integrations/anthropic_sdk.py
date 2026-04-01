"""Anthropic SDK integration — intercept tool calls with Airlock verification."""

from __future__ import annotations

from typing import Any

from airlock.crypto.keys import KeyPair
from airlock.schemas.envelope import TransportAck
from airlock.sdk.client import AirlockClient
from airlock.sdk.simple import build_signed_handshake


class AirlockToolInterceptor:
    """Verify tool calls via Airlock handshake before allowing execution."""

    def __init__(
        self,
        gateway_url: str,
        agent_keypair: KeyPair,
        issuer_keypair: KeyPair,
        target_did: str | None = None,
    ) -> None:
        self.gateway_url = gateway_url
        self.agent_kp = agent_keypair
        self.issuer_kp = issuer_keypair
        self.target_did = target_did or agent_keypair.did

    async def verify_before_tool(self, tool_name: str, tool_input: dict[str, Any]) -> bool:
        """Verify via Airlock handshake. Returns True on success, raises PermissionError on rejection."""
        req = build_signed_handshake(
            self.agent_kp,
            self.issuer_kp,
            self.target_did,
            action="tool_call",
            description=f"Anthropic tool: {tool_name}",
            claims={"role": "agent", "tool_input_keys": list(tool_input.keys())},
        )
        async with AirlockClient(self.gateway_url, self.agent_kp) as client:
            result = await client.handshake(req)
        if not isinstance(result, TransportAck):
            raise PermissionError(f"Airlock rejected tool '{tool_name}': {result}")
        return True
