"""LangChain integration — wraps any BaseTool with Airlock handshake verification."""

from __future__ import annotations

from typing import Any

from airlock.crypto.keys import KeyPair
from airlock.schemas.envelope import TransportAck
from airlock.sdk.client import AirlockClient
from airlock.sdk.simple import build_signed_handshake


class AirlockToolGuard:
    """Wrap LangChain tools so every invocation performs an Airlock handshake first."""

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

    async def _verify(self, tool_name: str) -> None:
        """Run Airlock handshake; raise PermissionError on rejection."""
        req = build_signed_handshake(
            self.agent_kp,
            self.issuer_kp,
            self.target_did,
            action="tool_call",
            description=f"LangChain tool: {tool_name}",
        )
        async with AirlockClient(self.gateway_url, self.agent_kp) as client:
            result = await client.handshake(req)
        if not isinstance(result, TransportAck):
            raise PermissionError(f"Airlock rejected tool '{tool_name}': {result}")

    def wrap(self, tool: Any) -> Any:
        """Return a new BaseTool subclass that verifies via Airlock before executing."""
        from langchain_core.tools import BaseTool as _BaseTool  # noqa: PLC0415

        guard = self

        class GuardedTool(_BaseTool):  # type: ignore[misc]
            name: str = tool.name
            description: str = tool.description

            async def _arun(self, *args: Any, **kwargs: Any) -> Any:
                await guard._verify(tool.name)
                return await tool._arun(*args, **kwargs)

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                raise NotImplementedError("Use _arun for async Airlock verification")

        return GuardedTool()
