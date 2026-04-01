"""Tests for framework integrations (LangChain, OpenAI Agents, Anthropic SDK)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from airlock.crypto.keys import KeyPair
from airlock.schemas.envelope import MessageEnvelope, TransportAck, TransportNack

# ── Helpers ───────────────────────────────────────────────────────────


def _envelope() -> MessageEnvelope:
    return MessageEnvelope(
        protocol_version="0.1.0",
        timestamp=datetime.now(UTC),
        sender_did="did:key:test",
        nonce="0" * 32,
    )


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def keypair() -> KeyPair:
    return KeyPair.generate()


@pytest.fixture()
def issuer_kp() -> KeyPair:
    return KeyPair.generate()


@pytest.fixture()
def ack() -> TransportAck:
    return TransportAck(
        status="ACCEPTED",
        session_id="sess-1",
        timestamp=datetime.now(UTC),
        envelope=_envelope(),
    )


@pytest.fixture()
def nack() -> TransportNack:
    return TransportNack(
        status="REJECTED",
        session_id="sess-1",
        reason="policy_violation",
        error_code="POLICY_VIOLATION",
        timestamp=datetime.now(UTC),
        envelope=_envelope(),
    )


GATEWAY = "http://localhost:8000"


# ── LangChain integration ────────────────────────────────────────────


class TestLangChainIntegration:
    async def test_verify_passes(
        self, keypair: KeyPair, issuer_kp: KeyPair, ack: TransportAck
    ) -> None:
        from airlock.integrations.langchain import AirlockToolGuard

        guard = AirlockToolGuard(GATEWAY, keypair, issuer_kp)

        with patch("airlock.integrations.langchain.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=ack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            # _verify should complete without error on ACK
            await guard._verify("search")
            instance.handshake.assert_called_once()

    async def test_verify_rejected(
        self, keypair: KeyPair, issuer_kp: KeyPair, nack: TransportNack
    ) -> None:
        from airlock.integrations.langchain import AirlockToolGuard

        guard = AirlockToolGuard(GATEWAY, keypair, issuer_kp)

        with patch("airlock.integrations.langchain.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=nack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(PermissionError, match="rejected"):
                await guard._verify("bad_tool")

    async def test_wrap_calls_verify(self, keypair: KeyPair, issuer_kp: KeyPair) -> None:
        """wrap() returns a tool whose _arun calls _verify then delegates."""
        from airlock.integrations.langchain import AirlockToolGuard

        guard = AirlockToolGuard(GATEWAY, keypair, issuer_kp)
        guard._verify = AsyncMock()  # type: ignore[method-assign]

        mock_tool = MagicMock()
        mock_tool.name = "search"
        mock_tool.description = "Search the web"
        mock_tool._arun = AsyncMock(return_value="result-42")

        # Mock langchain_core.tools.BaseTool for the deferred import
        import sys

        fake_tools = MagicMock()
        fake_tools.BaseTool = type(
            "BaseTool",
            (),
            {
                "__init_subclass__": classmethod(lambda cls, **kw: None),
            },
        )
        with patch.dict(
            sys.modules,
            {
                "langchain_core": MagicMock(),
                "langchain_core.tools": fake_tools,
            },
        ):
            wrapped = guard.wrap(mock_tool)
            result = await wrapped._arun("query")
            assert result == "result-42"
            guard._verify.assert_called_once_with("search")

    async def test_handshake_fields_langchain(
        self, keypair: KeyPair, issuer_kp: KeyPair, ack: TransportAck
    ) -> None:
        from airlock.integrations.langchain import AirlockToolGuard

        guard = AirlockToolGuard(GATEWAY, keypair, issuer_kp, target_did="did:example:target")

        with patch("airlock.integrations.langchain.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=ack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await guard._verify("my_tool")
            call_args = instance.handshake.call_args[0][0]
            assert call_args.intent.action == "tool_call"
            assert "my_tool" in call_args.intent.description

    def test_deferred_import_langchain(self) -> None:
        """Importing the module does NOT require langchain_core to be installed."""
        import airlock.integrations.langchain  # noqa: F401


# ── OpenAI Agents integration ────────────────────────────────────────


class TestOpenAIAgentsIntegration:
    async def test_decorator_passes(
        self, keypair: KeyPair, issuer_kp: KeyPair, ack: TransportAck
    ) -> None:
        from airlock.integrations.openai_agents import airlock_guard

        @airlock_guard(GATEWAY, keypair, issuer_kp)
        async def my_tool(x: int) -> int:
            return x * 2

        with patch("airlock.integrations.openai_agents.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=ack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await my_tool(5)
            assert result == 10

    async def test_decorator_rejected(
        self, keypair: KeyPair, issuer_kp: KeyPair, nack: TransportNack
    ) -> None:
        from airlock.integrations.openai_agents import airlock_guard

        @airlock_guard(GATEWAY, keypair, issuer_kp)
        async def my_tool(x: int) -> int:
            return x * 2

        with patch("airlock.integrations.openai_agents.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=nack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(PermissionError, match="rejected"):
                await my_tool(5)

    async def test_agent_guard_check(
        self, keypair: KeyPair, issuer_kp: KeyPair, ack: TransportAck
    ) -> None:
        from airlock.integrations.openai_agents import AirlockAgentGuard

        guard = AirlockAgentGuard(GATEWAY, keypair, issuer_kp)

        with patch("airlock.integrations.openai_agents.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=ack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            assert await guard.check("my-agent") is True

    async def test_agent_guard_rejected(
        self, keypair: KeyPair, issuer_kp: KeyPair, nack: TransportNack
    ) -> None:
        from airlock.integrations.openai_agents import AirlockAgentGuard

        guard = AirlockAgentGuard(GATEWAY, keypair, issuer_kp)

        with patch("airlock.integrations.openai_agents.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=nack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(PermissionError, match="rejected"):
                await guard.check("bad-agent")

    def test_deferred_import_openai(self) -> None:
        """Importing the module does NOT require openai to be installed."""
        import airlock.integrations.openai_agents  # noqa: F401


# ── Anthropic SDK integration ────────────────────────────────────────


class TestAnthropicIntegration:
    async def test_verify_passes(
        self, keypair: KeyPair, issuer_kp: KeyPair, ack: TransportAck
    ) -> None:
        from airlock.integrations.anthropic_sdk import AirlockToolInterceptor

        interceptor = AirlockToolInterceptor(GATEWAY, keypair, issuer_kp)

        with patch("airlock.integrations.anthropic_sdk.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=ack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await interceptor.verify_before_tool("calculator", {"expr": "2+2"})
            assert result is True

    async def test_verify_rejected(
        self, keypair: KeyPair, issuer_kp: KeyPair, nack: TransportNack
    ) -> None:
        from airlock.integrations.anthropic_sdk import AirlockToolInterceptor

        interceptor = AirlockToolInterceptor(GATEWAY, keypair, issuer_kp)

        with patch("airlock.integrations.anthropic_sdk.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=nack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(PermissionError, match="rejected"):
                await interceptor.verify_before_tool("evil_tool", {"data": "secret"})

    async def test_handshake_fields_anthropic(
        self, keypair: KeyPair, issuer_kp: KeyPair, ack: TransportAck
    ) -> None:
        from airlock.integrations.anthropic_sdk import AirlockToolInterceptor

        interceptor = AirlockToolInterceptor(
            GATEWAY, keypair, issuer_kp, target_did="did:example:t"
        )

        with patch("airlock.integrations.anthropic_sdk.AirlockClient") as MockClient:
            instance = AsyncMock()
            instance.handshake = AsyncMock(return_value=ack)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await interceptor.verify_before_tool("calc", {"x": 1})
            call_args = instance.handshake.call_args[0][0]
            assert call_args.intent.action == "tool_call"
            assert call_args.intent.target_did == "did:example:t"
            assert "calc" in call_args.intent.description

    def test_deferred_import_anthropic(self) -> None:
        """Importing the module does NOT require anthropic to be installed."""
        import airlock.integrations.anthropic_sdk  # noqa: F401
