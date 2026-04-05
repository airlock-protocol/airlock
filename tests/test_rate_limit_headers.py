"""Tests for RFC 6585 rate-limit headers on 429 responses."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential
from airlock.crypto.signing import sign_model
from airlock.gateway.app import create_app
from airlock.gateway.rate_limit import InMemorySlidingWindow, RateLimitResult
from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    HandshakeIntent,
    HandshakeRequest,
    create_envelope,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent_profile(kp: KeyPair) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name="Test Agent",
        capabilities=[AgentCapability(name="test", version="1.0", description="test cap")],
        endpoint_url="http://localhost:9999",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )


def _make_signed_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
) -> HandshakeRequest:
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={"role": "agent"},
        validity_days=365,
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    request = HandshakeRequest(
        envelope=envelope,
        session_id=str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(action="connect", description="test", target_did=target_did),
        credential=vc,
        signature=None,
    )
    request.signature = sign_model(request, agent_kp.signing_key)
    return request


# ---------------------------------------------------------------------------
# Unit tests — RateLimitResult
# ---------------------------------------------------------------------------


def test_rate_limit_result_retry_after_minimum() -> None:
    """retry_after is at least 1 second even if reset is nearly now."""
    import time

    rl = RateLimitResult(allowed=False, limit=10, remaining=0, reset_at=time.time() + 0.1)
    assert rl.retry_after >= 1


def test_rate_limit_result_retry_after_ceiling() -> None:
    """retry_after uses math.ceil to round up fractional seconds."""
    import time

    rl = RateLimitResult(allowed=False, limit=10, remaining=0, reset_at=time.time() + 5.3)
    assert rl.retry_after >= 5


# ---------------------------------------------------------------------------
# Unit tests — InMemorySlidingWindow.check()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_memory_check_allowed() -> None:
    """check() returns allowed=True with correct remaining count."""
    limiter = InMemorySlidingWindow(max_events=3, window_seconds=60.0)
    result = await limiter.check("key:a")
    assert result.allowed is True
    assert result.limit == 3
    assert result.remaining == 2  # 3 max - 1 used


@pytest.mark.asyncio
async def test_in_memory_check_denied() -> None:
    """check() returns allowed=False with remaining=0 when limit is hit."""
    limiter = InMemorySlidingWindow(max_events=2, window_seconds=60.0)
    await limiter.check("key:b")
    await limiter.check("key:b")
    result = await limiter.check("key:b")
    assert result.allowed is False
    assert result.remaining == 0
    assert result.limit == 2
    assert result.reset_at > 0


@pytest.mark.asyncio
async def test_in_memory_allow_still_works() -> None:
    """Backward-compatible allow() still returns a boolean."""
    limiter = InMemorySlidingWindow(max_events=1, window_seconds=60.0)
    assert await limiter.allow("key:c") is True
    assert await limiter.allow("key:c") is False


# ---------------------------------------------------------------------------
# Integration tests — 429 response headers via /register
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_429_includes_rate_limit_headers(tmp_path: object) -> None:
    """When /register returns 429, the response includes RFC 6585 headers."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rl_hdr.lance"),  # type: ignore[arg-type]
        rate_limit_per_ip_per_minute=1,
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            kp1 = KeyPair.from_seed(b"rl_agent_1_seed_0000000000000000")
            # First request succeeds (uses the 1 allowed event)
            resp1 = await client.post(
                "/register",
                content=_make_agent_profile(kp1).model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp1.status_code == 200

            # Second request from same IP hits rate limit
            kp2 = KeyPair.from_seed(b"rl_agent_2_seed_0000000000000000")
            resp2 = await client.post(
                "/register",
                content=_make_agent_profile(kp2).model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp2.status_code == 429
            assert "retry-after" in resp2.headers
            assert "x-ratelimit-limit" in resp2.headers
            assert "x-ratelimit-remaining" in resp2.headers
            assert "x-ratelimit-reset" in resp2.headers
            assert resp2.headers["x-ratelimit-remaining"] == "0"
            assert int(resp2.headers["x-ratelimit-limit"]) == 1
            assert int(resp2.headers["retry-after"]) >= 1


@pytest.mark.asyncio
async def test_register_200_does_not_include_rate_limit_headers(tmp_path: object) -> None:
    """Normal successful responses should not include rate-limit headers."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rl_ok.lance"),  # type: ignore[arg-type]
        rate_limit_per_ip_per_minute=100,
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            kp = KeyPair.from_seed(b"rl_ok_agent_seed_00000000000000_")
            resp = await client.post(
                "/register",
                content=_make_agent_profile(kp).model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 200
            assert "retry-after" not in resp.headers
            assert "x-ratelimit-limit" not in resp.headers


@pytest.mark.asyncio
async def test_handshake_429_includes_rate_limit_headers(tmp_path: object) -> None:
    """When /handshake returns 429, the response includes RFC 6585 headers."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rl_hs.lance"),  # type: ignore[arg-type]
        rate_limit_per_ip_per_minute=1,
    )
    app = create_app(cfg)
    agent_kp = KeyPair.from_seed(b"rl_hs_agent_seed_000000000000000")
    issuer_kp = KeyPair.from_seed(b"rl_hs_issuer_seed_00000000000000")
    target_kp = KeyPair.from_seed(b"rl_hs_target_seed_00000000000000")

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # First handshake uses the 1 allowed event
            req1 = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
            resp1 = await client.post(
                "/handshake",
                content=req1.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp1.status_code == 200

            # Second triggers rate limit
            req2 = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
            resp2 = await client.post(
                "/handshake",
                content=req2.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp2.status_code == 429
            assert "retry-after" in resp2.headers
            assert "x-ratelimit-limit" in resp2.headers
            assert resp2.headers["x-ratelimit-remaining"] == "0"


@pytest.mark.asyncio
async def test_429_body_follows_rfc7807_shape(tmp_path: object) -> None:
    """The 429 JSON body from /register follows RFC 7807 problem detail format."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rl_body.lance"),  # type: ignore[arg-type]
        rate_limit_per_ip_per_minute=1,
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            kp1 = KeyPair.from_seed(b"rl_body_agent1_seed_000000000000")
            await client.post(
                "/register",
                content=_make_agent_profile(kp1).model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            kp2 = KeyPair.from_seed(b"rl_body_agent2_seed_000000000000")
            resp = await client.post(
                "/register",
                content=_make_agent_profile(kp2).model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 429
            body = resp.json()
            assert body["status"] == 429
            assert body["title"] == "Too Many Requests"
            assert "type" in body
            assert "detail" in body
