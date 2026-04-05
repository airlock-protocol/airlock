"""Tests for per-DID rate limiting.

Covers:
  - DIDRateLimiter unit tests (under limit, over limit, window expiry, independence)
  - Integration tests via /handshake (429 status, headers, structured error body)
  - Configuration via AirlockConfig
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential
from airlock.crypto.signing import sign_model
from airlock.gateway.app import create_app
from airlock.gateway.rate_limit import DIDRateLimiter, InMemorySlidingWindow
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

# A syntactically valid DID for unit tests (not tied to a real key).
_VALID_DID_A = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
_VALID_DID_B = "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WNhqq6aKJHH"
_INVALID_DID = "not-a-did"


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
        initiator=AgentDID(
            did=agent_kp.did,
            public_key_multibase=agent_kp.public_key_multibase,
        ),
        intent=HandshakeIntent(
            action="connect",
            description="test",
            target_did=target_did,
        ),
        credential=vc,
        signature=None,
    )
    request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _make_agent_profile(kp: KeyPair) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name="Test Agent",
        capabilities=[
            AgentCapability(name="test", version="1.0", description="test cap"),
        ],
        endpoint_url="http://localhost:9999",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Unit tests — DIDRateLimiter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_did_rate_limiter_allows_under_limit() -> None:
    """Requests under the limit are allowed."""
    backend = InMemorySlidingWindow(max_events=5, window_seconds=60.0)
    limiter = DIDRateLimiter(backend)

    assert await limiter.is_rate_limited(_VALID_DID_A) is False
    assert await limiter.is_rate_limited(_VALID_DID_A) is False


@pytest.mark.asyncio
async def test_did_rate_limiter_blocks_over_limit() -> None:
    """Requests over the limit are blocked."""
    backend = InMemorySlidingWindow(max_events=2, window_seconds=60.0)
    limiter = DIDRateLimiter(backend)

    # First two consume the limit via check()
    r1 = await limiter.check(_VALID_DID_A)
    assert r1.allowed is True
    r2 = await limiter.check(_VALID_DID_A)
    assert r2.allowed is True

    # Third is blocked
    r3 = await limiter.check(_VALID_DID_A)
    assert r3.allowed is False
    assert r3.remaining == 0
    assert await limiter.is_rate_limited(_VALID_DID_A) is True


@pytest.mark.asyncio
async def test_did_rate_limiter_window_expiry() -> None:
    """Old requests expire and the DID becomes unblocked."""
    backend = InMemorySlidingWindow(max_events=1, window_seconds=0.1)
    limiter = DIDRateLimiter(backend)

    r1 = await limiter.check(_VALID_DID_A)
    assert r1.allowed is True

    # Immediately after, limit is hit
    r2 = await limiter.check(_VALID_DID_A)
    assert r2.allowed is False

    # Wait for the window to expire
    time.sleep(0.15)

    r3 = await limiter.check(_VALID_DID_A)
    assert r3.allowed is True


@pytest.mark.asyncio
async def test_different_dids_independent() -> None:
    """Rate limit for DID A does not affect DID B."""
    backend = InMemorySlidingWindow(max_events=1, window_seconds=60.0)
    limiter = DIDRateLimiter(backend)

    # Exhaust DID A's limit
    r1 = await limiter.check(_VALID_DID_A)
    assert r1.allowed is True
    r2 = await limiter.check(_VALID_DID_A)
    assert r2.allowed is False

    # DID B is still allowed
    r3 = await limiter.check(_VALID_DID_B)
    assert r3.allowed is True


@pytest.mark.asyncio
async def test_did_rate_limiter_rejects_invalid_did() -> None:
    """Invalid DID format is immediately rejected (rate-limited)."""
    backend = InMemorySlidingWindow(max_events=100, window_seconds=60.0)
    limiter = DIDRateLimiter(backend)

    assert await limiter.is_rate_limited(_INVALID_DID) is True
    result = await limiter.check(_INVALID_DID)
    assert result.allowed is False


@pytest.mark.asyncio
async def test_did_rate_limiter_record_request_invalid_raises() -> None:
    """record_request raises ValueError for invalid DIDs."""
    backend = InMemorySlidingWindow(max_events=100, window_seconds=60.0)
    limiter = DIDRateLimiter(backend)

    with pytest.raises(ValueError, match="Invalid DID format"):
        await limiter.record_request(_INVALID_DID)


@pytest.mark.asyncio
async def test_did_rate_limiter_check_returns_result() -> None:
    """check() returns a full RateLimitResult with correct fields."""
    backend = InMemorySlidingWindow(max_events=5, window_seconds=60.0)
    limiter = DIDRateLimiter(backend)

    result = await limiter.check(_VALID_DID_A)
    assert result.allowed is True
    assert result.limit == 5
    assert result.remaining == 4
    assert result.reset_at > time.time()


@pytest.mark.asyncio
async def test_did_rate_limiter_is_valid_did() -> None:
    """Static is_valid_did helper works correctly."""
    assert DIDRateLimiter.is_valid_did(_VALID_DID_A) is True
    assert DIDRateLimiter.is_valid_did(_VALID_DID_B) is True
    assert DIDRateLimiter.is_valid_did(_INVALID_DID) is False
    assert DIDRateLimiter.is_valid_did("") is False
    assert DIDRateLimiter.is_valid_did("did:key:") is False
    assert DIDRateLimiter.is_valid_did("did:key:z") is False


# ---------------------------------------------------------------------------
# Integration tests — /handshake DID rate limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_did_rate_limit_in_handshake(tmp_path: object) -> None:
    """DID rate limit is enforced during handshake processing."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "did_rl.lance"),  # type: ignore[arg-type]
        rate_limit_per_ip_per_minute=1000,  # high IP limit so it doesn't interfere
        rate_limit_handshake_per_did_per_minute=2,
        event_bus_drain_timeout_seconds=1.0,
    )
    app = create_app(cfg)
    agent_kp = KeyPair.from_seed(b"did_rl_agent_seed_00000000000000")
    issuer_kp = KeyPair.from_seed(b"did_rl_issuer_seed_0000000000000")
    target_kp = KeyPair.from_seed(b"did_rl_target_seed_0000000000000")

    async with LifespanManager(app, shutdown_timeout=60):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # First two handshakes succeed
            for _ in range(2):
                req = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
                resp = await client.post(
                    "/handshake",
                    content=req.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                )
                assert resp.status_code == 200, resp.text

            # Third handshake from same DID is rate-limited
            req3 = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
            resp3 = await client.post(
                "/handshake",
                content=req3.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp3.status_code == 429


@pytest.mark.asyncio
async def test_did_rate_limit_returns_429(tmp_path: object) -> None:
    """DID rate limit returns 429 with correct error body and Retry-After header."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "did_429.lance"),  # type: ignore[arg-type]
        rate_limit_per_ip_per_minute=1000,
        rate_limit_handshake_per_did_per_minute=1,
        event_bus_drain_timeout_seconds=1.0,
    )
    app = create_app(cfg)
    agent_kp = KeyPair.from_seed(b"did_429_agent_seed_0000000000000")
    issuer_kp = KeyPair.from_seed(b"did_429_issuer_seed_000000000000")
    target_kp = KeyPair.from_seed(b"did_429_target_seed_000000000000")

    async with LifespanManager(app, shutdown_timeout=60):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Exhaust the limit
            req1 = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
            resp1 = await client.post(
                "/handshake",
                content=req1.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp1.status_code == 200

            # Second triggers DID rate limit
            req2 = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
            resp2 = await client.post(
                "/handshake",
                content=req2.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp2.status_code == 429
            body = resp2.json()
            assert body["error"] == "rate_limited"
            assert body["detail"] == "DID rate limit exceeded"
            assert body["status_code"] == 429

            # Verify RFC 6585 headers
            assert "retry-after" in resp2.headers
            assert int(resp2.headers["retry-after"]) >= 1
            assert "x-ratelimit-limit" in resp2.headers
            assert "x-ratelimit-remaining" in resp2.headers
            assert resp2.headers["x-ratelimit-remaining"] == "0"


@pytest.mark.asyncio
async def test_did_rate_limit_does_not_affect_other_dids(tmp_path: object) -> None:
    """Rate-limiting one DID does not block a different DID."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "did_indep.lance"),  # type: ignore[arg-type]
        rate_limit_per_ip_per_minute=1000,
        rate_limit_handshake_per_did_per_minute=1,
        event_bus_drain_timeout_seconds=1.0,
    )
    app = create_app(cfg)
    agent_kp_a = KeyPair.from_seed(b"did_ind_agentA_seed_000000000000")
    agent_kp_b = KeyPair.from_seed(b"did_ind_agentB_seed_000000000000")
    issuer_kp = KeyPair.from_seed(b"did_ind_issuer_seed_00000000000_")
    target_kp = KeyPair.from_seed(b"did_ind_target_seed_00000000000_")

    async with LifespanManager(app, shutdown_timeout=60):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Agent A uses its 1 allowed request
            req_a = _make_signed_handshake(agent_kp_a, issuer_kp, target_kp.did)
            resp_a = await client.post(
                "/handshake",
                content=req_a.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp_a.status_code == 200

            # Agent A is now rate-limited
            req_a2 = _make_signed_handshake(agent_kp_a, issuer_kp, target_kp.did)
            resp_a2 = await client.post(
                "/handshake",
                content=req_a2.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp_a2.status_code == 429

            # Agent B is still allowed (different DID)
            req_b = _make_signed_handshake(agent_kp_b, issuer_kp, target_kp.did)
            resp_b = await client.post(
                "/handshake",
                content=req_b.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp_b.status_code == 200


# ---------------------------------------------------------------------------
# Config test
# ---------------------------------------------------------------------------


def test_did_rate_limit_config() -> None:
    """rate_limit_handshake_per_did_per_minute is configurable via AirlockConfig."""
    cfg_default = AirlockConfig()
    assert cfg_default.rate_limit_handshake_per_did_per_minute == 30

    cfg_custom = AirlockConfig(rate_limit_handshake_per_did_per_minute=10)
    assert cfg_custom.rate_limit_handshake_per_did_per_minute == 10

    # Minimum bound (ge=1)
    with pytest.raises(Exception):
        AirlockConfig(rate_limit_handshake_per_did_per_minute=0)
