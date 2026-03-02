from __future__ import annotations

"""Phase 3 integration tests: Airlock Gateway (FastAPI + in-process ASGI)."""

import uuid
from datetime import datetime, timezone

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.gateway.app import create_app
from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    HandshakeIntent,
    HandshakeRequest,
    create_envelope,
)
from airlock.schemas.challenge import ChallengeResponse
from airlock.schemas.handshake import SignatureEnvelope


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_config(tmp_path):
    return AirlockConfig(lancedb_path=str(tmp_path / "rep.lance"))


@pytest.fixture
async def gateway_app(gateway_config):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"gw_agent_seed_000000000000000000")


@pytest.fixture
def issuer_kp():
    return KeyPair.from_seed(b"gw_issuer_seed_00000000000000000")


@pytest.fixture
def target_kp():
    return KeyPair.from_seed(b"gw_target_seed_00000000000000000")


def _make_signed_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    session_id: str | None = None,
    validity_days: int = 365,
    sign: bool = True,
) -> HandshakeRequest:
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={"role": "agent"},
        validity_days=validity_days,
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id or str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(action="connect", description="test", target_did=target_did),
        credential=vc,
        signature=None,
    )
    if sign:
        request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _make_agent_profile(kp: KeyPair) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name="Test Agent",
        capabilities=[AgentCapability(name="test", version="1.0", description="test cap")],
        endpoint_url="http://localhost:9999",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_returns_ok(gateway_app):
    """GET /health returns {"status": "ok"}."""
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_register_agent(gateway_app, agent_kp):
    """POST /register with a valid AgentProfile returns {"registered": True}."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["registered"] is True
    assert data["did"] == agent_kp.did


@pytest.mark.asyncio
async def test_resolve_registered_agent(gateway_app, agent_kp):
    """Register then POST /resolve returns found: True."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        resp = await client.post("/resolve", json={"target_did": agent_kp.did})
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["profile"]["did"]["did"] == agent_kp.did


@pytest.mark.asyncio
async def test_resolve_unknown_agent(gateway_app):
    """POST /resolve for unknown DID returns found: False."""
    unknown_did = "did:key:zunknown000000000000000000000000"
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post("/resolve", json={"target_did": unknown_did})
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is False
    assert data["did"] == unknown_did


@pytest.mark.asyncio
async def test_handshake_valid_signature_returns_ack(gateway_app, agent_kp, issuer_kp, target_kp):
    """A properly signed HandshakeRequest returns status ACCEPTED."""
    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post(
            "/handshake",
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"


@pytest.mark.asyncio
async def test_handshake_invalid_signature_returns_nack(gateway_app, agent_kp, issuer_kp, target_kp):
    """A HandshakeRequest with no signature returns status REJECTED."""
    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did, sign=False)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post(
            "/handshake",
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "REJECTED"
    assert data["error_code"] == "INVALID_SIGNATURE"


@pytest.mark.asyncio
async def test_handshake_expired_vc_returns_ack(gateway_app, agent_kp, issuer_kp, target_kp):
    """Gateway ACKs immediately for a valid signature even with expired VC.

    The gateway only checks the transport-layer signature synchronously.
    Async orchestrator handles VC validation and may reject later.
    """
    request = _make_signed_handshake(
        agent_kp, issuer_kp, target_kp.did, validity_days=-1
    )
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post(
            "/handshake",
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"


@pytest.mark.asyncio
async def test_get_reputation_unknown(gateway_app):
    """GET /reputation/{did} returns score 0.5 for an unknown agent."""
    unknown_did = "did:key:zunknownreputationdid00000000000"
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.get(f"/reputation/{unknown_did}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0.5
    assert data["found"] is False


@pytest.mark.asyncio
async def test_heartbeat(gateway_app, agent_kp):
    """POST /heartbeat returns acknowledged: True."""
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post(
            "/heartbeat",
            json={"agent_did": agent_kp.did, "endpoint_url": "http://localhost:9999"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["acknowledged"] is True
    assert data["agent_did"] == agent_kp.did


@pytest.mark.asyncio
async def test_challenge_response_valid_signature(gateway_app, agent_kp):
    """A signed ChallengeResponse returns status ACCEPTED."""
    from airlock.crypto.signing import sign_model as _sign_model

    envelope = create_envelope(sender_did=agent_kp.did)
    challenge_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())

    response = ChallengeResponse(
        envelope=envelope,
        session_id=session_id,
        challenge_id=challenge_id,
        answer="A nonce is a random value used once to prevent replay attacks.",
        confidence=0.9,
        signature=None,
    )
    response.signature = _sign_model(response, agent_kp.signing_key)

    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post(
            "/challenge-response",
            content=response.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"
