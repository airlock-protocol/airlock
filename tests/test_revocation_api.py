"""Tests for the agent-scoped revocation API endpoints.

Covers:
  POST /admin/revoke/{did}
  POST /admin/unrevoke/{did}
  GET  /admin/revoked
  Revoked agent gets REJECTED on /handshake
  Unrevoked agent can verify again
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential
from airlock.crypto.signing import sign_model
from airlock.gateway.app import create_app
from airlock.schemas import (
    AgentDID,
    HandshakeIntent,
    HandshakeRequest,
    create_envelope,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ADMIN_TOKEN = "test-admin-revoke-api"


@pytest.fixture
def gateway_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "revapi.lance"),
        admin_token=ADMIN_TOKEN,
    )


@pytest.fixture
async def gateway_app(gateway_config):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"revapi_agent_seed_00000000000000")


@pytest.fixture
def issuer_kp():
    return KeyPair.from_seed(b"revapi_issuer_seed_0000000000000")


@pytest.fixture
def target_kp():
    return KeyPair.from_seed(b"revapi_target_seed_0000000000000")


def _admin_headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


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
# POST /admin/revoke/{did}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_succeeds_with_valid_token(gateway_app):
    """POST /admin/revoke/{did} returns did + revoked=true."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/admin/revoke/did:key:test123",
            headers=_admin_headers(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["did"] == "did:key:test123"
    assert data["revoked"] is True


@pytest.mark.asyncio
async def test_revoke_fails_without_token(gateway_app):
    """POST /admin/revoke/{did} without auth returns 401."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/admin/revoke/did:key:test123")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_revoke_fails_with_wrong_token(gateway_app):
    """POST /admin/revoke/{did} with bad token returns 403."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/admin/revoke/did:key:test123",
            headers={"Authorization": "Bearer wrong-token"},
        )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /admin/unrevoke/{did}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unrevoke_works(gateway_app):
    """Revoke then unrevoke returns did + unrevoked=true."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First revoke
        await client.post(
            "/admin/revoke/did:key:torevoke",
            headers=_admin_headers(),
        )
        # Then unrevoke
        resp = await client.post(
            "/admin/unrevoke/did:key:torevoke",
            headers=_admin_headers(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["did"] == "did:key:torevoke"
    assert data["unrevoked"] is True


@pytest.mark.asyncio
async def test_unrevoke_fails_without_token(gateway_app):
    """POST /admin/unrevoke/{did} without auth returns 401."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/admin/unrevoke/did:key:test123")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /admin/revoked
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_revoked_returns_correct_dids(gateway_app):
    """GET /admin/revoked returns revoked list and count."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Revoke two agents
        await client.post(
            "/admin/revoke/did:key:alpha",
            headers=_admin_headers(),
        )
        await client.post(
            "/admin/revoke/did:key:beta",
            headers=_admin_headers(),
        )
        resp = await client.get("/admin/revoked", headers=_admin_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    assert "did:key:alpha" in data["revoked"]
    assert "did:key:beta" in data["revoked"]


@pytest.mark.asyncio
async def test_list_revoked_empty(gateway_app):
    """GET /admin/revoked with no revocations returns empty list."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/admin/revoked", headers=_admin_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0
    assert data["revoked"] == []


@pytest.mark.asyncio
async def test_list_revoked_after_unrevoke(gateway_app):
    """Unrevoking an agent removes it from the revoked list."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/admin/revoke/did:key:temp",
            headers=_admin_headers(),
        )
        await client.post(
            "/admin/unrevoke/did:key:temp",
            headers=_admin_headers(),
        )
        resp = await client.get("/admin/revoked", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


# ---------------------------------------------------------------------------
# Revoked agent gets REJECTED on handshake
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoked_agent_rejected_on_handshake(
    gateway_app, agent_kp, issuer_kp, target_kp
):
    """A revoked agent's handshake gets REJECTED by the orchestrator."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Revoke the agent
        r = await client.post(
            f"/admin/revoke/{agent_kp.did}",
            headers=_admin_headers(),
        )
        assert r.status_code == 200

        # Attempt handshake
        hs = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
        resp = await client.post(
            "/handshake",
            content=hs.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        ack = resp.json()
        assert ack["status"] == "ACCEPTED"
        session_id = ack["session_id"]

        # Poll the session until orchestrator resolves it
        verdict = None
        for _ in range(60):
            await asyncio.sleep(0.05)
            sr = await client.get(f"/session/{session_id}")
            sdata = sr.json()
            if sdata.get("verdict"):
                verdict = sdata["verdict"]
                break

        assert verdict == "REJECTED"


# ---------------------------------------------------------------------------
# Unrevoked agent can verify again
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unrevoked_agent_can_handshake(
    gateway_app, agent_kp, issuer_kp, target_kp
):
    """After unrevoking, an agent's handshake is no longer rejected."""
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Revoke then unrevoke
        await client.post(
            f"/admin/revoke/{agent_kp.did}",
            headers=_admin_headers(),
        )
        await client.post(
            f"/admin/unrevoke/{agent_kp.did}",
            headers=_admin_headers(),
        )

        # Handshake should be accepted and NOT produce a REJECTED verdict
        hs = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
        resp = await client.post(
            "/handshake",
            content=hs.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        ack = resp.json()
        assert ack["status"] == "ACCEPTED"
        session_id = ack["session_id"]

        # Poll -- the verdict should NOT be REJECTED
        last_state = None
        for _ in range(60):
            await asyncio.sleep(0.05)
            sr = await client.get(f"/session/{session_id}")
            sdata = sr.json()
            last_state = sdata.get("state")
            verdict = sdata.get("verdict")
            if verdict:
                assert verdict != "REJECTED"
                break

        # If orchestrator hasn't decided yet, at least confirm it isn't failed
        if last_state:
            assert last_state != "failed"
