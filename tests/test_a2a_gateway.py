from __future__ import annotations

"""Integration tests for A2A-native gateway routes.

Tests the /a2a/agent-card, /a2a/register, and /a2a/verify endpoints
using the in-process ASGI transport (no real network).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.gateway.app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def a2a_config(tmp_path):
    return AirlockConfig(lancedb_path=str(tmp_path / "a2a_rep.lance"))


@pytest.fixture
async def a2a_app(a2a_config):
    app = create_app(a2a_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"a2a_agent_seed_0000000000000000x")


@pytest.fixture
def issuer_kp():
    return KeyPair.from_seed(b"a2a_issuer_seed_000000000000000x")


@pytest.fixture
def target_kp():
    return KeyPair.from_seed(b"a2a_target_seed_000000000000000x")


def _make_vc(issuer_kp: KeyPair, subject_did: str, valid: bool = True) -> dict:
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=subject_did,
        credential_type="AgentAuthorization",
        claims={"role": "agent"},
        validity_days=365 if valid else -1,
    )
    return vc.model_dump(mode="json", by_alias=True)


# ---------------------------------------------------------------------------
# GET /a2a/agent-card
# ---------------------------------------------------------------------------


class TestA2AAgentCard:
    @pytest.mark.asyncio
    async def test_returns_card(self, a2a_app):
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.get("/a2a/agent-card")

        assert resp.status_code == 200
        data = resp.json()
        assert "airlock_did" in data
        assert data["airlock_did"].startswith("did:key:")

    @pytest.mark.asyncio
    async def test_card_has_a2a_fields(self, a2a_app):
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.get("/a2a/agent-card")

        data = resp.json()
        a2a_card = data["a2a_card"]
        assert "name" in a2a_card
        assert a2a_card["name"] == "Airlock Trust Gateway"
        assert "skills" in a2a_card
        assert len(a2a_card["skills"]) == 3

    @pytest.mark.asyncio
    async def test_card_has_trust_metadata(self, a2a_app):
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.get("/a2a/agent-card")

        data = resp.json()
        assert data["supports_semantic_challenge"] is True
        assert "airlock_public_key_multibase" in data

    @pytest.mark.asyncio
    async def test_card_has_provider(self, a2a_app):
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.get("/a2a/agent-card")

        data = resp.json()
        provider = data["a2a_card"]["provider"]
        assert provider["organization"] == "Airlock Protocol"


# ---------------------------------------------------------------------------
# POST /a2a/register
# ---------------------------------------------------------------------------


class TestA2ARegister:
    @pytest.mark.asyncio
    async def test_register_agent(self, a2a_app, agent_kp):
        body = {
            "did": agent_kp.did,
            "public_key_multibase": agent_kp.public_key_multibase,
            "display_name": "A2A Test Agent",
            "endpoint_url": "http://localhost:9999/a2a",
            "skills": [
                {"name": "summarize", "version": "1.0", "description": "Summarize text"},
            ],
        }
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/register", json=body)

        assert resp.status_code == 200
        data = resp.json()
        assert data["registered"] is True
        assert data["did"] == agent_kp.did
        assert data["format"] == "a2a"

    @pytest.mark.asyncio
    async def test_register_then_resolve(self, a2a_app, agent_kp):
        body = {
            "did": agent_kp.did,
            "public_key_multibase": agent_kp.public_key_multibase,
            "display_name": "A2A Resolvable Agent",
            "endpoint_url": "http://localhost:9999/a2a",
        }
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            await client.post("/a2a/register", json=body)
            resp = await client.post("/resolve", json={"target_did": agent_kp.did})

        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True

    @pytest.mark.asyncio
    async def test_register_minimal(self, a2a_app, agent_kp):
        body = {
            "did": agent_kp.did,
            "public_key_multibase": agent_kp.public_key_multibase,
            "display_name": "Minimal Agent",
            "endpoint_url": "http://localhost:9999",
        }
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/register", json=body)

        assert resp.status_code == 200
        assert resp.json()["registered"] is True


# ---------------------------------------------------------------------------
# POST /a2a/verify
# ---------------------------------------------------------------------------


class TestA2AVerify:
    @pytest.mark.asyncio
    async def test_verify_with_valid_credential(self, a2a_app, agent_kp, issuer_kp, target_kp):
        vc_data = _make_vc(issuer_kp, agent_kp.did, valid=True)

        body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "Hello, I need data access"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/verify", json=body)

        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data
        assert "verdict" in data
        assert data["verdict"] in ["VERIFIED", "REJECTED", "DEFERRED"]

    @pytest.mark.asyncio
    async def test_verify_returns_a2a_metadata(self, a2a_app, agent_kp, issuer_kp, target_kp):
        vc_data = _make_vc(issuer_kp, agent_kp.did)

        body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "Request data"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/verify", json=body)

        data = resp.json()
        meta = data["a2a_metadata"]
        assert "airlock_verdict" in meta
        assert "airlock_trust_score" in meta
        assert "airlock_session_id" in meta
        assert "airlock_checks" in meta

    @pytest.mark.asyncio
    async def test_verify_returns_checks(self, a2a_app, agent_kp, issuer_kp, target_kp):
        vc_data = _make_vc(issuer_kp, agent_kp.did)

        body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "Verify me"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/verify", json=body)

        data = resp.json()
        checks = data["checks"]
        check_names = [c["check"] for c in checks]
        assert "schema" in check_names
        assert "signature" in check_names
        assert "credential" in check_names
        assert "reputation" in check_names

    @pytest.mark.asyncio
    async def test_verify_with_expired_credential(self, a2a_app, agent_kp, issuer_kp, target_kp):
        vc_data = _make_vc(issuer_kp, agent_kp.did, valid=False)

        body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "Expired VC"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/verify", json=body)

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "REJECTED"

    @pytest.mark.asyncio
    async def test_verify_with_metadata_action(self, a2a_app, agent_kp, issuer_kp, target_kp):
        vc_data = _make_vc(issuer_kp, agent_kp.did)

        body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "Query data"}],
            "message_metadata": {"airlock_action": "data_query"},
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/verify", json=body)

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_verify_session_id_unique(self, a2a_app, agent_kp, issuer_kp, target_kp):
        vc_data = _make_vc(issuer_kp, agent_kp.did)

        body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "First"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp1 = await client.post("/a2a/verify", json=body)
            resp2 = await client.post("/a2a/verify", json=body)

        assert resp1.json()["session_id"] != resp2.json()["session_id"]

    @pytest.mark.asyncio
    async def test_verify_trust_score_is_float(self, a2a_app, agent_kp, issuer_kp, target_kp):
        vc_data = _make_vc(issuer_kp, agent_kp.did)

        body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "Check score"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            resp = await client.post("/a2a/verify", json=body)

        assert isinstance(resp.json()["trust_score"], float)
        assert 0.0 <= resp.json()["trust_score"] <= 1.0


# ---------------------------------------------------------------------------
# Cross-route integration: A2A registration + Airlock resolve
# ---------------------------------------------------------------------------


class TestA2ACrossRouteIntegration:
    @pytest.mark.asyncio
    async def test_a2a_register_airlock_resolve(self, a2a_app, agent_kp):
        """Agent registers via /a2a/register, then resolves via /resolve."""
        reg_body = {
            "did": agent_kp.did,
            "public_key_multibase": agent_kp.public_key_multibase,
            "display_name": "Cross-Route Agent",
            "endpoint_url": "http://localhost:9999",
            "skills": [{"name": "test", "version": "1.0", "description": "test"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            await client.post("/a2a/register", json=reg_body)
            resolve_resp = await client.post("/resolve", json={"target_did": agent_kp.did})

        data = resolve_resp.json()
        assert data["found"] is True
        assert data["profile"]["display_name"] == "Cross-Route Agent"

    @pytest.mark.asyncio
    async def test_airlock_register_a2a_card(self, a2a_app):
        """Gateway's A2A agent card is always available."""
        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            card_resp = await client.get("/a2a/agent-card")
            health_resp = await client.get("/health")

        card = card_resp.json()
        health = health_resp.json()
        assert card["airlock_did"] == health["airlock_did"]

    @pytest.mark.asyncio
    async def test_a2a_verify_then_reputation(self, a2a_app, agent_kp, issuer_kp, target_kp):
        """Verify via /a2a/verify then check reputation via /reputation/{did}."""
        vc_data = _make_vc(issuer_kp, agent_kp.did)

        verify_body = {
            "sender_did": agent_kp.did,
            "sender_public_key_multibase": agent_kp.public_key_multibase,
            "target_did": target_kp.did,
            "credential": vc_data,
            "message_parts": [{"type": "text", "text": "Check rep after verify"}],
        }

        async with AsyncClient(transport=ASGITransport(app=a2a_app), base_url="http://test") as client:
            await client.post("/a2a/verify", json=verify_body)
            rep_resp = await client.get(f"/reputation/{agent_kp.did}")

        rep_data = rep_resp.json()
        assert "score" in rep_data
        assert isinstance(rep_data["score"], float)
