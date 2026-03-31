"""Tests for the agent revocation subsystem."""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.gateway.app import create_app
from airlock.gateway.revocation import RevocationStore
from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    HandshakeIntent,
    HandshakeRequest,
    create_envelope,
)
from airlock.schemas.verdict import VerificationCheck

# ---------------------------------------------------------------------------
# Unit tests: RevocationStore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_new_did():
    store = RevocationStore()
    assert await store.revoke("did:key:abc") is True


@pytest.mark.asyncio
async def test_revoke_already_revoked():
    store = RevocationStore()
    await store.revoke("did:key:abc")
    assert await store.revoke("did:key:abc") is False


@pytest.mark.asyncio
async def test_unrevoke_revoked_did():
    store = RevocationStore()
    await store.revoke("did:key:abc")
    assert await store.unrevoke("did:key:abc") is True


@pytest.mark.asyncio
async def test_unrevoke_not_revoked():
    store = RevocationStore()
    assert await store.unrevoke("did:key:abc") is False


@pytest.mark.asyncio
async def test_is_revoked():
    store = RevocationStore()
    assert await store.is_revoked("did:key:abc") is False
    await store.revoke("did:key:abc")
    assert await store.is_revoked("did:key:abc") is True


@pytest.mark.asyncio
async def test_is_revoked_sync():
    store = RevocationStore()
    assert store.is_revoked_sync("did:key:abc") is False
    await store.revoke("did:key:abc")
    assert store.is_revoked_sync("did:key:abc") is True


@pytest.mark.asyncio
async def test_list_revoked_empty():
    store = RevocationStore()
    assert await store.list_revoked() == []


@pytest.mark.asyncio
async def test_list_revoked_sorted():
    store = RevocationStore()
    await store.revoke("did:key:zzz")
    await store.revoke("did:key:aaa")
    await store.revoke("did:key:mmm")
    result = await store.list_revoked()
    assert result == ["did:key:aaa", "did:key:mmm", "did:key:zzz"]


@pytest.mark.asyncio
async def test_revoke_unrevoke_cycle():
    store = RevocationStore()
    await store.revoke("did:key:abc")
    assert await store.is_revoked("did:key:abc") is True
    await store.unrevoke("did:key:abc")
    assert await store.is_revoked("did:key:abc") is False
    assert await store.list_revoked() == []


# ---------------------------------------------------------------------------
# Integration tests: Gateway endpoints
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "rev.lance"),
        admin_token="test-admin-secret",
    )


@pytest.fixture
async def gateway_app(gateway_config):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"rev_agent_seed_00000000000000000")


@pytest.fixture
def issuer_kp():
    return KeyPair.from_seed(b"rev_issuer_seed_0000000000000000")


@pytest.fixture
def target_kp():
    return KeyPair.from_seed(b"rev_target_seed_0000000000000000")


def _admin_headers():
    return {"Authorization": "Bearer test-admin-secret"}


@pytest.mark.asyncio
async def test_admin_revoke_endpoint(gateway_app):
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/admin/revoke/did:key:test123", headers=_admin_headers()
        )
        assert r.status_code == 200
        data = r.json()
        assert data["revoked"] is True
        assert data["changed"] is True


@pytest.mark.asyncio
async def test_admin_revoke_idempotent(gateway_app):
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/admin/revoke/did:key:dup", headers=_admin_headers())
        r = await client.post("/admin/revoke/did:key:dup", headers=_admin_headers())
        assert r.status_code == 200
        assert r.json()["changed"] is False


@pytest.mark.asyncio
async def test_admin_unrevoke_endpoint(gateway_app):
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/admin/revoke/did:key:abc", headers=_admin_headers())
        r = await client.post(
            "/admin/unrevoke/did:key:abc", headers=_admin_headers()
        )
        assert r.status_code == 200
        data = r.json()
        assert data["unrevoked"] is True
        assert data["changed"] is True


@pytest.mark.asyncio
async def test_admin_list_revoked(gateway_app):
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/admin/revoke/did:key:one", headers=_admin_headers())
        await client.post("/admin/revoke/did:key:two", headers=_admin_headers())
        r = await client.get("/admin/revoked", headers=_admin_headers())
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        assert "did:key:one" in data["revoked"]
        assert "did:key:two" in data["revoked"]


@pytest.mark.asyncio
async def test_public_revocation_check(gateway_app):
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Not revoked
        r = await client.get("/revocation/did:key:clean")
        assert r.status_code == 200
        assert r.json()["revoked"] is False

        # Revoke via admin
        await client.post("/admin/revoke/did:key:clean", headers=_admin_headers())

        # Now revoked
        r = await client.get("/revocation/did:key:clean")
        assert r.status_code == 200
        assert r.json()["revoked"] is True


@pytest.mark.asyncio
async def test_admin_requires_auth(gateway_app):
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/admin/revoke/did:key:test")
        assert r.status_code in (401, 403)
