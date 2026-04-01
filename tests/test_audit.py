from __future__ import annotations

"""Tests for the hash-chained audit trail."""

import asyncio
from datetime import datetime, timezone

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.audit.trail import GENESIS_HASH, AuditEntry, AuditTrail, _compute_hash
from airlock.config import AirlockConfig
from airlock.crypto import KeyPair
from airlock.gateway.app import create_app
from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
)

ADMIN_TOKEN = "test-admin-token-audit"


# ---------------------------------------------------------------------------
# Unit tests: AuditTrail core
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_and_length():
    trail = AuditTrail()
    assert trail.length == 0

    entry = await trail.append(
        event_type="agent_registered",
        actor_did="did:key:zAlice",
        detail={"role": "agent"},
    )
    assert trail.length == 1
    assert entry.event_type == "agent_registered"
    assert entry.actor_did == "did:key:zAlice"
    assert entry.entry_hash != ""


@pytest.mark.asyncio
async def test_genesis_entry_previous_hash():
    """First entry's previous_hash must be all zeros."""
    trail = AuditTrail()
    entry = await trail.append(event_type="test", actor_did="did:key:z1")
    assert entry.previous_hash == GENESIS_HASH


@pytest.mark.asyncio
async def test_chain_links():
    """Each entry's previous_hash equals the prior entry's entry_hash."""
    trail = AuditTrail()
    e1 = await trail.append(event_type="first", actor_did="did:key:z1")
    e2 = await trail.append(event_type="second", actor_did="did:key:z2")
    e3 = await trail.append(event_type="third", actor_did="did:key:z3")

    assert e2.previous_hash == e1.entry_hash
    assert e3.previous_hash == e2.entry_hash


@pytest.mark.asyncio
async def test_verify_chain_intact():
    trail = AuditTrail()
    await trail.append(event_type="a", actor_did="did:key:z1")
    await trail.append(event_type="b", actor_did="did:key:z2")
    await trail.append(event_type="c", actor_did="did:key:z3")

    valid, msg = await trail.verify_chain()
    assert valid is True
    assert msg == "ok"


@pytest.mark.asyncio
async def test_verify_chain_empty():
    trail = AuditTrail()
    valid, msg = await trail.verify_chain()
    assert valid is True


@pytest.mark.asyncio
async def test_verify_chain_detects_tampered_hash():
    """Tampering with an entry's hash is detected by verify_chain."""
    trail = AuditTrail()
    await trail.append(event_type="a", actor_did="did:key:z1")
    await trail.append(event_type="b", actor_did="did:key:z2")

    # Tamper with the first entry's hash
    trail._entries[0].entry_hash = "deadbeef" * 8

    valid, msg = await trail.verify_chain()
    assert valid is False
    assert "entry_hash mismatch" in msg


@pytest.mark.asyncio
async def test_verify_chain_detects_tampered_data():
    """Tampering with entry data (keeping original hash) is detected."""
    trail = AuditTrail()
    await trail.append(event_type="legit", actor_did="did:key:z1")

    # Tamper with the event_type but keep the original hash
    trail._entries[0].event_type = "forged"

    valid, msg = await trail.verify_chain()
    assert valid is False


@pytest.mark.asyncio
async def test_verify_chain_detects_broken_link():
    """Breaking the previous_hash link between entries is detected."""
    trail = AuditTrail()
    await trail.append(event_type="a", actor_did="did:key:z1")
    await trail.append(event_type="b", actor_did="did:key:z2")

    # Break the chain link
    trail._entries[1].previous_hash = "0" * 64

    valid, msg = await trail.verify_chain()
    assert valid is False
    assert "previous_hash mismatch" in msg


@pytest.mark.asyncio
async def test_hash_is_deterministic():
    """Same input produces the same hash."""
    entry = AuditEntry(
        entry_id="fixed-id",
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        event_type="test",
        actor_did="did:key:z1",
        previous_hash=GENESIS_HASH,
    )
    h1 = _compute_hash(entry)
    h2 = _compute_hash(entry)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


@pytest.mark.asyncio
async def test_get_entry_by_id():
    trail = AuditTrail()
    entry = await trail.append(event_type="test", actor_did="did:key:z1")

    found = await trail.get_entry(entry.entry_id)
    assert found is not None
    assert found.entry_id == entry.entry_id

    missing = await trail.get_entry("nonexistent")
    assert missing is None


@pytest.mark.asyncio
async def test_pagination():
    trail = AuditTrail()
    for i in range(10):
        await trail.append(event_type=f"event_{i}", actor_did="did:key:z1")

    # Default: newest first
    page1 = await trail.get_entries(limit=3, offset=0)
    assert len(page1) == 3
    assert page1[0].event_type == "event_9"  # newest first

    page2 = await trail.get_entries(limit=3, offset=3)
    assert len(page2) == 3
    assert page2[0].event_type == "event_6"

    # Beyond range
    beyond = await trail.get_entries(limit=5, offset=20)
    assert len(beyond) == 0


# ---------------------------------------------------------------------------
# Integration tests: Gateway endpoints
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "audit_rep.lance"),
        admin_token=ADMIN_TOKEN,
    )


@pytest.fixture
async def gateway_app(gateway_config):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"audit_agent_seed_000000000000000")


def _admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _make_agent_profile(kp: KeyPair) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name="Audit Test Agent",
        capabilities=[AgentCapability(name="test", version="1.0", description="t")],
        endpoint_url="http://localhost:9999",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_register_creates_audit_entry(gateway_app, agent_kp):
    """POST /register should produce an audit trail entry."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200

    # Allow background task to complete
    await asyncio.sleep(0.05)

    trail = gateway_app.state.audit_trail
    assert trail.length >= 1
    entries = await trail.get_entries(limit=10)
    registered = [e for e in entries if e.event_type == "agent_registered"]
    assert len(registered) >= 1
    assert registered[0].actor_did == agent_kp.did


@pytest.mark.asyncio
async def test_admin_audit_endpoint(gateway_app, agent_kp):
    """GET /admin/audit returns audit entries (requires admin token)."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        await asyncio.sleep(0.05)

        resp = await client.get("/admin/audit?limit=10&offset=0", headers=_admin_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data
    assert data["total"] >= 1
    assert data["limit"] == 10
    assert data["offset"] == 0


@pytest.mark.asyncio
async def test_admin_audit_no_auth(gateway_app):
    """GET /admin/audit without auth should fail."""
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.get("/admin/audit")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_admin_audit_verify_endpoint(gateway_app, agent_kp):
    """GET /admin/audit/verify confirms chain integrity."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        await asyncio.sleep(0.05)

        resp = await client.get("/admin/audit/verify", headers=_admin_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["message"] == "ok"


@pytest.mark.asyncio
async def test_public_audit_latest_empty(gateway_app):
    """GET /audit/latest with no entries returns null hash."""
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.get("/audit/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["chain_length"] == 0
    assert data["latest_hash"] is None


@pytest.mark.asyncio
async def test_public_audit_latest_with_entries(gateway_app, agent_kp):
    """GET /audit/latest returns latest hash after events."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        await asyncio.sleep(0.05)

        resp = await client.get("/audit/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["chain_length"] >= 1
    assert data["latest_hash"] is not None
    assert len(data["latest_hash"]) == 64


@pytest.mark.asyncio
async def test_admin_audit_pagination(gateway_app):
    """Pagination via /admin/audit works correctly."""
    trail = gateway_app.state.audit_trail
    for i in range(5):
        await trail.append(event_type=f"test_{i}", actor_did="did:key:zPagTest")

    async with AsyncClient(transport=ASGITransport(app=gateway_app), base_url="http://test") as client:
        resp = await client.get("/admin/audit?limit=2&offset=0", headers=_admin_headers())
        data = resp.json()
        assert len(data["entries"]) == 2
        assert data["total"] == 5

        resp2 = await client.get("/admin/audit?limit=2&offset=2", headers=_admin_headers())
        data2 = resp2.json()
        assert len(data2["entries"]) == 2

        # Entries should not overlap
        ids1 = {e["entry_id"] for e in data["entries"]}
        ids2 = {e["entry_id"] for e in data2["entries"]}
        assert ids1.isdisjoint(ids2)
