from __future__ import annotations

"""Tests for the hash-chained audit trail."""

import asyncio
from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.audit.trail import GENESIS_HASH, AuditEntry, AuditStore, AuditTrail, _compute_hash
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
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
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
        registered_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_register_creates_audit_entry(gateway_app, agent_kp):
    """POST /register should produce an audit trail entry."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.get("/admin/audit")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_admin_audit_verify_endpoint(gateway_app, agent_kp):
    """GET /admin/audit/verify confirms chain integrity."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
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
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.get("/audit/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["chain_length"] == 0
    assert data["latest_hash"] is None


@pytest.mark.asyncio
async def test_public_audit_latest_with_entries(gateway_app, agent_kp):
    """GET /audit/latest returns latest hash after events."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
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

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
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


# ---------------------------------------------------------------------------
# Persistence tests: AuditStore + AuditTrail with SQLite
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_db_path(tmp_path):
    """Return a temporary SQLite database path for tests."""
    return str(tmp_path / "audit_test.db")


@pytest.mark.asyncio
async def test_audit_persist_survives_restart(audit_db_path):
    """Write entries, close store, reopen — chain must be intact."""
    # -- Session 1: write entries --
    store1 = AuditStore(audit_db_path)
    store1.open()
    trail1 = AuditTrail(store=store1)

    await trail1.append(event_type="a", actor_did="did:key:z1")
    await trail1.append(event_type="b", actor_did="did:key:z2")
    await trail1.append(event_type="c", actor_did="did:key:z3")

    assert trail1.length == 3
    last_hash_session1 = trail1._last_hash
    store1.close()

    # -- Session 2: reopen and verify --
    store2 = AuditStore(audit_db_path)
    store2.open()
    trail2 = AuditTrail(store=store2)

    assert trail2.length == 3
    assert trail2._last_hash == last_hash_session1

    # Chain must verify successfully from disk
    valid, msg = await trail2.verify_chain()
    assert valid is True
    assert msg == "ok"

    # New entries should chain correctly
    e4 = await trail2.append(event_type="d", actor_did="did:key:z4")
    assert e4.previous_hash == last_hash_session1
    assert trail2.length == 4

    valid2, msg2 = await trail2.verify_chain()
    assert valid2 is True
    assert msg2 == "ok"
    store2.close()


@pytest.mark.asyncio
async def test_audit_persist_chain_integrity(audit_db_path):
    """Write entries, verify_chain() on disk data."""
    store = AuditStore(audit_db_path)
    store.open()
    trail = AuditTrail(store=store)

    for i in range(10):
        await trail.append(
            event_type=f"event_{i}",
            actor_did=f"did:key:z{i}",
            detail={"index": i},
        )

    valid, msg = await trail.verify_chain()
    assert valid is True
    assert msg == "ok"
    assert trail.length == 10
    store.close()


@pytest.mark.asyncio
async def test_audit_persist_pagination_from_disk(audit_db_path):
    """Pagination reads from SQLite (newest first)."""
    store = AuditStore(audit_db_path)
    store.open()
    trail = AuditTrail(store=store)

    for i in range(10):
        await trail.append(event_type=f"event_{i}", actor_did="did:key:z1")

    # Page 1: newest first
    page1 = await trail.get_entries(limit=3, offset=0)
    assert len(page1) == 3
    assert page1[0].event_type == "event_9"
    assert page1[1].event_type == "event_8"
    assert page1[2].event_type == "event_7"

    # Page 2
    page2 = await trail.get_entries(limit=3, offset=3)
    assert len(page2) == 3
    assert page2[0].event_type == "event_6"

    # Beyond range
    beyond = await trail.get_entries(limit=5, offset=20)
    assert len(beyond) == 0
    store.close()


@pytest.mark.asyncio
async def test_audit_store_streamed_verification(audit_db_path):
    """Write many entries and verify chain via streamed fetchmany."""
    store = AuditStore(audit_db_path)
    store.open()
    trail = AuditTrail(store=store)

    # Write enough entries to exercise fetchmany batching (> 1 batch if batch=1000)
    for i in range(50):
        await trail.append(
            event_type="bulk",
            actor_did=f"did:key:z{i}",
            detail={"n": i},
        )

    assert trail.length == 50

    # Verification uses get_all_entries_ordered internally
    valid, msg = await trail.verify_chain()
    assert valid is True
    assert msg == "ok"

    # Confirm streamed method returns correct count
    all_entries = await store.get_all_entries_ordered()
    assert len(all_entries) == 50
    # First entry should be oldest
    assert all_entries[0].event_type == "bulk"
    assert all_entries[0].detail == {"n": 0}
    # Last entry should be newest
    assert all_entries[-1].detail == {"n": 49}
    store.close()


@pytest.mark.asyncio
async def test_audit_rotation_chain_id_in_hash():
    """rotation_chain_id=None produces a consistent, deterministic hash."""
    entry_a = AuditEntry(
        entry_id="fixed-id",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        event_type="test",
        actor_did="did:key:z1",
        previous_hash=GENESIS_HASH,
        rotation_chain_id=None,
    )
    entry_b = AuditEntry(
        entry_id="fixed-id",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        event_type="test",
        actor_did="did:key:z1",
        previous_hash=GENESIS_HASH,
        rotation_chain_id=None,
    )
    h_a = _compute_hash(entry_a)
    h_b = _compute_hash(entry_b)
    assert h_a == h_b
    assert len(h_a) == 64

    # With a non-None rotation_chain_id the hash must differ
    entry_c = AuditEntry(
        entry_id="fixed-id",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        event_type="test",
        actor_did="did:key:z1",
        previous_hash=GENESIS_HASH,
        rotation_chain_id="chain-123",
    )
    h_c = _compute_hash(entry_c)
    assert h_c != h_a  # different rotation_chain_id means different hash


@pytest.mark.asyncio
async def test_audit_store_wal_mode(audit_db_path):
    """Verify WAL journal mode is active on the audit database."""
    store = AuditStore(audit_db_path)
    store.open()

    assert store._conn is not None
    row = store._conn.execute("PRAGMA journal_mode").fetchone()
    assert row is not None
    assert row[0].lower() == "wal"
    store.close()


@pytest.mark.asyncio
async def test_audit_store_count(audit_db_path):
    """AuditStore.count() returns the correct number of entries."""
    store = AuditStore(audit_db_path)
    store.open()
    trail = AuditTrail(store=store)

    assert await store.count() == 0

    for i in range(5):
        await trail.append(event_type=f"e{i}", actor_did="did:key:z1")

    assert await store.count() == 5
    store.close()


@pytest.mark.asyncio
async def test_audit_persist_detail_round_trip(audit_db_path):
    """Detail dict survives JSON serialization round-trip through SQLite."""
    store = AuditStore(audit_db_path)
    store.open()
    trail = AuditTrail(store=store)

    detail = {"key": "value", "nested": {"a": 1}, "list": [1, 2, 3]}
    await trail.append(event_type="test", actor_did="did:key:z1", detail=detail)

    entries = await trail.get_entries(limit=1, offset=0)
    assert len(entries) == 1
    assert entries[0].detail == detail
    store.close()


@pytest.mark.asyncio
async def test_audit_trail_in_memory_unchanged():
    """AuditTrail without a store behaves exactly as before (backward compat)."""
    trail = AuditTrail()
    assert trail.length == 0

    e1 = await trail.append(event_type="a", actor_did="did:key:z1")
    e2 = await trail.append(event_type="b", actor_did="did:key:z2")

    assert trail.length == 2
    assert e2.previous_hash == e1.entry_hash

    valid, msg = await trail.verify_chain()
    assert valid is True
    assert msg == "ok"

    page = await trail.get_entries(limit=1, offset=0)
    assert len(page) == 1
    assert page[0].event_type == "b"  # newest first
