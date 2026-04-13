from __future__ import annotations

"""Tests for the compliance agent inventory and gateway routes."""

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.compliance.inventory import AgentInventory
from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel
from airlock.config import AirlockConfig
from airlock.gateway.app import create_app

# ---------------------------------------------------------------------------
# Unit tests: AgentInventory
# ---------------------------------------------------------------------------


def _make_entry(did: str = "did:key:z6MkTest1", **kwargs: object) -> AgentInventoryEntry:
    defaults = {
        "did": did,
        "display_name": "Test Agent",
        "trust_score": 0.5,
        "trust_tier": 0,
    }
    defaults.update(kwargs)
    return AgentInventoryEntry(**defaults)


class TestAgentInventory:
    def test_register_and_get(self) -> None:
        inv = AgentInventory()
        entry = _make_entry()
        result = inv.register(entry)
        assert result.did == entry.did

        fetched = inv.get(entry.did)
        assert fetched is not None
        assert fetched.display_name == "Test Agent"

    def test_get_missing_returns_none(self) -> None:
        inv = AgentInventory()
        assert inv.get("did:key:z6MkNonexistent") is None

    def test_update(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry())
        updated = inv.update("did:key:z6MkTest1", display_name="Updated Agent")
        assert updated is not None
        assert updated.display_name == "Updated Agent"

    def test_update_missing_returns_none(self) -> None:
        inv = AgentInventory()
        assert inv.update("did:key:z6MkNonexistent", display_name="X") is None

    def test_remove(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry())
        assert inv.remove("did:key:z6MkTest1") is True
        assert inv.get("did:key:z6MkTest1") is None

    def test_remove_missing_returns_false(self) -> None:
        inv = AgentInventory()
        assert inv.remove("did:key:z6MkNonexistent") is False

    def test_list_all(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry("did:key:z6MkA"))
        inv.register(_make_entry("did:key:z6MkB"))
        assert len(inv.list_all()) == 2

    def test_list_by_risk(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry("did:key:z6MkA", risk_level=RiskLevel.LOW))
        inv.register(_make_entry("did:key:z6MkB", risk_level=RiskLevel.HIGH))
        inv.register(_make_entry("did:key:z6MkC", risk_level=RiskLevel.LOW))

        low = inv.list_by_risk(RiskLevel.LOW)
        assert len(low) == 2
        high = inv.list_by_risk(RiskLevel.HIGH)
        assert len(high) == 1

    def test_count_by_risk(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry("did:key:z6MkA", risk_level=RiskLevel.LOW))
        inv.register(_make_entry("did:key:z6MkB", risk_level=RiskLevel.HIGH))
        counts = inv.count_by_risk()
        assert counts["low"] == 1
        assert counts["high"] == 1

    def test_search_by_did(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry("did:key:z6MkAlpha", display_name="Alpha Agent"))
        inv.register(_make_entry("did:key:z6MkBeta", display_name="Beta Agent"))
        results = inv.search("alpha")
        assert len(results) == 1
        assert results[0].did == "did:key:z6MkAlpha"

    def test_search_by_name(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry("did:key:z6MkA", display_name="Financial Bot"))
        inv.register(_make_entry("did:key:z6MkB", display_name="Chat Bot"))
        results = inv.search("financial")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------


@pytest.fixture
def compliance_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "comp_inv.lance"),
        compliance_enabled=True,
    )


@pytest.fixture
async def compliance_app(compliance_config):
    app = create_app(compliance_config)
    async with LifespanManager(app):
        yield app


async def test_route_list_inventory_empty(compliance_app):
    transport = ASGITransport(app=compliance_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/inventory")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["agents"] == []


async def test_route_register_and_get_agent(compliance_app):
    transport = ASGITransport(app=compliance_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/compliance/inventory",
            json={
                "did": "did:key:z6MkRouteTest",
                "display_name": "Route Test Agent",
                "trust_score": 0.6,
                "trust_tier": 1,
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["did"] == "did:key:z6MkRouteTest"

        r2 = await client.get("/compliance/inventory/did:key:z6MkRouteTest")
        assert r2.status_code == 200
        assert r2.json()["display_name"] == "Route Test Agent"


async def test_route_get_agent_not_found(compliance_app):
    transport = ASGITransport(app=compliance_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/inventory/did:key:z6MkNonexistent")
    assert r.status_code == 404


async def test_route_auto_risk_classification(compliance_app):
    transport = ASGITransport(app=compliance_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/compliance/inventory",
            json={
                "did": "did:key:z6MkHighRisk",
                "display_name": "High Risk Agent",
                "capabilities": ["financial_transaction", "data_access"],
                "trust_score": 0.3,
                "trust_tier": 0,
            },
        )
        assert r.status_code == 201
        body = r.json()
        # With auto-classify, high-risk caps + low trust => high or critical
        assert body["risk_level"] in ("high", "critical")
