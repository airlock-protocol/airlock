"""Tests for compliance inventory and inventory routes."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from airlock.compliance.inventory import AgentInventory
from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel
from airlock.config import AirlockConfig
from airlock.gateway.app import create_app


def _make_entry(
    did: str = "did:key:z6MkTest1",
    display_name: str = "Test Agent",
    agent_type: str = "autonomous",
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    capabilities: list[str] | None = None,
    description: str = "A test agent",
) -> AgentInventoryEntry:
    return AgentInventoryEntry(
        did=did,
        display_name=display_name,
        agent_type=agent_type,
        risk_level=risk_level,
        capabilities=capabilities or [],
        registered_at=datetime.now(UTC),
        description=description,
    )


# ---------------------------------------------------------------------------
# Unit tests: AgentInventory
# ---------------------------------------------------------------------------


def test_register_agent():
    inv = AgentInventory()
    entry = _make_entry()
    inv.register(entry)
    assert len(inv) == 1
    assert inv.get("did:key:z6MkTest1") is not None


def test_register_invalid_did_raises():
    inv = AgentInventory()
    entry = _make_entry(did="invalid-did")
    try:
        inv.register(entry)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_get_agent_by_did():
    inv = AgentInventory()
    entry = _make_entry(did="did:key:z6MkGetMe")
    inv.register(entry)
    result = inv.get("did:key:z6MkGetMe")
    assert result is not None
    assert result.display_name == "Test Agent"


def test_get_nonexistent_returns_none():
    inv = AgentInventory()
    assert inv.get("did:key:z6MkNope") is None


def test_list_all_agents():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkA"))
    inv.register(_make_entry(did="did:key:z6MkB"))
    inv.register(_make_entry(did="did:key:z6MkC"))
    assert len(inv.list_all()) == 3


def test_list_by_risk_level():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkLow", risk_level=RiskLevel.LOW))
    inv.register(_make_entry(did="did:key:z6MkMed", risk_level=RiskLevel.MEDIUM))
    inv.register(_make_entry(did="did:key:z6MkHigh", risk_level=RiskLevel.HIGH))
    low = inv.list_by_risk(RiskLevel.LOW)
    assert len(low) == 1
    assert low[0].did == "did:key:z6MkLow"


def test_update_agent_entry():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkUpd"))
    updated = inv.update("did:key:z6MkUpd", display_name="Updated Name")
    assert updated is not None
    assert updated.display_name == "Updated Name"
    assert inv.get("did:key:z6MkUpd").display_name == "Updated Name"


def test_update_nonexistent_returns_none():
    inv = AgentInventory()
    assert inv.update("did:key:z6MkNone", display_name="X") is None


def test_remove_agent():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkRm"))
    assert inv.remove("did:key:z6MkRm") is True
    assert inv.get("did:key:z6MkRm") is None
    assert len(inv) == 0


def test_remove_nonexistent_returns_false():
    inv = AgentInventory()
    assert inv.remove("did:key:z6MkNope") is False


def test_count_by_risk():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkL1", risk_level=RiskLevel.LOW))
    inv.register(_make_entry(did="did:key:z6MkL2", risk_level=RiskLevel.LOW))
    inv.register(_make_entry(did="did:key:z6MkH1", risk_level=RiskLevel.HIGH))
    counts = inv.count_by_risk()
    assert counts["low"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 0
    assert counts["critical"] == 0


def test_search_by_did():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkSearch1", display_name="Alpha"))
    inv.register(_make_entry(did="did:key:z6MkSearch2", display_name="Beta"))
    results = inv.search("Search1")
    assert len(results) == 1
    assert results[0].display_name == "Alpha"


def test_search_by_display_name():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkS1", display_name="Financial Bot"))
    inv.register(_make_entry(did="did:key:z6MkS2", display_name="Chat Bot"))
    results = inv.search("financial")
    assert len(results) == 1


def test_search_by_description():
    inv = AgentInventory()
    inv.register(_make_entry(did="did:key:z6MkD1", description="Handles payments"))
    inv.register(_make_entry(did="did:key:z6MkD2", description="Reads data"))
    results = inv.search("payments")
    assert len(results) == 1


# ---------------------------------------------------------------------------
# Route tests: compliance inventory endpoints
# ---------------------------------------------------------------------------


def test_inventory_post_and_get(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "inv.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        body = {
            "did": "did:key:z6MkRouteTest",
            "display_name": "Route Test Agent",
            "agent_type": "tool",
            "capabilities": ["data_read"],
            "registered_at": datetime.now(UTC).isoformat(),
        }
        r = c.post("/compliance/inventory", json=body)
        assert r.status_code == 200
        data = r.json()
        assert data["registered"] is True
        assert data["did"] == "did:key:z6MkRouteTest"

        # GET specific agent
        r2 = c.get("/compliance/inventory/did:key:z6MkRouteTest")
        assert r2.status_code == 200
        assert r2.json()["display_name"] == "Route Test Agent"


def test_inventory_get_nonexistent_returns_404(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "inv2.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get("/compliance/inventory/did:key:z6MkNope")
        assert r.status_code == 404


def test_inventory_list_all(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "inv3.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        for i in range(3):
            c.post(
                "/compliance/inventory",
                json={
                    "did": f"did:key:z6MkList{i}",
                    "display_name": f"Agent {i}",
                    "registered_at": datetime.now(UTC).isoformat(),
                },
            )
        r = c.get("/compliance/inventory")
        assert r.status_code == 200
        assert len(r.json()) == 3


def test_inventory_post_invalid_did_returns_400(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "inv4.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.post(
            "/compliance/inventory",
            json={
                "did": "bad-did",
                "display_name": "Bad",
                "registered_at": datetime.now(UTC).isoformat(),
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_did"


def test_compliance_disabled_hides_routes(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "inv5.lance"),
        compliance_enabled=False,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get("/compliance/inventory")
        assert r.status_code == 404
