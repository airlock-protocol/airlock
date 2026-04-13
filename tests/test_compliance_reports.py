from __future__ import annotations

"""Tests for compliance report generation and regulatory mapping."""

from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.compliance.regulatory_mapper import RECOMMENDATION_MAP, PRINCIPLES, RegulatoryMapper
from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory
from airlock.compliance.report_generator import ComplianceReportGenerator
from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel
from airlock.config import AirlockConfig
from airlock.gateway.app import create_app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(did: str, risk_level: RiskLevel = RiskLevel.MEDIUM) -> AgentInventoryEntry:
    return AgentInventoryEntry(
        did=did,
        display_name=f"Agent {did[-4:]}",
        risk_level=risk_level,
        trust_score=0.5,
        trust_tier=0,
    )


def _populated_inventory() -> AgentInventory:
    inv = AgentInventory()
    inv.register(_make_entry("did:key:z6MkA", RiskLevel.LOW))
    inv.register(_make_entry("did:key:z6MkB", RiskLevel.MEDIUM))
    inv.register(_make_entry("did:key:z6MkC", RiskLevel.HIGH))
    return inv


def _populated_incident_store() -> IncidentStore:
    store = IncidentStore()
    store.report("did:key:z6MkC", RiskLevel.HIGH, "unauthorized_access", "Breach attempt")
    store.report("did:key:z6MkB", RiskLevel.LOW, "config_drift", "Minor config change")
    return store


# ---------------------------------------------------------------------------
# Report generation tests
# ---------------------------------------------------------------------------


class TestComplianceReportGenerator:
    def test_generate_report(self) -> None:
        inv = _populated_inventory()
        store = _populated_incident_store()
        gen = ComplianceReportGenerator(inv, store)

        now = datetime.now(UTC)
        start = datetime(2020, 1, 1, tzinfo=UTC)
        report = gen.generate(start, now)

        assert report.total_agents == 3
        assert report.total_incidents == 2
        assert report.compliance_score > 0.0
        assert report.report_id != ""
        assert report.agents_by_risk.get("low") == 1
        assert report.agents_by_risk.get("high") == 1

    def test_generate_report_empty_data(self) -> None:
        inv = AgentInventory()
        store = IncidentStore()
        gen = ComplianceReportGenerator(inv, store)

        now = datetime.now(UTC)
        start = datetime(2020, 1, 1, tzinfo=UTC)
        report = gen.generate(start, now)

        assert report.total_agents == 0
        assert report.total_incidents == 0
        assert report.compliance_score == 100.0

    def test_generate_for_agent(self) -> None:
        inv = _populated_inventory()
        store = _populated_incident_store()
        gen = ComplianceReportGenerator(inv, store)

        now = datetime.now(UTC)
        start = datetime(2020, 1, 1, tzinfo=UTC)
        report = gen.generate_for_agent("did:key:z6MkC", start, now)

        assert report is not None
        assert report.total_agents == 1
        assert report.total_incidents == 1

    def test_generate_for_agent_not_found(self) -> None:
        inv = AgentInventory()
        store = IncidentStore()
        gen = ComplianceReportGenerator(inv, store)

        now = datetime.now(UTC)
        start = datetime(2020, 1, 1, tzinfo=UTC)
        report = gen.generate_for_agent("did:key:z6MkNonexistent", start, now)
        assert report is None

    def test_audit_summary(self) -> None:
        inv = _populated_inventory()
        store = _populated_incident_store()
        gen = ComplianceReportGenerator(inv, store)

        summary = gen.generate_audit_summary()
        assert summary["total_agents"] == 3
        assert summary["total_incidents"] == 2
        assert summary["open_incidents"] == 2
        assert summary["resolved_incidents"] == 0
        assert "incident_chain_hash" in summary

    def test_recommendations_with_critical_agents(self) -> None:
        inv = AgentInventory()
        inv.register(_make_entry("did:key:z6MkX", RiskLevel.CRITICAL))
        store = IncidentStore()
        gen = ComplianceReportGenerator(inv, store)

        now = datetime.now(UTC)
        start = datetime(2020, 1, 1, tzinfo=UTC)
        report = gen.generate(start, now)

        assert any("critical risk" in r for r in report.recommendations)


# ---------------------------------------------------------------------------
# Regulatory Mapper tests
# ---------------------------------------------------------------------------


class TestRegulatoryMapper:
    def test_principles_defined(self) -> None:
        assert len(PRINCIPLES) == 7
        assert "principle_1" in PRINCIPLES

    def test_recommendation_map_has_entries(self) -> None:
        assert len(RECOMMENDATION_MAP) > 0
        for rec_id, rec_data in RECOMMENDATION_MAP.items():
            assert "title" in rec_data
            assert "airlock_feature" in rec_data
            assert "principle" in rec_data

    def test_map_compliance_status(self) -> None:
        inv = _populated_inventory()
        store = _populated_incident_store()
        mapper = RegulatoryMapper()

        result = mapper.map_compliance_status(inv, store)
        assert result["framework"] == "airlock-compliance"
        assert "principles" in result
        assert "recommendations" in result
        assert result["total_agents_tracked"] == 3

    def test_map_compliance_status_empty(self) -> None:
        inv = AgentInventory()
        store = IncidentStore()
        mapper = RegulatoryMapper()

        result = mapper.map_compliance_status(inv, store)
        assert result["total_agents_tracked"] == 0

    def test_get_recommendation_status(self) -> None:
        mapper = RegulatoryMapper()
        inv = _populated_inventory()

        status = mapper.get_recommendation_status("rec_01", inventory=inv)
        assert status["implemented"] is True
        assert status["active"] is True

    def test_get_recommendation_status_unknown(self) -> None:
        mapper = RegulatoryMapper()
        status = mapper.get_recommendation_status("rec_999")
        assert "error" in status


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------


@pytest.fixture
def report_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "comp_rpt.lance"),
        compliance_enabled=True,
    )


@pytest.fixture
async def report_app(report_config):
    app = create_app(report_config)
    async with LifespanManager(app):
        yield app


async def test_route_generate_report(report_app):
    transport = ASGITransport(app=report_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/report")
    assert r.status_code == 200
    body = r.json()
    assert "report_id" in body
    assert "compliance_score" in body


async def test_route_agent_report_not_found(report_app):
    transport = ASGITransport(app=report_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/report/did:key:z6MkNonexistent")
    assert r.status_code == 404


async def test_route_audit_summary(report_app):
    transport = ASGITransport(app=report_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/audit-summary")
    assert r.status_code == 200
    body = r.json()
    assert "total_agents" in body
    assert "total_incidents" in body


async def test_route_report_incident_and_list(report_app):
    transport = ASGITransport(app=report_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/compliance/incident",
            json={
                "agent_did": "did:key:z6MkIncident",
                "severity": "high",
                "incident_type": "data_breach",
                "description": "Unauthorized data access",
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["severity"] == "high"
        assert body["incident_hash"] != ""

        r2 = await client.get("/compliance/incidents")
        assert r2.status_code == 200
        assert r2.json()["total"] == 1
