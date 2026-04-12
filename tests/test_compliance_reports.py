"""Tests for compliance reports, FREE-AI mapping, and audit summary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from airlock.compliance.free_ai_mapper import RECOMMENDATION_MAP, SUTRAS, FreeAIMapper
from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory
from airlock.compliance.report_generator import ComplianceReportGenerator
from airlock.compliance.schemas import (
    AgentInventoryEntry,
    IncidentReport,
    RiskLevel,
)
from airlock.config import AirlockConfig
from airlock.gateway.app import create_app


def _make_entry(
    did: str = "did:key:z6MkRpt1",
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    compliance_status: str = "compliant",
) -> AgentInventoryEntry:
    return AgentInventoryEntry(
        did=did,
        display_name="Report Agent",
        risk_level=risk_level,
        registered_at=datetime.now(UTC),
        last_assessed_at=datetime.now(UTC),
        compliance_status=compliance_status,
    )


def _make_incident(
    incident_id: str = "INC-001",
    agent_did: str = "did:key:z6MkRpt1",
    severity: RiskLevel = RiskLevel.MEDIUM,
) -> IncidentReport:
    now = datetime.now(UTC)
    return IncidentReport(
        incident_id=incident_id,
        agent_did=agent_did,
        severity=severity,
        incident_type="bias",
        description="Test incident",
        detected_at=now,
        reported_at=now,
    )


# ---------------------------------------------------------------------------
# Unit tests: ComplianceReportGenerator
# ---------------------------------------------------------------------------


def test_generate_compliance_report():
    inv = AgentInventory()
    inc = IncidentStore()
    mapper = FreeAIMapper()
    gen = ComplianceReportGenerator(inv, inc, mapper)

    inv.register(_make_entry(did="did:key:z6MkR1"))
    inv.register(_make_entry(did="did:key:z6MkR2", risk_level=RiskLevel.HIGH))

    period_end = datetime.now(UTC)
    period_start = period_end - timedelta(days=30)
    report = gen.generate(period_start, period_end)

    assert report.total_agents == 2
    assert report.report_id != ""
    assert report.compliance_score >= 0.0
    assert report.compliance_score <= 100.0


def test_generate_per_agent_report():
    inv = AgentInventory()
    inc = IncidentStore()
    mapper = FreeAIMapper()
    gen = ComplianceReportGenerator(inv, inc, mapper)

    inv.register(_make_entry(did="did:key:z6MkPA1"))
    inc.report(_make_incident(incident_id="INC-PA1", agent_did="did:key:z6MkPA1"))

    period_end = datetime.now(UTC)
    period_start = period_end - timedelta(days=30)
    report = gen.generate_for_agent("did:key:z6MkPA1", period_start, period_end)

    assert report.total_agents == 1
    assert report.total_incidents == 1


def test_generate_report_with_empty_data():
    inv = AgentInventory()
    inc = IncidentStore()
    mapper = FreeAIMapper()
    gen = ComplianceReportGenerator(inv, inc, mapper)

    period_end = datetime.now(UTC)
    period_start = period_end - timedelta(days=30)
    report = gen.generate(period_start, period_end)

    assert report.total_agents == 0
    assert report.total_incidents == 0
    assert report.compliance_score >= 0.0


def test_audit_summary_generation():
    inv = AgentInventory()
    inc = IncidentStore()
    mapper = FreeAIMapper()
    gen = ComplianceReportGenerator(inv, inc, mapper)

    inv.register(_make_entry(did="did:key:z6MkAS1", compliance_status="compliant"))
    inv.register(_make_entry(did="did:key:z6MkAS2", compliance_status="non_compliant"))

    summary = gen.generate_audit_summary()
    assert summary["total_agents"] == 2
    assert summary["compliant_agents"] == 1
    assert summary["compliance_rate"] == 0.5
    assert summary["incident_chain_valid"] is True


# ---------------------------------------------------------------------------
# Unit tests: FreeAIMapper
# ---------------------------------------------------------------------------


def test_free_ai_mapping_completeness():
    """All mapped recommendations must reference a valid sutra."""
    for rec_id, rec_info in RECOMMENDATION_MAP.items():
        assert rec_info["sutra"] in SUTRAS, f"{rec_id} references unknown sutra"


def test_map_compliance_status():
    inv = AgentInventory()
    inc = IncidentStore()
    inv.register(_make_entry(did="did:key:z6MkMap1"))
    mapper = FreeAIMapper()
    mapping = mapper.map_compliance_status(inv, inc)

    assert len(mapping) == len(RECOMMENDATION_MAP)
    for rec_id in RECOMMENDATION_MAP:
        assert rec_id in mapping
        assert "status" in mapping[rec_id]


def test_get_recommendation_status_unknown_rec():
    inv = AgentInventory()
    inc = IncidentStore()
    mapper = FreeAIMapper()
    status = mapper.get_recommendation_status("rec_99", inv, inc)
    assert status["status"] == "unknown"


def test_sutra_summary():
    inv = AgentInventory()
    inc = IncidentStore()
    inv.register(_make_entry(did="did:key:z6MkSutra1"))
    mapper = FreeAIMapper()
    summary = mapper.get_sutra_summary(inv, inc)
    assert "sutra_1" in summary
    assert "sutra_2" in summary
    assert summary["sutra_1"]["name"] == "Governance & Oversight"


# ---------------------------------------------------------------------------
# Route tests: compliance report endpoints
# ---------------------------------------------------------------------------


def test_report_endpoint(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rpt.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get("/compliance/report?period_days=7")
        assert r.status_code == 200
        data = r.json()
        assert "report_id" in data
        assert "compliance_score" in data
        assert "free_ai_mapping" in data


def test_agent_report_endpoint(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rpt2.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        # Register an agent first
        c.post(
            "/compliance/inventory",
            json={
                "did": "did:key:z6MkRptAgent",
                "display_name": "Report Agent",
                "registered_at": datetime.now(UTC).isoformat(),
            },
        )
        r = c.get("/compliance/report/did:key:z6MkRptAgent?period_days=7")
        assert r.status_code == 200
        data = r.json()
        assert data["total_agents"] == 1


def test_audit_summary_endpoint(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rpt3.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get("/compliance/audit-summary")
        assert r.status_code == 200
        data = r.json()
        assert "total_agents" in data
        assert "incident_chain_valid" in data


def test_incident_post_and_list(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rpt4.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    now = datetime.now(UTC).isoformat()
    with TestClient(app) as c:
        r = c.post(
            "/compliance/incident",
            json={
                "incident_id": "INC-RT1",
                "agent_did": "did:key:z6MkIncAgent",
                "severity": "high",
                "incident_type": "unauthorized_action",
                "description": "Agent performed unauthorized data access",
                "detected_at": now,
                "reported_at": now,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["recorded"] is True
        assert data["incident_hash"] != ""

        r2 = c.get("/compliance/incidents")
        assert r2.status_code == 200
        assert len(r2.json()) == 1


def test_incident_invalid_did_returns_400(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rpt5.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    now = datetime.now(UTC).isoformat()
    with TestClient(app) as c:
        r = c.post(
            "/compliance/incident",
            json={
                "incident_id": "INC-BAD",
                "agent_did": "bad-did",
                "severity": "low",
                "incident_type": "bias",
                "description": "Test",
                "detected_at": now,
                "reported_at": now,
            },
        )
        assert r.status_code == 400
